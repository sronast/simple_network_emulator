import os
import json
import portalocker
import errno
import sys
import socket
import pickle
import select
import threading
import time
from queue import Queue
from utils import *

class ARPPacket:
    def __init__(self, operation, sender_ip, sender_mac, target_ip, target_mac=None):
        self.operation = operation
        self.sender_ip = sender_ip
        self.sender_mac = sender_mac
        self.target_ip = target_ip
        self.target_mac = target_mac

# ARPCache class
class ARPCache:
    def __init__(self):
        self.cache = {}

    def add_mapping(self, ip_address, mac_address):
        self.cache[ip_address] = mac_address

    def get_mac_address(self, ip_address):
        return self.cache.get(ip_address, None)

# RoutingTable class
class RoutingTable:
    def __init__(self):
        self.table = {}

    def add_entry(self, destination, next_hop):
        self.table[destination] = next_hop

    def get_next_hop(self, destination):
        return self.table.get(destination, None)

# Function to create a data frame
def create_frame(source_mac, destination_mac, message):
    # frame = {
    #     'type': type,
    #     'payload': {
    #         'source_mac': source_mac,
    #         'destination_mac': destination_mac,
    #         'message': message,
    #     }
    frame = {
        'source_mac': source_mac,
        'destination_mac': destination_mac,
        'message': message,
    }
    return pickle.dumps(frame)

# Function to create an ARP request
def create_arp_request(sender_ip, sender_mac, target_ip, target_mac):
    arp_request = {
        'type': 'request',
        'sender_ip': sender_ip,
        'sender_mac': sender_mac,
        'target_ip': target_ip,
        'target_mac': target_mac,
    }
    return pickle.dumps(arp_request)

class PendingQueue:
    def __init__(self, next_hop_ipaddr, dst_ipaddr, pending_pkt):
        self.next_hop_ipaddr = next_hop_ipaddr
        self.dst_ipaddr = dst_ipaddr
        self.pending_pkt = pending_pkt
        self.next = None

class Station:
    def __init__(self, interface_file, routingtable_file, hostname_file):
        self.hostname_mapping = load_json_file(hostname_file)
        self.interface_info = load_json_file(interface_file)
        self.routing_table = load_json_file(routingtable_file)
        self.station_name = self.interface_info["stations"][0]
        self.my_username = self.interface_info[self.station_name]['ip']
        self.ip_address = self.interface_info[self.station_name]['ip']
        self.mac_address = self.interface_info[self.station_name]['mac']
        self.pending_queue = Queue()
        self.arp_table = ARPCache()
        self.forwarding_table = RoutingTable()
        self.HOST = socket.gethostbyname('localhost')
        self.LENGTH = 4096
        self.all_connections = set()
        self.connected_lans = {}
        self.read_sockets = None
        self.time_out = 2 #seconds
        self.client_socket = None
        return
    
    def connect_to_lans(self):
        print("Name: ", self.interface_info["stations"][0])
        for interface in self.interface_info["stations"]:
            bridge_name = self.interface_info[interface]["lan"]
            #check if there is an active lan with lan_name
            all_bridges = load_json_file('all_lans.json')
            if bridge_name not in all_bridges:
                print("No active lan with the given name")
                sys.exit(0)
            lan_info = load_json_file(f'bridge_{bridge_name}.json')
            bridge_ip = lan_info['ip']
            bridge_port = lan_info['port']
            print(f'Bridge ip: {bridge_ip} Bridge port: {bridge_port}')
            try:
                # Initialize a TCP socket connection to the bridge
                sock =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # self.set_socket_nonblocking(sock)
                retries = 5
                wait_time = 2  # seconds
                for _ in range(retries):
                    sock.connect((bridge_ip, int(bridge_port)))
                    self.all_connections.add(sock)
                    self.client_socket = sock
                    response = sock.recv(self.LENGTH)
                    response = pickle.loads(response)
                    if response['message'] == 'accept':
                        self.connected_lans[interface] = sock
                        print(f"Connected to {bridge_name} on interface {interface}")
                        break
                    elif response['message'] == 'reject':
                        print('The connection cannot be established')
                        sys.exit(0)
                    else:
                        print(f"Connection to {bridge_name} on interface {interface} rejected..\nRetrying...")
                    time.sleep(wait_time)                       
            except Exception as e:
                print(f"Error connecting to {bridge_name}: {e}")
                sys.exit(0)
        return
    
    def set_socket_nonblocking(self, sock):
        # Set the socket to non-blocking mode
        flags = portalocker.LOCK_NB
        portalocker.lock(sock, flags)
        return
    
    def create_ip_packet(self, source_ip, destination_ip, message):
        ip_packet = {
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'message': message,
        }
        return json.dumps(ip_packet).encode('utf-8')
    
    def get_frame_type(self, received_frame):
        try:
            frame = pickle.loads(received_frame)    
            if 'type' in frame:
                frame_type = frame['type']
                if frame_type == 'IP':
                    return 'IP'
                elif frame_type == 'ARP':
                    return 'ARP'
                else:
                    pass
        except Exception as e:
            print(f"Error parsing frame: {e}")
            return 'Error'
    
    def process_frame(self, frame):
        source_mac = frame['payload']['source_mac']
        destination_mac = frame['payload']['destination_mac']
        message = frame['payload']['message']
        if destination_mac == self.mac_address:
            print(f"Received message: {message} from {source_mac}")
        else:
            print(f"Received frame intended for {destination_mac}. Discarding.")
        return source_mac, destination_mac, message
    
    def receive_frame(self):
        try:
            retries = 5
            wait_time = 2 
            for _ in range(retries):
                message = self.client_socket.recv(self.LENGTH)
                received_frame = message
                if received_frame:
                    return received_frame
                else:
                    time.sleep(wait_time)
        except socket.timeout:
            pass
        return received_frame
    
    def send_frame(self, frame):
        self.client_socket.send(frame)

    def send_arp_request(self, destination_ip):
        # Check if the destination IP is in the ARP cache
        destination_mac = self.arp_table.get_mac_address(destination_ip)
        if destination_mac is not None:
            # If MAC address is known, no need to send ARP request, send the IP packet directly
            self.encapsulate_ip_packet(destination_ip, "Your message here")
        else:
            # If MAC address is not known, send an ARP request to discover it
            arp_request = create_arp_request(self.ip_address, self.mac_address, destination_ip, destination_mac)
            self.client_socket.send(arp_request)
            print(f"ARP request sent for {destination_ip}. Waiting for ARP reply...")
            # Wait for ARP reply
            received_frame = self.receive_frame()
            if received_frame:
                frame_type = self.get_frame_type(received_frame)
                if frame_type == "ARP":
                    # Process ARP reply
                    arp_reply = self.extract_arp_packet(received_frame)
                    if arp_reply.operation == "reply":
                        # Store the mapping between source IP and MAC address in ARP cache
                        self.arp_table.add_mapping(arp_reply.sender_ip, arp_reply.sender_mac)
                        # Check pending queue for IP packets waiting for ARP resolution
                        if not self.pending_queue.empty():
                            pending_ip_packet = self.pending_queue.get()
                            self.encapsulate_ip_packet(
                                pending_ip_packet['destination_ip'], pending_ip_packet['message']
                            )
                    else:
                        print("Received unexpected ARP frame.")
                else:
                    print("Received unexpected frame while waiting for ARP reply.")
            else:
                print("No response received for the ARP request.")
    
    def arp_reply(self, target_ip, target_mac):
        # Serialize the ARP reply packet
        arp_reply_frame = create_arp_request(self.ip_address, self.mac_address, target_ip, target_mac)
        # Send the ARP reply to the source
        self.send_to_mac_layer(target_mac, arp_reply_frame)
    
    def arp_request(self, destination_ip):
        arp_request = create_arp_request(self.ip_address, self.mac_address, destination_ip, None)
        self.client_socket.send(arp_request)
    
    def send_to_mac_layer(self, destination_mac, ip_packet):
        # Construct a frame using the destination MAC address and the IP packet
        frame = create_frame(self.mac_address, destination_mac, ip_packet)
        
        # Assuming you have a method to send the frame over the network
        self.send_frame(frame)
    
    def encapsulate_ip_packet(self, destination_ip, message):
        # Consult the forwarding table to determine the next-hop IP address
        next_hop_ip = self.forwarding_table.get_next_hop(destination_ip)
        # Use ARP to find the MAC address of the next-hop router or destination
        next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)
        if next_hop_mac is None:
            # If MAC address is not known, send an ARP request to discover it
            self.arp_request(next_hop_ip)
            # Wait for ARP reply (you may need to implement a timeout)
            next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)
        # Create the IP packet and pass it to the MAC layer for further encapsulation
        ip_packet = self.create_ip_packet(destination_ip, next_hop_ip, message)
        self.send_to_mac_layer(next_hop_mac, ip_packet)
    
    def enqueue_pending_ip_packet(self, destination_ip, message):
        # Enqueue the IP packet for which ARP resolution is pending
        pending_ip_packet = {'destination_ip': destination_ip, 'message': message}
        self.pending_queue.put(pending_ip_packet)

    def dequeue_pending_ip_packet(self):
        # Dequeue and return the next pending IP packet
        if not self.pending_queue.empty():
            return self.pending_queue.get()
        else:
            return None
        
    def process_pending_queue(self):
        # Process all pending IP packets in the queue
        while not self.pending_queue.empty():
            pending_ip_packet = self.dequeue_pending_ip_packet()
            if pending_ip_packet:
                self.encapsulate_ip_packet(pending_ip_packet['destination_ip'], pending_ip_packet['message'])
    
    def extract_arp_packet(self, frame):
        ip_packet = pickle.loads(frame)
        return ip_packet
    
    def process_arp_packet(self, arp_packet):
        if arp_packet.operation == "request":
            if arp_packet.target_ip == self.ip_address:
                # This station is the target of the ARP request
                # Send ARP reply back to the source with a local MAC address
                self.arp_reply(arp_packet.sender_ip, arp_packet.sender_mac)
        elif arp_packet.operation == "reply":
            # Store the mapping between source IP and MAC address in ARP cache
            self.arp_table.add_mapping(arp_packet.sender_ip, arp_packet.sender_mac)
            # Process pending queue for IP packets waiting for ARP resolution
            self.process_pending_queue()

    def extract_ip_packet(self, frame):
        ip_packet = pickle.loads(frame)
        return ip_packet
    
    def process_ip_packet(self, ip_packet):
        destination_ip = ip_packet['destination_ip']
        source_ip = ip_packet['source_ip']
        message = ip_packet['message']

        if destination_ip == self.ip_address:
            # This station is the intended recipient of the IP packet
            print(f"Received IP packet: {message} from {source_ip}")
        else:
            # Check if we know the next hop for the destination IP
            next_hop_ip = self.forwarding_table.get_next_hop(destination_ip)

            if next_hop_ip:
                next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)

                if next_hop_mac:
                    # We have the MAC address, send the IP packet to the next hop
                    self.send_to_mac_layer(next_hop_mac, ip_packet)
                else:
                    # We don't have the MAC address, send an ARP request
                    self.arp_request(next_hop_ip)
                    # Wait for ARP reply (may need to implement a timeout)
                    next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)

                    if next_hop_mac:
                        # If MAC address is obtained, send the IP packet
                        self.send_to_mac_layer(next_hop_mac, ip_packet)
                    else:
                        # MAC address is still not known, enqueue the packet for later
                        self.enqueue_pending_ip_packet(destination_ip, message)
            else:
                # No route found for the destination IP, drop the packet
                print(f"No route found for {destination_ip}. Packet dropped.")

    def send_messages(self):
        while True:
            # Simulate user input
            user_input = input("Enter message: ")
            destination_ip = input("Enter destination IP: ")
            self.send_message(destination_ip, user_input)

    def send_message(self, destination_ip, message):
        destination_mac = self.arp_table.get_mac_address(destination_ip)
        if destination_mac:
            frame = create_frame(self.mac_address, destination_mac, message)
            # Assuming self.client_socket is your socket for communication
            self.client_socket.send(frame)
        else:
            self.send_arp_request(destination_ip)
            self.pending_queue.put({'destination_ip': destination_ip, 'message': message})
    
    def start(self):
        self.connect_to_lans()

    def main_loop(self):
        try:
            self.possible_inputs = list(self.all_connections)

            # Start a thread for sending user messages
            threading.Thread(target=self.send_messages).start()

            while True:
                # Check for incoming frames
                received_frame = self.receive_frame()
                if received_frame:
                    frame_type = self.get_frame_type(received_frame)
                    if frame_type == "IP":
                        # Process IP packet
                        ip_packet = self.extract_ip_packet(received_frame)
                        self.process_ip_packet(ip_packet)
                    elif frame_type == "ARP":
                        # Process ARP packet
                        arp_packet = self.extract_arp_packet(received_frame)
                        self.process_arp_packet(arp_packet)

                # Check pending queue for IP packets waiting for ARP resolution
                if not self.pending_queue.empty():
                    pending_ip_packet = self.pending_queue.get()
                    self.encapsulate_ip_packet(pending_ip_packet['destination_ip'], pending_ip_packet['message'])

        except ConnectionRefusedError:
            print("Connection to the bridge refused. Exiting...")
        finally:
            # Cleanup tasks if needed
            pass            

    def close(self):
        self.client_socket.close()

class Router:
    def __init__(self, interface_file, routingtable_file, hostname_file):
        self.hostname_mapping = load_json_file(hostname_file)
        self.interface_info = load_json_file(interface_file)
        self.routing_table = load_json_file(routingtable_file)
        self.station_name = self.interface_info["stations"][0]
        self.my_username = self.interface_info[self.station_name]['ip']
        self.ip_address = self.interface_info[self.station_name]['ip']
        self.mac_address = self.interface_info[self.station_name]['mac']
        self.pending_queue = Queue()
        self.arp_table = ARPCache()
        self.forwarding_table = RoutingTable()
        self.HOST = socket.gethostbyname('localhost')
        self.LENGTH = 4096
        self.all_connections = set()
        self.connected_lans = {}
        self.read_sockets = None
        self.time_out = 2 #seconds
        self.client_socket = None
        self.connected_bridges = {}

    def connect_to_bridges(self):
        print("Name: ", self.interface_info["stations"][0])
        for interface in self.interface_info["stations"]:
            bridge_name = self.interface_info[interface]["lan"]
            #check if there is an active lan with lan_name
            all_bridges = load_json_file('all_lans.json')
            if bridge_name not in all_bridges:
                print("No active lan with the given name")
                sys.exit(0)
            lan_info = load_json_file(f'bridge_{bridge_name}.json')
            bridge_ip = lan_info['ip']
            bridge_port = lan_info['port']
            print(f'Bridge ip: {bridge_ip} Bridge port: {bridge_port}')
            try:
                # Initialize a TCP socket connection to the bridge
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM).settimeout(self.time_out) as sock:
                    self.set_socket_nonblocking(sock)
                    retries = 5
                    wait_time = 2  # seconds
                    for _ in range(retries):
                        sock.connect((bridge_ip, int(bridge_port)))
                        self.client_socket = sock
                        self.all_connections.add(sock)
                        response = sock.recv(self.LENGTH)
                        response = pickle.loads(response)
                        if response['message'] == 'accept':
                            self.connected_lans[interface] = sock
                            print(f"Connected to {bridge_name} on interface {interface}")
                            break
                        elif response['message'] == 'reject':
                            print('The connection cannot be established')
                            sys.exit(0)
                        else:
                            print(f"Connection to {bridge_name} on interface {interface} rejected..\nRetrying...")
                        time.sleep(wait_time)                       
            except Exception as e:
                print(f"Error connecting to {bridge_name}: {e}")
                sys.exit(0)
        return
    
    def set_socket_nonblocking(self, sock):
        # Set the socket to non-blocking mode
        flags = portalocker.LOCK_NB
        portalocker.lock(sock, flags)
        return
    
    def create_ip_packet(self, source_ip, destination_ip, message):
        ip_packet = {
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'message': message,
        }
        return json.dumps(ip_packet).encode('utf-8')
    
    def get_frame_type(self, received_frame):
        try:
            frame = pickle.loads(received_frame)    
            if 'type' in frame:
                frame_type = frame['type']
                if frame_type == 'IP':
                    return 'IP'
                elif frame_type == 'ARP':
                    return 'ARP'
                else:
                    pass
        except Exception as e:
            print(f"Error parsing frame: {e}")
            return 'Error'
    
    def process_frame(self, frame):
        source_mac = frame['payload']['source_mac']
        destination_mac = frame['payload']['destination_mac']
        message = frame['payload']['message']
        if destination_mac == self.mac_address:
            print(f"Received message: {message} from {source_mac}")
        else:
            print(f"Received frame intended for {destination_mac}. Discarding.")
        return source_mac, destination_mac, message
    
    def receive_frame(self):
        try:
            print('In recv frame')
            message = self.client_socket.recv(self.LENGTH)
            received_frame = message
            # frame = pickle.loads(message)
            # source_mac, destination_mac, message = self.process_frame(frame)
        except socket.timeout:
            pass
        return received_frame
    
    def send_frame(self, frame):
        self.client_socket.send(frame)

    def send_arp_request(self, destination_ip):
        # Check if the destination IP is in the ARP cache
        destination_mac = self.arp_table.get_mac_address(destination_ip)

        if destination_mac is not None:
            # If MAC address is known, no need to send ARP request, send the IP packet directly
            self.encapsulate_ip_packet(destination_ip, "Your message here")
        else:
            # If MAC address is not known, send an ARP request to discover it
            arp_request = create_arp_request(self.ip_address, self.mac_address, destination_ip)
            # Assuming self.client_socket is your socket for communication
            self.client_socket.send(arp_request)
            print(f"ARP request sent for {destination_ip}. Waiting for ARP reply...")

            # Wait for ARP reply (you may need to implement a timeout mechanism)
            # For simplicity, I'll use a blocking call here, you might want to handle it differently
            received_frame = self.receive_frame()

            if received_frame:
                frame_type = self.get_frame_type(received_frame)

                if frame_type == "ARP":
                    # Process ARP reply
                    arp_reply = self.extract_arp_packet(received_frame)

                    if arp_reply.operation == "reply":
                        # Store the mapping between source IP and MAC address in ARP cache
                        self.arp_table.add_mapping(arp_reply.sender_ip, arp_reply.sender_mac)

                        # Check pending queue for IP packets waiting for ARP resolution
                        if not self.pending_queue.empty():
                            pending_ip_packet = self.pending_queue.get()
                            self.encapsulate_ip_packet(
                                pending_ip_packet['destination_ip'], pending_ip_packet['message']
                            )
                    else:
                        print("Received unexpected ARP frame.")

                else:
                    print("Received unexpected frame while waiting for ARP reply.")
            else:
                print("No response received for the ARP request. Consider implementing a timeout.")
    
    def arp_reply(self, target_ip, target_mac):
        # Assuming target_mac is the MAC address of the station that sent the ARP request
        
        # Serialize the ARP reply packet
        arp_reply_frame = create_arp_request(self.ip_address, self.mac_address, target_ip, target_mac)

        # Send the ARP reply to the source
        self.send_to_mac_layer(target_mac, arp_reply_frame)
    
    def arp_request(self, destination_ip):
        arp_request = create_arp_request(self.ip_address, self.mac_address, destination_ip)
        self.client_socket.send(arp_request)
    
    def send_to_mac_layer(self, destination_mac, ip_packet):
        # Construct a frame using the destination MAC address and the IP packet
        frame = create_frame(self.mac_address, destination_mac, ip_packet)
        
        # Assuming you have a method to send the frame over the network
        self.send_frame(frame)
    
    def encapsulate_ip_packet(self, destination_ip, message):
        # Create an IP packet with header and message
        # Consult the forwarding table to determine the next-hop IP address
        next_hop_ip = self.forwarding_table.get_next_hop(destination_ip)

        # Use ARP to find the MAC address of the next-hop router or destination
        next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)

        if next_hop_mac is None:
            # If MAC address is not known, send an ARP request to discover it
            self.arp_request(next_hop_ip)
            # Wait for ARP reply (you may need to implement a timeout)
            next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)

        # Create the IP packet and pass it to the MAC layer for further encapsulation
        ip_packet = self.create_ip_packet(destination_ip, next_hop_ip, message)
        self.send_to_mac_layer(next_hop_mac, ip_packet)
    
    def enqueue_pending_ip_packet(self, destination_ip, message):
        # Enqueue the IP packet for which ARP resolution is pending
        pending_ip_packet = {'destination_ip': destination_ip, 'message': message}
        self.pending_queue.put(pending_ip_packet)

    def dequeue_pending_ip_packet(self):
        # Dequeue and return the next pending IP packet
        if not self.pending_queue.empty():
            return self.pending_queue.get()
        else:
            return None
        
    def process_pending_queue(self):
        # Process all pending IP packets in the queue
        while not self.pending_queue.empty():
            pending_ip_packet = self.dequeue_pending_ip_packet()
            if pending_ip_packet:
                self.encapsulate_ip_packet(pending_ip_packet['destination_ip'], pending_ip_packet['message'])
    
    def extract_arp_packet(self, frame):
        ip_packet = pickle.loads(frame)
        return ip_packet
    
    def process_arp_packet(self, arp_packet):
        if arp_packet.operation == "request":
            if arp_packet.target_ip == self.ip_address:
                # This station is the target of the ARP request
                # Send ARP reply back to the source with a local MAC address
                self.arp_reply(arp_packet.sender_ip, arp_packet.sender_mac)

        elif arp_packet.operation == "reply":
            # Store the mapping between source IP and MAC address in ARP cache
            self.arp_table.add_mapping(arp_packet.sender_ip, arp_packet.sender_mac)

            # Process pending queue for IP packets waiting for ARP resolution
            self.process_pending_queue()

    def extract_ip_packet(self, frame):
        ip_packet = pickle.loads(frame)
        return ip_packet
    
    def process_ip_packet(self, ip_packet):
        destination_ip = ip_packet['destination_ip']
        source_ip = ip_packet['source_ip']
        message = ip_packet['message']

        if destination_ip == self.ip_address:
            # This station is the intended recipient of the IP packet
            print(f"Received IP packet: {message} from {source_ip}")
        else:
            # Check if we know the next hop for the destination IP
            next_hop_ip = self.forwarding_table.get_next_hop(destination_ip)

            if next_hop_ip:
                next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)

                if next_hop_mac:
                    # We have the MAC address, send the IP packet to the next hop
                    self.send_to_mac_layer(next_hop_mac, ip_packet)
                else:
                    # We don't have the MAC address, send an ARP request
                    self.arp_request(next_hop_ip)
                    # Wait for ARP reply (may need to implement a timeout)
                    next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)

                    if next_hop_mac:
                        # If MAC address is obtained, send the IP packet
                        self.send_to_mac_layer(next_hop_mac, ip_packet)
                    else:
                        # MAC address is still not known, enqueue the packet for later
                        self.enqueue_pending_ip_packet(destination_ip, message)
            else:
                # No route found for the destination IP, drop the packet
                print(f"No route found for {destination_ip}. Packet dropped.")

    def send_to_bridge(self, interface, req):
        ip_address = self.hostname_mapping[interface]
        bridge_name = self.interface_info[interface]["lan"]
        # Check if there is an active LAN with the given name
        all_bridges = load_json_file('all_lans.json')
        if bridge_name not in all_bridges:
            print("No active LAN with the given name")
            sys.exit(0)
        lan_info = load_json_file(f'bridge_{bridge_name}.json')
        bridge_port = lan_info.get('port')
        print(f'Interface IP: {ip_address}, Bridge Port: {bridge_port}')
        if ip_address and bridge_port:
            try:
                # Initialize a TCP socket connection to the bridge
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    self.set_socket_nonblocking(s)
                    s.connect((ip_address, int(bridge_port)))
                    retries = 5
                    wait_time = 2  # seconds
                    for _ in range(retries):
                        ready_to_read, _, _ = select.select([s], [], [], wait_time)
                        if ready_to_read:
                            response = s.recv(self.LENGTH).decode('utf-8')
                            if response == 'accept':
                                self.connected_bridges[interface] = s
                                print(f"Connected to {bridge_name} on interface {interface}")
                                s.send(req)
                                print("Request sent")
                                break
                            else:
                                print(f"Connection to {bridge_name} on interface {interface} rejected")
                                break
                        else:
                            print(f"Retrying connection to {bridge_name} on interface {interface}")
                    else:
                        print(f"Failed to connect to {bridge_name} on interface {interface}")
            except Exception as e:
                print(f"Error connecting to {bridge_name}: {e}")

    def forward_packet(self, destination_ip, message):
        # Decide which interface to use based on the routing table
        interface = self.get_routing_interface(destination_ip)
        if interface:
            destination_mac = self.arp_table.get_mac_address(destination_ip)
            if destination_mac:
                frame = create_frame(self.mac_address, destination_mac, message)
                self.connected_bridges[interface].send(frame)
            else:
                req = create_arp_request(self.ip_address, self.mac_address, destination_ip)
                self.send_to_bridge(interface, req)
                self.pending_queue.put({'destination_ip': destination_ip, 'message': message})
        else:
            print(f"No route found for {destination_ip}. Packet dropped.")

    def get_routing_interface(self, destination_ip):
        interface = None
        for entry in self.routing_table.items():
            destination, route_info = entry
            if destination == destination_ip:
                interface = route_info['next_interface']
        return interface

    def start(self):
        self.connect_to_bridges()

    def main_loop(self):
        try:
            while True:
                # Code to receive frames and determine the type (IP or ARP)
                received_frame = self.receive_frame()
                if received_frame:
                    frame_type = self.get_frame_type(received_frame)
                    if frame_type == "IP":
                        # Process IP packet
                        ip_packet = self.extract_ip_packet(received_frame)
                        destination_ip = ip_packet['destination_ip']
                        message = ip_packet['message']
                        self.forward_packet(destination_ip, message)
                    elif frame_type == "ARP":
                        # Process ARP packet
                        arp_packet = self.extract_arp_packet(received_frame)
                        self.process_arp_reply(arp_packet)

        except KeyboardInterrupt:
            print("Router shutting down.")

    def close(self):
        self.client_socket.close()

if __name__ == '__main__':
    assert len(sys.argv) == 5, 'Usage: python station.py -no/route interface routingtable hostname'
    is_router = sys.argv[1] == "-route"

    inerface_file = sys.argv[2]
    routingtable_file = sys.argv[3]
    hostname_file = sys.argv[4]

    # is_router = input("Is this station a router? (y/n): ").lower() == 'y'

    if is_router:
        router = Router(inerface_file, routingtable_file, hostname_file)
        router.start()
        router.main_loop()
        router.close()
    else:
        station = Station(inerface_file, routingtable_file, hostname_file)
        station.start()
        station.main_loop()
        station.close()