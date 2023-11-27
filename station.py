import os
import json
import fcntl
import errno
import sys
import socket
import pickle
import select
import threading
import time
from queue import Queue
from utils import *

HEADER_LENGTH = 1024

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
    frame = {
        'source_mac': source_mac,
        'destination_mac': destination_mac,
        'message': message,
    }
    return pickle.dumps(frame)

# Function to create an ARP request
def create_arp_request(sender_ip, sender_mac, target_ip):
    arp_request = {
        'type': 'request',
        'sender_ip': sender_ip,
        'sender_mac': sender_mac,
        'target_ip': target_ip,
    }
    return pickle.dumps(arp_request)

class Station:
    def __init__(self, interface_file, routingtable_file, hostname_file):

        ##RS##

        '''
        Hostname mapping
        {
             "A": "128.252.11.23",
             "Acs1": "128.252.11.23",
             "D": "128.252.13.67",
        }
        '''
        self.hostname_mapping = load_json_file(hostname_file)
        ###########
        
        '''
        Station info
            {   
                "stations":["D"],
                "D": {
                    "ip":"128.252.13.67",
                    "mask":"255.255.255.224",
                    "mac":"00:00:0C:04:52:67",
                    "lan":"cs3"
                }
            }
        '''
        self.station_info = load_json_file(interface_file)

        '''
        -----Routing table----
        #key is the destination network prefix
        {
            "128.252.11.0":{
                            "next_hop":"0.0.0.0",
                            "mask":"255.255.255.0",
                            "next_interface":"R1-cs1"
                            },
            "128.252.13.32":{"next_hop":"0.0.0.0","mask":"255.255.255.224","next_interface":"R1-cs2"},
            "128.252.13.64":{"next_hop":"128.252.13.38","mask":"255.255.255.224","next_interface":"R1-cs2"}
}
        
        '''    


        self.routing_table = load_json_file(routingtable_file)
        # --------RS-------- #

        #if station has only one ip
        '''Need to handle case where 2 ips are associated with a station'''
        self.station_name = self.station_info["stations"][0]

        self.my_username = self.station_info[self.station_name]['ip']
        self.ip_address = self.station_info[self.station_name]['ip']
        self.mac_address = self.station_info[self.station_name]['mac']
        self.pending_queue = Queue()
        self.arp_table = ARPCache()
        self.forwarding_table = RoutingTable()
        self.HOST = socket.gethostbyname('localhost')
        self.LENGTH = 4096
        self.all_connections = set()
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.settimeout(2)
        self.hostname_mapping = {}
        self.connected_lans = {}

        # self.lan_name = self.station_info[station]["lan"]
        # self.host_name = load_from_json_file('hostname.json')
        # self.routing_table = load_from_json_file('routingtable.json')
        # self.interface_info = load_from_json_file('interface.json')

    def main_loop(self):
        threading.Thread(target=self.send_arp_requests).start()

        while True:
            # Simulate user input
            user_input = input("Enter message: ")
            destination_ip = input("Enter destination IP: ")
            self.send_message(destination_ip, user_input)

            # Simulate receiving frames
            time.sleep(1)
            self.receive_frame()
            
            # Check for incoming Ethernet frames
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

    def process_arp_packet(self, arp_packet):
        if arp_packet.operation == "request":
            if arp_packet.target_ip == self.ip_address:
                # This station is the target of the ARP request
                # Send ARP reply back to the source with a local MAC address
                self.arp_reply(arp_packet.sender_ip, arp_packet.sender_mac)

        elif arp_packet.operation == "reply":
            # Store the mapping between source IP and MAC address in ARP cache
            self.arp_table.add_mapping(arp_packet.sender_ip, arp_packet.sender_mac)

            # Check pending queue for IP packets waiting for ARP resolution
            if not self.pending_queue.empty():
                pending_ip_packet = self.pending_queue.get()
                self.encapsulate_ip_packet(pending_ip_packet['destination_ip'], pending_ip_packet['message'])

    def encapsulate_ip_packet(self, destination_ip, message):
        # Create an IP packet with header and message
        # Consult the forwarding table to determine the next-hop IP address
        next_hop_ip = self.forwarding_table.get_next_hop(destination_ip)

        # Use ARP to find the MAC address of the next-hop router or destination
        next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)

        if next_hop_mac is None:
            # If MAC address is not known, send an ARP request to discover it
            self.arp_request(next_hop_ip)
            # Wait for ARP reply (may need to implement a timeout)
            next_hop_mac = self.arp_table.get_mac_address(next_hop_ip)

        # Create the IP packet and pass it to the MAC layer for further encapsulation
        ip_packet = self.create_ip_packet(destination_ip, next_hop_ip, message)
        self.send_to_mac_layer(next_hop_mac, ip_packet)

    def enqueue_pending_ip_packet(self, destination_ip, message):
        # Enqueue the IP packet for which ARP resolution is pending
        self.pending_queue.put({'destination_ip': destination_ip, 'message': message})
        
    def set_socket_nonblocking(self, sock):
        # Set the socket to non-blocking mode
        flags = fcntl.fcntl(sock, fcntl.F_GETFL)
        fcntl.fcntl(sock, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def connect_to_lans(self):
        ####### RS ######
        print('in connect to lans')
        for interface in self.station_info["stations"]:
            bridge_name = self.station_info[interface]["lan"]
            #check if there is an active lan with lan_name
            all_bridges = load_json_file('all_lans.json')
            if bridge_name not in all_bridges:
                print("No active lan with the given name")
                sys.exit(0)
            lan_info = load_json_file(f'bridge_{bridge_name}.json')
            bridge_ip = lan_info['ip']
            bridge_port = lan_info['port']
            print('all info gathered')
            print(f'Bridge ip: {bridge_ip} Bridge port: {bridge_port}')
            try:
                    # Initialize a TCP socket connection to the bridge
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        # self.set_socket_nonblocking(s)

                        response = s.connect((bridge_ip, int(bridge_port)))
                        print('Connected to bridge ----------')
                        retries = 5
                        wait_time = 2  # seconds
                        for _ in range(retries):
                            ready_to_read, _, _ = select.select([s], [], [], wait_time)
                            if ready_to_read:
                                response = s.recv(HEADER_LENGTH)
                                response = pickle.loads(response)
                                if response['message'] == 'accept':
                                    self.connected_lans[interface] = s
                                    print(f"Connected to {bridge_name} on interface {interface}")
                                    break
                                else:
                                    print(f"Connection to {bridge_name} on interface {interface} rejected")
                                    break
                            else:
                                print(f"Retrying connection to {bridge_name} on interface {interface}")
                        else:
                            print(f"Failed to connect to {bridge_name} on interface {interface}")
                        print(f'Sleep for 60 sec........')
                        time.sleep(60)
            except Exception as e:
                print(f"Error connecting to {bridge_name}: {e}")
        ########### RS #######

        # for interface, bridge_info in self.interface_info.items():
        #     bridge_name, bridge_port = bridge_info.split()
        #     ip_address = self.hostname_mapping.get(bridge_name)
        #     if ip_address:
        #         try:
        #             # Initialize a TCP socket connection to the bridge
        #             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        #                 self.set_socket_nonblocking(s)
        #                 s.connect((ip_address, int(bridge_port)))
        #                 retries = 5
        #                 wait_time = 2  # seconds
        #                 for _ in range(retries):
        #                     ready_to_read, _, _ = select.select([s], [], [], wait_time)
        #                     if ready_to_read:
        #                         response = s.recv(HEADER_LENGTH).decode('utf-8')
        #                         if response == 'accept':
        #                             self.connected_lans[interface] = s
        #                             print(f"Connected to {bridge_name} on interface {interface}")
        #                             break
        #                         else:
        #                             print(f"Connection to {bridge_name} on interface {interface} rejected")
        #                             break
        #                     else:
        #                         print(f"Retrying connection to {bridge_name} on interface {interface}")
        #                 else:
        #                     print(f"Failed to connect to {bridge_name} on interface {interface}")
        #         except Exception as e:
        #             print(f"Error connecting to {bridge_name}: {e}")

    def send_messages(self, client_socket):
        while True:
            try:
                # Wait for the user to input a message
                message = input('{} > '.format(self.my_username))
                # If the message is not empty - send it
                if message:
                    message = message.encode('utf-8')
                    message_header = "{:<{}}".format(len(message), HEADER_LENGTH).encode('utf-8')
                    client_socket.send(message_header + message)
            except KeyboardInterrupt:
                print('Closing Connection!')
                sys.exit()

    def receive_messages(self):
        while True:
            for interface, client_socket in self.connected_lans.items():
                ready_to_read, _, _ = select.select([client_socket], [], [], 0.1)
                if ready_to_read:
                    try:
                        # Header contains the length of the message
                        username_header = client_socket.recv(HEADER_LENGTH)

                        # If no data is received, the connection with the server is closed
                        if not len(username_header):
                            print('Connection closed by the server')
                            sys.exit()

                        # Convert header to int value
                        username_length = int(username_header.decode('utf-8').strip())

                        # Receive and decode username
                        username = client_socket.recv(username_length).decode('utf-8')

                        # Now do the same for the message
                        message_header = client_socket.recv(HEADER_LENGTH)
                        message_length = int(message_header.decode('utf-8').strip())
                        message = client_socket.recv(message_length).decode('utf-8')

                        if message is False:
                            print('Closed connection from: {}'.format(username))
                            continue

                        # Print message
                        print('\nReceived message from {} > {}\n{} > '.format(username, message, self.my_username), end='')

                        if username == self.my_username:
                            print('Close Connection and Try Again!')

                    except KeyboardInterrupt:
                        print('Closing Connection!')
                        sys.exit()

                    except IOError as e:
                        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                            print('Reading error: {}'.format(str(e)))
                            sys.exit()
                        # We just did not receive anything
                        continue

                    except Exception as e:
                        # Any other exception - something happened, exit
                        print('Reading error: '.format(str(e)))
                        sys.exit()

    def send_message(self, destination_ip, message):
        destination_mac = self.arp_table.get_mac_address(destination_ip)
        if destination_mac:
            frame = create_frame(self.mac_address, destination_mac, message)
            self.client_socket.send(frame)
        else:
            self.send_arp_request(destination_ip)
            self.pending_queue.put({'destination_ip': destination_ip, 'message': message})

    def send_arp_request(self, destination_ip):
        arp_request = create_arp_request(self.ip_address, self.mac_address, destination_ip)
        self.client_socket.send(arp_request)

    def send_data_frame(self, destination_ip, destination_mac, message):
        frame = create_frame(self.mac_address, destination_mac, message)
        self.client_socket.send(frame)

    def receive_frame(self):
        try:
            message = self.client_socket.recv(self.LENGTH)
            frame = pickle.loads(message)
            self.process_frame(frame)
        except socket.timeout:
            pass

    def process_frame(self, frame):
        source_mac = frame['source_mac']
        destination_mac = frame['destination_mac']
        message = frame['message']

        if destination_mac == self.mac_address:
            print(f"Received message: {message} from {source_mac}")
        else:
            print(f"Received frame intended for {destination_mac}. Discarding.")

    def start(self):
        try:
            #try connecting to lans 
            res = self.connect_to_lans()
            print('Connected to lans')

            self.client_socket.connect((self.HOST, 5000))
            self.all_connections.add(self.client_socket)
            print('Connected to the bridge!')
            threading.Thread(target=self.send_messages, args=(self.client_socket,)).start()

            while True:
                read_sockets, _, _ = select.select(list(self.all_connections), [], [])
                for sock in read_sockets:
                    if sock == self.client_socket:
                        self.receive_frame()
                    else:
                        print('Unknown socket:', sock)
        except ConnectionRefusedError:
            print("Connection to the bridge refused. Exiting...")
        finally:
            self.client_socket.close()

    def close(self):
        self.client_socket.close()

class Router(Station):
    def __init__(self, ip_address, mac_address):
        super().__init__(ip_address, mac_address)
        self.connected_bridges = {}
        self.host_name = load_from_json_file('hostname.json')
        self.routing_table = load_from_json_file('routingtable.json')
        self.interface_info = load_from_json_file('interface.json')

    def connect_to_bridges(self):
        for interface, bridge_info in self.interface_info.items():
            bridge_name, bridge_port = bridge_info.split()
            ip_address = self.hostname_mapping.get(bridge_name)
            if ip_address:
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
                                response = s.recv(HEADER_LENGTH).decode('utf-8')
                                if response == 'accept':
                                    self.connected_bridges[interface] = s
                                    print(f"Connected to {bridge_name} on interface {interface}")
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
                self.send_arp_request(destination_ip, interface)
                self.pending_queue.put({'destination_ip': destination_ip, 'message': message})
        else:
            print(f"No route found for {destination_ip}. Packet dropped.")

    def get_routing_interface(self, destination_ip):
        for entry in self.routing_table:
            if (self.interface_info.ip_address(destination_ip) & self.interface_info.ip_network(entry['destination'], strict=False).network) == self.ip_network(entry['destination'], strict=False).network:
                return entry['interface']
        return None

    def main_loop(self):
        threading.Thread(target=self.send_arp_requests).start()

        while True:
            # Simulate user input
            user_input = input("Enter message: ")
            destination_ip = input("Enter destination IP: ")
            self.forward_packet(destination_ip, user_input)

            # Simulate receiving frames
            time.sleep(1)
            self.receive_frame()

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

if __name__ == '__main__':
    assert len(sys.argv) == 5, 'Usage: python station.py -no/route interface routingtable hostname'
    is_router = sys.argv[1] == "-route"

    inerface_file = sys.argv[2]
    routingtable_file = sys.argv[3]
    hostname_file = sys.argv[4]

    # is_router = input("Is this station a router? (y/n): ").lower() == 'y'

    if is_router:
        pass
        # router = Router(ip_address, mac_address)
        # router.connect_to_bridges()
        # router.start()
        # router.close()
    else:
        station = Station(inerface_file, routingtable_file, hostname_file)
        station.start()
        station.close()