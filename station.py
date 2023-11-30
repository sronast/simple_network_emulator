import os
import json
import fcntl
import errno
import sys
import socket
import pickle
import select
import ipaddress
import time
from collections import deque
from utils import *

HEADER_LENGTH = 1024

# class ARPPacket:
#     def __init__(self, operation, sender_ip, sender_mac, target_ip, target_mac=None):
#         self.operation = operation
#         self.sender_ip = sender_ip
#         self.sender_mac = sender_mac
#         self.target_ip = target_ip
#         self.target_mac = target_mac

# # ARPCache class
# class ARPCache:
#     def __init__(self):
#         self.cache = {}

#     def add_mapping(self, ip_address, mac_address):
#         self.cache[ip_address] = mac_address

#     def get_mac_address(self, ip_address):
#         return self.cache.get(ip_address, None)

# # RoutingTable class
# class RoutingTable:
#     def __init__(self):
#         self.table = {}

#     def add_entry(self, destination, next_hop):
#         self.table[destination] = next_hop

#     def get_next_hop(self, destination):
#         return self.table.get(destination, None)

# # Function to create a data frame
# def create_frame(source_mac, destination_mac, message):
#     frame = {
#         'source_mac': source_mac,
#         'destination_mac': destination_mac,
#         'message': message,
#     }
#     return pickle.dumps(frame)

# # Function to create an ARP request
# def create_arp_request(sender_ip, sender_mac, target_ip):
#     arp_request = {
#         'type': 'request',
#         'sender_ip': sender_ip,
#         'sender_mac': sender_mac,
#         'target_ip': target_ip,
#     }
#     return pickle.dumps(arp_request)

class Station:
    def __init__(self, interface_file, routingtable_file, hostname_file, is_router=True):
        self.is_router = is_router
        self.hostname_mapping = load_json_file(hostname_file)
        self.reverse_hostname_mapping = {v:k for k, v in self.hostname_mapping.items()}
        self.station_info = load_json_file(interface_file)
        self.routing_table = load_json_file(routingtable_file)
        # --------RS-------- #
        self.arp_table = {}
        self.pending_queue = deque()
        
        self.LENGTH = 4096
        self.all_connections = set()
        self.socket_to_ip = {}
        self.ip_to_socket = {}


    def connect_to_lans(self):
        ####### RS ######
        print(self.station_info["stations"])
        for interface in self.station_info["stations"]:
            bridge_name = self.station_info[interface]["lan"]
            #check if there is an active lan with lan_name
            all_bridges = load_json_file('all_lans.json')
            if bridge_name not in all_bridges:
                print(f"LAN {bridge_name} is unavilable ...")
                print('\n')
                continue
            lan_info = load_json_file(f'bridge_{bridge_name}.json')
            bridge_ip = lan_info['ip']
            bridge_port = lan_info['port']
            print('all info gathered')
            print(f'Bridge ip: {bridge_ip} Bridge port: {bridge_port}')

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                retries = 5
                wait_time = 2  # seconds
                for _ in range(retries):
                    sock.connect((bridge_ip, int(bridge_port)))
                    response = sock.recv(HEADER_LENGTH)
                    response = pickle.loads(response)
                    if response['message'] == 'accept':
                        print(f"Connected to {bridge_name} on interface {interface}.........")
                        self.all_connections.add(sock)
                        hostname,port=sock.getpeername()
                        station_ip = self.station_info[interface]["ip"]
                        self.socket_to_ip[f'{hostname}:{port}'] = station_ip
                        self.ip_to_socket[station_ip] = sock
                        break
                    elif response['message'] == 'reject':
                        print('No free port on the bridge {bridge_name}. The connection cannot be established...')
                        break
                    else:
                        print(f"Connection to {bridge_name} on interface {interface} rejected..\nRetrying...")
                    time.sleep(wait_time)
                    
                    # ready_to_read, _, _ = select.select([s], [], [], wait_time)
                        
            except Exception as e:
                print(f"Error connecting to {bridge_name}: {e}")
        ########### RS #######


    def print_tables(self, message):
        if message == 'rt':
                print('============ Printing Routing Table ===========')
                print(f'Network Address \t Next Hop Address \t Netmask \t Interface to next Hop')
                for k,v in self.routing_table.items():
                    res = f'{k}'
                    for kk, vv in v.items():
                        res = res + f'\t {vv}'
                    print(res)
                print('============ END ===========')
        elif message == 'dns':
            print('=========== Printing DNS Table ===============')
            
            print(f'Hostname \t IP')
            for k, v in self.hostname_mapping.items():
                print(f'{k}\t{v}')
            print('============ END ===========')
        elif message == 'arp':
            print('=========== Printing ARP Table ===============')
            print(f'IP \t MAC')
            for k,v in self.arp_table.items():
                print(f'{k} \t {v}')

            ## implement here 
            print('============ END ===========')
        else:
            print(f'Command {message} not found')
        return
    
    def send_arp(self, arp_msg, sock):
        print(f'sending {arp_msg["type"]}.....')
        sock.send(pickle.dumps(arp_msg))
    
    def create_ip_packet(self,source_ip, destination_ip, message):
        ip_packet = {
                'source_ip':source_ip,
                'destination_ip': destination_ip, 
                'message': message
            }
        return ip_packet
    
    def create_frame(self, source_mac, destination_mac, ip_packet):
        frame = {
                'type': 'IP',
                'source_mac': source_mac,
                'destination_mac':destination_mac,
                'ip_packet': ip_packet
            }
        return pickle.dumps(frame)
    
    def send_message(self, source_ip, destination_ip, source_mac, destination_mac, message, sock):
        ip_packet = self.create_ip_packet(source_ip, destination_ip, message)
        frame = self.create_frame(source_mac, destination_mac, ip_packet)
        sock.send(frame)
    
    def forward_message(self, messsage, sock):
        sock.send(pickle.dumps(messsage))


    def prepare_message(self, destination, message):
        destination_ip = self.hostname_mapping[destination]
        destination_mac = self.arp_table.get(destination_ip, None)

        source_name = self.station_info['stations'][0]
        source_ip = self.station_info[source_name]['ip']
        source_mac = self.station_info[source_name]['mac']
        sock = self.ip_to_socket[source_ip]

        if not destination_mac:
            self.pending_queue.append({'source_ip':source_ip ,'destination_ip': destination_ip, 'message':message, 'source_mac': source_mac, 'sock':sock})
            self.send_arp({'source_ip':source_ip ,'destination_ip': destination_ip, 'source_mac': source_mac, 'destination_mac':'ff:ff:ff:ff:ff:ff', 'type':'ARP_request'}, sock)
        else:
            self.send_message(source_ip, destination_ip, source_mac, destination_mac, message, sock)
    
    def process_pending_queue(self):
        new_queue = deque()
        for item in self.pending_queue:
            destination_mac = self.arp_table.get(item['destination_ip'], None)
            if destination_mac:
                self.send_message(item['source_ip'], item['destination_ip'], item['source_mac'], destination_mac, item['message'], item['sock'])
            else:
                new_queue.append(item)
        self.pending_queue = new_queue
            
    #consult routing table to get next interface
    def get_next_interface(self, destination_ip):
        for network_prefix, entry in self.routing_table.items():
            netmask = entry['mask']
            destination_network_prefix = ipaddress.ip_network((destination_ip, netmask), strict=False).network_address
            if destination_network_prefix == ipaddress.ip_address(network_prefix):
                return entry['next_interface']
        return False, False


    def process_arp(self, message, sock):
        destination_ip = message['destination_ip']
        source_ip = message['source_ip']
        socket_ip, socket_port = sock.getpeername()
        my_ip = self.socket_to_ip[f'{socket_ip}:{socket_port}']
        my_name =  self.reverse_hostname_mapping[my_ip]
        
        if message['source_ip'] not in self.arp_table:
            self.arp_table[message['source_ip']] = message['source_mac']

        if message['type'] == 'ARP_request':
            if self.is_router:
                #check if the destination ip is in the same network
                next_interface = self.get_next_interface(destination_ip)
                print(f'Next interface...{next_interface}')
                #if yes drop the packet
                if next_interface == my_name:
                    print('Received ARP request in router....The destination host is in  the same network...Dropping...')
                #else retrun the mac address of the router as arp reply
                else:
                    print('Received ARP request....The destination host is in  the different network...Forwarding...')
                    interface_ip = self.hostname_mapping[next_interface]
                    interface_socket = self.ip_to_socket[interface_ip]
                    self.send_arp(message, interface_socket)
                

            elif my_ip == destination_ip:
                print("Received ARP request...processing")
                my_mac = self.station_info[my_name]['mac']
                # sock = self.ip_to_socket[my_ip]
                self.send_arp({'source_ip':my_ip ,'destination_ip': source_ip, 'source_mac': my_mac, 'destination_mac':message['source_mac'], 'type':'ARP_response'}, sock)

            else:
                print("Received ARP request destined for different station...dropping.....")
        
        elif message['type'] == 'ARP_response':

            
            if self.is_router:
                print('Received ARP response in router')
                #forward the packet to necesary hop/drop

                next_interface = self.get_next_interface(destination_ip)
                #if yes drop the packet
                if next_interface == my_name:
                    print('Received ARP request in router....The destination host is in  the same network...Dropping...')
                #else retrun the mac address of the router as arp reply
                else:
                    print('Received ARP request....The destination host is in  the different network...Forwarding...')
                    interface_ip = self.hostname_mapping[next_interface]
                    interface_socket = self.ip_to_socket[interface_ip]
                    self.send_arp(message, interface_socket)


            elif my_ip == destination_ip:
                print("Received ARP response...Processing pending queue..")
                self.process_pending_queue()
            else:
                print("Received ARP response destined for different station..updated ARP cache.....")

    def process_frame(self, message, sock):
        socket_ip, socket_port = sock.getpeername()
        my_ip = self.socket_to_ip[f'{socket_ip}:{socket_port}']
        my_name =  self.reverse_hostname_mapping[my_ip]

        # print('process frame message....')
        # print(message)

        ip_packet = message['ip_packet']
        destination_ip = ip_packet['destination_ip']
        if self.is_router:
            next_interface = self.get_next_interface(destination_ip)
                #if yes drop the packet
            if next_interface == my_name:
                print('Received IP Packet in a router....The destination host is in  the same network...Dropping...')
            #else retrun the mac address of the router as arp reply
            else:
                print('Received IP Packet....The destination host is in  the different network...Forwarding...')
                interface_ip = self.hostname_mapping[next_interface]
                interface_socket = self.ip_to_socket[interface_ip]
                self.forward_message(message, interface_socket)

        else:
            if self.station_info[my_name]['mac'] == message['destination_mac']:
                ip_packet = message['ip_packet']
                print(f'Received message from station {self.reverse_hostname_mapping[ip_packet["source_ip"]]}')
                print(f'Message: {ip_packet["message"]}')
            else:
                print('Received message destined for different station....dropping...')
    
    def receive_message(self, message, sock):
        message = pickle.loads(message)

        if message['type'] in {'ARP_request', 'ARP_response'}:
            self.process_arp(message, sock)

        elif message['type'] == 'IP':
            self.process_frame(message, sock)

    def handle_input(self):
        usr_input = sys.stdin.readline()
        if ';' not in usr_input:
            print('Wrong input format...')
            return
        
        destination, message = usr_input.split(';')
        destination, message = destination.strip(), message.strip()
        print(f'dest: {destination}, message: {message}')

        if self.is_router and destination != 'print':
            print('Router only supports commands....')

        elif destination.lower() == 'print':
            self.print_tables(message) 
        
        elif destination == self.station_info["stations"][0]:
            print('Cannot send message to itself...')
            
        elif destination not in self.hostname_mapping:
            print('Destination not found....')

        else:
            self.prepare_message(destination, message)
        
    
    #if a bridge is disconnected reomove the connection
    def disconnect_from_lan(self, sock):
        socket_ip,socket_port=sock.getpeername()
        station_ip = self.socket_to_ip[f'{socket_ip}:{socket_port}']
        self.ip_to_socket.pop(station_ip, None)
        self.socket_to_ip.pop(f'{socket_ip}:{socket_port}', None)
        station_name = self.reverse_hostname_mapping[station_ip]
        print(station_name, '-------------')
        print(self.station_info['stations'])
        self.station_info['stations'].remove(station_name)
        bridge_name = self.station_info[station_name]['lan']
        self.station_info.pop(station_name, None)

        self.all_connections.remove(sock)
        return

    def start(self):
        try:
            #try connecting to lans 
            self.connect_to_lans()
            # print(f'Enter the message in format: destination_name;message')
            while True:
                if len(self.all_connections) == 0:
                    print('No active connections...')
                    break
                self.possible_inputs=[sys.stdin]+list(self.all_connections)
                read_sockets,_, _ = select.select(self.possible_inputs,[],[])
                for sock in read_sockets:
                    #if client needs to send message to the server
                    if sock == sys.stdin:
                        self.handle_input()
                    else:
                        for conn in self.all_connections.copy():
                        #if client receives message from the server
                            if sock == conn:
                                message = conn.recv(self.LENGTH)
                                if message:
                                    self.receive_message(message, sock)
                                #if message is empty, the server has died
                                else:
                                    self.disconnect_from_lan(sock)
                            # break
                                
        except ConnectionRefusedError:
            print("Connection to the bridge refused. Exiting...")
        except KeyboardInterrupt:
            for conn in self.all_connections.copy():
                self.disconnect_from_lan(conn)
            print('Keyboard Interrupt... Station disconnected from all lans')


if __name__ == '__main__':
    assert len(sys.argv) == 5, 'Usage: python station.py -no/route interface routingtable hostname'
    is_router = sys.argv[1] == "-route"

    inerface_file = sys.argv[2]
    routingtable_file = sys.argv[3]
    hostname_file = sys.argv[4]

    # is_router = input("Is this station a router? (y/n): ").lower() == 'y'
    station = Station(inerface_file, routingtable_file, hostname_file, is_router)
    station.start()
    