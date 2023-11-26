import sys
import socket
import pickle
import select
import threading
from utils import *

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
    def __init__(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.pending_queue = []
        self.arp_table = ARPCache()
        self.routing_table = RoutingTable()
        self.HOST = socket.gethostbyname('localhost')
        self.LENGTH = 4096
        self.all_connections = set()
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.settimeout(2)

    def send_message(self, destination_ip, message):
        destination_mac = self.arp_table.get_mac_address(destination_ip)
        if destination_mac:
            frame = create_frame(self.mac_address, destination_mac, message)
            self.client_socket.send(frame)
        else:
            self.send_arp_request(destination_ip)
            self.pending_queue.append({'destination_ip': destination_ip, 'message': message})

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
        source_mac = frame.source_mac
        destination_mac = frame.destination_mac
        message = frame.message

        if destination_mac == self.mac_address:
            print(f"Received message: {message} from {source_mac}")
        else:
            print(f"Received frame intended for {destination_mac}. Discarding.")

    def start(self):
        try:
            self.client_socket.connect((self.HOST, 5000))
            self.all_connections.add(self.client_socket)
            print('Connected to the bridge!')
            threading.Thread(target=self.send_messages).start()

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

    def send_messages(self):
        while True:
            user_input = input("Enter message: ")
            destination_ip = input("Enter destination IP: ")
            self.send_message(destination_ip, user_input)

    def close(self):
        self.client_socket.close()

if __name__ == '__main__':
    assert len(sys.argv) == 3, 'Usage: python3 station.py ip_address mac_address'
    ip_address = sys.argv[1]
    mac_address = sys.argv[2]

    station = Station(ip_address, mac_address)
    station.start()
    station.close()
