from queue import Queue
import threading
import time

class ARPPacket:
    def __init__(self, operation, sender_ip, sender_mac, target_ip, target_mac=None):
        self.operation = operation
        self.sender_ip = sender_ip
        self.sender_mac = sender_mac
        self.target_ip = target_ip
        self.target_mac = target_mac

class ARPCache:
    def __init__(self):
        self.cache = {}

    def add_mapping(self, ip_address, mac_address):
        self.cache[ip_address] = mac_address

    def get_mac_address(self, ip_address):
        return self.cache.get(ip_address, None)

class Station:
    def __init__(self, ip_address, mac_address):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.arp_table = ARPCache()
        self.pending_queue = Queue()

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

    def send_message(self, destination_ip, message):
        next_hop_mac = self.arp_table.get_mac_address(destination_ip)

        if next_hop_mac:
            self.send_data_frame(destination_ip, next_hop_mac, message)
        else:
            # Enqueue the IP packet for which ARP resolution is pending
            self.pending_queue.put({'destination_ip': destination_ip, 'message': message})

    def send_data_frame(self, destination_ip, next_hop_mac, message):
        print(f"Sending data frame to {destination_ip} with message: {message}")

    def send_arp_requests(self):
        while True:
            # Simulate sending ARP requests periodically
            time.sleep(5)
            self.send_arp_request()

    def send_arp_request(self):
        destination_ip = input("Enter IP for ARP request: ")
        arp_packet = ARPPacket("request", self.ip_address, self.mac_address, destination_ip)
        self.send_data_frame(destination_ip, "broadcast", arp_packet)

    def receive_frame(self):
        # Simulate receiving frames
        # In a real scenario, you would listen for incoming frames on a socket
        pass

# Example Usage
station1 = Station("192.168.1.1", "00:11:22:33:44:55")
station1.main_loop()
