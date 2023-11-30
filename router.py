from .station import *
class Router(Station):
    def __init__(self, inerface_file, routingtable_file, hostname_file):
        super().__init__(inerface_file, routingtable_file, hostname_file)
        self.connected_bridges = {}
        # self.host_name = load_from_json_file('hostname.json')
        # self.routing_table = load_from_json_file('routingtable.json')
        # self.interface_info = load_from_json_file('interface.json')

    def connect_to_bridges(self):
        self.connect_to_lans()
        return
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
        
        try:
            self.connect_to_lans()
            while True:
                read_sockets,_, _ = select.select(list(self.all_connections),[],[])
                print('Read socks')
                print(read_sockets)
                for sock in read_sockets:
                    #if client receives message from the server
                    if sock == list(self.all_connections)[0]:
                        message = list(self.all_connections)[0].recv(self.LENGTH)
                        if message:
                            message = pickle.loads(message)
                            print('Message from the server')
                            print(message)
                        #if message is empty, the server has died
                        else:
                            print(f'>>>The server died<<<')
                            self.is_connected = False
                    #if client needs to send message to the server
                    elif sock == list(self.all_connections)[1]:
                        message = list(self.all_connections)[1].recv(self.LENGTH)
                        if message:
                            message = pickle.loads(message)
                            print('Message from the server')
                            print(message)
                        #if message is empty, the server has died
                        else:
                            print(f'>>>The server died<<<')
        except ConnectionRefusedError:
            print("Connection to the bridge refused. Exiting...")
        finally:
            pass
            # self.client_socket.close()


        ############

        while True:
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
