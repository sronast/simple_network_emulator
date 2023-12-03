import sys
import os
import json
import pickle
import socket
import select
import time
import threading
from utils import *

class Bridge:
    def __init__(self, lan_name, num_ports):
        self.lan_name = lan_name
        self.num_ports = num_ports
        self.used_ports = 0
        self.HOST = socket.gethostbyname('localhost')
        self.LENGTH = 4096 # message length
        # self.MESSAGE_FORMAT = 'utf-8'
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.HOST, 0))
        self.server_socket.setblocking(False)
        self.all_connections1 = set([self.server_socket]) #set, so add and remove operation is performed in O(1)
        #tcp connection(ip:port) key, bridge_port: value
        self.station_ip_to_port = {}
        #port to tcp connection
        self.port_to_station_ip = {}
        #mac to port
        self.bridge_table = {}
        #port to mac
        self.reverse_bridge_table = {}
        self.available_ports = set(list(range(self.num_ports)))

    def unicast(self, frame, destination_mac):
        print('Bridge Table')
        print(self.bridge_table)
        destination_port = self.bridge_table[destination_mac]
        
        #get tcp connection asssociated with the port
        client = self.port_to_station_ip[destination_port]
        client.send(frame)

    #send incoming message to all the clients, but not to the one sending the message and the server
    def broadcast(self, frame, source_mac):
        source_port = self.bridge_table[source_mac]
        #get connection associated with the port
        source = self.port_to_station_ip[source_port]
        for client in self.all_connections1.copy():
            if client not in [source, self.server_socket]:
                try:
                    client.send(frame)
                except:
                    client.close()
                    self.all_connections1.remove(client)
    
    #if a station/router gets disconnected
    def free_bridge_port(self, port_of_bridge, sock):
        hostname, port = sock.getpeername()
        print(self.station_ip_to_port)
        self.station_ip_to_port.pop('{}:{}'.format(hostname, port))
        self.port_to_station_ip.pop(port_of_bridge)
        #free the port
        self.available_ports.add(port_of_bridge)
        self.used_ports-=1
        #get mac of the station if there is in the bridge table
        mac_of_station = self.reverse_bridge_table[port_of_bridge]
        self.reverse_bridge_table.pop(port_of_bridge, None)
        #remove the mapping form the bridge table if exists
        self.bridge_table.pop('{}'.format(mac_of_station), None)
        # print('>>>{} at port ({}) disconnected!!!!'.format(hostname, port_of_bridge))
        self.all_connections1.remove(sock)

        print('Station at port {} disconnected.....'.format(port_of_bridge))
        print('Remaining conns: ', self.all_connections1)
        print(self.station_ip_to_port)
        print('Available ports = {}'.format(self.available_ports))

        # self.broadcast(sock, '>>>{}({}) disconnected!!!!'.format(hostname, port))
        sock.close()

    def print_tables(self, message):
        if message == 'bt':
            print('\tMAC\t\tPort')
            for k,v in self.bridge_table.items():
                print('{}\t\t{}'.format(k, v))
        else:
            print('Command {} not found'.format(message))
        return
    
    def handle_input(self):
        # usr_input = sys.stdin.readline()
        # if ';' not in usr_input:
        #     print('Wrong input format...')
        #     return
        # dest,command = str(usr_input).split(';')
        # dest,command = dest.strip(), command.strip()

        dest = input("Enter the Destination or any command: ")
        command = input("Enter the Message or any command: ")
        dest,command = dest.strip(), command.strip()

        if dest.lower() == 'print':
            self.print_tables(command)
        else:
            print('Bridge only accepts command...')

    def start(self):
        print('Server started!! ')
        self.server_socket.listen(self.num_ports)
        ip_addr = self.server_socket.getsockname()[0]
        port_addr = self.server_socket.getsockname()[1]
        print('=== Hostname: {} Listening on Port: {} ==='.format(ip_addr, port_addr))

        #create json file to save bridge ip and port
        with open('bridge_{}.json'.format(self.lan_name), 'w') as f:
            json.dump({'ip': ip_addr, 'port':port_addr}, f)

        #Waiting for connection set-up requests from stations / routers.
        try:
            while True:
                read_sockets, write_socket, error_socket = select.select(list(self.all_connections1)+[sys.stdin],[],[])
                # read_sockets, write_socket, error_socket = select.select(list(self.all_connections1),[],[])
                for sock in read_sockets:
                    #if server receives a new connection 
                    if sock == self.server_socket:
                        connection, address = self.server_socket.accept()
                        # connection.setblocking(False)
                        ### Connect to bridge only if ports are available in bridge
                        
                        if self.used_ports < self.num_ports:
                            self.used_ports += 1 
                            self.all_connections1.add(connection)
                            #assign random port of the bridge to the client
                            random_port_of_bridge = self.available_ports.pop()
                            self.station_ip_to_port['{}:{}'.format(address[0], address[1])] = random_port_of_bridge
                            self.port_to_station_ip[random_port_of_bridge] = connection
                            self.reverse_bridge_table[random_port_of_bridge] = None
                            status = 'accept'
                            print('Station connected at port {}.......'.format(random_port_of_bridge))
                        # self.broadcast(connection, '>>>New client {}({}) connected<<<'.format(address[0], address[1]))
                        #no port available in the bridge
                        else:
                            status = 'reject'
                        # print('Sending response to the clent.....')
                        # print(status)
                        connection.send(pickle.dumps({'message': status, 'type': 'connection_establishment'}))

                    elif sock == sys.stdin:
                        self.handle_input()
                    
                    else:
                        # threading.Thread(target=self.handle_input).start()
                        hostname,port = sock.getpeername()
                        #which port is receiving the message
                        port_of_bridge =  self.station_ip_to_port['{}:{}'.format(hostname, port)]
                        try:
                            #message is a frame which contains source and destination mac addresses
                            try:
                                retries = 5
                                wait_time = 1
                                for _ in range(retries):
                                    message = sock.recv(self.LENGTH)
                                    if message:
                                        break
                                    else:
                                        print("Retrying...")
                                        time.sleep(wait_time)
                            except socket.timeout:
                                pass
                            if not message:
                                self.free_bridge_port(port_of_bridge, sock)
                                continue

                            frame = pickle.loads(message)
                            print('Message from client')
                            print(frame)
                            #if router or station is disconnected
                            if not frame:
                                self.free_bridge_port(port_of_bridge, sock)
                                continue
                            #bridge receives the frame
                            else:
                                print('Received frame from a station....')
                                source_mac = frame['source_mac']
                                destination_mac = frame['destination_mac']

                                #self learning:: addin sender's mac to the bridge table if not already exists
                                if source_mac not in self.bridge_table:
                                    self.bridge_table[source_mac] = port_of_bridge
                                    self.reverse_bridge_table[port_of_bridge] = source_mac
                                #check if destination mac is in the bridge table
                                #true pass the frame to that station
                                if destination_mac in self.bridge_table:
                                    print('...........Unicast:: ')
                                    #send the frame to the destination
                                    self.unicast(message, destination_mac)
                              

                                #false broadcast the frame to all ports except incoming
                                else:
                                    #if destination mac address not in the bridge table broadcast the frame
                                    self.broadcast(message, source_mac)
                                    print('...........Broadcast')
                                    
                            print('Available prots: ', self.available_ports)   
                            print('Used ports: ', self.used_ports)   
                        except:
                            print('In except')
                            self.free_bridge_port(port_of_bridge, sock)
                            continue
        #if server is closed by keyboard interruption.
        except KeyboardInterrupt:
            print('\n!!! Keyboard interrupt !!!')
            self.server_socket.close()

    def close(self):
        self.server_socket.close()
        print('=== Server socket closed ===')
        print("=== All clients closed ===")

if __name__ == '__main__':
    assert len(sys.argv) == 3, 'Usuage: python3 bridge.py lan-name num-ports'
    lan_name = sys.argv[1]
    try:
        num_ports = int(sys.argv[2])
    except:
        print('The number of ports has to be an integer')
        sys.exit()

    #load all lans in the network {'lan': no_of_ports}
    all_lans = load_from_json('all_lans.json')

    #check if the bridge with name same as the one in the argument is already there
    if lan_name in all_lans:
        print('Bridge with name {} already exists'.format(lan_name))
        sys.exit()
    else:
        all_lans[lan_name] = num_ports
    
    #save json containing all bridges info
    save_to_json('all_lans.json', all_lans)

    server = Bridge(lan_name, num_ports)
    server.start()
    server.close()

    #delete bridge from all bridge list after it is removed
    all_lans = load_from_json('all_lans.json')
    all_lans.pop(lan_name, None)
    save_to_json('all_lans.json', all_lans)

    ##remove json file associated with the bridge
    if os.path.exists('bridge_{}.json'.format(lan_name)):
        os.remove('bridge_{}.json'.format(lan_name))