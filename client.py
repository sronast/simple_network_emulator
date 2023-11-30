import sys
import socket
import threading
import select
import signal
import pickle
from frame import Frame

class Client:
    def __init__(self, host, port):
        self.is_connected = True
        self.PORT = port
        self.HOST = host
        self.ADDR = (self.HOST, self.PORT)
        self.LENGTH = 2048
        self.MESSAGE_FORMAT = 'utf-8'
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.ADDR)
        self.possible_inputs = [sys.stdin, self.client_socket]


    def monitor_message(self):
        try:
            while self.is_connected:
                print(self.client_socket)
                read_sockets,write_socket, error_socket = select.select(self.possible_inputs,[],[])
                print('Read socks')
                print(read_sockets)
                for sock in read_sockets:
                    #if client receives message from the server
                    if sock == self.client_socket:
                        message = self.client_socket.recv(self.LENGTH)
                        print(message)
                        if message:
                            message = pickle.loads(message)
                            print('Message from the server')
                            print(message)
                        #if message is empty, the server has died
                        else:
                            print(f'>>>The server died<<<')
                            self.is_connected = False
                    #if client needs to send message to the server
                    else:
                        message = sys.stdin.readline()
                        self.client_socket.send(pickle.dumps({'message': message}))  
        #if client is closed by keyboard interruption.
        except KeyboardInterrupt:
            print('\n!!! Keyboard interrupt !!!')
            self.client_socket.close()


    def close(self):
        print('=== Client socket closed ===')
        self.client_socket.close()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Command to start the client: python3.9 client.py host_name host_port !!!')
        sys.exit()
    client = Client(sys.argv[1], int(sys.argv[2]))
    client.monitor_message()
    client.close()