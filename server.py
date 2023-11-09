import socket
import threading
import select

class Server:
    def __init__(self):
        self.HOST = socket.gethostbyname('localhost')
        self.LENGTH = 4096
        self.MAX_CONNECTIONS = 10 
        self.MESSAGE_FORMAT = 'utf-8'
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.HOST, 0))
        self.server_socket.setblocking(False)
        self.all_connections1 = set([self.server_socket]) #set, so add and remove operation is performed in O(1)

    #send incoming message to all the clients, but not to the one sending the message and the server
    def broadcast(self, connection, message):
        for client in self.all_connections1.copy():
            if client not in [connection, self.server_socket]:
                try:
                    client.send(message.encode(self.MESSAGE_FORMAT))
                except:
                    client.close()
                    self.all_connections1.remove(client)

    def start(self):
        print('Server started!! ')
        self.server_socket.listen(self.MAX_CONNECTIONS)
        print(f'=== Hostname: {self.HOST} Listening on Port: {self.server_socket.getsockname()[1]} ===')

        try:
            while True:
                read_sockets,write_socket, error_socket = select.select(list(self.all_connections1),[],[])
                for sock in read_sockets:
                    #if server receives a new connection 
                    if sock == self.server_socket:
                        connection, address = self.server_socket.accept()
                        # connection.setblocking(False)
                        print(f'Client: {address[0]}, {address[1]} connected')
                        self.all_connections1.add(connection)
                        self.broadcast(connection, f'>>>New client {address[0]}({address[1]}) connected<<<')
                    
                    else:
                        hostname,port=sock.getpeername()
                        try:
                            message = sock.recv(self.LENGTH).decode(self.MESSAGE_FORMAT)
                            #if client is disconnected
                            if not message:
                                print(f'>>>{hostname}({port}) disconnected!!!!')
                                self.all_connections1.remove(sock)
                                self.broadcast(sock, f'>>>{hostname}({port}) disconnected!!!!')
                                sock.close()
                            #if server receives the message to broadcast
                            else:
                                broadcast_message = f'>>>{hostname}({port}): {message}'
                                print(f'{broadcast_message}')
                                self.broadcast(sock, broadcast_message)
                                
                        except:
                            print(f'>>>{hostname}({port}) disconnected!!!!')
                            self.all_connections1.remove(sock)
                            self.broadcast(sock, f'>>>{hostname}({port}) disconnected')
                            sock.close()
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
    server = Server()
    server.start()
    server.close()
