### Name: Varun Totakura

import socket
import select
import sys
import re

HEADER_LENGTH = 10

def is_valid_ip(ip):
    # Regular expression for matching an IPv4 address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

    if re.match(ip_pattern, ip):
        # Check if each octet is between 0 and 255
        octets = ip.split('.')
        for octet in octets:
            if not (0 <= int(octet) <= 255):
                return False
        return True
    else:
        return False

while True:
    IP = input("Enter the IP Address like 127.0.0.1 or for default IP press enter:")
    if IP == '0' or IP == 0 or IP == '':
        IP = "127.0.0.1" # Local Host
    if is_valid_ip(IP):
        print("{} is a valid IPv4 address.".format(IP))
        break
    else:
        print("{} is not a valid IPv4 address.".format(IP))


# Use different PORTs for different servers
PORT = int(input('Type the PORT Number of the Server: '))

# Create a socket using specified network configuration and steam like TCP/UDP
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Mention the IP Address and PORT Number to the Socket
server_socket.bind((IP, PORT))

# To make server listen to new connections from clients
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# Clients Dictionary to save the details of the clients in the format where socket as a key, user header and name as data
clients = {}

print("Server available for connections at {}:{}...".format(IP, PORT))

# To capture the messages sent by different clients
def receive_message(client_socket):
    try:
        # Header contains the length of the message
        message_header = client_socket.recv(HEADER_LENGTH)

        # In case header is empty, that means the client connection is closed
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())

        # Capture the message
        message_data = client_socket.recv(message_length)

        # Return message header and message data
        return {'header': message_header, 'data': message_data}

    except:
        # Incase of any issues, consider that the connection with the client is lost
        return False

while True:
    try:
        read_sockets, _, _ = select.select(sockets_list, [], sockets_list)

        # Iterate over notified sockets
        for notified_socket in read_sockets:

            # If notified socket is a server socket - new connection, accept it
            if notified_socket == server_socket:

                # Accept new connection
                client_socket, client_address = server_socket.accept()

                # Capture the username of the client
                user = receive_message(client_socket)

                # Check if user is already available
                if user in list(clients.values()):
                    mes = "Username already occupied, please use other username and reconnect!".encode('utf-8')
                    hed = "{:<{}}".format(len(mes), HEADER_LENGTH).encode('utf-8')
                    client_socket.send(user['header'] + user['data'] + hed + mes)
                    print("Username already occupied!")
                    continue

                # If False, Client Disconnected
                if user is False:
                    continue

                # Add accepted socket to select.select() list
                sockets_list.append(client_socket)

                # Also save username and username header
                clients[client_socket] = user
                print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))

                # Iterate over connected clients and broadcast message
                usrr = user['data'].decode('utf-8')
                for cl_socket in clients:
                    if cl_socket != client_socket:
                        mes = "I am Online!".encode('utf-8')
                        hed = "{:<{}}".format(len(mes), HEADER_LENGTH).encode('utf-8')
                        cl_socket.send(clients[client_socket]['header'] + clients[client_socket]['data'] + hed + mes)
            
            # If connection already exists
            else:
                # Receive message
                message = receive_message(notified_socket)

                # If False, client disconnected, cleanup
                if message is False:
                    usr = clients[notified_socket]['data'].decode('utf-8')
                    print('Closed connection from: {}'.format(usr))

                    # Iterate over connected clients and broadcast message
                    for client_socket in clients:
                        if client_socket != notified_socket:
                            mes = "Connection Closed!".encode('utf-8')
                            hed = "{:<{}}".format(len(mes), HEADER_LENGTH).encode('utf-8')
                            client_socket.send(clients[notified_socket]['header'] + clients[notified_socket]['data'] + hed + mes)

                    # Remove from list for socket.socket()
                    sockets_list.remove(notified_socket)

                    # Remove from our list of users
                    del clients[notified_socket]

                    continue

                # Get user by notified socket, so we will know who sent the message
                user = clients[notified_socket]
                print('Received message from {}: {}'.format(user["data"].decode("utf-8"), message["data"].decode("utf-8")))

                # Iterate over connected clients and broadcast message
                for client_socket in clients:
                    if client_socket != notified_socket:
                        client_socket.send(user['header'] + user['data'] + message['header'] + message['data'])

    except KeyboardInterrupt:
        print('Closing Server!')
        for client_socket in clients:
                mes = "Server Connection Closed! Please disconnect!".encode('utf-8')
                hed = "{:<{}}".format(len(mes), HEADER_LENGTH).encode('utf-8')
                client_socket.send(clients[client_socket]['header'] + clients[client_socket]['data'] + hed + mes)
                client_socket.close()
        server_socket.close()
        sys.exit()