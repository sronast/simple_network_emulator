### Name: Varun Totakura

import socket
import select
import re
import errno
import sys
import threading

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

# Use the right PORT number to connect the chosen server
PORT = int(input('Type the PORT Number of the Server: '))

my_username = input("Username: ")

# Create a socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to a given IP and port
    client_socket.connect((IP, PORT))
except:
    print("Server is not online!")
    sys.exit()

# Set connection to non-blocking state
client_socket.setblocking(False)

# Prepare username and header and send them to Server
username = my_username.encode('utf-8')
username_header = "{:<{}}".format(len(username), HEADER_LENGTH).encode('utf-8')
client_socket.send(username_header + username)

# To print the messages sent by different clients or users
def receive_messages():
    while True:
        try:
            # Header contains the length of the message
            username_header = client_socket.recv(HEADER_LENGTH)

            # If no data is received, the connection with Server is closed
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
            print('\nRecieved message from {} > {}\n{} > '.format(username, message, my_username), end='')

            if username == my_username:
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

# Create a separate thread to receive messages
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

while True:
    try:
        # Wait for user to input a message
        message = input('{} > '.format(my_username))

        # If message is not empty - send it
        if message:
            message = message.encode('utf-8')
            message_header = "{:<{}}".format(len(message), HEADER_LENGTH).encode('utf-8')
            client_socket.send(message_header + message)

    except KeyboardInterrupt:
        print('Closing Connection!')
        sys.exit()