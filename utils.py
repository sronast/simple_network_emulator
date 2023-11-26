import re
import os
import json

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

def load_from_json(file_name):
    #if there is at leaset one bridge in the network, get its info
    if os.path.exists(file_name):
        with open(file_name, 'r') as f:
            all_lans = json.load(f)
    #no bridge
    else:
        all_lans = {}
    
    return all_lans

def load_from_json_file(file_name):
    try:
        with open(file_name, 'r') as f:
            # For interface and hostname files
            if 'interface' in file_name or 'hostname' in file_name:
                # Assuming tab-separated values
                data = [line.strip().split('\t') for line in f]

                # Create a dictionary
                all_data = {row[0]: row[1:] for row in data}

            # For routing table file
            elif 'routingtable' in file_name:
                # Assuming space-separated values
                data = [line.strip().split() for line in f]

                # Create a list of dictionaries
                all_data = [{'destination': row[0], 'next_hop': row[1], 'subnet_mask': row[2], 'interface': row[3]} for row in data]

            else:
                # Unsupported file type
                all_data = None

    except FileNotFoundError:
        # If the file is not found, return None
        all_data = None

    return all_data

def load_hostname_file(self, file_path):
    with open(file_path, 'r') as file:
        for line in file:
            hostname, ip_address = line.strip().split()
            self.hostname_mapping[hostname] = ip_address

def load_routingtable_file(self, file_path):
    with open(file_path, 'r') as file:
        for line in file:
            destination, next_hop = line.strip().split()
            self.routing_table[destination] = next_hop

def load_interface_file(self, file_path):
    with open(file_path, 'r') as file:
        for line in file:
            interface, ip_address = line.strip().split()
            self.interface_info[interface] = ip_address

def save_to_json(file_name, hashmap):
    with open(file_name, 'w') as f:
        json.dump(hashmap, f)