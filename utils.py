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

def save_to_json(file_name, hashmap):
    with open(file_name, 'w') as f:
        json.dump(hashmap, f)