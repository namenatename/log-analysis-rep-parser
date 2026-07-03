# Extractor for IOC data from parser

def is_private(ip):
    """ Function to remove redundant API calls by checking for most common private IP addresses """
    if ip.startswith('10.') or ip.startswith('172.') or ip.startswith('192.168.') or ip.startswith('fe80'):
        return True
    else:
        return False


def extract_ips(events):
    """ Function to extract ips from event logs (EID 3) """
    # Set for storing unique IPs
    ip_list = set()
    for line in events:
        if line.get('SourceIp') is not None:
            source_ip = line.get('SourceIp')
            priv_check = is_private(source_ip)
            if priv_check == False:
                ip_list.add(source_ip)
        if line.get('DestinationIp') is not None:
            dest_ip = line.get('DestinationIp')
            priv_check = is_private(dest_ip)
            if priv_check == False:
                ip_list.add(dest_ip)
    return ip_list

def extract_hash(events):
    """ Function to extract hashes from event logs (EID 1) """
    # Set for storing unique hashes
    hash_list = set()
    for line in events:
        if line.get('EventID') == 1 and line.get('Hashes') is not None:
            raw_hash = line.get('Hashes')
            hash_source = raw_hash.split(',')
            for value in hash_source:
                if value.startswith('SHA256='):
                    sha256 = value.split('=')[1]
                    hash_list.add(sha256)
    return hash_list
