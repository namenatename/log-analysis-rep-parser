# VirusTotal API IP lookup and parsing data for malicious indicator factoring

import os
from dotenv import load_dotenv
import requests

load_dotenv()
api_key = os.getenv('VT_API_KEY', '')

# Default shape returned on any errors
def vt_ip_defaults():
    return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0,
            'timeout': 0, 'reputation': None, 'country': None, 'as_owner': None,
            'network': None, 'vt_permalink': None}

def vt_hash_defaults():
    return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0,
            'timeout': 0, 'reputation': None, 'type_description': None,
            'meaningful_name': None, 'names': None, 'size': None, 'vt_permalink': None}

def vt_check_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': api_key}
    try:
        # Make request to VT for IP check and parse data for use
        vt_check = requests.get(url, headers=headers)
        # Check for error codes
        vt_check.raise_for_status()
        data = vt_check.json()
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'timeout': stats.get('timeout', 0),
            'reputation': attrs.get('reputation'),
            'country': attrs.get('country'),
            'as_owner': attrs.get('as_owner'),
            'network': attrs.get('network'),
            'vt_permalink': f'https://www.virustotal.com/gui/ip-address/{ip}',
        }
    except Exception as e:
        print(f'Error checking {ip}: {e}')
        return vt_ip_defaults()

def check_hash(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': api_key}
    # Request and parse hash data
    try:
        vt_check = requests.get(url, headers=headers)
        vt_check.raise_for_status()
        data = vt_check.json()
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        names = attrs.get('names') or []
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'timeout': stats.get('timeout', 0),
            'reputation': attrs.get('reputation'),
            'type_description': attrs.get('type_description'),
            'meaningful_name': attrs.get('meaningful_name'),
            # Cap the alias list so a noisy sample can't blow up the cell
            'names': '; '.join(names[:5]) if names else None,
            'size': attrs.get('size'),
            'vt_permalink': f'https://www.virustotal.com/gui/file/{file_hash}',
        }
    except Exception as e:
        print(f'Error checking {file_hash}: {e}')
        return vt_hash_defaults()



