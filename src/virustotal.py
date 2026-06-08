# VirusTotal API IP lookup and parsing data for malicious indicator factoring

import os
from dotenv import load_dotenv
import requests

load_dotenv()
api_key = os.getenv('VT_API_KEY')

def vt_check_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': api_key}
    # Implement try/except to handle errors
    try:
        # Make request to VT for IP check and parse data for use
        vt_check = requests.get(url, headers=headers)
        # Check for error codes
        vt_check.raise_for_status
        data = vt_check.json()
        malicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious')
        sus = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious')
        harmless = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless')
        return {'malicious': malicious, 
            'suspicious': sus, 
            'harmless': harmless
        }
    except Exception as e:
        print(f'Error checking {ip}: {e}')
        return {'malicious': 0, 
            'suspicious': 0, 
            'harmless': 0
        }

def check_hash(file_hash):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': api_key}
    # Request and parse hash data
    try:
        vt_check = requests.get(url, headers=headers)
        vt_check.raise_for_status
        data = vt_check.json()
        malicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious')
        sus = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious')
        harmless = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless')
        return {'maliciou': malicious, 
            'suspicious': sus, 
            'harmless': harmless
        }
    except Exception as e:
        print(f'Error checking {file_hash}: {e}')
        return {'malicious': 0, 
            'suspicious': 0, 
            'harmless': 0
        }



