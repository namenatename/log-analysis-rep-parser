# AbuseIPDB functionality

import os
from dotenv import load_dotenv
import requests

load_dotenv()
api_key = os.getenv('ABUSEIPDB_API_KEY', '')

def abuse_check(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip}
    headers = {'Accept': 'application/json', 'Key': api_key}
    try:
        ipdb_check = requests.request(method='GET', url=url, headers=headers, params=params)
        ipdb_check.raise_for_status()
        data = ipdb_check.json().get('data', {})
        return {
            'confidence': data.get('abuseConfidenceScore'),
            'total_reports': data.get('totalReports'),
            'isTor': data.get('isTor'),
            'usageType': data.get('usageType'),
            'domain': data.get('domain'),
            'lastReportedAt': data.get('lastReportedAt'),
        }
    except Exception as e:
        print(f'Error checking {ip}: {e}')
        return {
            'confidence': 0,
            'total_reports': 0,
            'isTor': None,
            'usageType': None,
            'domain': None,
            'lastReportedAt': None,
        }

