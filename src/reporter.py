# Report generator to confirm findings of VT API 

import os
import csv
import time
from dotenv import load_dotenv
import requests
from parser import get_logs, network_events
from extractor import extract_ioc
from virustotal import check_ip

def generate_report(result):
    with open('output/report.csv', 'w') as file:
        writer = csv.writer(file)
        writer.writerow(['IP', 'Malicious', 'Suspicious', 'Harmless', 'Result'])
        # Loop through each iteration of a new IP and subsequent results and add new CSV line
        for ip in result:
            stats = result[ip]
            if stats['malicious'] >= 1:
                writer.writerow([ip, stats['malicious'], stats['suspicious'], stats['harmless'], "FLAGGED"])
            else:
                writer.writerow([ip, stats['malicious'], stats['suspicious'], stats['harmless'], "CLEAN"])

if __name__ == "__main__":
    events = get_logs('/Users/nate/log-parser/sample_logs/mimikatz_alerts.json')
    net_evts = network_events(events)
    ip_list = extract_ioc(net_evts)
    result_dict = {}
    for i in ip_list:
        print(f"Checking IP: {i}... ")
        result = check_ip(i)
        result_dict[i] = result
        time.sleep(15)
    generate_report(result_dict)

    

            






