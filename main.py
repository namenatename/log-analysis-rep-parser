""" Run the script and enrich IOCs! """

import time
from src.parser import get_logs, network_events, eid_1
from src.extractor import extract_hash, extract_ips
from src.virustotal import check_hash, vt_check_ip
from src.reporter import generate_report, main_menu
from src.abuseipdb import abuse_check

def main():
    events = get_logs('sample_logs/mimikatz_alerts.json')
    net_evts = network_events(events)
    hash_evts = eid_1(events)
    ip_list = extract_ips(net_evts)
    hash_list = extract_hash(hash_evts)
    result_dict = {}
    main_menu()
    choice = input('Option: ').upper().strip()
    while choice != 'Q' and choice != 'A' and choice !='B':
        choice = input('Option: ').upper().strip()
    if choice == 'A':
        for i in ip_list:
            print(f'Checking IP: {i}... ')
            result = vt_check_ip(i)
            ipdb_result = abuse_check(i)
            # Store both data references in same dict
            result_dict[i] = {**result, **ipdb_result}
            time.sleep(15)
        print('Done!')
        generate_report(result_dict, 'A')
    elif choice == 'B':
        for index, i in enumerate (hash_list, start=1):
            print('Checking Hash:', index, 'out of', len(hash_list))
            result = check_hash(i)
            result_dict[i] = result
            time.sleep(15)
        print('Done!')
        generate_report(result_dict, 'B')
    elif choice == 'Q':
        print('Thank you!')
    
if __name__ == '__main__':
    main()
