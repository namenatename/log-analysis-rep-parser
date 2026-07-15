""" Run the script and enrich IOCs! """

from rich.console import Console
from rich.progress import track
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
    console = Console()
    while choice != 'Q' and choice != 'A' and choice !='B' and choice != 'T':
        choice = input('Option: ').upper().strip()
    if choice == 'A':
        for i in track(ip_list, description='Processing IPs...'):
            result = vt_check_ip(i)
            ipdb_result = abuse_check(i)
            # Store both data references in same dict
            result_dict[i] = {**result, **ipdb_result}
            time.sleep(15)
        console.print('\n[bold cyan]Done! Find the reports in the output/ folder.')
        generate_report(result_dict, 'A')
    elif choice == 'B':
        for i in track(hash_list, description='Processing Hashes...'):
            result = check_hash(i)
            result_dict[i] = result
            time.sleep(15)
        console.print('\n[bold cyan]Done! Find the reports in the output/ folder.')
        generate_report(result_dict, 'B')
    elif choice == 'Q':
        console.print('\n[bold cyan] Thank you!')
    
if __name__ == '__main__':
    main()
