# Report generator to confirm findings of VT API

import csv
import json

# ip_std used for clean verdicts; verbose for sus and flagged
ip_std = ['Type', 'IOC', 'Verdict', 'VT Malicious', 'VT Suspicious', 'VT Harmless']
ip_verbose = [
    'VT Undetected', 'VT Timeout', 'VT Reputation', 'VT Country', 'VT Owner',
    'VT Network', 'VT Permalink', 'AbuseIPDB Confidence', 'AbuseIPDB Total Reports',
    'AbuseIPDB isTor', 'AbuseIPDB Usage Type', 'AbuseIPDB Domain', 'AbuseIPDB Last Reported',
]

# Same structure for hashes as ip, but no AbuseIPDB
hash_std = ['Type', 'IOC', 'Verdict', 'VT Malicious', 'VT Suspicious', 'VT Harmless']
hash_verbose = [
    'VT Undetected', 'VT Timeout', 'VT Reputation', 'VT Type Description',
    'VT Meaningful Name', 'VT Names', 'VT Size', 'VT Permalink',
]

def ip_verdict(stats):
    if (stats['malicious'] >= 1 or stats['suspicious'] >= 2) and stats['confidence'] >= 50:
        return 'FLAGGED/HIGH'
    elif stats['malicious'] >= 3:
        return 'FLAGGED BY VT'
    elif (stats['malicious'] >= 1 or stats['suspicious'] >= 1) and stats['confidence'] >= 20:
        return 'SUSPICIOUS'
    elif stats['isTor'] is True:
        return 'SUSPICIOUS (Tor Exit Node)'
    return 'CLEAN'

def ip_entry(ip, stats):
    # Build entry for json log
    verdict = ip_verdict(stats)
    entry = {
        'ioc': ip,
        'type': 'IP',
        'verdict': verdict,
        'VirusTotal': {
            'malicious': stats['malicious'],
            'suspicious': stats['suspicious'],
            'harmless': stats['harmless'],
        },
    }
    if verdict != 'CLEAN':
        # Verbose stats will use VT as default if same as AbuseIPDB
        # E.g. country will come from VT rather than both
        entry['VirusTotal'].update({
            'undetected': stats['undetected'],
            'timeout': stats['timeout'],
            'reputation': stats['reputation'],
            'country': stats['country'],
            'owner': stats['as_owner'],
            'network': stats['network'],
            'permalink': stats['vt_permalink'],
        })
        entry['AbuseIPDB'] = {
            'confidence': stats['confidence'],
            'total_reports': stats['total_reports'],
            'isTor': stats['isTor'],
            'usage_type': stats['usageType'],
            'domain': stats['domain'],
            'last_reported': stats['lastReportedAt'],
        }
    return entry

def hash_entry(file_hash, stats):
    # Matches the structure of ip json log
    flagged = stats['malicious'] >= 1 or stats['suspicious'] >= 2
    entry = {
        'ioc': file_hash,
        'type': 'HASH',
        'verdict': 'FLAGGED' if flagged else 'CLEAN',
        'VirusTotal': {
            'malicious': stats['malicious'],
            'suspicious': stats['suspicious'],
            'harmless': stats['harmless'],
        },
    }
    if flagged:
        entry['VirusTotal'].update({
            'undetected': stats['undetected'],
            'timeout': stats['timeout'],
            'reputation': stats['reputation'],
            'type_description': stats['type_description'],
            'meaningful_name': stats['meaningful_name'],
            'names': stats['names'],
            'size': stats['size'],
            'permalink': stats['vt_permalink'],
        })
    return entry

def write_json(result, choice):
    if choice == 'A':
        report = [ip_entry(ip, stats) for ip, stats in result.items()]
    elif choice == 'B':
        report = [hash_entry(file_hash, stats) for file_hash, stats in result.items()]
    else:
        report = []
    with open('output/report.json', 'w') as file:
        json.dump(report, file, indent=4)

def write_row(writer, core, verbose, flagged):
    if flagged:
        writer.writerow(core + verbose)
    else:
        writer.writerow(core + [''] * len(verbose))

def write_csv(result, choice):
    with open('output/report.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        if choice == 'A':
            writer.writerow(ip_std + ip_verbose)
            for ip, stats in result.items():
                verdict = ip_verdict(stats)
                core = ['IP', ip, verdict, stats['malicious'], stats['suspicious'], stats['harmless']]
                verbose = [
                    stats['undetected'], stats['timeout'], stats['reputation'],
                    stats['country'], stats['as_owner'], stats['network'], stats['vt_permalink'],
                    stats['confidence'], stats['total_reports'], stats['isTor'],
                    stats['usageType'], stats['domain'], stats['lastReportedAt'],
                ]
                write_row(writer, core, verbose, verdict != 'CLEAN')
        elif choice == 'B':
            writer.writerow(hash_std + hash_verbose)
            for file_hash, stats in result.items():
                flagged = stats['malicious'] >= 1 or stats['suspicious'] >= 2
                verdict = 'FLAGGED' if flagged else 'CLEAN'
                core = ['HASH', file_hash, verdict, stats['malicious'], stats['suspicious'], stats['harmless']]
                verbose = [
                    stats['undetected'], stats['timeout'], stats['reputation'],
                    stats['type_description'], stats['meaningful_name'], stats['names'],
                    stats['size'], stats['vt_permalink'],
                ]
                write_row(writer, core, verbose, flagged)
        
def generate_report(result, choice):
    write_json(result, choice)
    write_csv(result, choice)

def main_menu():
    print('Log Parser & IOC Scanner Menu')
    print('Select from choices: ')
    print('A) IP Check')
    print('B) Hash Check')
    print('Q) Quit')