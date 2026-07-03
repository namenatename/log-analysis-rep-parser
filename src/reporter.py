# Report generator to confirm findings of VT API

import csv

# Tidy/long layout: one row per data point as (Source, Field, Value). Core VT
# stats are written for every IOC; verbose enrichment rows only for flagged IOCs.
report_header = ['IOC', 'Verdict', 'Source', 'Field', 'Value']

def ip_verdict(stats):
    # Fix flagging condition
    if (stats['malicious'] >= 1 or stats['suspicious'] >= 2) and stats['confidence'] >= 50:
        return 'FLAGGED/HIGH'
    elif stats['malicious'] >= 3:
        return 'FLAGGED BY VT'
    elif (stats['malicious'] >= 1 or stats['suspicious'] >= 1) and stats['confidence'] >= 20:
        return 'SUSPICIOUS'
    elif stats['isTor'] is True:
        return 'SUSPICIOUS (Tor Exit Node)'
    return 'CLEAN'

def emit_rows(writer, ioc, verdict, rows):
    # rows is a list of (source, field, value) tuples for this IOC
    for source, field, value in rows:
        writer.writerow([ioc, verdict, source, field, value])

def ip_rows(stats, flagged):
    core = [
        ('VT', 'Malicious', stats['malicious']),
        ('VT', 'Suspicious', stats['suspicious']),
        ('VT', 'Harmless', stats['harmless']),
    ]
    if not flagged:
        return core
    # VT is the standard for country/owner, so AbuseIPDB's countryCode/isp are omitted
    verbose = [
        ('VT', 'Undetected', stats['undetected']),
        ('VT', 'Timeout', stats['timeout']),
        ('VT', 'Reputation', stats['reputation']),
        ('VT', 'Country', stats['country']),
        ('VT', 'Owner', stats['as_owner']),
        ('VT', 'Network', stats['network']),
        ('VT', 'Permalink', stats['vt_permalink']),
        ('AbuseIPDB', 'Confidence', stats['confidence']),
        ('AbuseIPDB', 'Total Reports', stats['total_reports']),
        ('AbuseIPDB', 'isTor', stats['isTor']),
        ('AbuseIPDB', 'Usage Type', stats['usageType']),
        ('AbuseIPDB', 'Domain', stats['domain']),
        ('AbuseIPDB', 'Last Reported', stats['lastReportedAt']),
    ]
    return core + verbose

def hash_rows(stats, flagged):
    core = [
        ('VT', 'Malicious', stats['malicious']),
        ('VT', 'Suspicious', stats['suspicious']),
        ('VT', 'Harmless', stats['harmless']),
    ]
    if not flagged:
        return core
    verbose = [
        ('VT', 'Undetected', stats['undetected']),
        ('VT', 'Timeout', stats['timeout']),
        ('VT', 'Reputation', stats['reputation']),
        ('VT', 'Type Description', stats['type_description']),
        ('VT', 'Meaningful Name', stats['meaningful_name']),
        ('VT', 'Names', stats['names']),
        ('VT', 'Size', stats['size']),
        ('VT', 'Permalink', stats['vt_permalink']),
    ]
    return core + verbose

def generate_report(result, choice):
    with open('output/report.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(report_header)
        # Loop through each IOC and emit its data points as labeled rows
        if choice == 'A':
            for ip in result:
                stats = result[ip]
                verdict = ip_verdict(stats)
                emit_rows(writer, ip, verdict, ip_rows(stats, verdict != 'CLEAN'))
        elif choice == 'B':
            for file_hash in result:
                stats = result[file_hash]
                flagged = stats['malicious'] >= 1 or stats['suspicious'] >= 2
                verdict = 'FLAGGED' if flagged else 'CLEAN'
                emit_rows(writer, file_hash, verdict, hash_rows(stats, flagged))

def main_menu():
    print('Log Parser & IOC Scanner Menu')
    print('Select from choices: ')
    print('A) IP Check')
    print('B) Hash Check')
    print('Q) Quit')
    

            






