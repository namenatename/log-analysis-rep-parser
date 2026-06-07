# Parser used to find total events in .json and parse key network event log (ID 3) total

import json

def get_logs(path):
    events = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip() 
            if line: # check for empty lines
                events.append(json.loads(line))
    return events

def network_events(events):
    return [e for e in events if e.get('EventID') == 3] # returns None by default

# function for EID 1 hash parsing
def eid_1(events):
    return [e for e in events if e.get('EventID') == 1]

