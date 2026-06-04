# Log-Parser-IOC-Scanner 

A Python-based tool that parses Sysmon JSON logs and uses extracted IOCs against the VirusTotal API to identify malicious indicators with MITRE ATT&CK framework mapping

## Features

- **Parser** - tool used to find total events within a .json and parse total events and network events (ID 3) from the file
- **Extractor** - gathers IOC (Indicator of Compromise) data from the parser, specifically Source IPs and Destination IPs from network events
- **VirusTotal API IP Lookup** - analyzes list of IPs against VirusTotal API to search for malicious indicators for each source
- **Reporter** - generates .csv reports for each IP and gives verdict on malicious status from VT API

## Dataset

Using raw log data provided by the OTRF Security Datasets project: https://github.com/OTRF/Security-Datasets/
Dataset used was the [Mimikatz Data Set](https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_extract_keys.zip)
*Mimikatz is a post-exploitation Windows tool that dumps credentials and its tasks, such as requesting Kerberos tickets, often generate originating IP logs within Windows Event Logs*

## Requirements

- Python 3.8+
- VirusTotal free API key (runs 4 req/min | https://virustotal.com)

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/namenatename/log-parser-ioc-scanner.git
cd log-parser-ioc-scanner

# 2. Activate venv
python -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add VirusTotal API key
echo "VT_API_KEY=your_key_here" > .env

# 5. Run the tool
python src/reporter.py
```

## Usage

Run the current VirusTotal API toolset using:
	python3 src/reporter.py
Note: VirusTotal free tier limits the script to ~2 minutes for the 8 IPs found in the test dataset, output will not generate until after all IPs are tested

## Output

The reporter tool will generate a .csv found within output/report.csv:
```csv
IP,Malicious,Suspicious,Harmless,Result
13.107.4.50,1,0,58,FLAGGED
40.90.22.192,0,0,57,CLEAN
172.18.38.5,0,0,56,CLEAN
104.117.16.77,0,0,58,CLEAN
172.18.39.5,0,0,54,CLEAN
172.18.39.255,0,0,0,CLEAN
172.18.39.6,0,0,55,CLEAN
52.167.249.196,0,0,56,CLEAN
```

## MITRE ATT&CK Mapping

Results from the dataset map to T1003 - OS Credential Dumping, which can correlate to Mimikatz execution
VirusTotal API mapping of Network IOCs from Sysmon Event ID 3 used to detect Mimikatz credential dumping activity and outbound connections

Relevant Detection Strategy: DET0234 - Credential Dumping via Sensitive Memory and Registry Access Correlation;
	Logs Sysmon Event IDs 10 and 1 to detect unauthorized access to sensitive OS subsystems for credential extraction
Mitigation Strategy: M1040 - Behavior Prevention on Endpoint
	Enable Attack Surface Reduction (ASR) rules to prevent credential stealing

## Future Features

- Include hash lookup against VirusTotal API to scan files for malicious indicators
- Include API mapping for AbuseIPDB and AlienVault OTX for multi-source IOC context
- AWS CLoudTrail support and querying logos via boto3
- Other log format support (Windows EVTX)


## Structure 

```
Log-Parser/
	output/
		.gitkeep
		report.csv
	sample_logs/
		sample_alerts.json # Datset used found in Datset section
	src/ # Source code with all tools
		extractor.py
		parser.py
		reporter.py
		virustotal.py
	.env
	.gitignore
	README.md
	requirements.txt
```
