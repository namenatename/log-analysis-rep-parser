# Log-Parser-IOC-Scanner 

An IOC Enrichment tool that parses Sysmon JSON logs and uses extracted IOCs against the VirusTotal API & AbuseIPDB API to identify malicious indicators with MITRE ATT&CK framework mapping

## Features

- **Parser** - tool used to find total events within a .json and parse total events, network events (ID 3), and process creation events (EID 1) from the file
- **Extractor** - gathers IOC (Indicator of Compromise) data from the parser, specifically Source/Destination IPs from network events and SHA256 hashes from process creation events
- **API Enrichment** - analyzes list of IPs/hashes against VirusTotal API and cross-references IP data with AbuseIPDB API to search for malicious indicators for each source
- **Reporter** - generates .csv reports for each IOC and gives verdict on malicious status from VT/AIPDB API cross-referencing

## Dataset

Using raw log data provided by the OTRF Security Datasets project: https://github.com/OTRF/Security-Datasets/
Dataset used was the [Mimikatz Data Set](https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_extract_keys.zip)
*Mimikatz is a post-exploitation Windows tool that dumps credentials and its tasks, such as requesting Kerberos tickets; the tool often generates originating IP logs within Windows Event Logs*

## Requirements

- Python 3.8+
- VirusTotal free API key (runs 4 req/min | https://virustotal.com)
- AbuseIPDB free API key (1000 req/day | https://abuseipdb.com)

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

# 4. Add API keys, fill out placeholders with individual keys
cp .env.example .env

# 5. Run the tool
python main.py
```

## Usage

Run the current IOC scanner toolset using:
	python main.py
Note: VirusTotal free tier limits the script to ~2 minutes for the 8 IPs found in the test dataset, output will not generate until after all IPs are tested

## Output

The reporter tool will generate a .csv found within output/report.csv:

**IP Lookup**
```csv
Type,IOC,Malicious,Suspicious,Harmless,AbuseIPDB Score,Threat
IP,13.107.4.50,1,0,58,0,CLEAN
IP,52.167.249.196,0,0,56,0,CLEAN
IP,104.117.16.77,0,0,58,0,CLEAN
IP,50.16.16.211,6,1,53,18,FLAGGED BY VT
```

**Hash Lookup**
```csv
Type,IOC,Malicious,Suspicious,Harmless,Result
HASH,11781CF9A807BDF44BC0B0E2D31EBCCBEA16F7DBF87753D5E107E93FAD91F48D,0,0,0,CLEAN
HASH,d5d224ea6b0a9002e4637c25d41edff516335fe132e6dd53938ee0decaadedc1,29,0,0,FLAGGED
HASH,924405FD4DF46B0A1D955AA492F441B938F051CC830AB494E88398DEF701FC1F,0,0,0,CLEAN
HASH,DD191A5B23DF92E12A8852291F9FB5ED594B76A28A5A464418442584AFD1E048,0,0,0,CLEAN
HASH,A8A4C4719113B071BB50D67F6E12C188B92C70EEAFDFCD6F5DA69B6AAA99A7FD,0,0,0,CLEAN
HASH,BAF97B2A629723947539CFF84E896CD29565AB4BB68B0CEC515EB5C5D6637B69,0,0,0,CLEAN
HASH,A75C85F3B089993E9C042FB82ECB7757E8F460ED8065FC7991CAA38A6DE0F50C,0,0,0,CLEAN
```

## Synthetic IOC Injection

To test the dataset, synthetic IOC injection was used to inject one known malicious IP and malicious hash into the original dataset. The IP used was found on [Feodo Tracker's blocklist](https://feodotracker.abuse.ch/blocklist/#ip-blocklist). The IP blocklist for C2 botnets tracked by Feodo will be provided in the sample_logs/ folder of this repo. Additionally, a [sample SHA256 malicious Mimikatz hash](https://bazaar.abuse.ch/sample/d5d224ea6b0a9002e4637c25d41edff516335fe132e6dd53938ee0decaadedc1/) from the Malware Bazaar database was used to test the capabilities of the hash detector tool. The original IOC from the OTRF Mimikatz Dataset, along with the injected IOC from the two malware databases specified are as follows:

| Original IOC | Injected IOC | Database |
|---|---|---|
| IP - 40.90.22.192| 50.16.16.211 | Feodo Tracker |
| SHA256 - 7567E455BA5F511680E68E38B416173A3D8744CBD172180A50EE2364BD3551F6 | d5d224ea6b0a9002e4637c25d41edff516335fe132e6dd53938ee0decaadedc1 | MalwareBazaar |


## MITRE ATT&CK Mapping (Based on Mimikatz Log)

Test dataset maps to **T1003 - OS Credential Dumping** correlated to Mimikatz execution.
Network IOCs extracted from Sysmon Event ID 3 logs detect suspicious outbound 
connections associated with post-exploitation activity. Results from tool usage verify that the outbound connections found in this dataset were run in a test environment, as AbuseIPDB scores show confidence scores of 0, most consistent with test infrastructure, along with minimal IP flagging. Hash sets found in process creation also come back clean and are not linked to any malicious indicators. Based on these test results in a real-world scenario, MITRE ATT&CK mapping is as follows:

| Category | ID | Description |
|---|---|---|
| Technique | T1003 | OS Credential Dumping via Mimikatz execution |
| Data Source | DS0029 | Network Traffic — Sysmon Event ID 3 network connection logs |
| Detection Strategy | DET0234 | Credential Dumping via Sensitive Memory and Registry Access Correlation — logs Sysmon Event IDs 10 and 1 to detect unauthorized access to sensitive OS subsystems |
| Mitigation | M1040 | Behavior Prevention on Endpoint — Enable Attack Surface Reduction (ASR) rules to prevent credential stealing |

## Future Features

- Include API mapping for AlienVault OTX for multi-source IOC context
- Other log format support (Windows EVTX)


## Structure 

```
log-parser-ioc-scanner/
	output/                    # Reports generated will be found here
		.gitkeep
		report.csv             # Not included, sample report
	sample_logs/
	    ipblocklist.json       # Included FEODO botnet C2s from past 30 days
		mimikatz_alerts.json   # Dataset used found in Dataset section
	src/                       # Source code with tools
		abuseipdb.py
		extractor.py
		parser.py
		reporter.py
		virustotal.py
	.env                       # Instructions to add API keys found in Setup
	.env.example               # Copy from example to .env
	.gitignore
	main.py
	README.md
	requirements.txt
```
