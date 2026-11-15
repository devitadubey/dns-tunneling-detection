
# DNS Tunneling Detection System

## Project Overview

This project identifies potentially suspicious DNS queries that may indicate DNS tunneling activity.

DNS tunneling is a technique in which DNS queries are used to transfer encoded data. This project analyzes DNS traffic from PCAP files and identifies suspicious query patterns using configurable detection thresholds.

Detected incidents are stored in an SQLite database and displayed through a Streamlit dashboard.

## Features

- DNS packet analysis from PCAP files.
- Detection based on DNS query length, entropy, and query frequency.
- Automatic recording of detected incidents in an SQLite database.
- Streamlit dashboard for viewing recent detection incidents.
- Baseline PCAP testing.

## Technologies Used

- Python
- Scapy
- Pandas
- Streamlit
- SQLite

## Detection Parameters

| Parameter | Threshold |
|---|---:|
| DNS label length | Greater than 50 |
| Shannon entropy | Greater than 3.5 |
| Query count per source | Greater than 10 |

These are experimental thresholds and may require tuning for different network environments.

## Project Structure

```text
abes/
├── dashboard.py
├── detector.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

Clone the repository:

```bash
git clone YOUR_REPOSITORY_URL
cd YOUR_REPOSITORY_NAME
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the Detector

Place an authorized PCAP file in the project directory and run:

```bash
python detector.py your_capture.pcap
```

The detector analyzes DNS queries and stores detected incidents in `incidents.db`.

## Running the Dashboard

Run:

```bash
streamlit run dashboard.py
```

Open the local URL displayed in your terminal to view the dashboard.

## Limitations

- The detector currently analyzes offline PCAP files; it does not perform continuous live network capture.
- Detection is based on heuristic thresholds and may produce false positives or miss some tunneling activity.
- The dashboard displays incidents stored in the local SQLite database.
- Automatic blocking or network remediation is not currently implemented.

## Disclaimer

This project is developed for educational and controlled laboratory testing purposes. Analyze only network traffic that you are authorized to inspect.

