# Network Traffic Monitor

A network traffic monitoring and analysis system made for our Computer Networks Lab (CL3001) project. It captures live packets from a network interface, saves them in a database, and shows them on a web dashboard.

## What it does

- Captures live packets using Scapy
- Reads the source and destination IP, ports, MAC addresses, packet size and time
- Identifies the protocol (TCP, UDP, DNS, HTTP, HTTPS, ICMP, ARP)
- Stores everything in an SQLite database
- Shows total packets, total data, top source IP and a protocol chart on a dashboard
- Lets you filter the packet table by protocol or IP address
- Start, Stop and Clear buttons on the dashboard

## Technologies

- Python
- Scapy
- Flask
- SQLite
- HTML, CSS, JavaScript
- Chart.js

## Project structure

```
.
├── app.py              # Flask server and API routes
├── capture.py          # packet capturing and protocol identification
├── db.py               # SQLite database functions
├── requirements.txt
└── templates/
    └── index.html      # the dashboard page
```

## How to run

These steps are for Ubuntu/Linux.

1. Clone the repo
https://github.com/hasnainNU/network-traffic-monitor.git


2. Create a virtual environment and install the requirements
python3 -m venv project_env
source project_env/bin/activate
pip install -r requirements.txt

3. Start the app. It needs sudo because capturing packets requires root access