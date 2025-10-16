# NETWOTK_SCANNER
# Robust Nmap Scanner


![Network Scanner Screenshot](NS.png)


A flexible Python wrapper around Nmap that provides commonly used scans (SYN, TCP connect, UDP, version, OS detection) and support for idle (zombie) scans. Designed for authorized security testing, lab use and learning.


> ⚠️ **Important:** Only scan hosts and networks you own or have explicit written permission to test. Unauthorized scanning may be illegal and/or disruptive.


## Features


- Multiple scan types: `connect`, `syn`, `udp`, `version`, `os`, `all`, `idle` (zombie).
- Accepts single IP, hostname or CIDR (e.g. `192.168.1.0/24`).
- Optional port ranges (e.g. `1-1024` or `22,80,443`).
- Save detailed results to JSON.
- Human-readable summary output.


## Requirements


- Python 3.8+
- [Nmap](https://nmap.org) binary installed and available in PATH.
- Python package: `python-nmap`


## Installation


```bash
# On Debian/Ubuntu / Parrot OS
sudo apt update && sudo apt install nmap
# Install python library for the Python interpreter you will use
python3 -m pip install --user python-nmap



///Optionally create a virtual environment:

python3 -m venv venv
source venv/bin/activate # Linux/macOS
# venv\Scripts\activate # Windows PowerShell
python -m pip install python-nmap

