# PortAd
Port scanner with service detection and basic security advice.
Overview
This project is a Python-based network security scanner that uses the nmap library to detect open ports, identify running services, and provide basic security recommendations.
It is designed for quick vulnerability checks on a given target IP or range.

Features

Port Scanning - Scans for open ports using nmap.

Service Detection - Identifies service versions running on open ports.

Security Recommendations - Provides best practice advice for common services.

Timestamp Logging - Records scan start and end times.

Requirements

Python 3.x 

python-nmap

Install dependencies:

pip install python-nmap

Usage

Run the script: python scanner.py

Enter the target IP address or hostname when prompted.

Disclaimer

This tool is intended for educational and authorized security testing only.
Do not use it on networks or systems you do not own or have explicit permission to test.


