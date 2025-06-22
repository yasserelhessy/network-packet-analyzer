# network-packet-analyzer
"""
Author: Yasser Elhessy
Created: May 31, 2025

Network Packet Analyzer, Risk Visualizer, and Splunk Logger

This script performs the following key tasks:
1. Opens international websites in Chrome to simulate outbound traffic.
2. Captures live network traffic using dumpcap and saves it as a PCAP file.
3. Parses captured packets using dpkt to extract IPs, ports, DNS domains, and TLS SNI values.
4. Geolocates source and destination IPs using the GeoLite2-City database.
5. Classifies each connection’s risk level (high, medium, low, or unknown) based on port or domain.
6. Visualizes connections on a world map using Folium, with colored lines indicating risk levels.
7. Sends structured connection metadata (IP, port, domain, risk, etc.) to a local Splunk instance via HEC.

This tool provides a visual representation of network activity, evaluates potential risks from outbound connections,
and integrates findings into Splunk for centralized security monitoring and analysis.
"""
