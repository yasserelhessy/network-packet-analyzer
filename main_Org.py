
#===--==-==--========-------------------------------- change to module ===============================-------------
"""
Author: Elhssy,Yasser 
Created: May 31, 2025

Network Packet Analyzer, Risk Visualizer, and Splunk Logger

This script performs the following key tasks:
1. Opens international websites in Chrome to simulate outbound traffic.
2. Captures live network traffic using dumpcap and saves it as a pcap file.
3. Parses the captured packets using dpkt to extract IPs, ports, DNS domains, and TLS SNI.
4. Geolocates the source and destination IPs using the GeoLite2-City database.
5. Classifies each connection’s risk level (high, medium, low, unknown) based on port or domain.
6. Visualizes these connections on a world map using Folium with colored lines indicating risk levels.
7. Sends structured connection metadata (IP, port, domain, risk, etc.) to a local Splunk instance via HEC.

This tool is useful for visualizing network activity, assessing potential risk from outbound connections,
and integrating findings with Splunk for centralized security monitoring and analysis.
"""

# Import libraries needed for packet parsing, networking, geolocation, visualization, and communication with Splunk
import dpkt                     # Used to parse pcap files and extract packet-level information
import socket                   # Converts raw IP addresses to human-readable format
import geoip2.database          # Accesses the MaxMind GeoLite2 City geolocation database
import os                       # OS-level operations like file and path handling
import subprocess               # For running system commands (e.g., launching Chrome or dumpcap)
import platform                 # (Imported but not used)
import time                     # For delays/sleep and timing control
import ssl                      # (Imported but not used)
import folium                   # For creating interactive maps
import requests                 # Sends HTTP requests (used here for Splunk HEC integration)
import json                     # Handles JSON encoding/decoding
import urllib3                  # HTTP library used to disable SSL warnings

# Disable warnings for insecure HTTPS connections (since we don't verify SSL in HEC post)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize the GeoIP reader using the GeoLite2-City database
reader = geoip2.database.Reader('GeoLite2-City.mmdb')

# Configure Splunk HTTP Event Collector (HEC) credentials and endpoint
SPLUNK_HEC_TOKEN = '35111295-7121-4399-a6b0-8c29e5aed30d'        # Token used for authenticating with Splunk HEC
SPLUNK_HEC_URL = 'https://127.0.0.1:8088/services/collector'     # URL of the HEC endpoint

# HTTP headers to include when sending data to Splunk
SPLUNK_HEADERS = {
    'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}',               # Auth header
    'Content-Type': 'application/json'                           # Data type
}

# Mapping of risk levels to colors for map visualization
RISK_STYLE_MAP = {
    'high': "red",
    'medium': "orange",
    'low': "green",
    'unknown': "gray"
}


# classify_risk — Classify determine risk level based on port and domain
def classify_risk(dst_ip, port, domain):
    high_risk_ports = [23, 2323, 445, 135, 139, 21]                 # Known risky ports (e.g., Telnet, SMB)
    suspicious_domains = [".ru", ".cn"]                            # Suspicious country-code TLDs

    if port in high_risk_ports: return 'high'
    if domain and any(domain.lower().endswith(s) for s in suspicious_domains):
        return 'medium'
    if port in [443, 80, 53]: return 'low'                         # Common, less suspicious ports
    return 'unknown'                                               # Default case


# send_to_splunk — Send event data to Splunk HEC
def send_to_splunk(event_data):
    payload = {
        "event": event_data,                                       # Main data payload
        "sourcetype": "_json"                                      # Set sourcetype in Splunk
    }
    try:
        print("[>] Sending to Splunk:", json.dumps(payload))       # Print what's being sent
        response = requests.post(SPLUNK_HEC_URL, headers=SPLUNK_HEADERS, data=json.dumps(payload), timeout=3, verify=False)
        if response.status_code != 200:
            print(f"[!] Failed to send event to Splunk: {response.text}")
    except Exception as e:
        print(f"[!] Error sending to Splunk: {e}")


# open_chrome_tabs_for_international_sites — Simulate international browsing
def open_chrome_tabs_for_international_sites():
    try:
        # Common paths for Google Chrome on Windows
        chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]
        # Select the first valid Chrome path
        chrome_exe = next((path for path in chrome_paths if os.path.exists(path)), None)
        if not chrome_exe:
            raise FileNotFoundError("Google Chrome not found.")

        # List of international websites
        international_urls = [
            "https://yandex.ru", "https://www.rambler.ru", "https://www.nic.ad.jp",
            "https://www.yahoo.co.jp", "https://www.baidu.com", "https://www.spiegel.de",
            "https://www.lemonde.fr", "https://www.uol.com.br", "https://www.ndtv.com",
            "https://www.naver.com",
        ]
        # Open each site in Chrome with a delay
        for url in international_urls:
            subprocess.Popen([chrome_exe, url])      # Open in new Chrome process
            time.sleep(1.5)                           # Delay to ensure traffic is generated
    except Exception as e:
        print(f"[!] Failed to open Chrome: {e}")


# plot_IPs_on_map — Visualize connections and send to Splunk
def plot_IPs_on_map(pcap):
    ip_map = folium.Map(location=[20, 0], zoom_start=2)            # Create base world map
    dns_map = {}                                                   # Store DNS responses
    sni_map = {}                                                   # Store TLS SNI values
    seen_connections = set()                                       # Avoid duplicate connections

    for ts, buf in pcap:                                           # Loop through each packet
        try:
            eth = dpkt.ethernet.Ethernet(buf)                      # Parse Ethernet frame
            ip = eth.data                                          # Extract IP layer
            if isinstance(ip, dpkt.ip.IP):                         # IPv4
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                l4 = ip.data                                       # TCP/UDP layer
            elif isinstance(ip, dpkt.ip6.IP6):                     # IPv6
                src = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
                l4 = ip.data
            else:
                continue

            port = 0
            domain = None
            sni = None

            # Extract domain from DNS query (UDP port 53)
            if isinstance(l4, dpkt.udp.UDP) and l4.dport == 53:
                try:
                    dns = dpkt.dns.DNS(l4.data)
                    if dns.qr == dpkt.dns.DNS_Q and dns.qd:
                        domain = dns.qd[0].name
                        dns_map[(src, dst)] = domain
                except: pass

            # Extract SNI from TLS Client Hello (TCP port 443)
            if isinstance(l4, dpkt.tcp.TCP) and l4.dport == 443:
                try:
                    if l4.data.startswith(b"\x16\x03"):
                        tls_record = dpkt.ssl.tls_multi_factory(l4.data)
                        for record in tls_record:
                            if isinstance(record, dpkt.ssl.TLSHandshake):
                                hs = record.data
                                if isinstance(hs, dpkt.ssl.TLSClientHello):
                                    for ext_type, ext_data in hs.extensions:
                                        if ext_type == 0:  # Server Name Indication
                                            sni = ext_data[5:].decode(errors='ignore')
                                            sni_map[(src, dst)] = sni
                except: pass

            port = l4.dport if isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)) else 0
            domain = dns_map.get((src, dst)) or dns_map.get((dst, src))
            sni = sni_map.get((src, dst)) or sni_map.get((dst, src))
            risk = classify_risk(dst, port, domain or sni)
            style = RISK_STYLE_MAP.get(risk, 'gray')
            protocol = 'TCP' if isinstance(l4, dpkt.tcp.TCP) else 'UDP' if isinstance(l4, dpkt.udp.UDP) else 'Other'

            key = (src, dst, port)
            if key in seen_connections:
                continue
            seen_connections.add(key)

            try:
                # Lookup latitude/longitude for source and destination IPs
                dst_response = reader.city(dst)
                src_response = reader.city(src)
                dstlat, dstlon = dst_response.location.latitude, dst_response.location.longitude
                srclat, srclon = src_response.location.latitude, src_response.location.longitude

                if None in (dstlat, dstlon, srclat, srclon): continue

                # Format popup content for map
                popup_info = f"""
                <b>Source IP:</b> {src}<br>
                <b>Destination IP:</b> {dst}<br>
                <b>Protocol:</b> {protocol}<br>
                <b>Port:</b> {port}<br>
                <b>Domain/SNI:</b> {domain or sni or 'N/A'}<br>
                <b>Risk Level:</b> <span style='color:{style}'>{risk}</span>
                """

                # Draw line between source and destination on map
                folium.PolyLine(
                    [(srclat, srclon), (dstlat, dstlon)],
                    color=style,
                    weight=3,
                    opacity=0.8,
                    popup=folium.Popup(popup_info, max_width=300)
                ).add_to(ip_map)

                # Add markers for source and destination
                folium.Marker(location=(srclat, srclon), tooltip=f"Source: {src}").add_to(ip_map)
                folium.Marker(location=(dstlat, dstlon), tooltip=f"Dest: {dst}").add_to(ip_map)

                # Send to Splunk
                event_data = {
                    "source_ip": src,
                    "destination_ip": dst,
                    "protocol": protocol,
                    "port": port,
                    "domain": domain or sni,
                    "risk": risk
                }
                send_to_splunk(event_data)

            except Exception as e:
                print(f"[!] Geolocation error for {src} or {dst}: {e}")
                continue

        except Exception as e:
            print("[!] Packet error:", e)
            continue

    return ip_map


# capture_with_dumpcap — Use Wireshark’s CLI tool to capture packets
def capture_with_dumpcap(interface="Wi-Fi 2", duration_sec=180, output_file="cap_int.pcap"):
    output_path = os.path.abspath(output_file)                          # Absolute path to output file
    try:
        subprocess.run([
            "dumpcap",                                                  # Capture command
            "-i", interface,                                            # Network interface name
            "-a", f"duration:{duration_sec}",                           # Stop after X seconds
            "-w", output_path,                                          # Write output to file
            "-F", "pcap"                                                # Specify pcap format
        ], check=True)
        print(f"[+] Capture complete: {output_path}")
    except Exception as e:
        print(f"[!] Packet capture error: {e}")

# open_in_browser — Open generated map in browser
def open_in_browser(map_object, file_name="ip_map.html"):
    map_object.save(file_name)                                         # Save map to HTML
    subprocess.run(["start", file_name], shell=True)                   # Open in browser on Windows

# main — Orchestrates the entire process
def main():
    open_chrome_tabs_for_international_sites()                         # Step 1: Simulate outbound traffic
    time.sleep(20)                                                     # Wait for DNS/HTTPS to resolve
    capture_with_dumpcap(interface="Wi-Fi 2", duration_sec=180, output_file="cap_int.pcap")  # Step 2: Capture packets
    with open('cap_int.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)                                     # Step 3: Read PCAP
        ip_map = plot_IPs_on_map(pcap)                                 # Step 4: Analyze & visualize
        print("[+] Map generated.")
        open_in_browser(ip_map)                                        # Step 5: Open map in browser

if __name__ == '__main__':
    main()
