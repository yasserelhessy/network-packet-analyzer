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

# Import libraries needed for packet parsing, networking, geolocation, visualization, and communication with Splunk
import dpkt                     # Used to parse pcap files and extract packet-level information
import socket                   # Converts raw IP addresses to human-readable format
import geoip2.database          # Accesses the MaxMind GeoLite2 City geolocation database
import os                       # OS-level operations like file and path handling
from dotenv import load_dotenv  # Loads environment variables from a .env file (if used for sensitive data)
import subprocess               # For running system commands (e.g., launching Chrome or dumpcap)
import time                     # For delays/sleep and timing control
import folium                   # For creating interactive maps
import requests                 # Sends HTTP requests (used here for Splunk HEC integration)
import json                     # Handles JSON encoding/decoding
import urllib3                  # HTTP library used to disable SSL warnings
import argparse                 # For command-line argument parsing
import logging                  # For logging messages and errors
from tqdm import tqdm           # For progress bars in loops
import threading                # For running tasks in parallel
from inputimeout import inputimeout, TimeoutOccurred # For handling user input with a timeout

load_dotenv()  # Load environment variables from .env file

# Configure logging to output to console
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler("network_analyzer.log"),  # Logs to file
        #logging.StreamHandler()                      # Also prints to console
    ]
)

# Disable warnings for insecure HTTPS connections (since we don't verify SSL in HEC post)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize the GeoIP reader using the GeoLite2-City database
reader = geoip2.database.Reader('GeoLite2-City.mmdb')

# Configure Splunk HTTP Event Collector (HEC) credentials and endpoint
SPLUNK_HEC_TOKEN = os.getenv('SPLUNK_HEC_TOKEN', '35111295-7121-4399-a6b0-8c29e5aed30d')      # Token used for authenticating with Splunk HEC
SPLUNK_HEC_URL = os.getenv('SPLUNK_HEC_URL', 'https://127.0.0.1:8088/services/collector')     # URL of the HEC endpoint
if not SPLUNK_HEC_TOKEN or not SPLUNK_HEC_URL:
    logging.error("Error: Missing SPLUNK_HEC_TOKEN or SPLUNK_HEC_URL in .env file.")
    exit(1)

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

# parse_args — Parse command-line arguments for interface, duration, and options
def parse_args():
    parser = argparse.ArgumentParser(description="Network Packet Analyzer and Risk Visualizer")
    parser.add_argument("--interface", default="Wi-Fi 2", help="Network interface for packet capture")
    parser.add_argument("--duration", type=int, default=80, help="Capture duration in seconds")
    parser.add_argument("--skip-chrome", action="store_true", help="Skip launching international websites")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the output map in a browser")
    parser.add_argument("--splunk-token", help="Override the default Splunk HEC token")
    parser.add_argument("--export", choices=["json", "csv"], help="Export parsed data to JSON or CSV")
    return parser.parse_args()


# classify_risk — Classify determine risk level based on port and domain
def classify_risk(dst_ip, port, domain, country=None):
    high_risk_ports = [21, 23, 25, 69, 110, 135, 139, 143, 445, 1433, 2323, 3306, 3389]
    suspicious_domains = [".ru", ".cn"]
    suspicious_keywords = ['vpn', 'tor', 'proxy', 'dark', 'exploit']
    blacklisted_keywords = ["malware", "phishing", "spyware", "hacker", "exploit"]
    blacklisted_countries = ["RU", "CN", "KP", "IR"]

    domain_lower = domain.lower() if domain else ""

    # High risk if matched
    if port in high_risk_ports:
        return 'high'
    if any(keyword in domain_lower for keyword in suspicious_keywords):
        return 'high'
    if any(keyword in domain_lower for keyword in blacklisted_keywords):
        return 'high'
    if country and country.upper() in blacklisted_countries:
        return 'high'

    # Medium risk if suspicious domain suffix
    if domain_lower.endswith(tuple(suspicious_domains)):
        return 'medium'

    # Low risk if known common safe ports
    if port in [443, 80, 53]:
        return 'low'

    # DEFAULT: treat everything else as unknown
    return 'unknown'

# def classify_risk(dst_ip, port, domain, country=None):
#     high_risk_ports = [21, 23, 25, 69, 110, 135, 139, 143, 445, 1433, 2323,3306, 3389]   # Known risky ports (e.g., Telnet, SMB)
#     suspicious_domains = [".ru", ".cn"]                            # Suspicious country-code TLDs
#     suspicious_keywords = ['vpn', 'tor', 'proxy', 'dark', 'exploit'] # Keywords indicating potential risk
#     blacklisted_keywords = ["malware", "phishing", "spyware", "hacker", "exploit"] # Keywords indicating malicious intent
#     blacklisted_countries = ["RU", "CN", "KP", "IR"]  # Add more if needed
    
#     domain_lower = domain.lower() if domain else ""
    
#     if (port in high_risk_ports or domain) and any(keyword in domain_lower for keyword in suspicious_keywords):
#         return 'high'
        
#     if country and country.upper() in blacklisted_countries:
#         return 'high'
#     if any(keyword in domain_lower for keyword in blacklisted_keywords):
#         return 'high'
    
#     # if domain:
#     #     domain_lower = domain.lower()
#     if any(domain_lower.endswith(s) for s in suspicious_domains):
#         return 'medium'
#     if domain and any(domain.lower().endswith(s) for s in suspicious_domains):
#         return 'medium'

#     if port in [443, 80, 53]:                                      # Common ports for web and DNS traffic
#         return 'low'

# # Default case
#     return 'unknown'    


# send_to_splunk — Send event data to Splunk HEC
def send_to_splunk(event_data):
    payload = {
        "event": event_data,                                       # Main data payload
        "sourcetype": "_json"                                      # Set sourcetype in Splunk
    }
    try:
        logging.debug("[>] Sending to Splunk:", json.dumps(payload))       # log what's being sent
        response = requests.post(SPLUNK_HEC_URL, headers=SPLUNK_HEADERS, data=json.dumps(payload), timeout=3, verify=False)
        if response.status_code != 200:
            logging.info("[!] Failed to send event to Splunk: {response.text}")
    except Exception as e:
        logging.info("[!] Error sending to Splunk: {e}")


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
            "https://www.naver.com"
        ]
        # Open each site in Chrome with a delay
        for url in international_urls:
            subprocess.Popen([chrome_exe, url])      # Open in new Chrome process
            time.sleep(1.5)                           # Delay to ensure traffic is generated
    except Exception as e:
        logging.info("[!] Failed to open Chrome: {e}")

# plot_IPs_on_map — Visualize connections and send to Splunk
def plot_IPs_on_map(packet_list):
    ip_map = folium.Map(location=[20, 0], zoom_start=2)            # Create base world map
    dns_map = {}                                                   # Store DNS responses
    sni_map = {}                                                   # Store TLS SNI values
    seen_connections = set()
    connection_log = []                                            # Store connection metadata for Splunk

    for timestamp, buf in packet_list:                             # Loop through each packet
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
                dst_country = dst_response.country.iso_code if dst_response.country else None
                src_country = src_response.country.iso_code if src_response.country else None
                style = RISK_STYLE_MAP.get(risk, 'gray')

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
                # Choose line color based on risk
                line_color = RISK_STYLE_MAP.get(risk, 'gray')
                # if risk == 'high':
                #     line_color = 'red'
                # elif risk == 'medium':
                #     line_color = 'orange'
                # elif risk == 'low':
                #     line_color = 'green'
                # else:
                #     line_color = 'gray'  # unknown

                # Draw colored polyline
                # folium.PolyLine(locations=[(37.7749, -122.4194), (latitude, longitude)],
                #                 color=line_color, weight=2.5, opacity=1).add_to(map_osm)

                folium.PolyLine(
                    [(srclat, srclon), (dstlat, dstlon)],
                    color=line_color,
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
                connection_log.append(event_data)                    # Store for Splunk
                send_to_splunk(event_data)

            except Exception as e:
                logging.warning(f"[!] Geolocation error for {src} or {dst}: {e}")
                continue

        except Exception as e:
            logging.warning(f"[!] Error processing packet: {e}")
            continue

    return ip_map, connection_log     # Return the map and connection log for further processing


# export_to_file — Export connection log to JSON or CSV file
def export_to_file(data, format="json", filename="connections"):
    try:
        if format == "json":
            with open(f"{filename}.json", "w") as f:
                json.dump(data, f, indent=4)
        elif format == "csv":
            import csv
            keys = data[0].keys() if data else []
            with open(f"{filename}.csv", "w", newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(data)
        logging.info(f"[+] Exported connection log to {filename}.{format}")
    except Exception as e:
        logging.warning(f"[!] Failed to export data: {e}")


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
        logging.info(f"[+] Capture complete: {output_path}")
    except Exception as e:
        logging.info(f"[!] Packet capture error: {e}")

# open_in_browser — Open generated map in browser
def open_in_browser(map_object, file_name="ip_map.html"):
    map_object.save(file_name)                                         # Save map to HTML
    subprocess.run(["start", file_name], shell=True)                   # Open in browser on Windows

responded = [False]    # Flag to track if user has responded to prompt

# Timer thread to auto-cancel prompt
def wait_and_timeout():
    time.sleep(10)
    if not responded[0]:
        print("\n[!] No input received. Skipping Splunk Web UI launch.")
        responded[0] = True
        return

def prompt_open_splunk():
    try:
        answer = inputimeout(prompt="Do you want to open Splunk Web UI? (yes/no) [no is the default after 60s]: ").strip().lower()
        responded[0] = True # Set flag to indicate user has responded
        if answer in ['yes', 'y']:
            logging.info("[+] Opening Splunk Web UI at http://localhost:8000 ...")
            subprocess.run(["start", "http://localhost:8000"], shell=True)  # Windows
            # subprocess.run(["xdg-open", "http://localhost:8000"])  # Linux
            # subprocess.run(["open", "http://localhost:8000"])  # macOS
        elif answer in ['no', 'n']  or answer == '':
            logging.info("[-] Splunk Web UI not opened.")
    except TimeoutOccurred: # Handle timeout if no input received
        logging.warning(f"[!] No input received. Skipping Splunk Web UI launch.")

# main — Orchestrates the entire process
def main():
    args = parse_args()

    if args.splunk_token:
        global SPLUNK_HEC_TOKEN
        SPLUNK_HEADERS['Authorization'] = f"Splunk {args.splunk_token}"

    if not args.skip_chrome:
        open_chrome_tabs_for_international_sites()
        time.sleep(20)  # Allow DNS/HTTPS resolution

    capture_with_dumpcap(interface=args.interface, duration_sec=args.duration, output_file="cap_int.pcap")

    with open('cap_int.pcap', 'rb') as f:
        pcap_reader = dpkt.pcap.Reader(f)
        packet_list = list(pcap_reader)
        ip_map, connection_log = plot_IPs_on_map(packet_list)

    ip_map.save("ip_map.html")  # Save the map to an HTML file
    logging.info("[+] Map generated.")
    
    # Optional export
    if args.export:
        export_to_file(connection_log, format=args.export)
            
    for timestamp, buf in tqdm(packet_list, desc="Processing packets"):
           try:
               eth = dpkt.ethernet.Ethernet(buf)
               # ... continue processing IP, TCP/UDP, etc.
           except Exception as e:
               logging.warning(f"[!] Error parsing packet: {e}")
              
    if not args.no_browser:
        open_in_browser(ip_map)
        
    # Wait 1 minute, then ask user if they want to open Splunk
    logging.info("[*] Waiting 1 minute before prompting to open Splunk...")
    time.sleep(10)
    
    # Start timeout thread before input prompt
    #threading.Thread(target=wait_and_timeout, daemon=True).start()
    prompt_open_splunk()

    logging.info("[+] Process complete. Check the generated map and Splunk for results.")
    
      
if __name__ == '__main__':
    main()
