#!/usr/bin/env python3

import ipaddress
import subprocess
import sys
import signal
import argparse
import logging
import asyncio
import platform
import json
from scapy.all import sr1, IP, TCP, conf
from socket import socket, AF_INET, SOCK_STREAM, timeout

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Suppress scapy warnings
conf.verb = 0

# Top 100 ports commonly targeted by attackers
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143, 161, 179, 389, 443,
    445, 512, 513, 514, 548, 993, 995, 1433, 1434, 1521, 1723, 2049, 2121, 3306,
    3389, 5060, 5432, 5900, 6000, 6667, 10000, 12345, 32768, 49152, 49153, 49154,
    49155, 49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165,
    49166, 49167, 49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175, 49176,
    49177, 49178, 49179, 49180, 49181, 49182, 49183, 49184, 49185, 49186, 49187,
    49188, 49189, 49190, 49191, 49192, 49193, 49194, 49195, 49196, 49197, 49198,
    49199, 49200, 49201, 49202, 49203, 49204, 49205, 49206, 49207, 49208, 49209,
    49210, 49211, 49212, 49213, 49214, 49215
]

async def async_ping_host(ip, semaphore):
    """Pings a host asynchronously and returns the IP if it's alive."""
    async with semaphore:
        logging.info(f"Executing ping at host {ip}")
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        proc = await asyncio.create_subprocess_exec(
            'ping', param, '1', '-W', '1', str(ip),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            return str(ip)
    return None

def scan_ports(ip):
    """Scans common ports on a given IP and returns open ports and banners."""
    open_ports = []
    for port in COMMON_PORTS:
        pkt = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            banner = grab_banner(ip, port)
            open_ports.append({"port": port, "banner": banner})
    return open_ports

def grab_banner(ip, port):
    """Grabs the banner of an open port."""
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(2)
        s.connect((str(ip), port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return None

async def async_check_host(ip, scan_ports_flag, semaphore, results):
    """Check a single host asynchronously and print results immediately."""
    ip = await async_ping_host(ip, semaphore)
    if ip:
        open_ports = []
        if scan_ports_flag:
            loop = asyncio.get_running_loop()
            open_ports = await loop.run_in_executor(None, scan_ports, ip)
            if open_ports:
                logging.info(f"{ip} is alive. Open ports: {open_ports}")
            else:
                logging.info(f"{ip} is alive. No open ports found.")
        else:
            logging.info(f"{ip} is alive.")
        results.append({"ip": ip, "ports": open_ports})

async def async_check_hosts(ip_list, scan_ports_flag):
    """Checks multiple hosts asynchronously and prints results immediately."""
    semaphore = asyncio.Semaphore(100)  # Limit the number of concurrent tasks
    results = []
    tasks = [async_check_host(ip, scan_ports_flag, semaphore, results) for ip in ip_list]
    await asyncio.gather(*tasks)
    return results

def generate_ip_list(ip_prefix):
    """Generates a list of IPs from a prefix or single IP."""
    try:
        network = ipaddress.ip_network(ip_prefix, strict=False)
        return [ip for ip in network.hosts()]
    except ValueError as e:
        logging.error(f"Invalid IP/prefix: {ip_prefix}")
        return []

def signal_handler(signal, frame):
    """Handle keyboard interrupt signal (Ctrl+C)."""
    logging.info("Keyboard interrupt received. Exiting...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Check host availability and optionally scan for open ports. Outputs results in JSON format.")
    parser.add_argument("ip_prefix", nargs='?', help="IP address or prefix (e.g., 192.168.1.0/24 or 192.168.1.1)")
    parser.add_argument("--scan-ports", action="store_true", help="Enable port scanning")
    parser.add_argument("--output-file", type=str, help="Output JSON file to store results")

    args = parser.parse_args()

    if not args.ip_prefix:
        parser.print_help()
        sys.exit(1)

    ip_list = generate_ip_list(args.ip_prefix)

    if not ip_list:
        logging.error("No valid IPs generated from the provided prefix.")
        sys.exit(1)

    results = asyncio.run(async_check_hosts(ip_list, args.scan_ports))

    if args.output_file:
        with open(args.output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results written to {args.output_file}")
