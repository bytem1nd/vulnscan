#!/usr/bin/env python

"""
Author: Angel Luis Rodriguez Martin-Palomino

NOTE: All code is written in one file to provide a standalone executable
with all documentation in it, although from a software engineering standpoint
it will be better to separate classes in different files.
"""

import os
import sys
import time
import ipaddress
import textwrap
import argparse
import nmap
import requests
from tabulate import tabulate

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class Host():
    """Class to store host info and open ports"""

    def __init__(self, host: str):
        self.host: str = host
        self.state: str = ""
        self.reason: str = ""
        self.os: str = ""
        self.ports: list[Port] = []


class Port():
    """Class to store port data such as state and service associated"""

    def __init__(self, num: int):
        self.id: int = num
        self.proto: str = ""
        self.state: str = ""
        self.service: Service = Service()


class Service():
    """Class to store service info and associated vulnerabilities"""

    def __init__(self):
        self.name: str = ""
        self.software: str = ""
        self.version: str = ""
        self.info: str = ""
        self.cves: list[CVE] = []


class CVE():
    """Class to store CVE related data"""

    # For now it is only going to store the CVE ID
    # Nevertheless the class is defined for future versions and to be more semantic
    def __init__(self, id: str):
        self.id: str = id
        self.description: str = ""

    def __str__(self):
        return self.id


def banner():
    """Prints app banner"""

    print("""\
 __   __    _      ___               
 \\ \\ / /  _| |_ _ / __| __ __ _ _ _  
  \\ V / || | | ' \\\\__ \\/ _/ _` | ' \\ 
   \\_/ \\_,_|_|_||_|___/\\__\\__,_|_||_|
    """)


def nmap_scan(target: str, scan_type: str = "tcp", aggressive: bool = False) -> nmap.PortScanner:
    """Perform nmap given scan type on target

    Args:
        `target`: Host (ip, net range) to be scanned
        `scan_type`: Type of scan to perform (tcp, udp or nmap default without args)
        `aggressive`: Reduce scan time by adding -T5 and --min-rate 1000 arguments to nmap
    
    Returns:
        `nmap.Portscanner` object with scan results
    """
    nm = nmap.PortScanner()
    args = ""

    if scan_type == "tcp":
        # Scan top 1000 ports extracting service banners and OS fingerprint
        args = "-sS -sV --version-intensity 0 -n -O"
    elif scan_type == "udp":
        # Scan top 100 ports extracting service banners and OS fingerprint
        # Apply optimization of scan with options --version-intesity 0 and --min-hostgroup
        # as recommended by nmap.org (https://nmap.org/book/scan-methods-udp-scan.html#scan-methods-udp-optimizing)
        # The official page do not recommend generating multiple nmap process or threads as it will be counter-productive
        # and because nmap apply optimization techniques itself during scan
        args = "-sU --top-ports=100 -sV --version-intensity 0 --min-hostgroup 100 -n -O"

    if aggressive:
        args += " -T5 --min-rate 1000"

    print(f"[*] Scanning {target} ({scan_type.upper()})...")
    try:
        start = time.time()
        nm.scan(target, arguments=args)
        end = time.time()
    except Exception as e:
        print(f"[!] ERROR: Scan of {target} ended in unexpected exception {e}")
        sys.exit(1)

    print(f"[+] Scanned {target} ({scan_type.upper()}) on {end - start:.3f} seconds")

    return nm


def parse_nmap_scan(scan: nmap.PortScanner, protocols: list[str] = ["tcp", "udp"]) -> list[Host]:
    """Parses scan results to get a list of hosts.
    
    Args:
        `scan`: Scan object created after `nmap.scan()`
        `protocols`: List of protocols to be parsed (default: ["tcp", "udp"])
        
    Returns:
        List of hosts with port status information
    """

    hosts = []
    for host in scan.all_hosts():
        h = Host(host)
        target = scan[host]
        h.state = target["status"]["state"]
        h.reason = target["status"]["reason"]
        if target["osmatch"]:
            h.os = target["osmatch"][0]["name"]
        for proto in protocols:
            if proto in target:
                get_port_data(h, target, proto)
        hosts.append(h)

    return hosts


def get_port_data(h: Host, target: nmap.PortScannerHostDict, proto: str):
    """Save into host a list of open ports of the target for a given protocol
    
    Args:
        `h`: Host object in which data is going to be stored
        `target`: Scan result data of target
        `proto`: Protocol to extract data
    """

    ports = target[proto].keys()
    for port in ports:
        port_data = target[proto][port]
        if port_data["state"] == "open":
            p = Port(port)
            p.state = port_data["state"]
            p.proto = proto
            p.service.name = port_data["name"]
            p.service.software = port_data["product"]
            p.service.version = port_data["version"]
            p.service.info = port_data["extrainfo"]
            h.ports.append(p)


def vuln_search(hosts: list[Host]):
    """Search vulnerabilities (CVE) for each host of the list given
    
    Args:
        `hosts`: list of hosts for search
    """

    for host in hosts:
        if host.ports:
            print(f"[*] Searching vulnerabilities of {host.host}...")
            for port in host.ports:
                if port.service.software:
                    print(f"  - Searching {port.service.software} {port.service.version}")
                    port.service.cves.extend(
                        search_cve(port.service.software, port.service.version))
            print("[+] Searching done!!")


def search_cve(software: str, version: str) -> list[CVE]:
    """Search for CVE of given software and version using the NVD API
    (https://services.nvd.nist.gov/rest/json/cves/2.0)

    Without an API key NVD allows ~5 requests every 30 seconds. A free key can be
    provided with the NVD_API_KEY environment variable to raise that limit.

    Args:
        `software`: Name of service
        `version`: Version of the software

    Returns:
        list[CVE]: CVEs with id and description (empty if none found or the request failed)
    """

    # `params` takes care of URL-encoding the keywords (banners are untrusted input)
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_API_URL,
            params={"keywordSearch": f"{software} {version or ''}".strip()},
            headers=headers,
            timeout=15
        )
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
    except (requests.RequestException, ValueError) as e:
        print(f"[!] CVE search failed for {software} {version}: {e}")
        return []

    cves = []
    for vuln in vulnerabilities:
        data = vuln.get("cve", {})
        if "id" not in data:
            continue
        cve = CVE(data["id"])
        # Prefer the English description
        for desc in data.get("descriptions", []):
            if desc.get("lang") == "en":
                cve.description = desc.get("value", "")
                break
        cves.append(cve)

    return cves


def show_results(hosts: list[Host], proto: str):
    """Show results in a pretty and concise way
    
    Args:
        `hosts`: list of hosts to print results from
        `proto`: protocol of the scan
    """
    print(f"[*] Showing results...")
    for host in hosts:
        print(f"  - {host.host}/{proto}", end="")
        if host.os: print(f" (OS: {host.os})", end="")
        print()
        if not host.ports: print("\tNo open ports\n")
        for port in host.ports:
            print(f"\t{port.id}/{port.proto} - {port.service.name or 'unknown'}", end="")
            if port.service.version:
                print(f" v{port.service.version}", end="")
            if port.service.info:
                print(f" ({port.service.info})", end="")

            pretty_print(port.service.cves)

def pretty_print(data: list[any]):
    """Print input in different columns depending on data length
    
    Args:
        `data`: List of elements to print
    """
    num_elements = len(data)

    if num_elements < 8:
        print_columns(data, num_columns=1)
    elif num_elements < 20:
        print_columns(data)
    elif num_elements < 32:
        print_columns(data, num_columns=3)
    elif num_elements < 44:
        print_columns(data, num_columns=4)
    elif num_elements < 56:
        print_columns(data, num_columns=5)
    else:
        print_columns(data, num_columns=6)


def print_columns(data: list[any], num_columns: int = 2):
    """Print input data in given number of columns
    
    Args:
        `data`: List of elements to print
        `num_columns`: Number of columns to print data (default: 2)
    """
    # Reshape the list into rows and columns
    rows = [data[i:i + num_columns] for i in range(0, len(data), num_columns)]

    # Print using tabulate to format the output as a table
    print(f"{textwrap.indent(tabulate(rows, tablefmt='plain'), '\t\t')}")


def vulnscan(target: str, scan_type: str, aggressive: bool = False):
    """Group nmap scan and vulnerability search
    
    Args:
        `target`: Host to perform nmap scan and CVE search
        `scan_type`: Type of scan perform (tcp, udp)
        `aggressive`: Specify if speed up the scan at the cost of stealthiness and eficacy (default: False)
    """
    scan_results = nmap_scan(target, scan_type, aggressive)

    hosts = parse_nmap_scan(scan_results)
    if not hosts:
        print(f"[-] {target} is down")
        sys.exit(0)

    vuln_search(hosts)

    show_results(hosts, scan_type)


def is_ip(ip: str) -> str:
    """Check if given input has IPv4 format.
    
    Args:
        ip: The IP of the target

    Returns:
        str: IP of input if it its a valid IPv4
    """

    address, sep, prefix = ip.partition("/")

    try:
        ipaddress.IPv4Address(address)
        # Only a plain prefix length (0-32) is accepted, not netmasks
        if sep and not (prefix.isascii() and prefix.isdigit() and 0 <= int(prefix) <= 32):
            raise ValueError(prefix)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{ip}' is not an IPv4 or CIDR range")

    return ip


def arguments_handler():
    """Specify the options of the program and return the parsed arguments"""

    parser = argparse.ArgumentParser(
        description="Vulnscan! A script to search vulnerabilities of a target or network",
        epilog="Examples:\n  %(prog)s 8.8.8.8              # Scan vulnerabilities of given IP (TCP only)\n  %(prog)s 192.168.1.0/24       # Scan vulnerabilities of whole CIDR range (TCP only)\n  %(prog)s -u 192.168.1.1       # UDP scan only\n  %(prog)s -tu 192.168.1.1      # TCP and UDP scan",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("hosts", nargs="+",
                        type=is_ip,
                        help="List of host addresses (IP, CIDR range) to scan",
                        metavar="host(s)")
    parser.add_argument("-q", "--quiet",
                        action="store_true",
                        default=False,
                        help="Disable banner output")
    parser.add_argument("-t", "--tcp",
                        action="store_true",
                        default=False,
                        help="Enable TCP scan (default: enabled)")
    parser.add_argument("-u", "--udp",
                        action="store_true",
                        default=False,
                        help="Enable UDP scan (default: disabled).\nIf enabled it deactivates TCP scan unless explicitly indicated with '-tu'")
    parser.add_argument("-A", "--aggressive",
                        action="store_true",
                        default=False,
                        help="Reduce the time of scan a the cost of stealthiness.\nWARNING: results may be less accurate with this option")

    return parser.parse_args()


def main():
    """MAIN FUNCTION"""

    args = arguments_handler()
    if not args.quiet:
        banner()

    try:
        for host in args.hosts:
            if args.tcp or not args.udp:
                vulnscan(host, "tcp", args.aggressive)
            if args.udp:
                vulnscan(host, "udp", args.aggressive)
    except KeyboardInterrupt:
        print("[-] Terminating...")
        print("Bye!")


if __name__=='__main__':
    main()

