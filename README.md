**English** | [Español](README.es.md)

# VulnScan

```
 __   __    _      ___
 \ \ / /  _| |_ _ / __| __ __ _ _ _
  \ V / || | | ' \\__ \/ _/ _` | ' \
   \_/ \_,_|_|_||_|___/\__\__,_|_||_|
```

Command-line script that discovers the exposed services of a host or network with **Nmap** and looks up the **vulnerabilities (CVEs)** associated with each detected service by querying the public **NVD** (National Vulnerability Database) API.

All the code lives in a single file (`vulnscan.py`) so it works as a standalone, self-documented executable.

> ⚠️ **Responsible use**: only scan systems you own or have explicit authorization to test. Port scanning without permission may be illegal.

## Features

- **TCP** (SYN, top 1000 ports) and/or **UDP** (top 100 ports) scanning.
- Service version detection (`-sV`) and operating system fingerprinting (`-O`).
- Support for single IPs and **CIDR** ranges (IPv4), with several targets per run.
- CVE lookup in the NVD by detected software and version.
- Optional aggressive mode to reduce scan time.
- Compact column output, adapted to the number of CVEs found.

## How it works

1. **Scan**: runs Nmap against the target (through `python-nmap`).
   - TCP: `-sS -sV --version-intensity 0 -n -O`
   - UDP: `-sU --top-ports=100 -sV --version-intensity 0 --min-hostgroup 100 -n -O`
   - With `-A`: adds `-T5 --min-rate 1000`.
2. **Parsing**: extracts the live hosts, their OS and the open ports with product, version and service info.
3. **CVE lookup**: for each service with an identified product, queries
   `https://services.nvd.nist.gov/rest/json/cves/2.0` using `keywordSearch=<software> <version>`.
4. **Results**: prints, per host and port, the detected service and the list of CVEs.

## Requirements

- **Python 3.12 or later** (the code uses f-string syntax introduced in 3.12).
- **[Nmap](https://nmap.org/)** installed and available in the `PATH`.
- **Root/administrator privileges**: SYN (`-sS`) and UDP (`-sU`) scans and OS detection (`-O`) require them.
- Internet connection to query the NVD API.
- Python dependencies (see `requirements.txt`): `python-nmap`, `requests` and `tabulate`, plus the dependencies of `requests` (`certifi`, `charset-normalizer`, `idna`, `urllib3`).

## Installation

1. Install Nmap (Debian/Ubuntu example)
```bash
sudo apt install nmap
```

2. Clone the project
```bash
git clone https://github.com/bytem1nd/vulnscan && cd vulnscan
```

3. Create and activate a virtual environment (recommended)
```bash
python3 -m venv vulnscan-venv
source vulnscan-venv/bin/activate
```

4. Install dependencies
```bash
pip install -r requirements.txt
```

## Usage

```
vulnscan.py [-h] [-q] [-t] [-u] [-A] host(s) [host(s) ...]
```

| Option | Description |
| --- | --- |
| `host(s)` | One or more IPv4 addresses or CIDR ranges (e.g. `192.168.1.0/24`). |
| `-t`, `--tcp` | Enable TCP scan (enabled by default). |
| `-u`, `--udp` | Enable UDP scan. Disables TCP unless `-t` is also given (`-tu`). |
| `-A`, `--aggressive` | Reduce scan time at the cost of stealthiness and accuracy. |
| `-q`, `--quiet` | Do not show the banner. |
| `-h`, `--help` | Show the help message. |

> Addresses are validated as IPv4 or CIDR with a numeric prefix (0-32); hostnames and netmasks are not accepted.

### Examples

```bash
# TCP scan of a single IP
sudo vulnscan-venv/bin/python vulnscan.py 192.168.1.10

# TCP scan of a whole network
sudo vulnscan-venv/bin/python vulnscan.py 192.168.1.0/24

# UDP only
sudo vulnscan-venv/bin/python vulnscan.py -u 192.168.1.1

# TCP and UDP, aggressive mode, no banner
sudo vulnscan-venv/bin/python vulnscan.py -tuAq 192.168.1.1 10.0.0.5
```

> Use the virtual environment's `python` path with `sudo`, since `sudo` does not inherit the activated environment.

### Example output

```
[*] Scanning 192.168.1.10 (TCP)...
[+] Scanned 192.168.1.10 (TCP) on 14.532 seconds
[*] Searching vulnerabilities of 192.168.1.10...
  - Searching OpenSSH 8.2p1
[+] Searching done!!
[*] Showing results...
  - 192.168.1.10/tcp (OS: Linux 5.4)
	22/tcp - ssh v8.2p1 (Ubuntu Linux; protocol 2.0)
		CVE-XXXX-XXXXX    CVE-XXXX-XXXXX
```

## NVD API key (optional)

Without a key, the NVD allows about **5 requests every 30 seconds**, so scanning many services may trigger rate-limit errors. You can request a free key at <https://nvd.nist.gov/developers/request-an-api-key> and export it:

```bash
export NVD_API_KEY="your-key"
sudo --preserve-env=NVD_API_KEY vulnscan-venv/bin/python vulnscan.py 192.168.1.10
```

If a query fails (network, rate limit, invalid response), a warning is shown and the remaining services are still processed.

## Known limitations

- IPv4 only; domain names are not supported.
- The NVD keyword search may return false positives (matches by name/version, not by exact CPE) or false negatives if the banner does not reveal the product or version.
- `--version-intensity 0` is used for speed, which reduces version detection accuracy.
- Only ports in `open` state are considered.
