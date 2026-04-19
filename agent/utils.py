#agents\utils.py
import ipaddress
import time

def parse_ip_range(ip_range_str):
    """
    Parse IP addresses and ranges (including CIDR).
    Supports:
    - Single IP: "192.168.1.1"
    - CIDR: "192.168.1.0/24"
    - Mixed: "192.168.1.1, 192.168.1.0/30"

    Returns a list of IP addresses.
    """
    ip_list = []
    ip_parts = ip_range_str.split(',')

    for part in ip_parts:
        part = part.strip()

        if '/' in part:  # CIDR notation
            network = ipaddress.IPv4Network(part, strict=False)
            ip_list.extend([str(ip) for ip in network.hosts()])
        else:  # Single IP
            ip_list.append(part)

    return ip_list

def parse_ports(port_range_str):
    """
    Parse port ranges and individual ports.
    Supports:
    - Single port: "22"
    - Range of ports: "1-65535"
    - Multiple discrete ports: "22, 80, 443"
    - Mixed combinations: "20, 30, 40-50"

    Returns a list of ports to scan.
    """
    ports = []
    port_parts = port_range_str.split(',')

    for part in port_parts:
        part = part.strip()

        if '-' in part:  # Range of ports
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:  # Single port
            ports.append(int(part))

    return sorted(set(ports))  # Sort and remove duplicates

def generate_scan_list(task):
    """
    Given a task (from the pulled tasks), generate the list of IPs and empty list of ports to scan.

    task: dict - task object containing 'targets' and 'ports'.

    Returns a list of dictionaries with IPs and empty ports:
    [{"ip": "192.168.1.1", "found_ports": []}, ...]
    """
    # Parse IPs from targets
    ips = []
    for target in task['targets']:
        ips.extend(parse_ip_range(target))  # Expands IPs, e.g., from ranges or CIDRs

    # Parse the ports
    ports = []
    for port_str in task['ports']:
        ports.extend(parse_ports(str(port_str)))  # Expands ports, e.g., from ranges

    # Generate scan list with empty 'found_ports' for each IP
    scan_list = []
    for ip in set(ips):  # Avoid duplicates in IPs
        scan_list.append({"ip": ip, "found_ports": []})  # Empty list for ports, to be filled later

    return scan_list

def sort_scan_results(scan_list):
    """
    Sort scan results by IP address correctly (numeric IP order),
    while preserving full dictionary structure.
    """
    return sorted(
        scan_list,
        key=lambda entry: ipaddress.IPv4Address(entry["ip"])
    )

def compute_next_parse_date(schedule: str):
    now = int(time.time())

    if schedule == "daily":
        return now + 60 * 60 * 24

    if schedule == "weekly":
        return now + 60 * 60 * 24 * 7

    if schedule == "once":
        # effectively disable re-run (far future lock)
        return 32503680000  # year 3000-ish

    # fallback safety
    return now + 60 * 60 * 24