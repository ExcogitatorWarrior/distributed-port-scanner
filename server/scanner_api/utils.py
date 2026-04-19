import re

# Validate IP addresses
def is_valid_ip(ip):
    # Split multiple IPs if comma separated (e.g., "192.168.1.0/24, 10.0.0.0/32")
    ips = ip.split(',')
    for single_ip in ips:
        single_ip = single_ip.strip()  # Remove any leading/trailing spaces
        # Matches IP format and CIDR like 192.168.1.0/24
        pattern = r"^(\d{1,3}\.){3}\d{1,3}(/([1-9]|[1-2][0-9]|3[0-2]))?$"
        if not re.match(pattern, single_ip):
            return False  # Invalid IP if any part doesn't match the pattern
    return True  # All IPs are valid


# Validate ports, ensuring proper format and valid ranges
def validate_ports(ports):
    valid_ports = []
    for port in ports:
        if isinstance(port, str):  # Handling range like '1-65535'
            if '-' in port:
                start, end = port.split('-')
                start, end = int(start), int(end)
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    valid_ports.append(f"{start}-{end}")
                else:
                    return None  # Invalid port range
            else:
                if port.isdigit() and 1 <= int(port) <= 65535:
                    valid_ports.append(int(port))
                else:
                    return None  # Invalid single port
        elif isinstance(port, int):  # Handling integer port like 22, 80
            if 1 <= port <= 65535:
                valid_ports.append(port)
            else:
                return None  # Invalid single port
        else:
            return None  # Invalid port format
    return valid_ports