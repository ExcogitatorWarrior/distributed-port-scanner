#agents\utils.py
import socket
import os
import subprocess
import re
import ipaddress
import time
from datetime import datetime

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
    cached_net_ip = None
    for target in task['targets']:
        target_str = str(target)
        
        if "0.0.0.0" in target_str:
            if not cached_net_ip:
                cached_net_ip = get_default_gateway_network_ip()
            
            # Заменяем только сами нули. 
            # Если было "0.0.0.0/24", станет "192.168.1.0/24"
            target_str = target_str.replace("0.0.0.0", cached_net_ip)

        # Теперь скармливаем результат парсеру
        ips.extend(parse_ip_range(target_str))

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

def get_default_gateway_network_ip():
    """
    Вычисляет адрес сети и возвращает только IP (например, '192.168.1.0')
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("77.88.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        return "127.0.0.1"

    mask = "255.255.255.0" # Дефолт
    try:
        if os.name == "nt": # Windows
            output = subprocess.check_output("ipconfig", shell=True).decode("cp866")
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if local_ip in line:
                    for j in range(i, len(lines)):
                        if "Subnet Mask" in lines[j] or "Маска подсети" in lines[j]:
                            mask = lines[j].split(":")[-1].strip()
                            break
                    break
        else: # Linux
            output = subprocess.check_output("ip addr", shell=True).decode()
            match = re.search(rf"inet\s+{local_ip}/(\d+)", output)
            if match:
                # Создаем интерфейс, чтобы получить адрес сети
                iface = ipaddress.IPv4Interface(f"{local_ip}/{match.group(1)}")
                return str(iface.network.network_address) # <--- СТРОГО IP
    except:
        pass

    # Финальный расчет для Windows или если Linux/ip-addr не выдал префикс
    try:
        network = ipaddress.IPv4Interface(f"{local_ip}/{mask}").network
        return str(network.network_address) # Напр. '192.168.1.0'
    except:
        return "127.0.0.1"

def is_working_hour(start_str, end_str):
    """
    Проверяет, входит ли текущее время в интервал [start_str, end_str].
    Поддерживает переход через полночь.
    """
    fmt = "%H:%M:%S"
    try:
        # Превращаем строки в объекты времени (time)
        start_time = datetime.strptime(start_str, fmt).time()
        end_time = datetime.strptime(end_str, fmt).time()
        now_time = datetime.now().time()

        if start_time <= end_time:
            # Интервал внутри одного дня (например, 09:00 - 18:00)
            return start_time <= now_time <= end_time
        else:
            # Интервал с переходом через полночь (например, 22:00 - 05:00)
            return now_time >= start_time or now_time <= end_time
    except ValueError as e:
        # Если в конфиге напутали с форматом, лучше логировать это
        print(f"Ошибка формата времени в конфиге: {e}")
        return False