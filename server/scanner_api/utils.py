import re
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from zabbix_utils import Sender
from .models import TaskItem, Agent

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

def update_zabbix_global_status():
    # 1. Проверяем, включена ли отправка
    if not getattr(settings, 'IS_ZABBIX_SENDER_ACTIVE', False):
        return  # Просто выходим, если не активно

    # 2. Берем настройки из settings.py
    z_server = settings.ZABBIX_SERVER
    z_port = settings.ZABBIX_PORT
    z_host = settings.ZABBIX_HOST_NAME
    
    sender = Sender(server=z_server, port=z_port)
    
    # --- ПРОВЕРКА 1: Наличие Алертов ---
    has_alerts = TaskItem.objects.filter(status='alert').exists()
    alert_value = "1" if has_alerts else "0"
    
    # --- ПРОВЕРКА 2: Живые Агенты ---
    now = timezone.now()
    active_agents_count = 0
    all_active_agents = Agent.objects.filter(is_active=True)
    
    for agent in all_active_agents:
        if agent.last_contact_at:
            threshold = agent.last_contact_at + timedelta(seconds=agent.contract_interval_seconds + 60)
            if now <= threshold:
                active_agents_count += 1

    try:
        packet = [
            (z_host, 'django.alert.status', alert_value),
            (z_host, 'agent.alive.count', str(active_agents_count))
        ]
        
        # Отправляем данные
        for host, key, value in packet:
            sender.send_value(host, key, value)
            
        return True
    except Exception as e:
        # Используем логгер вместо print, это правильнее для Django
        print(f"Zabbix reporting error: {e}")
        return False