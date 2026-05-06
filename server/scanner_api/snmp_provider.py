import os
import sys
import django

# 1. Добавляем путь к корню проекта (папка server), чтобы Django видел все модули
# Это на два уровня выше от текущего файла
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

# 2. Указываем путь к настройкам. У тебя это папка config
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# 3. Инициализируем Django
django.setup()

# 4. Теперь импортируем модели
from scanner_api.models import TaskItem, Agent
from django.utils import timezone
from datetime import timedelta

def collect_metrics():
    # Проверка алертов
    has_alerts = TaskItem.objects.filter(status='alert').exists()
    print(1 if has_alerts else 0)
    
    # Проверка живых агентов
    now = timezone.now()
    active_agents_count = 0
    all_active_agents = Agent.objects.filter(is_active=True)
    
    for agent in all_active_agents:
        if agent.last_contact_at:
            # Считаем агента живым, если он выходил на связь вовремя + 60 сек запаса
            threshold = agent.last_contact_at + timedelta(seconds=agent.contract_interval_seconds + 60)
            if now <= threshold:
                active_agents_count += 1
    
    print(active_agents_count)

if __name__ == "__main__":
    try:
        collect_metrics()
    except Exception as e:
        # Пишем в лог ошибок, если что-то пошло не так
        # Но SNMP всегда должен получить цифру, чтобы не было ошибки типа
        print(0)
        print(0)