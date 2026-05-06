import os

# os.getenv('ИМЯ', 'дефолт') — ищет переменную в системе, если нет, берет второй параметр
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")
SECRET = os.getenv("SECRET", "13e3e5a7c895a56cbfa080b25775c822ccde7a83b9b79d8d779d85ffe85feaa1")

# Для чисел нужно обязательно делать int(), так как из окружения всё приходит строкой
CONTACT_INTERVAL_DEFAULT = int(os.getenv("CONTACT_INTERVAL", 30))

TASK_DB_PATH = os.getenv("TASK_DB_PATH", "tasks_db.json")

TIMER = os.getenv("TIMER", "False").lower() in ("true", "1", "yes")

START_TIME = os.getenv("START_TIME", "00:00:00")
END_TIME = os.getenv("END_TIME", "00:00:00")