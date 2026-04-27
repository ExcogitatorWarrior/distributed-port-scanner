# 1. Берем основу — "легкий" Python
FROM python:3.14.4-slim-bookworm

# 2. Указываем рабочую папку внутри Docker (как диск C: только внутри контейнера)
WORKDIR /app

# 3. Копируем файл со списком библиотек внутрь
COPY requirements.txt .

# 4. Командуем Docker-у установить эти библиотеки
RUN pip install --no-cache-dir -r requirements.txt

# 5. Копируем весь остальной код агента в контейнер
COPY . .

# 6. Главная команда: что запустить при старте (замените main.py на ваш главный файл)
CMD ["python", "main.py"]