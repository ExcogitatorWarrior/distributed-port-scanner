# 🛡️ Docker Agent Cheatsheet

## 1. Сборка (Build)
# Всегда запускать после изменений в коде или requirements.txt
docker build -t scanner-agent-test .

## 2. Запуск (Run)
# Запуск с пробросом переменных и связью с хостом
docker run -d `
  --name my-test-agent `
  --network host `
  -e BASE_URL="http://yourserver-ip:yourserver-port" `
  -e SECRET="13e3e5a7c895a56cbfa080b25775c822ccde7a83b9b79d8d779d85ffe85feaa1" `
  scanner-agent-test