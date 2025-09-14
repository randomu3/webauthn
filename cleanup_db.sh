#!/bin/bash

# Скрипт для очистки базы данных WebAuthn
# Запускает PHP скрипт очистки внутри Docker контейнера

echo "=== Скрипт очистки базы данных WebAuthn ==="
echo "Этот скрипт удалит всех пользователей и их данные из базы"
echo ""

# Проверяем, запущен ли контейнер
if ! docker-compose ps | grep -q "otpechatokv2-web-1.*Up"; then
    echo "❌ Docker контейнер не запущен!"
    echo "Запустите контейнер командой: docker-compose up -d"
    exit 1
fi

echo "✓ Docker контейнер запущен"
echo ""

# Подтверждение от пользователя
read -p "Вы уверены, что хотите очистить базу данных? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Операция отменена"
    exit 0
fi

echo ""
echo "Запускаем очистку базы данных..."
echo ""

# Выполняем PHP скрипт внутри контейнера
docker-compose exec web php /var/www/html/cleanup_db.php

echo ""
echo "=== Очистка завершена ==="
echo "Теперь можно тестировать регистрацию WebAuthn с чистой базой"
