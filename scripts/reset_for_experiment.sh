#!/bin/bash

# Скрипт для полного сброса проекта к чистому состоянию
# Использовать перед каждым новым экспериментом

echo "🔄 Сброс WebAuthn проекта для чистого эксперимента"
echo "================================================="

# Остановка контейнеров
echo "🛑 Остановка контейнеров..."
docker-compose down

# Удаление данных БД
echo "🗑️  Удаление данных базы данных..."
docker volume rm webauthn_mysql_data 2>/dev/null || echo "Volume уже удален или не существует"

# Запуск контейнеров
echo "🚀 Запуск контейнеров..."
docker-compose up -d

# Ожидание инициализации БД
echo "⏳ Ожидание инициализации базы данных..."
sleep 15

# Проверка что БД работает
echo "🔍 Проверка состояния базы данных..."
docker-compose exec web php -r "
require_once '/var/www/html/src/Database.php';
use WebAuthn\Database;

try {
    \$db = new Database();
    \$pdo = \$db->getPdo();
    \$stmt = \$pdo->query('SHOW TABLES');
    \$tables = \$stmt->fetchAll(PDO::FETCH_COLUMN);
    echo '✅ База данных работает, таблиц: ' . count(\$tables) . PHP_EOL;
    echo '🎯 Проект готов для эксперимента!' . PHP_EOL;
} catch (Exception \$e) {
    echo '❌ Ошибка БД: ' . \$e->getMessage() . PHP_EOL;
    exit(1);
}
"

echo ""
echo "✅ Сброс завершен успешно!"
echo "🌐 Откройте http://localhost:8080 для тестирования"
echo "📱 Или используйте Tuna tunnel для мобильного тестирования"
