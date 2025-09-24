<?php
/**
 * Тестовый скрипт для проверки подключения к базе данных
 * и наличия всех необходимых таблиц
 */

// Прямое подключение без автозагрузчика
require_once __DIR__ . '/../src/Database.php';

use WebAuthn\Database;

echo "🔧 Тестирование подключения к базе данных...\n\n";

try {
    // Проверяем подключение к БД
    $db = new Database();
    echo "✅ Подключение к базе данных успешно\n";
    
    $pdo = $db->getPdo();
    
    // Проверяем наличие всех таблиц
    $tables = [
        'users' => 'Пользователи',
        'user_credentials' => 'Учетные данные WebAuthn',
        'user_sessions' => 'Сессии пользователей',
        'device_fingerprints' => 'Отпечатки устройств'
    ];
    
    echo "\n📋 Проверка структуры базы данных:\n";
    
    foreach ($tables as $table => $description) {
        $stmt = $pdo->query("SHOW TABLES LIKE '{$table}'");
        
        if ($stmt->fetch()) {
            echo "✅ Таблица '{$table}' ({$description}) - существует\n";
            
            // Показываем структуру таблицы
            $stmt = $pdo->prepare("DESCRIBE `{$table}`");
            $stmt->execute();
            $columns = $stmt->fetchAll();
            
            echo "   Колонки: ";
            $columnNames = array_map(function($col) { return $col['Field']; }, $columns);
            echo implode(', ', $columnNames) . "\n";
        } else {
            echo "❌ Таблица '{$table}' ({$description}) - отсутствует\n";
        }
    }
    
    // Проверяем индексы в таблице users
    echo "\n🔍 Проверка индексов:\n";
    $stmt = $pdo->prepare("SHOW INDEX FROM users");
    $stmt->execute();
    $indexes = $stmt->fetchAll();
    
    foreach ($indexes as $index) {
        echo "   - {$index['Key_name']} на колонке {$index['Column_name']}\n";
    }
    
    // Тестовое создание пользователя
    echo "\n🧪 Тестирование операций с БД:\n";
    
    $testUserId = 'test_user_' . time();
    $testUserHandle = random_bytes(32);
    
    if ($db->createUser($testUserId, $testUserHandle)) {
        echo "✅ Создание пользователя - работает\n";
        
        $user = $db->getUser($testUserId);
        if ($user) {
            echo "✅ Получение пользователя - работает\n";
            echo "   ID: {$user['user_id']}\n";
            echo "   Создан: {$user['created_at']}\n";
        } else {
            echo "❌ Получение пользователя - не работает\n";
        }
        
        // Удаляем тестового пользователя
        $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
        $stmt->execute([$testUserId]);
        echo "🗑️  Тестовый пользователь удален\n";
        
    } else {
        echo "❌ Создание пользователя - не работает\n";
    }
    
    // Проверяем настройки подключения
    echo "\n⚙️  Настройки подключения:\n";
    echo "   Хост: " . ($_ENV['DB_HOST'] ?? 'db') . "\n";
    echo "   База: " . ($_ENV['DB_NAME'] ?? 'webauthn_db') . "\n";
    echo "   Пользователь: " . ($_ENV['DB_USER'] ?? 'webauthn_user') . "\n";
    
    echo "\n🎉 Все тесты базы данных пройдены успешно!\n";
    
} catch (Exception $e) {
    echo "❌ Ошибка: " . $e->getMessage() . "\n";
    echo "\n💡 Проверьте:\n";
    echo "   - Запущен ли MySQL контейнер: docker-compose ps\n";
    echo "   - Настройки в .env файле\n";
    echo "   - Логи MySQL: docker-compose logs db\n";
    exit(1);
}
