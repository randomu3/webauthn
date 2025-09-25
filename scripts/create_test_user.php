<?php
/**
 * Создание тестового пользователя для демонстрации банковской авторизации
 */

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/AnalyticsManager.php';
require_once __DIR__ . '/../src/AuthManager.php';

use WebAuthn\Database;
use WebAuthn\AnalyticsManager;
use WebAuthn\AuthManager;

echo "👤 Создание тестового пользователя..." . PHP_EOL;
echo "=====================================" . PHP_EOL;

try {
    $db = new Database();
    $analytics = new AnalyticsManager($db);
    $auth = new AuthManager($db, $analytics);

    // Создаем тестового пользователя
    $result = $auth->createUser(
        'testuser',           // username
        'test@example.com',   // email
        'password123',        // password
        'Тестовый Пользователь' // display name
    );

    if ($result['success']) {
        echo "✅ Пользователь создан успешно!" . PHP_EOL;
        echo "   Username: testuser" . PHP_EOL;
        echo "   Email: test@example.com" . PHP_EOL;
        echo "   Password: password123" . PHP_EOL;
        echo "   User ID: " . $result['user_id'] . PHP_EOL;
        echo "" . PHP_EOL;

        // Создаем дополнительных пользователей для тестирования
        $users = [
            [
                'username' => 'admin',
                'email' => 'admin@example.com', 
                'password' => 'admin123',
                'display_name' => 'Администратор'
            ],
            [
                'username' => 'demo',
                'email' => 'demo@example.com',
                'password' => 'demo123',
                'display_name' => 'Демо Пользователь'
            ]
        ];

        foreach ($users as $userData) {
            $userResult = $auth->createUser(
                $userData['username'],
                $userData['email'],
                $userData['password'],
                $userData['display_name']
            );

            if ($userResult['success']) {
                echo "✅ Пользователь {$userData['username']} создан" . PHP_EOL;
            } else {
                echo "⚠️  Пользователь {$userData['username']}: " . $userResult['error'] . PHP_EOL;
            }
        }

        echo "" . PHP_EOL;
        echo "🔍 Проверка созданных пользователей:" . PHP_EOL;

        $pdo = $db->getPdo();
        $stmt = $pdo->query("
            SELECT username, email, display_name, created_at, account_status 
            FROM users 
            WHERE username IN ('testuser', 'admin', 'demo')
            ORDER BY created_at DESC
        ");
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($users as $user) {
            echo "  👤 {$user['username']} ({$user['email']}) - {$user['display_name']}" . PHP_EOL;
            echo "     Создан: {$user['created_at']}, Статус: {$user['account_status']}" . PHP_EOL;
        }

        echo "" . PHP_EOL;
        echo "🚀 Инструкции для тестирования:" . PHP_EOL;
        echo "1. Откройте http://localhost:8080/login.html" . PHP_EOL;
        echo "2. Введите логин: testuser, пароль: password123" . PHP_EOL;
        echo "3. Включите 'Запомнить меня' для демонстрации" . PHP_EOL;
        echo "4. После входа настройте 6-значный PIN" . PHP_EOL;
        echo "5. Затем настройте WebAuthn для полной безопасности" . PHP_EOL;

    } else {
        echo "❌ Ошибка создания пользователя: " . $result['error'] . PHP_EOL;
    }

} catch (Exception $e) {
    echo "❌ Критическая ошибка: " . $e->getMessage() . PHP_EOL;
}
