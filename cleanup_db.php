<?php
/**
 * Скрипт для очистки базы данных WebAuthn
 * Удаляет всех пользователей, их учетные данные и сессии
 * Используется для тестирования дублирования пользователей при регистрации
 */

echo "=== Скрипт очистки базы данных WebAuthn ===\n";

try {
    // Подключение к базе данных
    $pdo = new PDO('mysql:host=db;dbname=webauthn_db;charset=utf8mb4', 'webauthn_user', 'webauthn_pass');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    echo "✓ Подключение к базе данных установлено\n";
    
    // Начинаем транзакцию
    $pdo->beginTransaction();
    
    // Получаем количество записей до очистки
    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    $usersCount = $stmt->fetchColumn();
    
    $stmt = $pdo->query("SELECT COUNT(*) FROM user_credentials");
    $credentialsCount = $stmt->fetchColumn();
    
    $stmt = $pdo->query("SELECT COUNT(*) FROM user_sessions");
    $sessionsCount = $stmt->fetchColumn();
    
    echo "\nТекущее состояние базы данных:\n";
    echo "- Пользователи: $usersCount\n";
    echo "- Учетные данные: $credentialsCount\n";
    echo "- Сессии: $sessionsCount\n\n";
    
    if ($usersCount == 0 && $credentialsCount == 0 && $sessionsCount == 0) {
        echo "✓ База данных уже пуста!\n";
        $pdo->rollback();
        exit(0);
    }
    
    // Очищаем таблицы в правильном порядке (соблюдая внешние ключи)
    echo "Очистка таблиц...\n";
    
    // 1. Удаляем сессии пользователей
    $pdo->exec("DELETE FROM user_sessions");
    echo "✓ Очищена таблица user_sessions\n";
    
    // 2. Удаляем учетные данные пользователей
    $pdo->exec("DELETE FROM user_credentials");
    echo "✓ Очищена таблица user_credentials\n";
    
    // 3. Удаляем пользователей
    $pdo->exec("DELETE FROM users");
    echo "✓ Очищена таблица users\n";
    
    // Сбрасываем автоинкремент
    $pdo->exec("ALTER TABLE users AUTO_INCREMENT = 1");
    $pdo->exec("ALTER TABLE user_credentials AUTO_INCREMENT = 1");
    $pdo->exec("ALTER TABLE user_sessions AUTO_INCREMENT = 1");
    echo "✓ Сброшены счетчики AUTO_INCREMENT\n";
    
    // Подтверждаем транзакцию
    $pdo->commit();
    
    echo "\n🎉 База данных успешно очищена!\n";
    echo "Теперь можно протестировать регистрацию WebAuthn с нуля\n";
    
} catch (PDOException $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollback();
    }
    echo "❌ Ошибка базы данных: " . $e->getMessage() . "\n";
    exit(1);
} catch (Exception $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollback();
    }
    echo "❌ Общая ошибка: " . $e->getMessage() . "\n";
    exit(1);
}
