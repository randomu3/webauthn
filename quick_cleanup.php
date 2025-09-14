<?php
// Быстрая очистка БД
try {
    $pdo = new PDO('mysql:host=db;dbname=webauthn_db;charset=utf8mb4', 'webauthn_user', 'webauthn_pass');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $pdo->exec("DELETE FROM user_sessions");
    $pdo->exec("DELETE FROM user_credentials");
    $pdo->exec("DELETE FROM users");
    
    echo "✓ База данных очищена\n";
} catch (Exception $e) {
    echo "❌ Ошибка: " . $e->getMessage() . "\n";
}
