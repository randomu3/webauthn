<?php
/**
 * Миграция для добавления таблицы отслеживания устройств
 */

try {
    // Подключение к базе данных
    $pdo = new PDO('mysql:host=db;dbname=webauthn_db;charset=utf8mb4', 'webauthn_user', 'webauthn_pass');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    echo "✓ Подключение к базе данных установлено\n";
    
    // Создаем таблицу device_fingerprints
    $sql = "
    CREATE TABLE IF NOT EXISTS device_fingerprints (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_hash VARCHAR(64) UNIQUE NOT NULL COMMENT 'SHA256 хеш device fingerprint',
        device_fingerprint TEXT NOT NULL COMMENT 'Полный fingerprint устройства', 
        user_agent TEXT NOT NULL COMMENT 'User Agent устройства',
        screen_info VARCHAR(255) COMMENT 'Разрешение экрана и характеристики',
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        registration_count INT DEFAULT 0 COMMENT 'Количество попыток регистрации с этого устройства',
        INDEX idx_device_hash (device_hash)
    )";
    
    $pdo->exec($sql);
    echo "✓ Таблица device_fingerprints создана\n";
    
    // Добавляем столбец device_hash в таблицу users
    try {
        $pdo->exec("ALTER TABLE users ADD COLUMN device_hash VARCHAR(64) COMMENT 'Хеш устройства пользователя'");
        echo "✓ Столбец device_hash добавлен в таблицу users\n";
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'Duplicate column name') !== false) {
            echo "- Столбец device_hash уже существует в таблице users\n";
        } else {
            throw $e;
        }
    }
    
    // Добавляем индекс для device_hash
    try {
        $pdo->exec("ALTER TABLE users ADD INDEX idx_device_hash (device_hash)");
        echo "✓ Индекс idx_device_hash добавлен\n";
    } catch (PDOException $e) {
        if (strpos($e->getMessage(), 'Duplicate key name') !== false) {
            echo "- Индекс idx_device_hash уже существует\n";
        } else {
            throw $e;
        }
    }
    
    echo "\n🎉 Миграция завершена успешно!\n";
    
} catch (PDOException $e) {
    echo "❌ Ошибка базы данных: " . $e->getMessage() . "\n";
    exit(1);
} catch (Exception $e) {
    echo "❌ Общая ошибка: " . $e->getMessage() . "\n";
    exit(1);
}
