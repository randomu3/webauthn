-- Добавляем таблицу для отслеживания устройств
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
);

-- Добавляем связь устройств с пользователями  
ALTER TABLE users ADD COLUMN IF NOT EXISTS device_hash VARCHAR(64) COMMENT 'Хеш устройства пользователя';
ALTER TABLE users ADD INDEX IF NOT EXISTS idx_device_hash (device_hash);

-- Добавляем constraint для связи с device_fingerprints
-- ALTER TABLE users ADD CONSTRAINT fk_users_device_hash 
--     FOREIGN KEY (device_hash) REFERENCES device_fingerprints(device_hash) ON DELETE SET NULL;
