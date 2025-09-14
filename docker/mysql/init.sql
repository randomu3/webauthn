CREATE DATABASE IF NOT EXISTS webauthn_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE webauthn_db;

-- Таблица для хранения пользователей (только по отпечатку пальца)
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) UNIQUE NOT NULL,
    user_handle VARBINARY(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Таблица для хранения учетных данных WebAuthn
CREATE TABLE user_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    credential_id VARBINARY(1024) NOT NULL,
    credential_public_key TEXT NOT NULL,
    counter INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_credential_id (credential_id(255)),
    INDEX idx_user_id (user_id)
);

-- Таблица для хранения сессий
CREATE TABLE user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_session_id (session_id),
    INDEX idx_expires_at (expires_at)
);
