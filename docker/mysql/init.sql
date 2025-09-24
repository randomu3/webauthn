-- WebAuthn Database Schema
-- Полная схема для enterprise-ready WebAuthn приложения
-- Включает аналитику, аудит, безопасность и мониторинг

CREATE DATABASE IF NOT EXISTS webauthn_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE webauthn_db;

-- ============================================================================
-- ОСНОВНЫЕ ТАБЛИЦЫ WEBAUTHN
-- ============================================================================

-- Таблица пользователей с расширенными полями для аналитики
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) UNIQUE NOT NULL,
    user_handle VARBINARY(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    device_hash VARCHAR(64) COMMENT 'Хеш устройства пользователя',
    
    -- Аналитические поля
    email VARCHAR(255) NULL COMMENT 'User email for recovery',
    display_name VARCHAR(255) NULL COMMENT 'User display name',
    last_login TIMESTAMP NULL COMMENT 'Last successful login',
    login_count INT UNSIGNED DEFAULT 0 COMMENT 'Total login count',
    failed_login_count INT UNSIGNED DEFAULT 0 COMMENT 'Failed login attempts',
    account_status ENUM('ACTIVE', 'SUSPENDED', 'LOCKED') DEFAULT 'ACTIVE',
    risk_score TINYINT UNSIGNED DEFAULT 0 COMMENT 'User risk score 0-100',
    preferences JSON NULL COMMENT 'User preferences and settings',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_user_id (user_id),
    INDEX idx_device_hash (device_hash),
    INDEX idx_email (email),
    INDEX idx_status (account_status, created_at),
    INDEX idx_risk (risk_score, last_login)
);

-- Таблица учетных данных WebAuthn с расширенной аналитикой  
CREATE TABLE user_credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    credential_id VARBINARY(1024) NOT NULL,
    credential_public_key TEXT NOT NULL,
    counter INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL,
    
    -- Расширенные поля для аналитики
    nickname VARCHAR(100) NULL COMMENT 'User-friendly credential name',
    device_info JSON NULL COMMENT 'Device information snapshot',
    registration_ip VARCHAR(45) NULL COMMENT 'IP when credential was registered',
    last_used_ip VARCHAR(45) NULL COMMENT 'Last IP that used this credential',
    usage_count INT UNSIGNED DEFAULT 0 COMMENT 'Number of times used',
    is_backup BOOLEAN DEFAULT FALSE COMMENT 'Is this a backup credential',
    is_primary BOOLEAN DEFAULT TRUE COMMENT 'Is this the primary credential',
    expires_at TIMESTAMP NULL COMMENT 'Credential expiration',
    revoked_at TIMESTAMP NULL COMMENT 'When credential was revoked',
    
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_credential_id (credential_id(255)),
    INDEX idx_user_id (user_id),
    INDEX idx_backup (is_backup, user_id),
    INDEX idx_primary (is_primary, user_id),
    INDEX idx_active (revoked_at, user_id),
    INDEX idx_usage (usage_count, last_used_at)
);

-- Таблица сессий пользователей
CREATE TABLE user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_session_id (session_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
);

-- Таблица отпечатков устройств
CREATE TABLE device_fingerprints (
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

-- ============================================================================
-- ТАБЛИЦЫ БЕЗОПАСНОСТИ
-- ============================================================================

-- Таблица ограничений скорости (rate limiting)
CREATE TABLE rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    user_id VARCHAR(255) NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_ip_action (ip_address, action, created_at),
    INDEX idx_user_action (user_id, action, created_at),
    INDEX idx_created_at (created_at)
);

-- Таблица заблокированных IP адресов
CREATE TABLE blocked_ips (
    ip_address VARCHAR(45) PRIMARY KEY,
    blocked_until TIMESTAMP NOT NULL,
    reason VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_blocked_until (blocked_until),
    INDEX idx_created_at (created_at)
);

-- Таблица кодов восстановления
CREATE TABLE recovery_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP NULL,
    
    INDEX idx_user_id (user_id),
    INDEX idx_used_at (used_at),
    INDEX idx_created_at (created_at)
);

-- Таблица экстренных токенов
CREATE TABLE emergency_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP NULL,
    
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_used_at (used_at)
);

-- ============================================================================
-- ТАБЛИЦЫ АНАЛИТИКИ И АУДИТА
-- ============================================================================

-- Таблица аудита всех действий пользователей
CREATE TABLE audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NULL,
    session_id VARCHAR(255) NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    action_type ENUM(
        'REGISTRATION_ATTEMPT', 'REGISTRATION_SUCCESS', 'REGISTRATION_FAILURE',
        'AUTH_ATTEMPT', 'AUTH_SUCCESS', 'AUTH_FAILURE',
        'SESSION_START', 'SESSION_END', 'SESSION_EXPIRED',
        'RECOVERY_CODE_GENERATED', 'RECOVERY_CODE_USED',
        'EMERGENCY_TOKEN_CREATED', 'EMERGENCY_TOKEN_USED',
        'PASSWORD_RESET_REQUEST', 'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED',
        'SUSPICIOUS_ACTIVITY', 'RATE_LIMIT_EXCEEDED', 'IP_BLOCKED',
        'DEVICE_ADDED', 'DEVICE_REMOVED', 'SETTINGS_CHANGED'
    ) NOT NULL,
    action_details JSON NULL,
    result ENUM('SUCCESS', 'FAILURE', 'BLOCKED', 'ERROR') NOT NULL,
    error_message TEXT NULL,
    risk_score TINYINT UNSIGNED DEFAULT 0 COMMENT 'Risk score 0-100',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_user_action (user_id, action_type, created_at),
    INDEX idx_ip_action (ip_address, action_type, created_at),
    INDEX idx_session (session_id),
    INDEX idx_time_action (created_at, action_type),
    INDEX idx_risk_score (risk_score, created_at),
    INDEX idx_result (result, created_at)
) ENGINE=InnoDB COMMENT='Audit log for all user actions and security events';

-- Таблица детальной аналитики устройств
CREATE TABLE device_analytics (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    device_hash VARCHAR(64) NOT NULL,
    device_fingerprint JSON NOT NULL COMMENT 'Full device fingerprint data',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    total_logins INT UNSIGNED DEFAULT 1,
    failed_attempts INT UNSIGNED DEFAULT 0,
    location_data JSON NULL COMMENT 'Geolocation data if available',
    is_trusted BOOLEAN DEFAULT FALSE,
    risk_level ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
    device_name VARCHAR(255) NULL COMMENT 'User-friendly device name',
    last_ip VARCHAR(45) NULL,
    operating_system VARCHAR(100) NULL,
    browser_name VARCHAR(100) NULL,
    browser_version VARCHAR(50) NULL,
    screen_resolution VARCHAR(20) NULL,
    timezone VARCHAR(50) NULL,
    language VARCHAR(10) NULL,
    notes TEXT NULL,
    
    UNIQUE KEY unique_user_device (user_id, device_hash),
    INDEX idx_user_devices (user_id, last_seen),
    INDEX idx_device_hash (device_hash),
    INDEX idx_risk_level (risk_level, last_seen),
    INDEX idx_trusted_devices (is_trusted, user_id),
    INDEX idx_location (last_ip, last_seen)
) ENGINE=InnoDB COMMENT='Detailed device analytics and tracking';

-- Таблица анализа безопасности сессий
CREATE TABLE session_analytics (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    device_hash VARCHAR(64) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    ended_at TIMESTAMP NULL,
    end_reason ENUM('LOGOUT', 'TIMEOUT', 'EXPIRED', 'FORCE_LOGOUT', 'SECURITY_VIOLATION') NULL,
    duration_seconds INT UNSIGNED NULL,
    page_views INT UNSIGNED DEFAULT 0,
    api_calls INT UNSIGNED DEFAULT 0,
    failed_actions INT UNSIGNED DEFAULT 0,
    location_changes INT UNSIGNED DEFAULT 0,
    is_suspicious BOOLEAN DEFAULT FALSE,
    security_events JSON NULL,
    
    UNIQUE KEY unique_session (session_id),
    INDEX idx_user_sessions (user_id, started_at),
    INDEX idx_device_sessions (device_hash, started_at),
    INDEX idx_ip_sessions (ip_address, started_at),
    INDEX idx_suspicious (is_suspicious, started_at),
    INDEX idx_duration (duration_seconds),
    INDEX idx_activity (last_activity)
) ENGINE=InnoDB COMMENT='Session analytics and behavior tracking';

-- Таблица мониторинга безопасности
CREATE TABLE security_incidents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    incident_type ENUM(
        'BRUTE_FORCE', 'CREDENTIAL_STUFFING', 'ACCOUNT_TAKEOVER',
        'SUSPICIOUS_LOGIN', 'IMPOSSIBLE_TRAVEL', 'DEVICE_SPOOFING',
        'SESSION_HIJACKING', 'RATE_LIMIT_ABUSE', 'BOT_ACTIVITY',
        'PHISHING_ATTEMPT', 'MALWARE_DETECTED', 'DATA_BREACH_ATTEMPT',
        'PRIVILEGE_ESCALATION', 'UNAUTHORIZED_ACCESS'
    ) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    status ENUM('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE') DEFAULT 'OPEN',
    user_id VARCHAR(255) NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    attack_vector TEXT NULL,
    indicators JSON NULL COMMENT 'Technical indicators and evidence',
    mitigation_actions JSON NULL COMMENT 'Actions taken to mitigate',
    analyst_notes TEXT NULL,
    auto_detected BOOLEAN DEFAULT TRUE,
    detection_rule VARCHAR(255) NULL,
    first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    assigned_to VARCHAR(255) NULL,
    
    INDEX idx_incident_type (incident_type, first_detected),
    INDEX idx_severity_status (severity, status),
    INDEX idx_user_incidents (user_id, first_detected),
    INDEX idx_ip_incidents (ip_address, first_detected),
    INDEX idx_detection_time (first_detected),
    INDEX idx_open_incidents (status, severity, first_detected)
) ENGINE=InnoDB COMMENT='Security incident tracking and management';

-- Таблица геолокации и анализа местоположений
CREATE TABLE user_locations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) NULL,
    ip_address VARCHAR(45) NOT NULL,
    country_code CHAR(2) NULL,
    country_name VARCHAR(100) NULL,
    region VARCHAR(100) NULL,
    city VARCHAR(100) NULL,
    postal_code VARCHAR(20) NULL,
    latitude DECIMAL(10, 8) NULL,
    longitude DECIMAL(11, 8) NULL,
    timezone VARCHAR(50) NULL,
    isp VARCHAR(255) NULL,
    organization VARCHAR(255) NULL,
    is_vpn BOOLEAN DEFAULT FALSE,
    is_tor BOOLEAN DEFAULT FALSE,
    is_proxy BOOLEAN DEFAULT FALSE,
    is_datacenter BOOLEAN DEFAULT FALSE,
    threat_level ENUM('NONE', 'LOW', 'MEDIUM', 'HIGH') DEFAULT 'NONE',
    accuracy_radius INT NULL COMMENT 'Accuracy in kilometers',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    visit_count INT UNSIGNED DEFAULT 1,
    
    INDEX idx_user_locations (user_id, last_seen),
    INDEX idx_ip_location (ip_address),
    INDEX idx_country_stats (country_code, last_seen),
    INDEX idx_threat_locations (threat_level, last_seen),
    INDEX idx_vpn_detection (is_vpn, is_tor, is_proxy),
    INDEX idx_coordinates (latitude, longitude)
) ENGINE=InnoDB COMMENT='User geolocation tracking and analysis';

-- Таблица WebAuthn специфичной аналитики
CREATE TABLE webauthn_analytics (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    credential_id VARBINARY(1024) NOT NULL,
    authenticator_type ENUM('PLATFORM', 'CROSS_PLATFORM', 'UNKNOWN') DEFAULT 'UNKNOWN',
    attestation_format VARCHAR(50) NULL COMMENT 'packed, fido-u2f, none, etc',
    transport_methods JSON NULL COMMENT 'usb, nfc, ble, internal',
    aaguid BINARY(16) NULL COMMENT 'Authenticator Attestation GUID',
    algorithm VARCHAR(20) NULL COMMENT 'ES256, RS256, etc',
    curve VARCHAR(20) NULL COMMENT 'P-256, P-384, etc',
    counter_initial INT UNSIGNED NULL,
    counter_current INT UNSIGNED NULL,
    backup_eligible BOOLEAN NULL,
    backup_state BOOLEAN NULL,
    user_verified BOOLEAN NULL,
    user_present BOOLEAN NULL,
    registration_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP NULL,
    usage_count INT UNSIGNED DEFAULT 0,
    failed_usage_count INT UNSIGNED DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    deactivated_at TIMESTAMP NULL,
    deactivation_reason VARCHAR(255) NULL,
    
    UNIQUE KEY unique_credential (credential_id),
    INDEX idx_user_authenticators (user_id, registration_time),
    INDEX idx_authenticator_type (authenticator_type, registration_time),
    INDEX idx_usage_stats (usage_count, last_used),
    INDEX idx_failed_usage (failed_usage_count, last_used),
    INDEX idx_active_authenticators (is_active, user_id)
) ENGINE=InnoDB COMMENT='WebAuthn authenticator analytics and tracking';

-- ============================================================================
-- ПОЛЬЗОВАТЕЛИ И ПРАВА ДОСТУПА
-- ============================================================================

-- Устанавливаем пароль root и создаем пользователя приложения
ALTER USER 'root'@'localhost' IDENTIFIED BY 'rootpassword';

-- Создаем пользователя для приложения
CREATE USER IF NOT EXISTS 'webauthn_user'@'%' IDENTIFIED BY 'webauthn_pass';
GRANT ALL PRIVILEGES ON webauthn_db.* TO 'webauthn_user'@'%';

-- Обновляем привилегии
FLUSH PRIVILEGES;