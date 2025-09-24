<?php

namespace WebAuthn;

/**
 * Класс для управления механизмами восстановления доступа
 * Реализует резервные методы аутентификации согласно рекомендациям WebAuthn
 */
class RecoveryManager
{
    private Database $db;
    
    public function __construct(Database $db)
    {
        $this->db = $db;
    }
    
    /**
     * Генерирует резервные коды для пользователя
     */
    public function generateRecoveryCodes(string $userId, int $codeCount = 8): array
    {
        $codes = [];
        
        try {
            $pdo = $this->db->getPdo();
            
            // Создаем таблицу для recovery кодов если не существует
            $this->createRecoveryCodesTable($pdo);
            
            // Удаляем старые коды пользователя
            $stmt = $pdo->prepare("DELETE FROM recovery_codes WHERE user_id = ?");
            $stmt->execute([$userId]);
            
            // Генерируем новые коды
            for ($i = 0; $i < $codeCount; $i++) {
                $code = $this->generateSecureCode();
                $hashedCode = password_hash($code, PASSWORD_ARGON2ID, [
                    'memory_cost' => 65536, // 64 MB
                    'time_cost' => 4,       // 4 iterations
                    'threads' => 3          // 3 threads
                ]);
                
                // Сохраняем хешированный код в БД
                $stmt = $pdo->prepare("
                    INSERT INTO recovery_codes (user_id, code_hash, created_at) 
                    VALUES (?, ?, NOW())
                ");
                $stmt->execute([$userId, $hashedCode]);
                
                $codes[] = $code;
            }
            
            return $codes;
            
        } catch (\Exception $e) {
            error_log('RecoveryManager: Failed to generate recovery codes: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Проверяет recovery код пользователя
     */
    public function verifyRecoveryCode(string $userId, string $inputCode): bool
    {
        try {
            $pdo = $this->db->getPdo();
            
            // Получаем все активные коды пользователя
            $stmt = $pdo->prepare("
                SELECT id, code_hash 
                FROM recovery_codes 
                WHERE user_id = ? AND used_at IS NULL
            ");
            $stmt->execute([$userId]);
            $codes = $stmt->fetchAll();
            
            foreach ($codes as $codeData) {
                if (password_verify($inputCode, $codeData['code_hash'])) {
                    // Помечаем код как использованный
                    $stmt = $pdo->prepare("
                        UPDATE recovery_codes 
                        SET used_at = NOW() 
                        WHERE id = ?
                    ");
                    $stmt->execute([$codeData['id']]);
                    
                    error_log("RecoveryManager: Recovery code used for user $userId");
                    return true;
                }
            }
            
            error_log("RecoveryManager: Invalid recovery code for user $userId");
            return false;
            
        } catch (\Exception $e) {
            error_log('RecoveryManager: Database error: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Получает количество оставшихся recovery кодов
     */
    public function getRemainingCodesCount(string $userId): int
    {
        try {
            $pdo = $this->db->getPdo();
            
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as count 
                FROM recovery_codes 
                WHERE user_id = ? AND used_at IS NULL
            ");
            $stmt->execute([$userId]);
            $result = $stmt->fetch();
            
            return $result['count'] ?? 0;
            
        } catch (\Exception $e) {
            error_log('RecoveryManager: Database error: ' . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Создает emergency access token для восстановления аккаунта
     */
    public function createEmergencyToken(string $userId, string $email): ?string
    {
        try {
            $pdo = $this->db->getPdo();
            
            $this->createEmergencyTokensTable($pdo);
            
            // Генерируем токен
            $token = bin2hex(random_bytes(32));
            $hashedToken = hash('sha256', $token);
            $expiresAt = date('Y-m-d H:i:s', time() + (24 * 60 * 60)); // 24 часа
            
            // Удаляем старые токены пользователя
            $stmt = $pdo->prepare("DELETE FROM emergency_tokens WHERE user_id = ?");
            $stmt->execute([$userId]);
            
            // Сохраняем новый токен
            $stmt = $pdo->prepare("
                INSERT INTO emergency_tokens (user_id, token_hash, email, expires_at, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            $stmt->execute([$userId, $hashedToken, $email, $expiresAt]);
            
            // В реальном приложении здесь должна быть отправка email
            error_log("RecoveryManager: Emergency token created for user $userId");
            
            return $token;
            
        } catch (\Exception $e) {
            error_log('RecoveryManager: Failed to create emergency token: ' . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Проверяет emergency token
     */
    public function verifyEmergencyToken(string $token): ?string
    {
        try {
            $pdo = $this->db->getPdo();
            
            $hashedToken = hash('sha256', $token);
            
            $stmt = $pdo->prepare("
                SELECT user_id, email 
                FROM emergency_tokens 
                WHERE token_hash = ? AND expires_at > NOW() AND used_at IS NULL
            ");
            $stmt->execute([$hashedToken]);
            $result = $stmt->fetch();
            
            if ($result) {
                // Помечаем токен как использованный
                $stmt = $pdo->prepare("
                    UPDATE emergency_tokens 
                    SET used_at = NOW() 
                    WHERE token_hash = ?
                ");
                $stmt->execute([$hashedToken]);
                
                error_log("RecoveryManager: Emergency token used for user " . $result['user_id']);
                return $result['user_id'];
            }
            
            return null;
            
        } catch (\Exception $e) {
            error_log('RecoveryManager: Database error: ' . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Добавляет дополнительное устройство для пользователя
     */
    public function addBackupDevice(string $userId, array $credentialData): bool
    {
        try {
            $pdo = $this->db->getPdo();
            
            $this->createBackupDevicesTable($pdo);
            
            $credentialId = $credentialData['credentialId'];
            $publicKey = $credentialData['publicKey'];
            $deviceName = $credentialData['deviceName'] ?? 'Backup Device';
            
            $stmt = $pdo->prepare("
                INSERT INTO backup_devices (user_id, credential_id, public_key, device_name, created_at) 
                VALUES (?, ?, ?, ?, NOW())
            ");
            $stmt->execute([$userId, $credentialId, $publicKey, $deviceName]);
            
            error_log("RecoveryManager: Backup device added for user $userId");
            return true;
            
        } catch (\Exception $e) {
            error_log('RecoveryManager: Failed to add backup device: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Получает список backup устройств пользователя
     */
    public function getBackupDevices(string $userId): array
    {
        try {
            $pdo = $this->db->getPdo();
            
            $stmt = $pdo->prepare("
                SELECT credential_id, device_name, created_at 
                FROM backup_devices 
                WHERE user_id = ? AND active = 1
                ORDER BY created_at DESC
            ");
            $stmt->execute([$userId]);
            
            return $stmt->fetchAll();
            
        } catch (\Exception $e) {
            error_log('RecoveryManager: Database error: ' . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Генерирует безопасный recovery код
     */
    private function generateSecureCode(int $length = 8): string
    {
        // Используем безопасные символы (исключаем похожие: 0, O, 1, I, l)
        $chars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
        $code = '';
        
        for ($i = 0; $i < $length; $i++) {
            $code .= $chars[random_int(0, strlen($chars) - 1)];
        }
        
        // Добавляем дефисы для читаемости
        return substr($code, 0, 4) . '-' . substr($code, 4, 4);
    }
    
    /**
     * Создает таблицу recovery кодов
     */
    private function createRecoveryCodesTable($pdo): void
    {
        $sql = "CREATE TABLE IF NOT EXISTS recovery_codes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            code_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP NULL,
            INDEX idx_user_active (user_id, used_at)
        ) ENGINE=InnoDB";
        
        $pdo->exec($sql);
    }
    
    /**
     * Создает таблицу emergency токенов
     */
    private function createEmergencyTokensTable($pdo): void
    {
        $sql = "CREATE TABLE IF NOT EXISTS emergency_tokens (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            token_hash VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP NULL,
            INDEX idx_token (token_hash),
            INDEX idx_user (user_id)
        ) ENGINE=InnoDB";
        
        $pdo->exec($sql);
    }
    
    /**
     * Создает таблицу backup устройств
     */
    private function createBackupDevicesTable($pdo): void
    {
        $sql = "CREATE TABLE IF NOT EXISTS backup_devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id VARCHAR(255) NOT NULL,
            credential_id TEXT NOT NULL,
            public_key TEXT NOT NULL,
            device_name VARCHAR(255) NOT NULL,
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_user (user_id),
            INDEX idx_credential (credential_id(50))
        ) ENGINE=InnoDB";
        
        $pdo->exec($sql);
    }
}
