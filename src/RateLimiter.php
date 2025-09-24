<?php

namespace WebAuthn;

/**
 * Класс для ограничения частоты запросов (Rate Limiting)
 * Защищает от brute force атак и DoS
 */
class RateLimiter
{
    private Database $db;
    
    public function __construct(Database $db)
    {
        $this->db = $db;
    }
    
    /**
     * Проверяет лимиты для IP адреса
     */
    public function checkIPLimit(string $action, int $maxAttempts = 10, int $windowMinutes = 15): bool
    {
        $ip = $this->getClientIP();
        $windowStart = date('Y-m-d H:i:s', time() - ($windowMinutes * 60));
        
        try {
            $pdo = $this->db->getPdo();
            
            // Создаем таблицу для rate limiting если не существует
            $this->createRateLimitTable($pdo);
            
            // Очищаем старые записи
            $stmt = $pdo->prepare("DELETE FROM rate_limits WHERE created_at < ?");
            $stmt->execute([$windowStart]);
            
            // Считаем текущие попытки
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as attempts 
                FROM rate_limits 
                WHERE ip_address = ? AND action = ? AND created_at >= ?
            ");
            $stmt->execute([$ip, $action, $windowStart]);
            $result = $stmt->fetch();
            
            $currentAttempts = $result['attempts'] ?? 0;
            
            if ($currentAttempts >= $maxAttempts) {
                error_log("RateLimiter: IP $ip exceeded limit for action $action ($currentAttempts/$maxAttempts)");
                return false;
            }
            
            // Записываем текущую попытку
            $stmt = $pdo->prepare("
                INSERT INTO rate_limits (ip_address, action, created_at) 
                VALUES (?, ?, NOW())
            ");
            $stmt->execute([$ip, $action]);
            
            return true;
            
        } catch (\Exception $e) {
            error_log('RateLimiter: Database error: ' . $e->getMessage());
            // В случае ошибки БД пропускаем запрос (fail open)
            return true;
        }
    }
    
    /**
     * Проверяет лимиты для пользователя/устройства
     */
    public function checkUserLimit(string $userId, string $action, int $maxAttempts = 5, int $windowMinutes = 10): bool
    {
        $windowStart = date('Y-m-d H:i:s', time() - ($windowMinutes * 60));
        
        try {
            $pdo = $this->db->getPdo();
            
            // Считаем попытки пользователя
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as attempts 
                FROM rate_limits 
                WHERE user_id = ? AND action = ? AND created_at >= ?
            ");
            $stmt->execute([$userId, $action, $windowStart]);
            $result = $stmt->fetch();
            
            $currentAttempts = $result['attempts'] ?? 0;
            
            if ($currentAttempts >= $maxAttempts) {
                error_log("RateLimiter: User $userId exceeded limit for action $action ($currentAttempts/$maxAttempts)");
                return false;
            }
            
            // Записываем попытку (с пустым IP для user limits)
            $stmt = $pdo->prepare("
                INSERT INTO rate_limits (ip_address, user_id, action, created_at) 
                VALUES ('', ?, ?, NOW())
            ");
            $stmt->execute([$userId, $action]);
            
            return true;
            
        } catch (\Exception $e) {
            error_log('RateLimiter: Database error: ' . $e->getMessage());
            return true;
        }
    }
    
    /**
     * Возвращает информацию о текущих лимитах
     */
    public function getLimitInfo(string $action, int $windowMinutes = 15): array
    {
        $ip = $this->getClientIP();
        $windowStart = date('Y-m-d H:i:s', time() - ($windowMinutes * 60));
        
        try {
            $pdo = $this->db->getPdo();
            
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as attempts, MAX(created_at) as last_attempt
                FROM rate_limits 
                WHERE ip_address = ? AND action = ? AND created_at >= ?
            ");
            $stmt->execute([$ip, $action, $windowStart]);
            $result = $stmt->fetch();
            
            return [
                'attempts' => $result['attempts'] ?? 0,
                'last_attempt' => $result['last_attempt'],
                'window_start' => $windowStart,
                'ip' => $ip
            ];
            
        } catch (\Exception $e) {
            error_log('RateLimiter: Database error: ' . $e->getMessage());
            return ['attempts' => 0, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Блокирует IP на определенное время за подозрительную активность
     */
    public function blockIP(string $ip, int $blockMinutes = 60, string $reason = 'Suspicious activity'): void
    {
        try {
            $pdo = $this->db->getPdo();
            
            $this->createBlockedIPsTable($pdo);
            
            $blockUntil = date('Y-m-d H:i:s', time() + ($blockMinutes * 60));
            
            $stmt = $pdo->prepare("
                INSERT INTO blocked_ips (ip_address, blocked_until, reason, created_at) 
                VALUES (?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE 
                blocked_until = VALUES(blocked_until), 
                reason = VALUES(reason)
            ");
            $stmt->execute([$ip, $blockUntil, $reason]);
            
            error_log("RateLimiter: IP $ip blocked until $blockUntil. Reason: $reason");
            
        } catch (\Exception $e) {
            error_log('RateLimiter: Failed to block IP: ' . $e->getMessage());
        }
    }
    
    /**
     * Проверяет, заблокирован ли IP
     */
    public function isIPBlocked(string $ip = null): bool
    {
        $ip = $ip ?? $this->getClientIP();
        
        try {
            $pdo = $this->db->getPdo();
            
            $stmt = $pdo->prepare("
                SELECT blocked_until 
                FROM blocked_ips 
                WHERE ip_address = ? AND blocked_until > NOW()
            ");
            $stmt->execute([$ip]);
            $result = $stmt->fetch();
            
            return $result !== false;
            
        } catch (\Exception $e) {
            error_log('RateLimiter: Database error checking blocked IP: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Получает реальный IP клиента с учетом proxy
     */
    private function getClientIP(): string
    {
        // Проверяем заголовки от прокси/load balancer
        $headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_CLIENT_IP',            // Прокси
            'HTTP_X_FORWARDED_FOR',      // Load Balancer/Прокси
            'HTTP_X_FORWARDED',          // Прокси
            'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
            'HTTP_FORWARDED_FOR',        // Прокси
            'HTTP_FORWARDED',            // Прокси
            'REMOTE_ADDR'                // Стандартный
        ];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);
                
                // Валидируем IP
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        // Fallback к REMOTE_ADDR
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Создает таблицу для rate limiting если не существует
     */
    private function createRateLimitTable($pdo): void
    {
        $sql = "CREATE TABLE IF NOT EXISTS rate_limits (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            user_id VARCHAR(255) NULL,
            action VARCHAR(50) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip_action_time (ip_address, action, created_at),
            INDEX idx_user_action_time (user_id, action, created_at),
            INDEX idx_cleanup (created_at)
        ) ENGINE=InnoDB";
        
        $pdo->exec($sql);
    }
    
    /**
     * Создает таблицу для заблокированных IP если не существует
     */
    private function createBlockedIPsTable($pdo): void
    {
        $sql = "CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_address VARCHAR(45) PRIMARY KEY,
            blocked_until TIMESTAMP NOT NULL,
            reason VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_blocked_until (blocked_until)
        ) ENGINE=InnoDB";
        
        $pdo->exec($sql);
    }
}
