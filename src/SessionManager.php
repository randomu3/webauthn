<?php

namespace WebAuthn;

/**
 * Менеджер сессий
 */
class SessionManager
{
    private Database $db;
    
    public function __construct(Database $db)
    {
        $this->db = $db;
        
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }
    
    /**
     * Проверяет, авторизован ли пользователь
     */
    public function isUserLoggedIn(): bool
    {
        if (!isset($_SESSION['user_id']) || !isset($_SESSION['session_id'])) {
            return false;
        }
        
        // Проверяем валидность сессии в БД
        $session = $this->db->getSession($_SESSION['session_id']);
        return $session !== null;
    }
    
    /**
     * Получает ID текущего пользователя
     */
    public function getCurrentUserId(): ?string
    {
        return $_SESSION['user_id'] ?? null;
    }
    
    /**
     * Создает новую сессию для пользователя
     */
    public function createSession(string $userId): string
    {
        $sessionId = bin2hex(random_bytes(16));
        
        if (!$this->db->createSession($sessionId, $userId, 3600)) {
            throw new \Exception('Failed to create session');
        }
        
        $_SESSION['session_id'] = $sessionId;
        $_SESSION['user_id'] = $userId;
        
        return $sessionId;
    }
    
    /**
     * Уничтожает текущую сессию
     */
    public function destroySession(): void
    {
        if (isset($_SESSION['session_id'])) {
            $this->db->deleteSession($_SESSION['session_id']);
        }
        
        session_destroy();
    }
    
    /**
     * Сохраняет данные регистрации в сессии
     */
    public function saveRegistrationData(string $challenge, string $userId, string $userHandle): void
    {
        $_SESSION['reg_challenge'] = $challenge;
        $_SESSION['reg_user_id'] = $userId;
        $_SESSION['reg_user_handle'] = $userHandle;
    }
    
    /**
     * Получает данные регистрации из сессии
     */
    public function getRegistrationData(): ?array
    {
        if (!isset($_SESSION['reg_challenge']) || !isset($_SESSION['reg_user_id'])) {
            return null;
        }
        
        return [
            'challenge' => $_SESSION['reg_challenge'],
            'userId' => $_SESSION['reg_user_id'],
            'userHandle' => $_SESSION['reg_user_handle']
        ];
    }
    
    /**
     * Очищает данные регистрации из сессии
     */
    public function clearRegistrationData(): void
    {
        unset($_SESSION['reg_challenge'], $_SESSION['reg_user_id'], $_SESSION['reg_user_handle']);
    }
    
    /**
     * Сохраняет challenge аутентификации в сессии
     */
    public function saveAuthChallenge(string $challenge): void
    {
        $_SESSION['auth_challenge'] = $challenge;
    }
    
    /**
     * Получает challenge аутентификации из сессии
     */
    public function getAuthChallenge(): ?string
    {
        return $_SESSION['auth_challenge'] ?? null;
    }
    
    /**
     * Очищает challenge аутентификации из сессии
     */
    public function clearAuthChallenge(): void
    {
        unset($_SESSION['auth_challenge']);
    }
}
