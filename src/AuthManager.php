<?php

namespace WebAuthn;

use PDO;
use Exception;

/**
 * Менеджер традиционной авторизации с PIN кодами
 * Реализует банковскую модель: логин/пароль → PIN → WebAuthn
 */
class AuthManager
{
    private Database $db;
    private PDO $pdo;
    private AnalyticsManager $analytics;

    public function __construct(Database $db, AnalyticsManager $analytics)
    {
        $this->db = $db;
        $this->pdo = $db->getPdo();
        $this->analytics = $analytics;
    }

    /**
     * Создание нового пользователя с логином и паролем
     */
    public function createUser(string $username, string $email, string $password, string $displayName = null): array
    {
        try {
            // Проверяем уникальность
            if ($this->getUserByUsername($username) || $this->getUserByEmail($email)) {
                throw new Exception('Пользователь с таким логином или email уже существует');
            }

            // Генерируем уникальные идентификаторы
            $userId = $this->generateUserId();
            $userHandle = random_bytes(32);
            $passwordHash = password_hash($password, PASSWORD_ARGON2ID, [
                'memory_cost' => 65536,
                'time_cost' => 4,
                'threads' => 3
            ]);

            $stmt = $this->pdo->prepare("
                INSERT INTO users (
                    user_id, user_handle, username, email, password_hash, 
                    display_name, account_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', NOW())
            ");

            $result = $stmt->execute([
                $userId,
                $userHandle,
                $username,
                $email,
                $passwordHash,
                $displayName ?? $username
            ]);

            if ($result) {
                $this->analytics->logUserAction(
                    $userId,
                    'REGISTRATION_SUCCESS',
                    'SUCCESS',
                    null,
                    ['method' => 'traditional', 'username' => $username]
                );

                return [
                    'success' => true,
                    'user_id' => $userId,
                    'username' => $username,
                    'email' => $email
                ];
            }

            throw new Exception('Ошибка создания пользователя');

        } catch (Exception $e) {
            $this->analytics->logUserAction(
                null,
                'REGISTRATION_FAILURE',
                'ERROR',
                null,
                ['username' => $username, 'email' => $email],
                $e->getMessage()
            );

            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Авторизация по логину и паролю
     */
    public function authenticateUser(string $login, string $password, bool $rememberMe = false): array
    {
        try {
            // Ищем пользователя по username или email
            $user = $this->getUserByUsername($login) ?? $this->getUserByEmail($login);

            if (!$user) {
                throw new Exception('Пользователь не найден');
            }

            if ($user['account_status'] !== 'ACTIVE') {
                throw new Exception('Аккаунт заблокирован');
            }

            // Проверяем пароль
            if (!password_verify($password, $user['password_hash'])) {
                $this->incrementFailedAttempts($user['user_id']);
                throw new Exception('Неверный пароль');
            }

            // Обновляем статистику входа
            $this->updateLoginStats($user['user_id'], 'PASSWORD');

            $result = [
                'success' => true,
                'user_id' => $user['user_id'],
                'username' => $user['username'],
                'display_name' => $user['display_name'],
                'pin_enabled' => $user['pin_enabled'],
                'webauthn_enabled' => $user['webauthn_enabled'],
                'quick_login_enabled' => $user['quick_login_enabled'],
                'remember_me_requested' => $rememberMe
            ];

            // Если включено "Запомнить меня" - создаем токен и указываем что нужен PIN setup
            if ($rememberMe) {
                $rememberToken = $this->createRememberToken($user['user_id']);
                $result['remember_token'] = $rememberToken;
                $result['needs_pin_setup'] = !$user['pin_enabled'];
                $result['redirect_to'] = $user['pin_enabled'] ? 'dashboard' : 'setup_pin';
            } else {
                // Обычный вход - сразу в dashboard без PIN
                $result['needs_pin_setup'] = false;
                $result['redirect_to'] = 'dashboard';
            }

            $this->analytics->logUserAction(
                $user['user_id'],
                'AUTH_SUCCESS',
                'SUCCESS',
                null,
                ['method' => 'password', 'remember_me' => $rememberMe]
            );

            return $result;

        } catch (Exception $e) {
            $this->analytics->logUserAction(
                null,
                'AUTH_FAILURE',
                'FAILURE',
                null,
                ['login' => $login, 'method' => 'password'],
                $e->getMessage()
            );

            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Установка 6-значного PIN кода
     */
    public function setupPIN(string $userId, string $pin): array
    {
        try {
            if (!preg_match('/^\d{6}$/', $pin)) {
                throw new Exception('PIN должен состоять из 6 цифр');
            }

            $pinHash = password_hash($pin, PASSWORD_ARGON2ID);

            $stmt = $this->pdo->prepare("
                UPDATE users SET 
                    pin_hash = ?, 
                    pin_enabled = TRUE,
                    pin_created_at = NOW(),
                    pin_attempts = 0,
                    quick_login_enabled = TRUE,
                    updated_at = NOW()
                WHERE user_id = ?
            ");

            if ($stmt->execute([$pinHash, $userId])) {
                $this->analytics->logUserAction(
                    $userId,
                    'DEVICE_ADDED',
                    'SUCCESS',
                    null,
                    ['type' => 'PIN_SETUP']
                );

                return [
                    'success' => true,
                    'message' => 'PIN код успешно установлен'
                ];
            }

            throw new Exception('Ошибка сохранения PIN кода');

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Авторизация по PIN коду
     */
    public function authenticateByPIN(string $userId, string $pin): array
    {
        try {
            $user = $this->getUserById($userId);

            if (!$user || !$user['pin_enabled']) {
                throw new Exception('PIN авторизация недоступна');
            }

            if ($user['account_status'] !== 'ACTIVE') {
                throw new Exception('Аккаунт заблокирован');
            }

            // Проверяем количество попыток
            if ($user['pin_attempts'] >= 3) {
                $this->resetUserSecurity($userId, 'Превышено количество попыток ввода PIN (3 раза)');
                
                $this->analytics->logUserAction(
                    $userId,
                    'ACCOUNT_LOCKED',
                    'BLOCKED',
                    null,
                    ['reason' => 'PIN_ATTEMPTS_EXCEEDED', 'attempts' => $user['pin_attempts']]
                );
                
                throw new Exception('PIN заблокирован после 3 неверных попыток. Войдите через логин и пароль для восстановления доступа.');
            }

            // Проверяем PIN
            if (!password_verify($pin, $user['pin_hash'])) {
                $newAttempts = $this->incrementPINAttempts($userId);
                $attemptsLeft = 3 - $newAttempts;
                
                $this->analytics->logUserAction(
                    $userId,
                    'AUTH_FAILURE',
                    'FAILURE',
                    null,
                    ['method' => 'pin', 'attempts' => $newAttempts, 'attempts_left' => $attemptsLeft]
                );
                
                if ($attemptsLeft > 0) {
                    throw new Exception("Неверный PIN код. Осталось попыток: {$attemptsLeft}");
                } else {
                    $this->resetUserSecurity($userId, 'PIN заблокирован после 3 попыток');
                    throw new Exception('PIN заблокирован. Войдите через логин и пароль.');
                }
            }

            // Сбрасываем счетчик попыток при успехе
            $this->resetPINAttempts($userId);
            $this->updateLoginStats($userId, 'PIN');

            $this->analytics->logUserAction(
                $userId,
                'AUTH_SUCCESS',
                'SUCCESS',
                null,
                ['method' => 'pin']
            );

            return [
                'success' => true,
                'user_id' => $userId,
                'username' => $user['username'],
                'display_name' => $user['display_name'],
                'webauthn_enabled' => $user['webauthn_enabled'],
                'login_method' => 'PIN'
            ];

        } catch (Exception $e) {
            $this->analytics->logUserAction(
                $userId,
                'AUTH_FAILURE',
                'FAILURE',
                null,
                ['method' => 'pin'],
                $e->getMessage()
            );

            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Авторизация по remember token
     */
    public function authenticateByRememberToken(string $token): array
    {
        try {
            $stmt = $this->pdo->prepare("
                SELECT * FROM users 
                WHERE remember_token = ? 
                AND remember_expires > NOW() 
                AND account_status = 'ACTIVE'
            ");
            $stmt->execute([hash('sha256', $token)]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                throw new Exception('Недействительный или истекший токен');
            }

            $this->updateLoginStats($user['user_id'], 'REMEMBER_TOKEN');

            return [
                'success' => true,
                'user_id' => $user['user_id'],
                'username' => $user['username'],
                'display_name' => $user['display_name'],
                'pin_enabled' => $user['pin_enabled'],
                'webauthn_enabled' => $user['webauthn_enabled'],
                'quick_login_enabled' => $user['quick_login_enabled'],
                'quick_login_available' => true, // Если токен валиден - быстрый вход доступен
                'login_method' => 'REMEMBER_TOKEN'
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Включение WebAuthn для пользователя
     */
    public function enableWebAuthn(string $userId): bool
    {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE users SET 
                    webauthn_enabled = TRUE,
                    webauthn_setup_at = NOW(),
                    updated_at = NOW()
                WHERE user_id = ?
            ");

            if ($stmt->execute([$userId])) {
                $this->analytics->logUserAction(
                    $userId,
                    'DEVICE_ADDED',
                    'SUCCESS',
                    null,
                    ['type' => 'WEBAUTHN_SETUP']
                );
                return true;
            }

            return false;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Сброс всех методов быстрого входа (при выходе или ошибках)
     */
    public function resetUserSecurity(string $userId, string $reason = 'Security reset'): bool
    {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE users SET 
                    pin_hash = NULL,
                    pin_enabled = FALSE,
                    pin_attempts = 0,
                    quick_login_enabled = FALSE,
                    remember_token = NULL,
                    remember_expires = NULL,
                    webauthn_enabled = FALSE,
                    updated_at = NOW()
                WHERE user_id = ?
            ");

            $result = $stmt->execute([$userId]);

            if ($result) {
                // Удаляем WebAuthn credentials
                $stmt = $this->pdo->prepare("DELETE FROM user_credentials WHERE user_id = ?");
                $stmt->execute([$userId]);

                $this->analytics->logUserAction(
                    $userId,
                    'DEVICE_REMOVED',
                    'SUCCESS',
                    null,
                    ['reason' => $reason, 'reset_type' => 'FULL_SECURITY_RESET']
                );
            }

            return $result;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * Обработка ошибки WebAuthn (сброс после первой ошибки)
     */
    public function handleWebAuthnFailure(string $userId, string $errorReason = 'WebAuthn authentication failed'): array
    {
        try {
            // При любой ошибке WebAuthn - полный сброс безопасности
            $this->resetUserSecurity($userId, "WebAuthn ошибка: {$errorReason}");
            
            $this->analytics->logUserAction(
                $userId,
                'AUTH_FAILURE',
                'BLOCKED',
                null,
                ['method' => 'webauthn', 'reason' => $errorReason, 'action' => 'SECURITY_RESET']
            );
            
            $this->analytics->recordSecurityIncident(
                'SUSPICIOUS_LOGIN',
                'HIGH',
                $userId,
                ['webauthn_error' => $errorReason, 'action' => 'full_reset'],
                'WebAuthn failure triggered security reset'
            );
            
            return [
                'success' => false,
                'error' => 'WEBAUTHN_FAILED',
                'message' => 'Ошибка биометрической аутентификации. Быстрый доступ отключен для безопасности.',
                'security_reset' => true,
                'redirect_to' => 'login'
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'SECURITY_ERROR',
                'message' => 'Ошибка системы безопасности'
            ];
        }
    }

    /**
     * Выход из системы
     */
    public function logout(string $userId, bool $resetSecurity = false): array
    {
        try {
            if ($resetSecurity) {
                $this->resetUserSecurity($userId, 'Manual logout with security reset');
            } else {
                // Только сбрасываем remember token
                $stmt = $this->pdo->prepare("
                    UPDATE users SET 
                        remember_token = NULL,
                        remember_expires = NULL,
                        updated_at = NOW()
                    WHERE user_id = ?
                ");
                $stmt->execute([$userId]);
            }

            $this->analytics->logUserAction(
                $userId,
                'SESSION_END',
                'SUCCESS',
                null,
                ['reset_security' => $resetSecurity]
            );

            return [
                'success' => true,
                'security_reset' => $resetSecurity
            ];

        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Получение пользователя по ID
     */
    public function getUserById(string $userId): ?array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE user_id = ?");
        $stmt->execute([$userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /**
     * Получение пользователя по username
     */
    public function getUserByUsername(string $username): ?array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /**
     * Получение пользователя по email
     */
    public function getUserByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    // Приватные методы

    private function generateUserId(): string
    {
        return 'user_' . bin2hex(random_bytes(16));
    }

    private function createRememberToken(string $userId): string
    {
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $expires = date('Y-m-d H:i:s', strtotime('+30 days'));

        $stmt = $this->pdo->prepare("
            UPDATE users SET 
                remember_token = ?,
                remember_expires = ?,
                updated_at = NOW()
            WHERE user_id = ?
        ");
        $stmt->execute([$tokenHash, $expires, $userId]);

        return $token;
    }

    private function updateLoginStats(string $userId, string $method): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE users SET 
                last_login = NOW(),
                last_login_method = ?,
                login_count = login_count + 1,
                failed_login_count = 0,
                updated_at = NOW()
            WHERE user_id = ?
        ");
        $stmt->execute([$method, $userId]);

        if ($method === 'PIN') {
            $stmt = $this->pdo->prepare("
                UPDATE users SET pin_last_used = NOW() WHERE user_id = ?
            ");
            $stmt->execute([$userId]);
        }
    }

    private function incrementFailedAttempts(string $userId): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE users SET 
                failed_login_count = failed_login_count + 1,
                updated_at = NOW()
            WHERE user_id = ?
        ");
        $stmt->execute([$userId]);
    }

    private function incrementPINAttempts(string $userId): int
    {
        $stmt = $this->pdo->prepare("
            UPDATE users SET 
                pin_attempts = pin_attempts + 1,
                updated_at = NOW()
            WHERE user_id = ?
        ");
        $stmt->execute([$userId]);
        
        // Возвращаем новое количество попыток
        $stmt = $this->pdo->prepare("SELECT pin_attempts FROM users WHERE user_id = ?");
        $stmt->execute([$userId]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return $result['pin_attempts'] ?? 0;
    }

    private function resetPINAttempts(string $userId): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE users SET 
                pin_attempts = 0,
                pin_last_used = NOW(),
                updated_at = NOW()
            WHERE user_id = ?
        ");
        $stmt->execute([$userId]);
    }
}
