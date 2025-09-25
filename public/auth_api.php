<?php
/**
 * API для традиционной авторизации с PIN и WebAuthn
 * Банковская модель: логин/пароль → PIN → WebAuthn
 */

// Подключаем классы
require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/AnalyticsManager.php';
require_once __DIR__ . '/../src/AuthManager.php';
require_once __DIR__ . '/../src/SecurityHeaders.php';
require_once __DIR__ . '/../src/RateLimiter.php';

use WebAuthn\Database;
use WebAuthn\AnalyticsManager;
use WebAuthn\AuthManager;
use WebAuthn\SecurityHeaders;
use WebAuthn\RateLimiter;

// Устанавливаем security headers
SecurityHeaders::setSecurityHeaders();

// Проверяем HTTPS (в продакшене обязательно)
if (!SecurityHeaders::enforceHTTPS()) {
    exit;
}

// Валидируем origin для защиты от CSRF
if (!SecurityHeaders::validateOrigin()) {
    exit;
}

// CORS заголовки
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

/**
 * Отправка JSON ответа
 */
function respond(array $data, int $httpCode = 200): void
{
    http_response_code($httpCode);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    // Инициализация компонентов
    $db = new Database();
    $analytics = new AnalyticsManager($db);
    $auth = new AuthManager($db, $analytics);
    $rateLimiter = new RateLimiter($db);
    
    // Проверяем заблокированные IP
    if ($rateLimiter->isIPBlocked()) {
        $analytics->recordSecurityIncident(
            'RATE_LIMIT_ABUSE',
            'HIGH',
            null,
            ['blocked_ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'],
            'IP address blocked due to rate limit violations'
        );
        
        respond([
            'success' => false,
            'error' => 'IP_BLOCKED',
            'message' => 'Your IP address has been temporarily blocked'
        ], 429);
    }
    
    // Обработка JSON input
    $jsonInput = file_get_contents('php://input');
    $input = json_decode($jsonInput, true) ?? [];
    $action = $_GET['action'] ?? $_POST['action'] ?? $input['action'] ?? 'unknown';
    
    switch ($action) {
        case 'login':
            // Rate limiting для попыток входа
            if (!$rateLimiter->checkIPLimit('login', 5, 15)) {
                respond([
                    'success' => false,
                    'error' => 'RATE_LIMIT_EXCEEDED',
                    'message' => 'Слишком много попыток входа. Попробуйте позже.'
                ], 429);
            }
            
            $username = $input['username'] ?? '';
            $password = $input['password'] ?? '';
            $rememberMe = $input['remember_me'] ?? false;
            
            if (empty($username) || empty($password)) {
                respond([
                    'success' => false,
                    'error' => 'MISSING_CREDENTIALS',
                    'message' => 'Введите логин и пароль'
                ], 400);
            }
            
            $result = $auth->authenticateUser($username, $password, $rememberMe);
            
            if ($result['success']) {
                // Создаем сессию
                session_start();
                $_SESSION['user_id'] = $result['user_id'];
                $_SESSION['username'] = $result['username'];
                $_SESSION['authenticated'] = true;
                $_SESSION['auth_time'] = time();
                
                if (isset($result['remember_token'])) {
                    setcookie('remember_token', $result['remember_token'], 
                        time() + (30 * 24 * 60 * 60), '/', '', true, true);
                }
            }
            
            respond($result);
            
        case 'setup-pin':
            session_start();
            $userId = null;
            
            // Проверяем сессию или remember token
            if (isset($_SESSION['user_id'])) {
                $userId = $_SESSION['user_id'];
            } else {
                // Попробуем получить пользователя через remember token
                $token = $_COOKIE['remember_token'] ?? $input['remember_token'] ?? '';
                if (!empty($token)) {
                    $tokenResult = $auth->authenticateByRememberToken($token);
                    if ($tokenResult['success']) {
                        $userId = $tokenResult['user_id'];
                        // Создаем временную сессию для setup
                        $_SESSION['user_id'] = $userId;
                        $_SESSION['temp_session'] = true;
                    }
                }
            }
            
            if (!$userId) {
                respond([
                    'success' => false,
                    'error' => 'NOT_AUTHENTICATED',
                    'message' => 'Необходима авторизация'
                ], 401);
            }
            
            $pin = $input['pin'] ?? '';
            $confirmPin = $input['confirm_pin'] ?? '';
            
            if ($pin !== $confirmPin) {
                respond([
                    'success' => false,
                    'error' => 'PIN_MISMATCH',
                    'message' => 'PIN коды не совпадают'
                ], 400);
            }
            
            $result = $auth->setupPIN($userId, $pin);
            respond($result);
            
        case 'login-pin':
            // Rate limiting для PIN попыток
            if (!$rateLimiter->checkIPLimit('pin-login', 3, 10)) {
                respond([
                    'success' => false,
                    'error' => 'RATE_LIMIT_EXCEEDED',
                    'message' => 'Слишком много попыток ввода PIN'
                ], 429);
            }
            
            $userId = $input['user_id'] ?? '';
            $pin = $input['pin'] ?? '';
            
            if (empty($userId) || empty($pin)) {
                respond([
                    'success' => false,
                    'error' => 'MISSING_DATA',
                    'message' => 'Не указан пользователь или PIN'
                ], 400);
            }
            
            $result = $auth->authenticateByPIN($userId, $pin);
            
            if ($result['success']) {
                session_start();
                $_SESSION['user_id'] = $result['user_id'];
                $_SESSION['username'] = $result['username'];
                $_SESSION['authenticated'] = true;
                $_SESSION['auth_time'] = time();
                $_SESSION['auth_method'] = 'PIN';
            }
            
            respond($result);
            
        case 'check-remember':
            $token = $_COOKIE['remember_token'] ?? $input['remember_token'] ?? '';
            
            if (empty($token)) {
                respond([
                    'success' => false,
                    'error' => 'NO_REMEMBER_TOKEN',
                    'message' => 'Токен не найден'
                ]);
            }
            
            $result = $auth->authenticateByRememberToken($token);
            respond($result);
            
        case 'enable-webauthn':
            session_start();
            if (!isset($_SESSION['user_id'])) {
                respond([
                    'success' => false,
                    'error' => 'NOT_AUTHENTICATED',
                    'message' => 'Необходима авторизация'
                ], 401);
            }
            
            $success = $auth->enableWebAuthn($_SESSION['user_id']);
            respond([
                'success' => $success,
                'message' => $success ? 'WebAuthn включен' : 'Ошибка включения WebAuthn'
            ]);
            
        case 'logout':
            session_start();
            $userId = $_SESSION['user_id'] ?? null;
            $resetSecurity = $input['reset_security'] ?? false;
            
            if ($userId) {
                $auth->logout($userId, $resetSecurity);
            }
            
            // Очищаем сессию
            session_destroy();
            
            // Удаляем remember cookie
            setcookie('remember_token', '', time() - 3600, '/', '', true, true);
            
            respond([
                'success' => true,
                'message' => 'Выход выполнен успешно',
                'security_reset' => $resetSecurity
            ]);
            
        case 'status':
            session_start();
            
            $isAuthenticated = isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
            $user = null;
            
            if ($isAuthenticated && isset($_SESSION['user_id'])) {
                $user = $auth->getUserById($_SESSION['user_id']);
                if ($user) {
                    unset($user['password_hash'], $user['pin_hash'], $user['remember_token']);
                }
            }
            
            respond([
                'success' => true,
                'authenticated' => $isAuthenticated,
                'user' => $user,
                'session_info' => [
                    'auth_time' => $_SESSION['auth_time'] ?? null,
                    'auth_method' => $_SESSION['auth_method'] ?? 'PASSWORD'
                ]
            ]);
            
        case 'reset-security':
            session_start();
            if (!isset($_SESSION['user_id'])) {
                respond([
                    'success' => false,
                    'error' => 'NOT_AUTHENTICATED'
                ], 401);
            }
            
            $success = $auth->resetUserSecurity($_SESSION['user_id'], 'Manual security reset');
            
            respond([
                'success' => $success,
                'message' => $success ? 'Безопасность сброшена' : 'Ошибка сброса'
            ]);
            
        case 'webauthn-failure':
            $userId = $input['user_id'] ?? '';
            $errorReason = $input['error_reason'] ?? 'Unknown WebAuthn error';
            
            if (empty($userId)) {
                respond([
                    'success' => false,
                    'error' => 'MISSING_USER_ID',
                    'message' => 'Не указан пользователь'
                ], 400);
            }
            
            $result = $auth->handleWebAuthnFailure($userId, $errorReason);
            
            // Очищаем сессию при ошибке WebAuthn
            session_start();
            session_destroy();
            setcookie('remember_token', '', time() - 3600, '/', '', true, true);
            
            respond($result);
            
        default:
            respond([
                'success' => false,
                'error' => 'UNKNOWN_ACTION',
                'message' => "Неизвестное действие: $action"
            ], 400);
    }
    
} catch (Exception $e) {
    error_log("Auth API Error: " . $e->getMessage());
    
    respond([
        'success' => false,
        'error' => 'INTERNAL_ERROR',
        'message' => 'Внутренняя ошибка сервера',
        'debug' => ($_ENV['APP_ENV'] ?? 'production') === 'development' ? $e->getMessage() : null
    ], 500);
}
