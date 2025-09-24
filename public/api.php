<?php
/**
 * Рефакторнутый API для WebAuthn с использованием классов
 */

// Подключаем классы
require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/DeviceHelper.php';
require_once __DIR__ . '/../src/WebAuthnHelper.php';
require_once __DIR__ . '/../src/SessionManager.php';

use WebAuthn\Database;
use WebAuthn\DeviceHelper;
use WebAuthn\WebAuthnHelper;
use WebAuthn\SessionManager;

// Настройка заголовков
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

/**
 * Функция для JSON ответа
 */
function respond(array $data, int $code = 200): void
{
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Функция для логирования ошибок с контекстом
 */
function logError(string $message, array $context = []): void
{
    $logMessage = $message;
    if (!empty($context)) {
        $logMessage .= ' | Context: ' . json_encode($context);
    }
    error_log($logMessage);
}

try {
    // Инициализация компонентов
    $db = new Database();
    $sessionManager = new SessionManager($db);
    
    // Обработка JSON input
    $jsonInput = file_get_contents('php://input');
    $input = json_decode($jsonInput, true) ?? [];
    $action = $_GET['action'] ?? $_POST['action'] ?? $input['action'] ?? 'unknown';
    
    logError("API Request", [
        'action' => $action,
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'none'
    ]);
    
    switch ($action) {
        case 'device-info':
            $deviceInfo = DeviceHelper::getDeviceInfo();
            respond(['success' => true] + $deviceInfo);
            break;
            
        case 'register-options':
            handleRegisterOptions($db, $sessionManager, $input);
            break;
            
        case 'register-verify':
            handleRegisterVerify($db, $sessionManager, $input);
            break;
            
        case 'auth-options':
            handleAuthOptions($db, $sessionManager);
            break;
            
        case 'auth-verify':
            handleAuthVerify($db, $sessionManager, $input);
            break;
            
        case 'logout':
            handleLogout($sessionManager);
            break;
            
        case 'status':
            handleStatus($sessionManager);
            break;
            
        default:
            respond(['success' => false, 'message' => 'Unknown action: ' . $action], 400);
            break;
    }
    
} catch (Exception $e) {
    logError("API Error", ['message' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
    respond(['success' => false, 'message' => 'Server error: ' . $e->getMessage()], 500);
}

/**
 * Обработка запроса опций регистрации
 */
function handleRegisterOptions(Database $db, SessionManager $sessionManager, array $input): void
{
    if (!DeviceHelper::isMobileDevice()) {
        respond([
            'success' => false, 
            'message' => 'Доступ разрешен только с мобильных устройств',
            'debug' => [
                'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? 'none',
                'isMobile' => false
            ]
        ], 403);
    }
    
    if ($sessionManager->isUserLoggedIn()) {
        respond([
            'success' => false, 
            'message' => 'Пользователь уже авторизован. Выйдите из системы для регистрации нового пользователя.',
            'code' => 'ALREADY_LOGGED_IN'
        ], 400);
    }
    
    // Получаем существующие учетные данные для исключения
    $pdo = $db->getPdo();
    $stmt = $pdo->prepare("SELECT credential_id FROM user_credentials");
    $stmt->execute();
    $existingCredentials = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    $excludeCredentials = [];
    foreach ($existingCredentials as $credId) {
        $excludeCredentials[] = [
            'type' => 'public-key',
            'id' => WebAuthnHelper::base64urlEncode($credId)
        ];
    }
    
    // Генерируем пользователя на основе устройства
    $deviceData = $input['deviceData'] ?? [];
    $deviceId = DeviceHelper::generateDeviceFingerprint($deviceData);
    $userData = WebAuthnHelper::generateUserFromDevice($deviceId);
    
    logError("Device Registration", [
        'device_id' => substr($deviceId, 0, 16),
        'user_id' => $userData['userId']
    ]);
    
    // Проверяем, существует ли уже пользователь с таким device ID
    $stmt = $pdo->prepare("SELECT id, user_id FROM users WHERE user_handle = ?");
    $stmt->execute([WebAuthnHelper::base64urlEncode($userData['userHandle'])]);
    $existingUser = $stmt->fetch();
    
    if ($existingUser) {
        respond([
            'success' => true,
            'alreadyRegistered' => true,
            'message' => 'Это устройство уже зарегистрировано! Используйте кнопку "Войти" для авторизации.',
            'code' => 'DEVICE_ALREADY_REGISTERED',
            'action' => 'LOGIN_REQUIRED',
            'debug' => [
                'existing_user_id' => $existingUser['user_id'],
                'current_device_id' => $userData['userId']
            ]
        ]);
    }
    
    // Создаем параметры регистрации
    $options = WebAuthnHelper::createRegistrationOptions(
        $userData['userId'],
        $userData['userHandle'],
        $excludeCredentials
    );
    
    // Сохраняем данные в сессии
    $challenge = WebAuthnHelper::base64urlDecode($options['challenge']);
    $sessionManager->saveRegistrationData(
        $options['challenge'],
        $userData['userId'],
        WebAuthnHelper::base64urlEncode($userData['userHandle'])
    );
    
    respond(['success' => true] + $options);
}

/**
 * Обработка верификации регистрации
 */
function handleRegisterVerify(Database $db, SessionManager $sessionManager, array $input): void
{
    $regData = $sessionManager->getRegistrationData();
    if (!$regData) {
        respond(['success' => false, 'message' => 'Invalid session'], 400);
    }
    
    if (!isset($input['response']['clientDataJSON'])) {
        respond(['success' => false, 'message' => 'Invalid request data'], 400);
    }
    
    // Проверяем challenge
    $expectedChallenge = $regData['challenge'];
    if (!WebAuthnHelper::verifyChallenge($input['response']['clientDataJSON'], $expectedChallenge)) {
        respond([
            'success' => false, 
            'message' => 'Challenge mismatch'
        ], 400);
    }
    
    // Сохраняем пользователя и учетные данные
    $userId = $regData['userId'];
    $userHandle = $regData['userHandle'];
    
    // Создаем пользователя
    if (!$db->createUser($userId, $userHandle)) {
        throw new Exception('Failed to create user');
    }
    
    // Сохраняем credential
    $credentialId = $input['rawId']; // Бинарные данные в base64url
    if (!$db->saveCredential($userId, $credentialId, 'dummy_key')) {
        throw new Exception('Failed to save credential');
    }
    
    // Создаем сессию
    $sessionManager->createSession($userId);
    $sessionManager->clearRegistrationData();
    
    respond(['success' => true, 'message' => 'Registration successful']);
}

/**
 * Обработка запроса опций аутентификации
 */
function handleAuthOptions(Database $db, SessionManager $sessionManager): void
{
    if (!DeviceHelper::isMobileDevice()) {
        respond([
            'success' => false, 
            'message' => 'Доступ разрешен только с мобильных устройств'
        ], 403);
    }
    
    if ($sessionManager->isUserLoggedIn()) {
        respond([
            'success' => false, 
            'message' => 'Пользователь уже авторизован. Для повторной авторизации сначала выйдите из системы.',
            'code' => 'ALREADY_LOGGED_IN'
        ], 400);
    }
    
    // Получаем все существующие учетные данные
    $pdo = $db->getPdo();
    $stmt = $pdo->prepare("SELECT credential_id FROM user_credentials");
    $stmt->execute();
    $existingCredentials = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    if (empty($existingCredentials)) {
        respond([
            'success' => false,
            'message' => 'Нет зарегистрированных учетных данных. Сначала зарегистрируйтесь.',
            'code' => 'NO_CREDENTIALS'
        ], 400);
    }
    
    $allowCredentials = [];
    foreach ($existingCredentials as $credId) {
        $allowCredentials[] = [
            'type' => 'public-key',
            'id' => $credId // credential_id уже сохранен в base64url формате
        ];
    }
    
    $options = WebAuthnHelper::createAuthenticationOptions($allowCredentials);
    
    // Сохраняем challenge в сессии
    $sessionManager->saveAuthChallenge($options['challenge']);
    
    respond(['success' => true] + $options);
}

/**
 * Обработка верификации аутентификации
 */
function handleAuthVerify(Database $db, SessionManager $sessionManager, array $input): void
{
    $expectedChallenge = $sessionManager->getAuthChallenge();
    if (!$expectedChallenge) {
        respond(['success' => false, 'message' => 'Invalid session'], 400);
    }
    
    if (!isset($input['response']['clientDataJSON'])) {
        respond(['success' => false, 'message' => 'Invalid request data'], 400);
    }
    
    // Проверяем challenge
    if (!WebAuthnHelper::verifyChallenge($input['response']['clientDataJSON'], $expectedChallenge)) {
        respond(['success' => false, 'message' => 'Challenge mismatch'], 400);
    }
    
    // Проверяем credential в базе
    $credentialRawId = $input['rawId']; // Бинарные данные в base64url
    
    $pdo = $db->getPdo();
    $stmt = $pdo->prepare("SELECT user_id, credential_id FROM user_credentials WHERE credential_id = ?");
    $stmt->execute([$credentialRawId]);
    $credential = $stmt->fetch();
    
    if (!$credential) {
        respond([
            'success' => false, 
            'message' => 'Credential not found'
        ], 404);
    }
    
    // Создаем сессию
    $sessionManager->createSession($credential['user_id']);
    $sessionManager->clearAuthChallenge();
    
    respond(['success' => true, 'message' => 'Authentication successful']);
}

/**
 * Обработка выхода из системы
 */
function handleLogout(SessionManager $sessionManager): void
{
    $sessionManager->destroySession();
    respond(['success' => true, 'message' => 'Logged out']);
}

/**
 * Обработка запроса статуса
 */
function handleStatus(SessionManager $sessionManager): void
{
    $isLoggedIn = $sessionManager->isUserLoggedIn();
    $userId = $sessionManager->getCurrentUserId();
    
    respond([
        'success' => true,
        'authenticated' => $isLoggedIn,
        'isLoggedIn' => $isLoggedIn,
        'userId' => $userId,
        'canRegister' => !$isLoggedIn,
        'canLogin' => !$isLoggedIn,
        'message' => $isLoggedIn ? 'Пользователь уже авторизован' : 'Пользователь не авторизован'
    ]);
}
