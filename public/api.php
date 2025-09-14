<?php
// Максимально простой API для WebAuthn без библиотек
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Простая функция для JSON ответа
function respond($data, $code = 200) {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// Функция для конвертации base64url в обычный base64
function base64url_decode($data) {
    // Заменяем URL-safe символы обратно
    $data = str_replace(['-', '_'], ['+', '/'], $data);
    
    // Добавляем padding если нужно
    $pad = strlen($data) % 4;
    if ($pad) {
        $data .= str_repeat('=', 4 - $pad);
    }
    
    return base64_decode($data);
}

// Функция для конвертации в base64url
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// Простая функция для базы данных
function getDb() {
    try {
        $pdo = new PDO('mysql:host=db;dbname=webauthn_db;charset=utf8mb4', 'webauthn_user', 'webauthn_pass');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (Exception $e) {
        respond(['success' => false, 'message' => 'Database error: ' . $e->getMessage()], 500);
    }
}

// Проверка устройства
function checkMobile() {
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    return preg_match('/iPhone|iPad|Android/i', $ua);
}

// Проверка авторизации пользователя
function isUserLoggedIn() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['user_id'])) {
        return false;
    }
    
    // Проверяем валидность сессии в БД
    $db = getDb();
    $stmt = $db->prepare("SELECT user_id FROM user_sessions WHERE session_id = ? AND expires_at > NOW()");
    $stmt->execute([session_id()]);
    
    return $stmt->fetch() !== false;
}

// Получение ID текущего пользователя
function getCurrentUserId() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    return $_SESSION['user_id'] ?? null;
}

// Обработка JSON input
$jsonInput = file_get_contents('php://input');
$input = json_decode($jsonInput, true);
$action = $_GET['action'] ?? $_POST['action'] ?? $input['action'] ?? 'unknown';

error_log("DEBUG: Action requested: " . $action);
error_log("DEBUG: Request method: " . ($_SERVER['REQUEST_METHOD'] ?? 'unknown'));
error_log("DEBUG: JSON input: " . ($jsonInput ?: 'empty'));

try {
    switch ($action) {
        case 'device-info':
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $isMobile = checkMobile();
            respond([
                'isMobile' => $isMobile,
                'supportsWebAuthn' => true,
                'hasBiometricSupport' => $isMobile,
                'isCompatible' => $isMobile,
                'userAgent' => $ua,
                'deviceType' => $isMobile ? 'Mobile' : 'Desktop',
                'browserName' => 'Browser'
            ]);
            break;

        case 'register-options':
            error_log("DEBUG: register-options called");
            error_log("DEBUG: User-Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'none'));
            
            if (!checkMobile()) {
                error_log("DEBUG: Mobile check failed");
                respond([
                    'success' => false, 
                    'message' => 'Доступ разрешен только с мобильных устройств', 
                    'debug' => [
                        'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? 'none',
                        'isMobile' => false
                    ]
                ], 403);
            }

            // Проверяем, не авторизован ли уже пользователь
            if (isUserLoggedIn()) {
                error_log("DEBUG: User already logged in");
                respond([
                    'success' => false, 
                    'message' => 'Пользователь уже авторизован. Выйдите из системы для регистрации нового пользователя.',
                    'code' => 'ALREADY_LOGGED_IN'
                ], 400);
            }
            
            error_log("DEBUG: Checks passed, proceeding with registration");

            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            
            // Проверяем существующие учетные данные для исключения из регистрации
            $db = getDb();
            $stmt = $db->prepare("SELECT credential_id FROM user_credentials");
            $stmt->execute();
            $existingCredentials = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            $excludeCredentials = [];
            foreach ($existingCredentials as $credId) {
                $excludeCredentials[] = [
                    'type' => 'public-key',
                    'id' => base64url_encode($credId)
                ];
            }
            
            // Генерируем стабильный userID на основе устройства
            // Получаем дополнительные данные устройства от клиента
            $deviceData = $input['deviceData'] ?? [];
            
            // Используем только стабильные характеристики для идентификации устройства
            $deviceFingerprint = implode('|', [
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                $_SERVER['REMOTE_ADDR'] ?? 'unknown', // Убираем порт - он меняется
                // Добавляем стабильные данные с клиента
                $deviceData['screenWidth'] ?? 'unknown',
                $deviceData['screenHeight'] ?? 'unknown',
                $deviceData['colorDepth'] ?? 'unknown',
                $deviceData['pixelRatio'] ?? 'unknown',
                $deviceData['timezone'] ?? 'unknown',
                $deviceData['platform'] ?? 'unknown',
                $deviceData['hardwareConcurrency'] ?? 'unknown',
                $deviceData['maxTouchPoints'] ?? 'unknown'
            ]);
            
            error_log("DEBUG: Device fingerprint components: " . $deviceFingerprint);
            $deviceId = hash('sha256', $deviceFingerprint);
            error_log("DEBUG: Generated device ID: " . $deviceId);
            error_log("DEBUG: Device hash (first 16 chars): " . substr($deviceId, 0, 16));
            $userId = substr($deviceId, 0, 16); // Используем первые 16 символов хеша
            $userHandle = hex2bin($userId . str_pad('', 16, '0')); // Дополняем до 16 байт
            
            // Проверяем, существует ли уже пользователь с таким device ID
            $stmt = $db->prepare("SELECT id, user_id FROM users WHERE user_handle = ?");
            $stmt->execute([base64url_encode($userHandle)]);
            $existingUser = $stmt->fetch();
            
            if ($existingUser) {
                error_log("DEBUG: Found existing user - ID: " . $existingUser['id'] . ", user_id: " . $existingUser['user_id']);
                respond([
                    'success' => false,
                    'message' => 'Это устройство уже зарегистрировано! Используйте кнопку "Войти" для авторизации.',
                    'code' => 'DEVICE_ALREADY_REGISTERED',
                    'debug' => [
                        'existing_user_id' => $existingUser['user_id'],
                        'current_device_id' => $userId,
                        'fingerprint_hash' => substr($deviceId, 0, 16)
                    ]
                ], 400);
            }
            
            // Дополнительная проверка по credential - возможно есть existing credentials для этого устройства
            $stmt = $db->prepare("SELECT user_id FROM user_credentials");
            $stmt->execute();
            $existingCredentials = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            if (!empty($existingCredentials)) {
                error_log("DEBUG: Found " . count($existingCredentials) . " existing credentials in database");
                foreach ($existingCredentials as $credId) {
                    error_log("DEBUG: Existing credential ID: " . bin2hex($credId));
                }
            }
            
            $challenge = random_bytes(32);
            
            // Сохраняем в сессии (используем base64url)
            $_SESSION['reg_challenge'] = base64url_encode($challenge);
            $_SESSION['reg_user_id'] = $userId;
            $_SESSION['reg_user_handle'] = base64url_encode($userHandle);
            
            respond([
                'success' => true,
                'rp' => [
                    'name' => 'WebAuthn Test',
                    'id' => $_SERVER['HTTP_HOST'] ?? 'localhost'
                ],
                'user' => [
                    'id' => base64url_encode($userHandle),
                    'name' => 'Device-' . substr($userId, 0, 8),
                    'displayName' => 'Device User'
                ],
                'challenge' => base64url_encode($challenge),
                'pubKeyCredParams' => [
                    ['type' => 'public-key', 'alg' => -7],
                    ['type' => 'public-key', 'alg' => -257]
                ],
                'timeout' => 60000,
                'excludeCredentials' => $excludeCredentials,
                'authenticatorSelection' => [
                    'authenticatorAttachment' => 'platform', // Только встроенные (отпечаток/Face ID)
                    'residentKey' => 'preferred',
                    'requireResidentKey' => false,
                    'userVerification' => 'required'
                ],
                'attestation' => 'none',
                'extensions' => (object)[
                    'credProps' => true
                ]
            ]);
            break;

        case 'register-verify':
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            
            if (!isset($_SESSION['reg_challenge']) || !isset($_SESSION['reg_user_id'])) {
                respond(['success' => false, 'message' => 'Invalid session'], 400);
            }

            $input = file_get_contents('php://input');
            $data = json_decode($input, true);
            
            if (!$data || !isset($data['response']['clientDataJSON'])) {
                respond(['success' => false, 'message' => 'Invalid request data'], 400);
            }

            // Простая проверка challenge (используем base64url)
            $clientDataJSON = base64url_decode($data['response']['clientDataJSON']);
            $clientData = json_decode($clientDataJSON, true);
            
            $expectedChallenge = $_SESSION['reg_challenge'];
            $receivedChallenge = $clientData['challenge'];
            
            // Debug информация для диагностики
            error_log("Expected challenge: " . $expectedChallenge);
            error_log("Received challenge: " . $receivedChallenge);
            
            // Проверяем challenge (оба должны быть в base64)
            if ($receivedChallenge !== $expectedChallenge) {
                respond([
                    'success' => false, 
                    'message' => 'Challenge mismatch',
                    'debug' => [
                        'expected' => $expectedChallenge,
                        'received' => $receivedChallenge,
                        'expected_length' => strlen($expectedChallenge),
                        'received_length' => strlen($receivedChallenge)
                    ]
                ], 400);
            }

            // Сохраняем в базу (упрощенно)
            try {
                $db = getDb();
                $userId = $_SESSION['reg_user_id'];
                $userHandle = $_SESSION['reg_user_handle'];
                
                // Создаем пользователя
                $stmt = $db->prepare("INSERT IGNORE INTO users (user_id, user_handle) VALUES (?, ?)");
                $stmt->execute([$userId, $userHandle]);
                
                // Сохраняем credential (используем rawId для поиска)
                $credentialId = $data['id']; // Это строковый ID для отображения
                $credentialRawId = $data['rawId']; // Это бинарные данные в base64url
                
                // Логируем для отладки
                error_log("Saving credential - ID: " . $credentialId . ", RawID: " . $credentialRawId);
                
                $stmt = $db->prepare("INSERT INTO user_credentials (user_id, credential_id, credential_public_key) VALUES (?, ?, ?)");
                $stmt->execute([$userId, $credentialRawId, 'dummy_key']); // Сохраняем rawId для поиска
                
                // Создаем сессию
                $sessionId = bin2hex(random_bytes(16));
                $stmt = $db->prepare("INSERT INTO user_sessions (session_id, user_id, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))");
                $stmt->execute([$sessionId, $userId]);
                
                // Очищаем регистрационную сессию
                unset($_SESSION['reg_challenge'], $_SESSION['reg_user_id'], $_SESSION['reg_user_handle']);
                $_SESSION['session_id'] = $sessionId;
                $_SESSION['user_id'] = $userId;
                
                respond(['success' => true, 'message' => 'Registration successful']);
                
            } catch (Exception $e) {
                respond(['success' => false, 'message' => 'Database error: ' . $e->getMessage()], 500);
            }
            break;

        case 'auth-options':
            error_log("DEBUG: auth-options called");
            error_log("DEBUG: User-Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'none'));
            
            if (!checkMobile()) {
                error_log("DEBUG: Mobile check failed for auth");
                respond([
                    'success' => false, 
                    'message' => 'Доступ разрешен только с мобильных устройств', 
                    'debug' => [
                        'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? 'none',
                        'isMobile' => false
                    ]
                ], 403);
            }

            // Проверяем, не авторизован ли уже пользователь
            if (isUserLoggedIn()) {
                error_log("DEBUG: User already logged in for auth");
                respond([
                    'success' => false, 
                    'message' => 'Пользователь уже авторизован. Для повторной авторизации сначала выйдите из системы.',
                    'code' => 'ALREADY_LOGGED_IN'
                ], 400);
            }
            
            error_log("DEBUG: Auth checks passed, proceeding");

            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $challenge = random_bytes(32);
            $_SESSION['auth_challenge'] = base64url_encode($challenge);
            
            // Получаем все существующие учетные данные
            $db = getDb();
            $stmt = $db->prepare("SELECT credential_id FROM user_credentials");
            $stmt->execute();
            $existingCredentials = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            $allowCredentials = [];
            foreach ($existingCredentials as $credId) {
                $allowCredentials[] = [
                    'type' => 'public-key',
                    'id' => $credId // credential_id уже сохранен в base64url формате
                ];
            }
            
            // Если нет зарегистрированных учетных данных
            if (empty($allowCredentials)) {
                respond([
                    'success' => false,
                    'message' => 'Нет зарегистрированных учетных данных. Сначала зарегистрируйтесь.',
                    'code' => 'NO_CREDENTIALS'
                ], 400);
            }
            
            respond([
                'success' => true,
                'challenge' => base64url_encode($challenge),
                'timeout' => 60000,
                'rpId' => $_SERVER['HTTP_HOST'] ?? 'localhost',
                'allowCredentials' => $allowCredentials,
                'userVerification' => 'required'
            ]);
            break;

        case 'auth-verify':
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            
            if (!isset($_SESSION['auth_challenge'])) {
                respond(['success' => false, 'message' => 'Invalid session'], 400);
            }

            $input = file_get_contents('php://input');
            $data = json_decode($input, true);
            
            if (!$data || !isset($data['response']['clientDataJSON'])) {
                respond(['success' => false, 'message' => 'Invalid request data'], 400);
            }

            // Простая проверка challenge (используем base64url)
            $clientDataJSON = base64url_decode($data['response']['clientDataJSON']);
            $clientData = json_decode($clientDataJSON, true);
            
            $expectedChallenge = $_SESSION['auth_challenge'];
            $receivedChallenge = $clientData['challenge'];
            
            // Debug информация для диагностики
            error_log("Auth Expected challenge: " . $expectedChallenge);
            error_log("Auth Received challenge: " . $receivedChallenge);
            
            // Проверяем challenge (оба должны быть в base64)
            if ($receivedChallenge !== $expectedChallenge) {
                respond([
                    'success' => false, 
                    'message' => 'Challenge mismatch',
                    'debug' => [
                        'expected' => $expectedChallenge,
                        'received' => $receivedChallenge,
                        'expected_length' => strlen($expectedChallenge),
                        'received_length' => strlen($receivedChallenge)
                    ]
                ], 400);
            }

            // Проверяем credential в базе
            try {
                $db = getDb();
                $credentialId = $data['id']; // Строковый ID
                $credentialRawId = $data['rawId']; // Бинарные данные в base64url
                
                // Логируем для отладки
                error_log("Looking for credential - ID: " . $credentialId . ", RawID: " . $credentialRawId);
                
                // Ищем по rawId (как сохраняли при регистрации)
                $stmt = $db->prepare("SELECT user_id, credential_id FROM user_credentials WHERE credential_id = ?");
                $stmt->execute([$credentialRawId]);
                $credential = $stmt->fetch();
                
                // Если не нашли, попробуем найти по обычному ID
                if (!$credential) {
                    error_log("Not found by rawId, trying by ID");
                    $stmt = $db->prepare("SELECT user_id, credential_id FROM user_credentials WHERE credential_id = ?");
                    $stmt->execute([$credentialId]);
                    $credential = $stmt->fetch();
                }
                
                if (!$credential) {
                    // Получаем все credentials для отладки
                    $stmt = $db->prepare("SELECT credential_id, user_id FROM user_credentials ORDER BY created_at DESC LIMIT 5");
                    $stmt->execute();
                    $allCredentials = $stmt->fetchAll();
                    
                    error_log("All credentials in DB: " . json_encode($allCredentials));
                    
                    respond([
                        'success' => false, 
                        'message' => 'Credential not found',
                        'debug' => [
                            'searched_id' => $credentialId,
                            'searched_rawid' => $credentialRawId,
                            'credentials_in_db' => count($allCredentials),
                            'recent_credentials' => $allCredentials
                        ]
                    ], 404);
                }
                
                // Создаем сессию
                $sessionId = bin2hex(random_bytes(16));
                $stmt = $db->prepare("INSERT INTO user_sessions (session_id, user_id, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))");
                $stmt->execute([$sessionId, $credential['user_id']]);
                
                unset($_SESSION['auth_challenge']);
                $_SESSION['session_id'] = $sessionId;
                $_SESSION['user_id'] = $credential['user_id'];
                
                respond(['success' => true, 'message' => 'Authentication successful']);
                
            } catch (Exception $e) {
                respond(['success' => false, 'message' => 'Database error: ' . $e->getMessage()], 500);
            }
            break;

        case 'logout':
            error_log("DEBUG: logout called");
            error_log("DEBUG: Request method: " . $_SERVER['REQUEST_METHOD']);
            error_log("DEBUG: Content-Type: " . ($_SERVER['CONTENT_TYPE'] ?? 'none'));
            
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            if (isset($_SESSION['session_id'])) {
                try {
                    $db = getDb();
                    $stmt = $db->prepare("DELETE FROM user_sessions WHERE session_id = ?");
                    $stmt->execute([$_SESSION['session_id']]);
                } catch (Exception $e) {
                    // Ignore database errors for logout
                }
            }
            session_destroy();
            respond(['success' => true, 'message' => 'Logged out']);
            break;

        case 'status':
            $isLoggedIn = isUserLoggedIn();
            $userId = getCurrentUserId();
            
            respond([
                'success' => true,
                'authenticated' => $isLoggedIn,
                'isLoggedIn' => $isLoggedIn,
                'userId' => $userId,
                'canRegister' => !$isLoggedIn,
                'canLogin' => !$isLoggedIn,
                'message' => $isLoggedIn ? 'Пользователь уже авторизован' : 'Пользователь не авторизован'
            ]);
            break;

        default:
            respond(['success' => false, 'message' => 'Unknown action: ' . $action], 400);
            break;
    }

} catch (Exception $e) {
    respond(['success' => false, 'message' => 'Server error: ' . $e->getMessage()], 500);
}
?>
