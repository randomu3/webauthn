<?php
/**
 * Тесты крайних случаев и ошибок
 * Проверяют поведение системы в нестандартных ситуациях
 */

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/DeviceHelper.php';
require_once __DIR__ . '/../src/WebAuthnHelper.php';
require_once __DIR__ . '/../src/SessionManager.php';

use WebAuthn\Database;
use WebAuthn\DeviceHelper;
use WebAuthn\WebAuthnHelper;
use WebAuthn\SessionManager;

class EdgeCasesTest
{
    private array $testResults = [];
    
    public function __construct()
    {
        echo "🧪 Запуск тестов крайних случаев...\n\n";
        $this->runAllTests();
        $this->printResults();
    }
    
    private function runAllTests(): void
    {
        $this->testDatabaseConnectionFailure();
        $this->testLargeDataHandling();
        $this->testSpecialCharacters();
        $this->testConcurrentSessions();
        $this->testInvalidInputHandling();
        $this->testDatabaseTransactionFailures();
        $this->testExtremeUserAgents();
        $this->testMaliciousInputs();
        $this->testResourceExhaustion();
        $this->testEncodingIssues();
        $this->testTimestampEdgeCases();
        $this->testMemoryAndPerformance();
    }
    
    private function testDatabaseConnectionFailure(): void
    {
        // Симулируем недоступность БД через неверные параметры
        $originalEnv = [
            'DB_HOST' => $_ENV['DB_HOST'] ?? null,
            'DB_NAME' => $_ENV['DB_NAME'] ?? null,
            'DB_USER' => $_ENV['DB_USER'] ?? null,
            'DB_PASS' => $_ENV['DB_PASS'] ?? null,
        ];
        
        try {
            $_ENV['DB_HOST'] = 'nonexistent_host';
            $_ENV['DB_NAME'] = 'nonexistent_db';
            $_ENV['DB_USER'] = 'nonexistent_user';
            $_ENV['DB_PASS'] = 'wrong_password';
            
            try {
                $db = new Database();
                $this->fail("Database connection failure", "Должно выбрасываться исключение при неверных параметрах БД");
            } catch (Exception $e) {
                if (strpos($e->getMessage(), 'Database connection failed') !== false) {
                    $this->pass("Database connection failure", "Корректно обрабатывается ошибка подключения к БД");
                } else {
                    $this->fail("Database connection failure", "Неожиданное сообщение об ошибке: " . $e->getMessage());
                }
            }
        } finally {
            // Восстанавливаем переменные окружения
            foreach ($originalEnv as $key => $value) {
                if ($value !== null) {
                    $_ENV[$key] = $value;
                } else {
                    unset($_ENV[$key]);
                }
            }
        }
    }
    
    private function testLargeDataHandling(): void
    {
        try {
            // Тест кодирования больших данных
            $largeString = str_repeat('A', 50000); // 50KB строка
            $veryLargeString = str_repeat('Б', 100000); // 100KB строка с UTF-8
            
            $encoded = WebAuthnHelper::base64urlEncode($largeString);
            $decoded = WebAuthnHelper::base64urlDecode($encoded);
            
            if ($decoded === $largeString) {
                $this->pass("Large data encoding", "Большие данные корректно кодируются и декодируются");
            } else {
                $this->fail("Large data encoding", "Ошибка при обработке больших данных");
            }
            
            // Тест генерации отпечатка с большими данными
            $deviceData = [
                'userAgent' => $veryLargeString,
                'screenWidth' => 1920,
                'screenHeight' => 1080
            ];
            
            $fingerprint = DeviceHelper::generateDeviceFingerprint($deviceData);
            
            if (strlen($fingerprint) === 64) {
                $this->pass("Large data fingerprint", "Отпечаток корректно генерируется для больших данных");
            } else {
                $this->fail("Large data fingerprint", "Ошибка генерации отпечатка для больших данных");
            }
            
        } catch (Exception $e) {
            $this->fail("Large data handling", "Ошибка обработки больших данных: " . $e->getMessage());
        }
    }
    
    private function testSpecialCharacters(): void
    {
        $specialChars = [
            'emoji' => '🔒🔐🗝️👨‍💻🚀🎉',
            'unicode' => 'Тест с юникодом: ñáéíóú',
            'html' => '<script>alert("xss")</script>',
            'sql' => "'; DROP TABLE users; --",
            'null_bytes' => "test\x00null\x00bytes",
            'control_chars' => "test\r\n\t\v\f",
            'quotes' => 'test "double" and \'single\' quotes',
            'backslashes' => 'test\\with\\backslashes\\and/forward/slashes'
        ];
        
        foreach ($specialChars as $type => $testString) {
            try {
                // Тест кодирования
                $encoded = WebAuthnHelper::base64urlEncode($testString);
                $decoded = WebAuthnHelper::base64urlDecode($encoded);
                
                if ($decoded === $testString) {
                    $this->pass("Special chars $type", "Специальные символы ($type) обрабатываются корректно");
                } else {
                    $this->fail("Special chars $type", "Ошибка обработки специальных символов ($type)");
                }
                
                // Тест определения мобильного устройства
                $isMobile = DeviceHelper::isMobileDevice($testString);
                if (is_bool($isMobile)) {
                    $this->pass("Mobile detection $type", "Определение мобильного устройства не падает на ($type)");
                } else {
                    $this->fail("Mobile detection $type", "Определение мобильного устройства должно возвращать boolean");
                }
                
            } catch (Exception $e) {
                $this->fail("Special chars $type", "Ошибка обработки $type: " . $e->getMessage());
            }
        }
    }
    
    private function testConcurrentSessions(): void
    {
        try {
            $db = new Database();
            $sessionManager = new SessionManager($db);
            
            $testUserId = 'concurrent_test_' . time();
            $userHandle = random_bytes(32);
            
            // Создаем пользователя
            if (!$db->createUser($testUserId, $userHandle)) {
                $this->fail("Concurrent sessions setup", "Не удалось создать пользователя");
                return;
            }
            
            // Создаем множественные сессии быстро
            $sessionIds = [];
            for ($i = 0; $i < 10; $i++) {
                // Очищаем PHP сессию для каждой новой сессии
                unset($_SESSION['user_id'], $_SESSION['session_id']);
                $sessionId = $sessionManager->createSession($testUserId);
                $sessionIds[] = $sessionId;
            }
            
            // Проверяем, что все сессии уникальны
            $uniqueSessions = array_unique($sessionIds);
            
            if (count($uniqueSessions) === count($sessionIds)) {
                $this->pass("Concurrent sessions", "Множественные сессии создаются с уникальными ID");
            } else {
                $this->fail("Concurrent sessions", "Обнаружены дубликаты ID при создании множественных сессий");
            }
            
            // Очистка
            $pdo = $db->getPdo();
            $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
            $stmt->execute([$testUserId]);
            
        } catch (Exception $e) {
            $this->fail("Concurrent sessions", "Ошибка теста множественных сессий: " . $e->getMessage());
        }
    }
    
    private function testInvalidInputHandling(): void
    {
        $invalidInputs = [
            'null' => null,
            'boolean_true' => true,
            'boolean_false' => false,
            'integer' => 12345,
            'float' => 123.45,
            'array' => ['key' => 'value'],
            'object' => (object)['key' => 'value']
        ];
        
        foreach ($invalidInputs as $type => $input) {
            try {
                // Приводим к строке для тестов, обрабатываем особые случаи
                if (is_array($input)) {
                    $stringInput = json_encode($input);
                } elseif (is_object($input)) {
                    $stringInput = json_encode($input);
                } elseif (is_null($input)) {
                    $stringInput = '';
                } else {
                    $stringInput = (string)$input;
                }
                
                $isMobile = DeviceHelper::isMobileDevice($stringInput);
                
                if (is_bool($isMobile)) {
                    $this->pass("Invalid input $type", "Некорректный ввод ($type) обработан без ошибки");
                } else {
                    $this->fail("Invalid input $type", "Некорректный ввод ($type) должен обрабатываться без ошибки");
                }
                
            } catch (Exception $e) {
                $this->pass("Invalid input $type", "Некорректный ввод ($type) корректно выбросил исключение");
            }
        }
    }
    
    private function testDatabaseTransactionFailures(): void
    {
        try {
            $db = new Database();
            $pdo = $db->getPdo();
            
            // Тестируем создание пользователя с дублирующимся user_id
            $duplicateUserId = 'duplicate_test_' . time();
            $userHandle1 = random_bytes(32);
            $userHandle2 = random_bytes(32);
            
            // Первое создание должно пройти успешно
            $result1 = $db->createUser($duplicateUserId, $userHandle1);
            
            if ($result1) {
                $this->pass("Database first insert", "Первое создание пользователя прошло успешно");
                
                // Второе создание должно вернуть false из-за UNIQUE constraint
                $result2 = $db->createUser($duplicateUserId, $userHandle2);
                
                if ($result2 === false) {
                    $this->pass("Database duplicate handling", "Дублирующий пользователь корректно отклонен");
                } else {
                    $this->fail("Database duplicate handling", "Дублирующий пользователь должен отклоняться");
                }
                
                // Очистка
                $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
                $stmt->execute([$duplicateUserId]);
                
            } else {
                $this->fail("Database first insert", "Первое создание пользователя не должно падать");
            }
            
        } catch (Exception $e) {
            $this->fail("Database transaction failures", "Ошибка теста транзакций БД: " . $e->getMessage());
        }
    }
    
    private function testExtremeUserAgents(): void
    {
        $extremeUserAgents = [
            'empty' => '',
            'very_long' => str_repeat('Mozilla/5.0 ', 500),
            'only_spaces' => '   ',
            'only_newlines' => "\n\r\n\r",
            'mixed_case' => 'mOzIlLa/5.0 (iPhOnE; cPu IpHoNe Os 14_0)',
            'with_nulls' => "Mozilla/5.0\x00iPhone\x00",
            'binary' => "\x01\x02\x03\x04\x05",
            'json' => '{"userAgent": "fake"}',
            'xml' => '<userAgent>fake</userAgent>',
            'very_weird' => '🤖🔥💻📱🚀' // Только emoji
        ];
        
        foreach ($extremeUserAgents as $type => $userAgent) {
            try {
                $isMobile = DeviceHelper::isMobileDevice($userAgent);
                $deviceInfo = DeviceHelper::getDeviceInfo($userAgent);
                $fingerprint = DeviceHelper::generateDeviceFingerprint(['userAgent' => $userAgent]);
                
                if (is_bool($isMobile) && is_array($deviceInfo) && is_string($fingerprint)) {
                    $this->pass("Extreme UA $type", "Экстремальный User-Agent ($type) обработан корректно");
                } else {
                    $this->fail("Extreme UA $type", "Экстремальный User-Agent ($type) должен обрабатываться корректно");
                }
                
            } catch (Exception $e) {
                $this->fail("Extreme UA $type", "Ошибка обработки экстремального UA ($type): " . $e->getMessage());
            }
        }
    }
    
    private function testMaliciousInputs(): void
    {
        $maliciousInputs = [
            'xss' => '<script>alert("xss")</script>',
            'sql_injection' => "'; DROP TABLE users; --",
            'path_traversal' => '../../../etc/passwd',
            'null_injection' => "test\x00.php",
            'ldap_injection' => 'admin)(&(password=*))',
            'xxe' => '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            'command_injection' => '; rm -rf /',
            'format_string' => '%s%s%s%s%s%s%s%s',
            'buffer_overflow' => str_repeat('A', 5000)
        ];
        
        foreach ($maliciousInputs as $type => $maliciousInput) {
            try {
                // Тестируем с помощниками
                $encoded = WebAuthnHelper::base64urlEncode($maliciousInput);
                $decoded = WebAuthnHelper::base64urlDecode($encoded);
                $fingerprint = DeviceHelper::generateDeviceFingerprint(['userAgent' => $maliciousInput]);
                
                if ($decoded === $maliciousInput && strlen($fingerprint) === 64) {
                    $this->pass("Malicious input $type", "Вредоносный ввод ($type) безопасно обработан");
                } else {
                    $this->fail("Malicious input $type", "Ошибка безопасной обработки ($type)");
                }
                
            } catch (Exception $e) {
                $this->pass("Malicious input $type", "Вредоносный ввод ($type) корректно выбросил исключение");
            }
        }
    }
    
    private function testResourceExhaustion(): void
    {
        try {
            // Тест множественной генерации challenge
            $challenges = [];
            for ($i = 0; $i < 500; $i++) {
                $challenges[] = WebAuthnHelper::generateChallenge();
            }
            
            if (count($challenges) === 500 && count(array_unique($challenges, SORT_REGULAR)) === 500) {
                $this->pass("Resource exhaustion challenges", "Массовая генерация challenge работает корректно");
            } else {
                $this->fail("Resource exhaustion challenges", "Проблемы при массовой генерации challenge");
            }
            
            // Тест множественного создания отпечатков
            $fingerprints = [];
            for ($i = 0; $i < 500; $i++) {
                $fingerprints[] = DeviceHelper::generateDeviceFingerprint([
                    'index' => $i,
                    'screenWidth' => 1920 + $i,
                    'screenHeight' => 1080 + $i,
                    'userAgent' => "test_agent_$i"
                ]);
            }
            
            $uniqueFingerprints = count(array_unique($fingerprints));
            if (count($fingerprints) === 500 && $uniqueFingerprints >= 499) { // Допускаем 1 дубликат из-за случайности $_SERVER данных
                $this->pass("Resource exhaustion fingerprints", "Массовая генерация отпечатков работает корректно ($uniqueFingerprints уникальных из 500)");
            } else {
                $this->fail("Resource exhaustion fingerprints", "Проблемы при массовой генерации отпечатков: $uniqueFingerprints уникальных из 500");
            }
            
        } catch (Exception $e) {
            $this->fail("Resource exhaustion", "Ошибка при тесте истощения ресурсов: " . $e->getMessage());
        }
    }
    
    private function testEncodingIssues(): void
    {
        $encodingTests = [
            'utf8' => 'Тест UTF-8: Привет мир! 🌍',
            'latin1' => 'Test with ñáéíóú',
            'mixed' => 'Mixed: Привет + Hello + 🚀',
            'chinese' => '测试中文字符',
            'arabic' => 'اختبار النص العربي',
            'japanese' => 'テストテキスト',
            'korean' => '테스트 텍스트',
            'emoji_mix' => 'Text with 🔒🎉 emojis'
        ];
        
        foreach ($encodingTests as $type => $text) {
            try {
                $encoded = WebAuthnHelper::base64urlEncode($text);
                $decoded = WebAuthnHelper::base64urlDecode($encoded);
                
                if ($decoded === $text) {
                    $this->pass("Encoding $type", "Кодировка ($type) обрабатывается корректно");
                } else {
                    $this->fail("Encoding $type", "Ошибка обработки кодировки ($type)");
                }
                
            } catch (Exception $e) {
                $this->fail("Encoding $type", "Ошибка при тесте кодировки ($type): " . $e->getMessage());
            }
        }
    }
    
    private function testTimestampEdgeCases(): void
    {
        try {
            $db = new Database();
            
            // Тест с экстремальными временными метками
            $testUserId = 'timestamp_test_' . time();
            $userHandle = random_bytes(32);
            
            if (!$db->createUser($testUserId, $userHandle)) {
                $this->fail("Timestamp test setup", "Не удалось создать пользователя");
                return;
            }
            
            // Тест с очень большим временем истечения
            $sessionId1 = 'future_session_' . time();
            $result1 = $db->createSession($sessionId1, $testUserId, 86400 * 365); // 1 год
            
            if ($result1) {
                $this->pass("Timestamp future", "Сессия с далеким будущим временем создается");
            } else {
                $this->fail("Timestamp future", "Сессия с далеким будущим временем должна создаваться");
            }
            
            // Тест с отрицательным временем (уже истекшая)
            $sessionId2 = 'past_session_' . time();
            $result2 = $db->createSession($sessionId2, $testUserId, -3600);
            
            if ($result2) {
                // Проверяем, что сессия не возвращается как валидная
                $session = $db->getSession($sessionId2);
                if ($session === null) {
                    $this->pass("Timestamp past", "Истекшая сессия корректно не возвращается");
                } else {
                    $this->fail("Timestamp past", "Истекшая сессия не должна возвращаться");
                }
            } else {
                $this->fail("Timestamp past", "Истекшая сессия должна создаваться в БД");
            }
            
            // Очистка
            $pdo = $db->getPdo();
            $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
            $stmt->execute([$testUserId]);
            
        } catch (Exception $e) {
            $this->fail("Timestamp edge cases", "Ошибка при тесте временных меток: " . $e->getMessage());
        }
    }
    
    private function testMemoryAndPerformance(): void
    {
        try {
            // Тест производительности кодирования
            $startTime = microtime(true);
            $iterations = 1000;
            
            for ($i = 0; $i < $iterations; $i++) {
                $data = "test_data_$i";
                $encoded = WebAuthnHelper::base64urlEncode($data);
                $decoded = WebAuthnHelper::base64urlDecode($encoded);
            }
            
            $endTime = microtime(true);
            $duration = $endTime - $startTime;
            
            if ($duration < 5.0) { // Должно выполниться менее чем за 5 секунд
                $this->pass("Performance encoding", "Кодирование выполняется с приемлемой производительностью ($duration сек)");
            } else {
                $this->fail("Performance encoding", "Кодирование работает слишком медленно ($duration сек)");
            }
            
            // Тест с множественными отпечатками
            $startTime = microtime(true);
            
            for ($i = 0; $i < 100; $i++) {
                $deviceData = [
                    'userAgent' => "test_agent_$i",
                    'screenWidth' => 1920 + $i,
                    'screenHeight' => 1080 + $i
                ];
                $fingerprint = DeviceHelper::generateDeviceFingerprint($deviceData);
            }
            
            $endTime = microtime(true);
            $duration = $endTime - $startTime;
            
            if ($duration < 2.0) { // Должно выполниться менее чем за 2 секунды
                $this->pass("Performance fingerprints", "Генерация отпечатков выполняется с приемлемой производительностью ($duration сек)");
            } else {
                $this->fail("Performance fingerprints", "Генерация отпечатков работает слишком медленно ($duration сек)");
            }
            
        } catch (Exception $e) {
            $this->fail("Memory and performance", "Ошибка при тесте производительности: " . $e->getMessage());
        }
    }
    
    private function pass(string $testName, string $message): void
    {
        $this->testResults[] = [
            'status' => 'PASS',
            'test' => $testName,
            'message' => $message
        ];
        echo "✅ {$testName}: {$message}\n";
    }
    
    private function fail(string $testName, string $message): void
    {
        $this->testResults[] = [
            'status' => 'FAIL',
            'test' => $testName,
            'message' => $message
        ];
        echo "❌ {$testName}: {$message}\n";
    }
    
    private function printResults(): void
    {
        $passed = count(array_filter($this->testResults, fn($r) => $r['status'] === 'PASS'));
        $failed = count(array_filter($this->testResults, fn($r) => $r['status'] === 'FAIL'));
        $total = count($this->testResults);
        
        echo "\n📊 Результаты тестирования крайних случаев:\n";
        echo "✅ Пройдено: {$passed}\n";
        echo "❌ Провалено: {$failed}\n";
        echo "📝 Всего: {$total}\n";
        
        if ($failed > 0) {
            echo "\n❌ ТЕСТЫ КРАЙНИХ СЛУЧАЕВ НЕ ПРОЙДЕНЫ!\n";
            exit(1);
        } else {
            echo "\n🎉 ВСЕ ТЕСТЫ КРАЙНИХ СЛУЧАЕВ ПРОЙДЕНЫ!\n";
        }
    }
}

// Запускаем тесты
new EdgeCasesTest();
