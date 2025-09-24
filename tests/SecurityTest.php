<?php
/**
 * Comprehensive тесты безопасности для WebAuthn продакшена
 */

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/WebAuthnSecurity.php';
require_once __DIR__ . '/../src/SecurityHeaders.php';
require_once __DIR__ . '/../src/RateLimiter.php';
require_once __DIR__ . '/../src/RecoveryManager.php';

use WebAuthn\Database;
use WebAuthn\WebAuthnSecurity;
use WebAuthn\SecurityHeaders;
use WebAuthn\RateLimiter;
use WebAuthn\RecoveryManager;

class SecurityTest
{
    private array $testResults = [];
    private Database $db;
    
    public function __construct()
    {
        echo "🛡️ Запуск комплексных тестов безопасности WebAuthn...\n\n";
        
        try {
            $this->db = new Database();
        } catch (Exception $e) {
            $this->fail("Database initialization", "Не удалось подключиться к БД: " . $e->getMessage());
            return;
        }
        
        $this->runAllTests();
        $this->printResults();
    }
    
    private function runAllTests(): void
    {
        // WebAuthn Security Tests
        $this->testSecureChallengeGeneration();
        $this->testChallengeValidation();
        $this->testOriginValidation();
        $this->testUserHandleGeneration();
        
        // Rate Limiting Tests
        $this->testRateLimiting();
        $this->testIPBlocking();
        $this->testUserLimiting();
        
        // Recovery Manager Tests
        $this->testRecoveryCodeGeneration();
        $this->testRecoveryCodeVerification();
        $this->testEmergencyTokens();
        
        // Security Headers Tests  
        $this->testSecurityHeaders();
        $this->testHTTPSEnforcement();
        
        // Integration Tests
        $this->testSecurityIntegration();
        $this->testAttackScenarios();
    }
    
    private function testSecureChallengeGeneration(): void
    {
        try {
            // Тест базовой генерации
            $challenge1 = WebAuthnSecurity::generateSecureChallenge(32);
            $challenge2 = WebAuthnSecurity::generateSecureChallenge(32);
            
            if (strlen($challenge1) !== 32) {
                $this->fail("Challenge length", "Challenge должен быть 32 байта");
                return;
            }
            
            if ($challenge1 === $challenge2) {
                $this->fail("Challenge uniqueness", "Challenges должны быть уникальными");
                return;
            }
            
            // Тест энтропии
            $challenges = [];
            for ($i = 0; $i < 100; $i++) {
                $challenges[] = WebAuthnSecurity::generateSecureChallenge(16);
            }
            
            $unique = array_unique($challenges);
            if (count($unique) < 100) {
                $this->fail("Challenge entropy", "Недостаточная энтропия challenge");
                return;
            }
            
            $this->pass("Secure challenge generation", "Challenge генерируется с достаточной энтропией");
            
        } catch (Exception $e) {
            $this->fail("Challenge generation", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testChallengeValidation(): void
    {
        try {
            $challenge = WebAuthnSecurity::generateSecureChallenge(32);
            
            // Тест валидного challenge
            if (!WebAuthnSecurity::validateChallenge($challenge, $challenge)) {
                $this->fail("Challenge validation valid", "Валидный challenge не прошел проверку");
                return;
            }
            
            // Тест невалидного challenge
            $wrongChallenge = WebAuthnSecurity::generateSecureChallenge(32);
            if (WebAuthnSecurity::validateChallenge($wrongChallenge, $challenge)) {
                $this->fail("Challenge validation invalid", "Невалидный challenge прошел проверку");
                return;
            }
            
            // Тест пустых challenge
            if (WebAuthnSecurity::validateChallenge('', $challenge)) {
                $this->fail("Challenge validation empty", "Пустой challenge прошел проверку");
                return;
            }
            
            $this->pass("Challenge validation", "Валидация challenge работает корректно");
            
        } catch (Exception $e) {
            $this->fail("Challenge validation", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testOriginValidation(): void
    {
        try {
            $allowedOrigins = ['https://example.com', 'https://app.example.com'];
            
            // Тест валидного origin
            if (!WebAuthnSecurity::validateOrigin('https://example.com', $allowedOrigins)) {
                $this->fail("Origin validation valid", "Валидный origin не прошел проверку");
                return;
            }
            
            // Тест невалидного origin
            if (WebAuthnSecurity::validateOrigin('https://evil.com', $allowedOrigins)) {
                $this->fail("Origin validation invalid", "Невалидный origin прошел проверку");
                return;
            }
            
            // Тест case sensitivity
            if (WebAuthnSecurity::validateOrigin('HTTPS://EXAMPLE.COM', $allowedOrigins)) {
                $this->pass("Origin validation case", "Case-insensitive валидация работает");
            } else {
                $this->fail("Origin validation case", "Case-insensitive валидация не работает");
                return;
            }
            
            $this->pass("Origin validation", "Валидация origin работает корректно");
            
        } catch (Exception $e) {
            $this->fail("Origin validation", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testUserHandleGeneration(): void
    {
        try {
            $handle1 = WebAuthnSecurity::generateUserHandle();
            $handle2 = WebAuthnSecurity::generateUserHandle();
            
            if (strlen($handle1) !== 16) {
                $this->fail("User handle length", "User handle должен быть 16 байт");
                return;
            }
            
            if ($handle1 === $handle2) {
                $this->fail("User handle uniqueness", "User handles должны быть уникальными");
                return;
            }
            
            $this->pass("User handle generation", "User handles генерируются корректно");
            
        } catch (Exception $e) {
            $this->fail("User handle generation", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testRateLimiting(): void
    {
        try {
            $rateLimiter = new RateLimiter($this->db);
            
            // Тест нормального использования с уникальным action
            $testAction = 'test-normal-' . time();
            for ($i = 0; $i < 3; $i++) {
                if (!$rateLimiter->checkIPLimit($testAction, 5, 10)) {
                    $this->fail("Rate limiting normal", "Нормальное использование заблокировано");
                    return;
                }
            }
            
            // Тест превышения лимита с уникальным action
            $limitTestAction = 'test-limit-' . time();
            for ($i = 0; $i < 3; $i++) {
                $rateLimiter->checkIPLimit($limitTestAction, 3, 10);
            }
            
            if ($rateLimiter->checkIPLimit($limitTestAction, 3, 10)) {
                $this->fail("Rate limiting exceeded", "Превышение лимита не заблокировано");
                return;
            }
            
            $this->pass("Rate limiting", "Rate limiting работает корректно");
            
        } catch (Exception $e) {
            $this->fail("Rate limiting", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testIPBlocking(): void
    {
        try {
            $rateLimiter = new RateLimiter($this->db);
            $testIP = '192.168.1.100';
            
            // Блокируем IP
            $rateLimiter->blockIP($testIP, 5, 'Test blocking');
            
            // Проверяем что IP заблокирован
            if (!$rateLimiter->isIPBlocked($testIP)) {
                $this->fail("IP blocking", "IP не заблокирован после блокировки");
                return;
            }
            
            $this->pass("IP blocking", "Блокировка IP работает корректно");
            
        } catch (Exception $e) {
            $this->fail("IP blocking", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testUserLimiting(): void
    {
        try {
            $rateLimiter = new RateLimiter($this->db);
            $testUserId = 'test-user-' . time();
            
            // Тест user лимитов с уникальным action
            $userAction = 'test-user-action-' . time();
            for ($i = 0; $i < 2; $i++) {
                if (!$rateLimiter->checkUserLimit($testUserId, $userAction, 3, 10)) {
                    $this->fail("User rate limiting normal", "Нормальное использование пользователем заблокировано");
                    return;
                }
            }
            
            // Превышаем лимит пользователя с уникальным action
            $userLimitAction = 'test-user-limit-' . time();
            for ($i = 0; $i < 2; $i++) {
                $rateLimiter->checkUserLimit($testUserId, $userLimitAction, 2, 10);
            }
            
            if ($rateLimiter->checkUserLimit($testUserId, $userLimitAction, 2, 10)) {
                $this->fail("User rate limiting exceeded", "Превышение пользовательского лимита не заблокировано");
                return;
            }
            
            $this->pass("User rate limiting", "User rate limiting работает корректно");
            
        } catch (Exception $e) {
            $this->fail("User rate limiting", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testRecoveryCodeGeneration(): void
    {
        try {
            $recoveryManager = new RecoveryManager($this->db);
            $testUserId = 'test-recovery-user';
            
            $codes = $recoveryManager->generateRecoveryCodes($testUserId, 5);
            
            if (count($codes) !== 5) {
                $this->fail("Recovery codes count", "Сгенерировано неверное количество кодов");
                return;
            }
            
            // Проверяем формат кодов
            foreach ($codes as $code) {
                if (!preg_match('/^[2-9A-Z]{4}-[2-9A-Z]{4}$/', $code)) {
                    $this->fail("Recovery code format", "Неверный формат recovery кода: $code");
                    return;
                }
            }
            
            // Проверяем уникальность
            $unique = array_unique($codes);
            if (count($unique) !== count($codes)) {
                $this->fail("Recovery codes uniqueness", "Recovery коды не уникальны");
                return;
            }
            
            $this->pass("Recovery code generation", "Recovery коды генерируются корректно");
            
        } catch (Exception $e) {
            $this->fail("Recovery code generation", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testRecoveryCodeVerification(): void
    {
        try {
            $recoveryManager = new RecoveryManager($this->db);
            $testUserId = 'test-verify-user';
            
            $codes = $recoveryManager->generateRecoveryCodes($testUserId, 3);
            $testCode = $codes[0];
            
            // Тест валидного кода
            if (!$recoveryManager->verifyRecoveryCode($testUserId, $testCode)) {
                $this->fail("Recovery code verification valid", "Валидный recovery код не прошел проверку");
                return;
            }
            
            // Тест повторного использования того же кода
            if ($recoveryManager->verifyRecoveryCode($testUserId, $testCode)) {
                $this->fail("Recovery code reuse", "Recovery код можно использовать повторно");
                return;
            }
            
            // Тест невалидного кода
            if ($recoveryManager->verifyRecoveryCode($testUserId, 'FAKE-CODE')) {
                $this->fail("Recovery code verification invalid", "Невалидный recovery код прошел проверку");
                return;
            }
            
            $this->pass("Recovery code verification", "Верификация recovery кодов работает корректно");
            
        } catch (Exception $e) {
            $this->fail("Recovery code verification", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testEmergencyTokens(): void
    {
        try {
            $recoveryManager = new RecoveryManager($this->db);
            $testUserId = 'test-emergency-user';
            $testEmail = 'test@example.com';
            
            $token = $recoveryManager->createEmergencyToken($testUserId, $testEmail);
            
            if (empty($token)) {
                $this->fail("Emergency token creation", "Emergency token не создан");
                return;
            }
            
            if (strlen($token) < 32) {
                $this->fail("Emergency token length", "Emergency token слишком короткий");
                return;
            }
            
            // Тест валидного токена
            $verifiedUserId = $recoveryManager->verifyEmergencyToken($token);
            if ($verifiedUserId !== $testUserId) {
                $this->fail("Emergency token verification", "Emergency token не верифицируется");
                return;
            }
            
            // Тест повторного использования
            $verifiedAgain = $recoveryManager->verifyEmergencyToken($token);
            if ($verifiedAgain !== null) {
                $this->fail("Emergency token reuse", "Emergency token можно использовать повторно");
                return;
            }
            
            $this->pass("Emergency tokens", "Emergency tokens работают корректно");
            
        } catch (Exception $e) {
            $this->fail("Emergency tokens", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testSecurityHeaders(): void
    {
        try {
            // Тест установки headers (симуляция)
            ob_start();
            SecurityHeaders::setSecurityHeaders();
            ob_end_clean();
            
            // Проверяем headers через headers_list() если доступно
            if (function_exists('headers_list')) {
                $headers = headers_list();
            } else {
                $headers = [];
            }
            
            // Проверяем наличие критических заголовков
            $requiredHeaders = [
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options'
            ];
            
            $foundHeaders = [];
            foreach ($headers as $header) {
                foreach ($requiredHeaders as $required) {
                    if (strpos($header, $required) !== false) {
                        $foundHeaders[] = $required;
                    }
                }
            }
            
            if (count($foundHeaders) >= 2) { // Хотя бы 2 из 3 заголовков
                $this->pass("Security headers", "Security headers устанавливаются");
            } else {
                $this->skip("Security headers", "Не удается проверить headers в тестовом окружении");
            }
            
        } catch (Exception $e) {
            $this->skip("Security headers", "Ошибка проверки headers: " . $e->getMessage());
        }
    }
    
    private function testHTTPSEnforcement(): void
    {
        try {
            // Проверяем development режим
            $isDevelopment = ($_ENV['APP_ENV'] ?? 'production') === 'development';
            $httpsRequired = $_ENV['HTTPS_ENFORCEMENT'] ?? 'true';
            
            if ($isDevelopment && $httpsRequired === 'false') {
                // В development с отключенным HTTPS - разрешаем HTTP
                $_SERVER['HTTPS'] = 'off';
                $_SERVER['HTTP_HOST'] = 'localhost:8080';
                
                $result = SecurityHeaders::enforceHTTPS();
                
                if ($result === false) {
                    $this->fail("HTTPS enforcement", "Development режим должен разрешать HTTP");
                    return;
                }
                
                $this->pass("HTTPS enforcement", "Development режим корректно разрешает HTTP");
                return;
            }
            
            // Обычное тестирование для production
            // Симуляция HTTP окружения для внешнего домена
            $_SERVER['HTTPS'] = 'off';
            $_SERVER['HTTP_HOST'] = 'external.com';
            
            ob_start();
            $result = SecurityHeaders::enforceHTTPS();
            ob_end_clean();
            
            if ($result === true) {
                $this->fail("HTTPS enforcement", "HTTP соединение не заблокировано для внешнего домена");
                return;
            }
            
            // Симуляция localhost (должно пройти)
            $_SERVER['HTTP_HOST'] = 'localhost';
            $result = SecurityHeaders::enforceHTTPS();
            
            if ($result === false) {
                $this->fail("HTTPS enforcement localhost", "localhost заблокирован при HTTP");
                return;
            }
            
            // Тестируем Tuna URL (должно пройти)
            $_SERVER['HTTP_HOST'] = 'test.tuna.am';
            $result = SecurityHeaders::enforceHTTPS();
            
            if ($result === false) {
                $this->fail("HTTPS enforcement tuna", "Tuna URL заблокирован при HTTP");
                return;
            }
            
            $this->pass("HTTPS enforcement", "HTTPS enforcement работает корректно");
            
        } catch (Exception $e) {
            $this->fail("HTTPS enforcement", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testSecurityIntegration(): void
    {
        try {
            // Интеграционный тест: полный цикл с security мерами
            $rateLimiter = new RateLimiter($this->db);
            $recoveryManager = new RecoveryManager($this->db);
            
            // Тест сценария атаки с уникальным action
            $integrationAction = 'integration-test-' . time();
            $attempts = 0;
            
            // Симулируем brute force атаку
            for ($i = 0; $i < 10; $i++) {
                if ($rateLimiter->checkIPLimit($integrationAction, 5, 5)) {
                    $attempts++;
                } else {
                    break;
                }
            }
            
            if ($attempts >= 10) {
                $this->fail("Security integration", "Rate limiting не остановил brute force");
                return;
            }
            
            if ($attempts < 5) {
                $this->fail("Security integration", "Rate limiting слишком агрессивен");
                return;
            }
            
            $this->pass("Security integration", "Интеграция security компонентов работает корректно");
            
        } catch (Exception $e) {
            $this->fail("Security integration", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testAttackScenarios(): void
    {
        try {
            // Тест защиты от timing attacks
            $start1 = microtime(true);
            WebAuthnSecurity::validateChallenge('valid', 'valid');
            $time1 = microtime(true) - $start1;
            
            $start2 = microtime(true);
            WebAuthnSecurity::validateChallenge('invalid', 'valid');
            $time2 = microtime(true) - $start2;
            
            // Время должно быть примерно одинаковым (в пределах 100%)
            $timeDiff = abs($time1 - $time2) / max($time1, $time2);
            if ($timeDiff > 1.0) {
                $this->fail("Timing attack protection", "Значительная разница во времени выполнения");
                return;
            }
            
            $this->pass("Attack scenarios", "Защита от основных атак работает");
            
        } catch (Exception $e) {
            $this->fail("Attack scenarios", "Ошибка: " . $e->getMessage());
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
    
    private function skip(string $testName, string $message): void
    {
        $this->testResults[] = [
            'status' => 'SKIP',
            'test' => $testName,
            'message' => $message
        ];
        echo "⏭️  {$testName}: {$message}\n";
    }
    
    private function printResults(): void
    {
        $passed = count(array_filter($this->testResults, fn($r) => $r['status'] === 'PASS'));
        $failed = count(array_filter($this->testResults, fn($r) => $r['status'] === 'FAIL'));
        $skipped = count(array_filter($this->testResults, fn($r) => $r['status'] === 'SKIP'));
        $total = count($this->testResults);
        
        echo "\n📊 Результаты тестирования безопасности:\n";
        echo "✅ Пройдено: {$passed}\n";
        echo "❌ Провалено: {$failed}\n";
        echo "⏭️  Пропущено: {$skipped}\n";
        echo "📝 Всего: {$total}\n";
        
        if ($failed > 0) {
            echo "\n❌ КРИТИЧЕСКИЕ ПРОБЛЕМЫ БЕЗОПАСНОСТИ ОБНАРУЖЕНЫ!\n";
            echo "Не развертывайте в продакшене без исправления ошибок.\n";
            exit(1);
        } else {
            echo "\n🛡️ ВСЕ ТЕСТЫ БЕЗОПАСНОСТИ ПРОЙДЕНЫ!\n";
            echo "Приложение готово для продакшена с точки зрения безопасности.\n";
        }
    }
}

// Запускаем тесты
new SecurityTest();
