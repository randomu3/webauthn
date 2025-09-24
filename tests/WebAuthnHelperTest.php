<?php
/**
 * Тесты для класса WebAuthnHelper
 * Проверяют функциональность WebAuthn утилит
 */

require_once __DIR__ . '/../src/WebAuthnHelper.php';

use WebAuthn\WebAuthnHelper;

class WebAuthnHelperTest
{
    private array $testResults = [];
    
    public function __construct()
    {
        echo "🧪 Запуск тестов WebAuthnHelper класса...\n\n";
        $this->runAllTests();
        $this->printResults();
    }
    
    private function runAllTests(): void
    {
        $this->testBase64urlEncodeDecode();
        $this->testBase64urlEncodeDecodeEdgeCases();
        $this->testBase64urlDecodeInvalidInput();
        $this->testGenerateChallenge();
        $this->testChallengeUniqueness();
        $this->testCreateRegistrationOptions();
        $this->testCreateRegistrationOptionsWithCredentials();
        $this->testCreateAuthenticationOptions();
        $this->testCreateAuthenticationOptionsEmpty();
        $this->testVerifyChallenge();
        $this->testVerifyChallengeInvalid();
        $this->testVerifyChallengeMalformedJSON();
        $this->testGenerateUserFromDevice();
        $this->testGenerateUserFromDeviceConsistency();
        $this->testEnvironmentVariables();
        $this->testSpecialCharacters();
        $this->testLargeDataHandling();
    }
    
    private function testBase64urlEncodeDecode(): void
    {
        $testData = [
            'Hello World!',
            'Test string with special chars: !@#$%^&*()',
            'Русский текст',
            json_encode(['key' => 'value', 'number' => 123]),
            str_repeat('A', 100), // Средняя строка
            '', // Пустая строка
            "\x00\x01\x02\x03", // Бинарные данные
        ];
        
        foreach ($testData as $index => $original) {
            try {
                $encoded = WebAuthnHelper::base64urlEncode($original);
                $decoded = WebAuthnHelper::base64urlDecode($encoded);
                
                if ($decoded === $original) {
                    $this->pass("Base64url encode/decode $index", "Кодирование и декодирование работает корректно");
                } else {
                    $this->fail("Base64url encode/decode $index", "Ошибка кодирования/декодирования");
                }
            } catch (Exception $e) {
                $this->fail("Base64url encode/decode $index", "Исключение при кодировании: " . $e->getMessage());
            }
        }
    }
    
    private function testBase64urlEncodeDecodeEdgeCases(): void
    {
        // Проверяем, что base64url не содержит +, /, =
        $testString = 'Test string that will produce + and / in regular base64??>>';
        $encoded = WebAuthnHelper::base64urlEncode($testString);
        
        if (strpos($encoded, '+') === false && strpos($encoded, '/') === false && strpos($encoded, '=') === false) {
            $this->pass("Base64url format", "Base64url не содержит запрещенных символов");
        } else {
            $this->fail("Base64url format", "Base64url содержит запрещенные символы: $encoded");
        }
        
        // Проверяем обратную совместимость с обычным base64
        $regularBase64 = base64_encode($testString);
        $convertedToUrl = str_replace(['+', '/'], ['-', '_'], rtrim($regularBase64, '='));
        
        if ($encoded === $convertedToUrl) {
            $this->pass("Base64url compatibility", "Base64url совместим с обычным base64");
        } else {
            $this->fail("Base64url compatibility", "Base64url должен быть совместим с обычным base64");
        }
    }
    
    private function testBase64urlDecodeInvalidInput(): void
    {
        $invalidInputs = [
            'Contains invalid chars: +/',
            'Too short',
            '!!!invalid!!!'
        ];
        
        foreach ($invalidInputs as $index => $invalidInput) {
            try {
                $result = WebAuthnHelper::base64urlDecode($invalidInput);
                // Проверяем, что результат разумный
                if (is_string($result)) {
                    $this->pass("Invalid base64url $index", "Некорректный ввод обработан как строка");
                } else {
                    $this->fail("Invalid base64url $index", "Некорректный ввод должен возвращать строку");
                }
            } catch (Exception $e) {
                $this->pass("Invalid base64url $index", "Некорректный ввод корректно выбросил исключение");
            }
        }
    }
    
    private function testGenerateChallenge(): void
    {
        $challenge = WebAuthnHelper::generateChallenge();
        
        if (is_string($challenge) && strlen($challenge) === 32) {
            $this->pass("Generate challenge", "Challenge сгенерирован корректно (32 байта)");
        } else {
            $this->fail("Generate challenge", "Challenge должен быть строкой длиной 32 байта, получен: " . strlen($challenge));
        }
    }
    
    private function testChallengeUniqueness(): void
    {
        $challenges = [];
        $iterations = 100;
        
        for ($i = 0; $i < $iterations; $i++) {
            $challenges[] = WebAuthnHelper::generateChallenge();
        }
        
        $uniqueChallenges = array_unique($challenges, SORT_REGULAR);
        
        if (count($uniqueChallenges) === $iterations) {
            $this->pass("Challenge uniqueness", "Все сгенерированные challenge уникальны");
        } else {
            $duplicates = $iterations - count($uniqueChallenges);
            $this->fail("Challenge uniqueness", "Найдено $duplicates дубликатов среди $iterations challenge");
        }
    }
    
    private function testCreateRegistrationOptions(): void
    {
        $userId = 'test_user_123';
        $userHandle = 'test_handle_data';
        
        $options = WebAuthnHelper::createRegistrationOptions($userId, $userHandle);
        
        $requiredFields = ['rp', 'user', 'challenge', 'pubKeyCredParams', 'timeout', 'excludeCredentials', 'authenticatorSelection', 'attestation'];
        
        $allFieldsPresent = true;
        foreach ($requiredFields as $field) {
            if (!isset($options[$field])) {
                $allFieldsPresent = false;
                break;
            }
        }
        
        if ($allFieldsPresent && 
            isset($options['rp']['name']) && 
            isset($options['user']['id']) && 
            strlen($options['challenge']) > 0) {
            $this->pass("Registration options structure", "Параметры регистрации содержат все необходимые поля");
        } else {
            $this->fail("Registration options structure", "Параметры регистрации должны содержать все необходимые поля");
        }
        
        // Проверяем authenticatorSelection
        if ($options['authenticatorSelection']['authenticatorAttachment'] === 'platform' &&
            $options['authenticatorSelection']['userVerification'] === 'required') {
            $this->pass("Registration authenticator selection", "Настройки аутентификатора корректны");
        } else {
            $this->fail("Registration authenticator selection", "Настройки аутентификатора некорректны");
        }
    }
    
    private function testCreateRegistrationOptionsWithCredentials(): void
    {
        $excludeCredentials = [
            ['type' => 'public-key', 'id' => 'credential1'],
            ['type' => 'public-key', 'id' => 'credential2']
        ];
        
        $options = WebAuthnHelper::createRegistrationOptions('user', 'handle', $excludeCredentials);
        
        if ($options['excludeCredentials'] === $excludeCredentials) {
            $this->pass("Registration exclude credentials", "Исключаемые учетные данные переданы корректно");
        } else {
            $this->fail("Registration exclude credentials", "Исключаемые учетные данные должны передаваться корректно");
        }
    }
    
    private function testCreateAuthenticationOptions(): void
    {
        $allowCredentials = [
            ['type' => 'public-key', 'id' => 'credential1'],
            ['type' => 'public-key', 'id' => 'credential2']
        ];
        
        $options = WebAuthnHelper::createAuthenticationOptions($allowCredentials);
        
        $requiredFields = ['challenge', 'timeout', 'allowCredentials', 'userVerification'];
        
        $allFieldsPresent = true;
        foreach ($requiredFields as $field) {
            if (!isset($options[$field])) {
                $allFieldsPresent = false;
                break;
            }
        }
        
        if ($allFieldsPresent && 
            $options['allowCredentials'] === $allowCredentials &&
            $options['userVerification'] === 'required') {
            $this->pass("Authentication options", "Параметры аутентификации созданы корректно");
        } else {
            $this->fail("Authentication options", "Параметры аутентификации должны содержать все необходимые поля");
        }
    }
    
    private function testCreateAuthenticationOptionsEmpty(): void
    {
        $options = WebAuthnHelper::createAuthenticationOptions([]);
        
        if (isset($options['allowCredentials']) && is_array($options['allowCredentials']) && empty($options['allowCredentials'])) {
            $this->pass("Authentication empty credentials", "Пустой список учетных данных обработан корректно");
        } else {
            $this->fail("Authentication empty credentials", "Пустой список учетных данных должен обрабатываться корректно");
        }
    }
    
    private function testVerifyChallenge(): void
    {
        $challenge = WebAuthnHelper::base64urlEncode(random_bytes(32));
        $clientData = [
            'type' => 'webauthn.create',
            'challenge' => $challenge,
            'origin' => 'https://example.com'
        ];
        
        $clientDataJSON = WebAuthnHelper::base64urlEncode(json_encode($clientData));
        
        $result = WebAuthnHelper::verifyChallenge($clientDataJSON, $challenge);
        
        if ($result === true) {
            $this->pass("Verify challenge valid", "Корректный challenge проходит проверку");
        } else {
            $this->fail("Verify challenge valid", "Корректный challenge должен проходить проверку");
        }
    }
    
    private function testVerifyChallengeInvalid(): void
    {
        $challenge = WebAuthnHelper::base64urlEncode(random_bytes(32));
        $wrongChallenge = WebAuthnHelper::base64urlEncode(random_bytes(32));
        
        $clientData = [
            'type' => 'webauthn.create',
            'challenge' => $wrongChallenge,
            'origin' => 'https://example.com'
        ];
        
        $clientDataJSON = WebAuthnHelper::base64urlEncode(json_encode($clientData));
        
        $result = WebAuthnHelper::verifyChallenge($clientDataJSON, $challenge);
        
        if ($result === false) {
            $this->pass("Verify challenge invalid", "Некорректный challenge не проходит проверку");
        } else {
            $this->fail("Verify challenge invalid", "Некорректный challenge не должен проходить проверку");
        }
    }
    
    private function testVerifyChallengeMalformedJSON(): void
    {
        $challenge = WebAuthnHelper::base64urlEncode(random_bytes(32));
        $malformedJSON = WebAuthnHelper::base64urlEncode('{"invalid": json}');
        
        $result = WebAuthnHelper::verifyChallenge($malformedJSON, $challenge);
        
        if ($result === false) {
            $this->pass("Verify challenge malformed", "Некорректный JSON не проходит проверку");
        } else {
            $this->fail("Verify challenge malformed", "Некорректный JSON не должен проходить проверку");
        }
        
        // Тест с отсутствующим полем challenge
        $clientDataWithoutChallenge = ['type' => 'webauthn.create'];
        $jsonWithoutChallenge = WebAuthnHelper::base64urlEncode(json_encode($clientDataWithoutChallenge));
        
        $result2 = WebAuthnHelper::verifyChallenge($jsonWithoutChallenge, $challenge);
        
        if ($result2 === false) {
            $this->pass("Verify challenge missing field", "JSON без поля challenge не проходит проверку");
        } else {
            $this->fail("Verify challenge missing field", "JSON без поля challenge не должен проходить проверку");
        }
    }
    
    private function testGenerateUserFromDevice(): void
    {
        // Используем hex строку для тестирования
        $deviceId = 'abcdef1234567890abcdef1234567890'; // 32 hex символа
        
        try {
            $userData = WebAuthnHelper::generateUserFromDevice($deviceId);
            
            if (isset($userData['userId']) && isset($userData['userHandle']) &&
                strlen($userData['userId']) === 16 &&
                is_string($userData['userHandle'])) {
                $this->pass("Generate user from device", "Пользователь сгенерирован корректно из device ID");
            } else {
                $this->fail("Generate user from device", "Пользователь должен генерироваться корректно из device ID");
            }
        } catch (Exception $e) {
            $this->fail("Generate user from device", "Ошибка генерации пользователя: " . $e->getMessage());
        }
    }
    
    private function testGenerateUserFromDeviceConsistency(): void
    {
        $deviceId = 'abcdef1234567890abcdef1234567890';
        
        try {
            $userData1 = WebAuthnHelper::generateUserFromDevice($deviceId);
            $userData2 = WebAuthnHelper::generateUserFromDevice($deviceId);
            
            if ($userData1['userId'] === $userData2['userId'] && 
                $userData1['userHandle'] === $userData2['userHandle']) {
                $this->pass("Generate user consistency", "Генерация пользователя стабильна для одного device ID");
            } else {
                $this->fail("Generate user consistency", "Генерация пользователя должна быть стабильной для одного device ID");
            }
            
            // Проверяем разные device ID дают разных пользователей
            $differentDeviceId = '1234567890abcdef1234567890abcdef';
            $userData3 = WebAuthnHelper::generateUserFromDevice($differentDeviceId);
            
            if ($userData1['userId'] !== $userData3['userId']) {
                $this->pass("Generate user uniqueness", "Разные device ID дают разных пользователей");
            } else {
                $this->fail("Generate user uniqueness", "Разные device ID должны давать разных пользователей");
            }
        } catch (Exception $e) {
            $this->fail("Generate user consistency", "Ошибка теста консистентности: " . $e->getMessage());
        }
    }
    
    private function testEnvironmentVariables(): void
    {
        // Сохраняем оригинальные значения
        $originalRpName = $_ENV['WEBAUTHN_RP_NAME'] ?? null;
        $originalRpId = $_ENV['WEBAUTHN_RP_ID'] ?? null;
        $originalHttpHost = $_SERVER['HTTP_HOST'] ?? null;
        
        try {
            // Тестируем с переменными окружения
            $_ENV['WEBAUTHN_RP_NAME'] = 'Test App';
            $_ENV['WEBAUTHN_RP_ID'] = 'test.example.com';
            
            $options = WebAuthnHelper::createRegistrationOptions('user', 'handle');
            
            if ($options['rp']['name'] === 'Test App' && $options['rp']['id'] === 'test.example.com') {
                $this->pass("Environment variables", "Переменные окружения используются корректно");
            } else {
                $this->fail("Environment variables", "Переменные окружения должны использоваться корректно");
            }
            
            // Тестируем fallback на HTTP_HOST
            unset($_ENV['WEBAUTHN_RP_ID']);
            $_SERVER['HTTP_HOST'] = 'fallback.example.com';
            
            $options2 = WebAuthnHelper::createRegistrationOptions('user', 'handle');
            
            if ($options2['rp']['id'] === 'fallback.example.com') {
                $this->pass("Environment fallback", "Fallback на HTTP_HOST работает корректно");
            } else {
                $this->fail("Environment fallback", "Fallback на HTTP_HOST должен работать корректно");
            }
        } finally {
            // Восстанавливаем оригинальные значения
            if ($originalRpName !== null) {
                $_ENV['WEBAUTHN_RP_NAME'] = $originalRpName;
            } else {
                unset($_ENV['WEBAUTHN_RP_NAME']);
            }
            
            if ($originalRpId !== null) {
                $_ENV['WEBAUTHN_RP_ID'] = $originalRpId;
            } else {
                unset($_ENV['WEBAUTHN_RP_ID']);
            }
            
            if ($originalHttpHost !== null) {
                $_SERVER['HTTP_HOST'] = $originalHttpHost;
            } else {
                unset($_SERVER['HTTP_HOST']);
            }
        }
    }
    
    private function testSpecialCharacters(): void
    {
        $specialInputs = [
            'unicode' => 'Тест с юникодом: ñáéíóú',
            'html' => '<script>alert("xss")</script>',
            'sql' => "'; DROP TABLE users; --",
            'quotes' => 'test "double" and \'single\' quotes',
            'backslashes' => 'test\\with\\backslashes'
        ];
        
        foreach ($specialInputs as $type => $input) {
            try {
                $encoded = WebAuthnHelper::base64urlEncode($input);
                $decoded = WebAuthnHelper::base64urlDecode($encoded);
                
                if ($decoded === $input) {
                    $this->pass("Special chars $type", "Специальные символы ($type) обрабатываются корректно");
                } else {
                    $this->fail("Special chars $type", "Ошибка обработки специальных символов ($type)");
                }
            } catch (Exception $e) {
                $this->fail("Special chars $type", "Ошибка обработки $type: " . $e->getMessage());
            }
        }
    }
    
    private function testLargeDataHandling(): void
    {
        try {
            // Тест с большой строкой
            $largeString = str_repeat('A', 10000); // 10KB строка
            
            $encoded = WebAuthnHelper::base64urlEncode($largeString);
            $decoded = WebAuthnHelper::base64urlDecode($encoded);
            
            if ($decoded === $largeString) {
                $this->pass("Large data encoding", "Большие данные корректно кодируются и декодируются");
            } else {
                $this->fail("Large data encoding", "Ошибка при обработке больших данных");
            }
            
            // Тест генерации множественных challenge
            $challenges = [];
            for ($i = 0; $i < 100; $i++) {
                $challenges[] = WebAuthnHelper::generateChallenge();
            }
            
            if (count($challenges) === 100) {
                $this->pass("Multiple challenges", "Множественная генерация challenge работает корректно");
            } else {
                $this->fail("Multiple challenges", "Проблемы при множественной генерации challenge");
            }
            
        } catch (Exception $e) {
            $this->fail("Large data handling", "Ошибка обработки больших данных: " . $e->getMessage());
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
        
        echo "\n📊 Результаты тестирования WebAuthnHelper:\n";
        echo "✅ Пройдено: {$passed}\n";
        echo "❌ Провалено: {$failed}\n";
        echo "📝 Всего: {$total}\n";
        
        if ($failed > 0) {
            echo "\n❌ ТЕСТЫ WebAuthnHelper НЕ ПРОЙДЕНЫ!\n";
            exit(1);
        } else {
            echo "\n🎉 ВСЕ ТЕСТЫ WebAuthnHelper ПРОЙДЕНЫ!\n";
        }
    }
}

// Запускаем тесты
new WebAuthnHelperTest();
