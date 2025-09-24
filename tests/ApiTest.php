<?php
/**
 * Тесты для WebAuthn API
 * Проверяют основную функциональность API endpoints
 */

class ApiTest
{
    private string $baseUrl;
    private array $testResults = [];
    
    public function __construct()
    {
        echo "🧪 Запуск тестов WebAuthn API...\n\n";
        
        // Используем внутреннее имя сервиса для тестов внутри контейнера
        $this->baseUrl = 'http://127.0.0.1/api.php';
        
        $this->runAllTests();
        $this->printResults();
    }
    
    private function runAllTests(): void
    {
        $this->testDeviceInfo();
        $this->testRegisterOptions();
        $this->testAuthOptions();
        $this->testStatus();
        $this->testLogout();
        $this->testInvalidAction();
    }
    
    private function testDeviceInfo(): void
    {
        try {
            $response = $this->makeRequest('GET', '?action=device-info');
            $data = json_decode($response, true);
            
            if ($data && isset($data['isMobile']) && isset($data['isCompatible'])) {
                $this->pass("Device info", "API возвращает информацию об устройстве");
            } else {
                $this->fail("Device info", "Неверный формат ответа: " . $response);
            }
        } catch (Exception $e) {
            $this->fail("Device info", "Ошибка запроса: " . $e->getMessage());
        }
    }
    
    private function testRegisterOptions(): void
    {
        try {
            // Симулируем мобильное устройство через User-Agent
            $headers = ['User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'];
            
            $response = $this->makeRequest('POST', '?action=register-options', [
                'deviceData' => [
                    'screenWidth' => 390,
                    'screenHeight' => 844,
                    'colorDepth' => 32,
                    'pixelRatio' => 3,
                    'timezone' => 'Europe/Moscow',
                    'platform' => 'iPhone',
                    'hardwareConcurrency' => 6,
                    'maxTouchPoints' => 5
                ]
            ], $headers);
            
            $data = json_decode($response, true);
            
            if ($data && isset($data['success'])) {
                if ($data['success'] === true && isset($data['challenge']) && isset($data['user'])) {
                    $this->pass("Register options", "API возвращает параметры регистрации");
                } elseif ($data['success'] === false && isset($data['code']) && $data['code'] === 'DEVICE_ALREADY_REGISTERED') {
                    $this->pass("Register options", "API корректно обрабатывает уже зарегистрированное устройство");
                } else {
                    $this->fail("Register options", "Неожиданный ответ: " . $response);
                }
            } else {
                $this->fail("Register options", "Неверный формат ответа: " . $response);
            }
        } catch (Exception $e) {
            $this->fail("Register options", "Ошибка запроса: " . $e->getMessage());
        }
    }
    
    private function testAuthOptions(): void
    {
        try {
            // Симулируем мобильное устройство
            $headers = ['User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'];
            
            $response = $this->makeRequest('POST', '?action=auth-options', [], $headers);
            $data = json_decode($response, true);
            
            if ($data && isset($data['success'])) {
                if ($data['success'] === true && isset($data['challenge'])) {
                    $this->pass("Auth options", "API возвращает параметры аутентификации");
                } elseif ($data['success'] === false && (
                    (isset($data['code']) && ($data['code'] === 'NO_CREDENTIALS' || $data['code'] === 'ALREADY_LOGGED_IN')) ||
                    strpos($data['message'], 'Нет зарегистрированных') !== false
                )) {
                    $this->pass("Auth options", "API корректно обрабатывает отсутствие учетных данных или уже авторизованного пользователя");
                } else {
                    $this->fail("Auth options", "Неожиданный ответ: " . $response);
                }
            } else {
                $this->fail("Auth options", "Неверный формат ответа: " . $response);
            }
        } catch (Exception $e) {
            $this->fail("Auth options", "Ошибка запроса: " . $e->getMessage());
        }
    }
    
    private function testStatus(): void
    {
        try {
            $response = $this->makeRequest('GET', '?action=status');
            $data = json_decode($response, true);
            
            if ($data && isset($data['success']) && isset($data['authenticated']) && isset($data['canRegister'])) {
                $this->pass("Status", "API возвращает статус пользователя");
            } else {
                $this->fail("Status", "Неверный формат ответа: " . $response);
            }
        } catch (Exception $e) {
            $this->fail("Status", "Ошибка запроса: " . $e->getMessage());
        }
    }
    
    private function testLogout(): void
    {
        try {
            $response = $this->makeRequest('POST', '?action=logout');
            $data = json_decode($response, true);
            
            if ($data && isset($data['success']) && $data['success'] === true) {
                $this->pass("Logout", "API корректно обрабатывает выход из системы");
            } else {
                $this->fail("Logout", "Неверный ответ на выход: " . $response);
            }
        } catch (Exception $e) {
            $this->fail("Logout", "Ошибка запроса: " . $e->getMessage());
        }
    }
    
    private function testInvalidAction(): void
    {
        try {
            $response = $this->makeRequest('GET', '?action=invalid-action');
            $data = json_decode($response, true);
            
            if ($data && isset($data['success']) && $data['success'] === false) {
                $this->pass("Invalid action", "API корректно обрабатывает неверные действия");
            } else {
                $this->fail("Invalid action", "API должен возвращать ошибку для неверных действий");
            }
        } catch (Exception $e) {
            $this->fail("Invalid action", "Ошибка запроса: " . $e->getMessage());
        }
    }
    
    private function makeRequest(string $method, string $endpoint, array $data = [], array $headers = []): string
    {
        $url = $this->baseUrl . $endpoint;
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CUSTOMREQUEST => $method,
        ]);
        
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }
        
        if ($method === 'POST' && !empty($data)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($headers, ['Content-Type: application/json']));
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if (curl_errno($ch)) {
            throw new Exception('cURL error: ' . curl_error($ch));
        }
        
        curl_close($ch);
        
        if ($httpCode >= 400) {
            // Для некоторых тестов ошибки ожидаемы
            if ($httpCode === 403 || $httpCode === 400) {
                return $response; // Возвращаем ответ для анализа
            }
            throw new Exception("HTTP error $httpCode: $response");
        }
        
        return $response;
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
        
        echo "\n📊 Результаты тестирования API:\n";
        echo "✅ Пройдено: {$passed}\n";
        echo "❌ Провалено: {$failed}\n";
        echo "⏭️  Пропущено: {$skipped}\n";
        echo "📝 Всего: {$total}\n";
        
        if ($failed > 0) {
            echo "\n❌ ТЕСТЫ API НЕ ПРОЙДЕНЫ! Есть ошибки в коде.\n";
            exit(1);
        } else {
            echo "\n🎉 ВСЕ ТЕСТЫ API ПРОЙДЕНЫ! Код работает корректно.\n";
        }
    }
}

// Запускаем тесты
new ApiTest();
