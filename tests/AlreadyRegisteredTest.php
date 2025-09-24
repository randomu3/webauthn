<?php
/**
 * Тест сценария с уже зарегистрированным устройством
 */

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/DeviceHelper.php';
require_once __DIR__ . '/../src/WebAuthnHelper.php';

use WebAuthn\Database;
use WebAuthn\DeviceHelper;
use WebAuthn\WebAuthnHelper;

class AlreadyRegisteredTest
{
    private array $testResults = [];
    private Database $db;
    private array $createdUsers = [];
    
    public function __construct()
    {
        echo "🧪 Запуск тестов для уже зарегистрированного устройства...\n\n";
        
        try {
            $this->db = new Database();
        } catch (Exception $e) {
            $this->fail("Database initialization", "Не удалось подключиться к БД: " . $e->getMessage());
            return;
        }
        
        $this->runAllTests();
        $this->cleanup();
        $this->printResults();
    }
    
    private function runAllTests(): void
    {
        $this->testAlreadyRegisteredDeviceResponse();
        $this->testNewDeviceRegistration();
    }
    
    private function testAlreadyRegisteredDeviceResponse(): void
    {
        // Очищаем БД от предыдущих тестовых данных
        $this->cleanupExistingUsers();
        
        // Создаем тестового пользователя с конкретным device fingerprint
        $testUserAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15';
        $deviceData = [
            'screenWidth' => 1920,
            'screenHeight' => 1080,
            'userAgent' => $testUserAgent
        ];
        
        $deviceHash = DeviceHelper::generateDeviceFingerprint($deviceData);
        $userData = WebAuthnHelper::generateUserFromDevice($deviceHash);
        
        echo "🔍 Debug: Device Hash: " . $deviceHash . "\n";
        echo "🔍 Debug: User ID: " . $userData['userId'] . "\n";
        echo "🔍 Debug: User Handle: " . WebAuthnHelper::base64urlEncode($userData['userHandle']) . "\n";
        
        // Регистрируем пользователя в БД
        $result = $this->db->createUser($userData['userId'], $userData['userHandle']);
        
        if ($result) {
            $this->createdUsers[] = $userData['userId'];
            $this->pass("User creation", "Тестовый пользователь создан успешно");
            
            // Теперь делаем запрос на регистрацию с тем же устройством
            echo "🔍 Debug: Отправляемые deviceData: " . json_encode($deviceData, JSON_UNESCAPED_UNICODE) . "\n";
            
            $response = $this->makeApiRequest('register-options', [
                'deviceData' => $deviceData
            ]);
            
            if ($response) {
                echo "🔍 Debug: Ответ API для уже зарегистрированного устройства: " . json_encode($response, JSON_UNESCAPED_UNICODE) . "\n";
                
                // Проверяем, что ответ корректный для уже зарегистрированного устройства
                if ($response['success'] === true && 
                    isset($response['alreadyRegistered']) && 
                    $response['alreadyRegistered'] === true &&
                    $response['code'] === 'DEVICE_ALREADY_REGISTERED' &&
                    $response['action'] === 'LOGIN_REQUIRED') {
                    
                    $this->pass("Already registered response", "API корректно обрабатывает уже зарегистрированное устройство");
                    
                    // Проверяем содержание сообщения
                    if (strpos($response['message'], 'уже зарегистрировано') !== false) {
                        $this->pass("Already registered message", "Сообщение корректно информирует о регистрации");
                    } else {
                        $this->fail("Already registered message", "Сообщение должно информировать о регистрации");
                    }
                    
                    // Проверяем debug информацию
                    if (isset($response['debug']['existing_user_id']) && 
                        isset($response['debug']['current_device_id'])) {
                        $this->pass("Already registered debug", "Debug информация присутствует");
                    } else {
                        $this->fail("Already registered debug", "Debug информация должна присутствовать");
                    }
                    
                } else {
                    $this->fail("Already registered response", "API должен корректно обрабатывать уже зарегистрированное устройство");
                }
            } else {
                $this->fail("API request", "Не удалось выполнить запрос к API");
            }
            
        } else {
            $this->fail("User creation", "Не удалось создать тестового пользователя");
        }
    }
    
    private function testNewDeviceRegistration(): void
    {
        // Тестируем с новым устройством
        $newDeviceData = [
            'screenWidth' => 1366,
            'screenHeight' => 768,
            'userAgent' => 'Test Agent for New Device'
        ];
        
        $response = $this->makeApiRequest('register-options', [
            'deviceData' => $newDeviceData
        ]);
        
        if ($response) {
            // Проверяем, что для нового устройства возвращаются опции регистрации
            if ($response['success'] === true && 
                !isset($response['alreadyRegistered']) &&
                isset($response['challenge']) &&
                isset($response['user']) &&
                isset($response['rp'])) {
                
                $this->pass("New device registration", "API корректно возвращает опции для нового устройства");
                
                // Проверяем структуру ответа
                if (isset($response['user']['id']) && isset($response['user']['name'])) {
                    $this->pass("New device user data", "Данные пользователя присутствуют");
                } else {
                    $this->fail("New device user data", "Данные пользователя должны присутствовать");
                }
                
                if (isset($response['pubKeyCredParams']) && is_array($response['pubKeyCredParams'])) {
                    $this->pass("New device pub key params", "Параметры публичного ключа присутствуют");
                } else {
                    $this->fail("New device pub key params", "Параметры публичного ключа должны присутствовать");
                }
                
            } else {
                $this->fail("New device registration", "API должен возвращать опции регистрации для нового устройства");
            }
        } else {
            $this->fail("New device API request", "Не удалось выполнить запрос к API для нового устройства");
        }
    }
    
    private function makeApiRequest(string $action, array $data = []): ?array
    {
        $url = 'http://127.0.0.1/api.php?action=' . $action;
        
        // Используем тот же User-Agent что и в deviceData для консистентности
        $userAgent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15';
        
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => [
                    'Content-Type: application/json',
                    'User-Agent: ' . $userAgent
                ],
                'content' => json_encode($data),
                'timeout' => 10
            ]
        ]);
        
        try {
            $response = file_get_contents($url, false, $context);
            
            if ($response === false) {
                return null;
            }
            
            $decodedResponse = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                return null;
            }
            
            return $decodedResponse;
            
        } catch (Exception $e) {
            echo "⚠️  Ошибка запроса к API: " . $e->getMessage() . "\n";
            return null;
        }
    }
    
    private function cleanupExistingUsers(): void
    {
        try {
            $pdo = $this->db->getPdo();
            
            // Удаляем всех пользователей перед тестом
            $stmt = $pdo->prepare("DELETE FROM users");
            $stmt->execute();
            
            // Удаляем все связанные данные
            $stmt = $pdo->prepare("DELETE FROM user_credentials");
            $stmt->execute();
            
            $stmt = $pdo->prepare("DELETE FROM user_sessions");
            $stmt->execute();
            
        } catch (Exception $e) {
            echo "⚠️  Ошибка очистки существующих данных: " . $e->getMessage() . "\n";
        }
    }
    
    private function cleanup(): void
    {
        try {
            $pdo = $this->db->getPdo();
            
            // Удаляем тестовых пользователей
            foreach ($this->createdUsers as $userId) {
                $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
                $stmt->execute([$userId]);
            }
            
        } catch (Exception $e) {
            echo "⚠️  Ошибка очистки тестовых данных: " . $e->getMessage() . "\n";
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
        
        echo "\n📊 Результаты тестирования уже зарегистрированного устройства:\n";
        echo "✅ Пройдено: {$passed}\n";
        echo "❌ Провалено: {$failed}\n";
        echo "📝 Всего: {$total}\n";
        
        if ($failed > 0) {
            echo "\n❌ ТЕСТЫ НЕ ПРОЙДЕНЫ!\n";
            exit(1);
        } else {
            echo "\n🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!\n";
        }
    }
}

// Запускаем тесты
new AlreadyRegisteredTest();
