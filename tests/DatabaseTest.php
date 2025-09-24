<?php
/**
 * Тесты для класса Database
 * Проверяют основную функциональность работы с БД
 */

require_once __DIR__ . '/../src/Database.php';

use WebAuthn\Database;

class DatabaseTest
{
    private Database $db;
    private array $testResults = [];
    
    public function __construct()
    {
        echo "🧪 Запуск тестов Database класса...\n\n";
        
        try {
            $this->db = new Database();
        } catch (Exception $e) {
            $this->fail("Database connection", "Не удалось подключиться к БД: " . $e->getMessage());
            return;
        }
        
        $this->runAllTests();
        $this->printResults();
    }
    
    private function runAllTests(): void
    {
        $this->testConnection();
        $this->testCreateUser();
        $this->testGetUser();
        $this->testGetNonExistentUser();
        $this->testCreateDuplicateUser();
        $this->testSaveCredential();
        $this->testGetCredential();
        $this->testCreateSession();
        $this->testGetValidSession();
        $this->testGetExpiredSession();
        $this->testCleanupExpiredSessions();
    }
    
    private function testConnection(): void
    {
        try {
            $pdo = $this->db->getPdo();
            $stmt = $pdo->query("SELECT 1");
            $result = $stmt->fetch();
            
            if ($result) {
                $this->pass("Database connection", "Подключение к БД работает");
            } else {
                $this->fail("Database connection", "Не удалось выполнить тестовый запрос");
            }
        } catch (Exception $e) {
            $this->fail("Database connection", "Ошибка подключения: " . $e->getMessage());
        }
    }
    
    private function testCreateUser(): void
    {
        $testUserId = 'test_user_' . time() . '_' . rand(1000, 9999);
        $testUserHandle = random_bytes(32);
        
        try {
            $result = $this->db->createUser($testUserId, $testUserHandle);
            
            if ($result) {
                $this->pass("Create user", "Пользователь создан успешно");
                
                // Сохраняем для последующих тестов
                $this->testUserId = $testUserId;
                $this->testUserHandle = $testUserHandle;
            } else {
                $this->fail("Create user", "Не удалось создать пользователя");
            }
        } catch (Exception $e) {
            $this->fail("Create user", "Ошибка создания пользователя: " . $e->getMessage());
        }
    }
    
    private function testGetUser(): void
    {
        if (!isset($this->testUserId)) {
            $this->skip("Get user", "Нет тестового пользователя");
            return;
        }
        
        try {
            $user = $this->db->getUser($this->testUserId);
            
            if ($user && $user['user_id'] === $this->testUserId) {
                $this->pass("Get user", "Пользователь найден успешно");
            } else {
                $this->fail("Get user", "Пользователь не найден или данные неверны");
            }
        } catch (Exception $e) {
            $this->fail("Get user", "Ошибка получения пользователя: " . $e->getMessage());
        }
    }
    
    private function testGetNonExistentUser(): void
    {
        $fakeUserId = 'nonexistent_user_12345';
        
        try {
            $user = $this->db->getUser($fakeUserId);
            
            if ($user === null) {
                $this->pass("Get non-existent user", "Корректно возвращает null для несуществующего пользователя");
            } else {
                $this->fail("Get non-existent user", "Должен возвращать null для несуществующего пользователя");
            }
        } catch (Exception $e) {
            $this->fail("Get non-existent user", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testCreateDuplicateUser(): void
    {
        if (!isset($this->testUserId)) {
            $this->skip("Create duplicate user", "Нет тестового пользователя");
            return;
        }
        
        try {
            $result = $this->db->createUser($this->testUserId, $this->testUserHandle);
            
            if ($result === false) {
                $this->pass("Create duplicate user", "Корректно обрабатывает дублирование пользователя");
            } else {
                $this->fail("Create duplicate user", "Должен возвращать false при попытке создания дубликата");
            }
        } catch (Exception $e) {
            // PDO exception ожидается при UNIQUE constraint
            $this->pass("Create duplicate user", "Корректно генерирует исключение при дублировании");
        }
    }
    
    private function testSaveCredential(): void
    {
        if (!isset($this->testUserId)) {
            $this->skip("Save credential", "Нет тестового пользователя");
            return;
        }
        
        $testCredentialId = 'test_credential_' . time() . '_' . rand(1000, 9999);
        $testPublicKey = 'test_public_key_data';
        
        try {
            $result = $this->db->saveCredential($this->testUserId, $testCredentialId, $testPublicKey);
            
            if ($result) {
                $this->pass("Save credential", "Учетные данные сохранены успешно");
                $this->testCredentialId = $testCredentialId;
            } else {
                $this->fail("Save credential", "Не удалось сохранить учетные данные");
            }
        } catch (Exception $e) {
            $this->fail("Save credential", "Ошибка сохранения учетных данных: " . $e->getMessage());
        }
    }
    
    private function testGetCredential(): void
    {
        if (!isset($this->testCredentialId)) {
            $this->skip("Get credential", "Нет тестовых учетных данных");
            return;
        }
        
        try {
            $credential = $this->db->getCredential($this->testCredentialId);
            
            if ($credential && $credential['credential_id'] === $this->testCredentialId) {
                $this->pass("Get credential", "Учетные данные найдены успешно");
            } else {
                $this->fail("Get credential", "Учетные данные не найдены или данные неверны");
            }
        } catch (Exception $e) {
            $this->fail("Get credential", "Ошибка получения учетных данных: " . $e->getMessage());
        }
    }
    
    private function testCreateSession(): void
    {
        if (!isset($this->testUserId)) {
            $this->skip("Create session", "Нет тестового пользователя");
            return;
        }
        
        $testSessionId = 'test_session_' . time() . '_' . rand(1000, 9999);
        
        try {
            $result = $this->db->createSession($testSessionId, $this->testUserId, 3600);
            
            if ($result) {
                $this->pass("Create session", "Сессия создана успешно");
                $this->testSessionId = $testSessionId;
            } else {
                $this->fail("Create session", "Не удалось создать сессию");
            }
        } catch (Exception $e) {
            $this->fail("Create session", "Ошибка создания сессии: " . $e->getMessage());
        }
    }
    
    private function testGetValidSession(): void
    {
        if (!isset($this->testSessionId)) {
            $this->skip("Get valid session", "Нет тестовой сессии");
            return;
        }
        
        try {
            $session = $this->db->getSession($this->testSessionId);
            
            if ($session && $session['session_id'] === $this->testSessionId) {
                $this->pass("Get valid session", "Действующая сессия найдена успешно");
            } else {
                $this->fail("Get valid session", "Действующая сессия не найдена");
            }
        } catch (Exception $e) {
            $this->fail("Get valid session", "Ошибка получения сессии: " . $e->getMessage());
        }
    }
    
    private function testGetExpiredSession(): void
    {
        // Создаем истекшую сессию
        $expiredSessionId = 'expired_session_' . time() . '_' . rand(1000, 9999);
        
        if (!isset($this->testUserId)) {
            $this->skip("Get expired session", "Нет тестового пользователя");
            return;
        }
        
        try {
            // Создаем сессию с истекшим временем (отрицательное время = истекшая)
            $this->db->createSession($expiredSessionId, $this->testUserId, -3600);
            
            $session = $this->db->getSession($expiredSessionId);
            
            if ($session === null) {
                $this->pass("Get expired session", "Истекшая сессия корректно не возвращается");
            } else {
                $this->fail("Get expired session", "Истекшая сессия не должна возвращаться");
            }
        } catch (Exception $e) {
            $this->fail("Get expired session", "Ошибка: " . $e->getMessage());
        }
    }
    
    private function testCleanupExpiredSessions(): void
    {
        try {
            $deletedCount = $this->db->cleanExpiredSessions();
            
            if ($deletedCount >= 0) { // Может быть 0, если нет истекших сессий
                $this->pass("Cleanup expired sessions", "Очистка истекших сессий прошла успешно (удалено: $deletedCount)");
            } else {
                $this->fail("Cleanup expired sessions", "Некорректный результат очистки");
            }
        } catch (Exception $e) {
            $this->fail("Cleanup expired sessions", "Ошибка очистки: " . $e->getMessage());
        }
        
        // Очищаем тестовые данные
        $this->cleanup();
    }
    
    private function cleanup(): void
    {
        try {
            $pdo = $this->db->getPdo();
            
            // Удаляем тестовые данные
            if (isset($this->testUserId)) {
                $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
                $stmt->execute([$this->testUserId]);
            }
            
            if (isset($this->testSessionId)) {
                $stmt = $pdo->prepare("DELETE FROM user_sessions WHERE session_id = ?");
                $stmt->execute([$this->testSessionId]);
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
        
        echo "\n📊 Результаты тестирования Database:\n";
        echo "✅ Пройдено: {$passed}\n";
        echo "❌ Провалено: {$failed}\n";
        echo "⏭️  Пропущено: {$skipped}\n";
        echo "📝 Всего: {$total}\n";
        
        if ($failed > 0) {
            echo "\n❌ ТЕСТЫ НЕ ПРОЙДЕНЫ! Есть ошибки в коде.\n";
            exit(1);
        } else {
            echo "\n🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ! Код работает корректно.\n";
        }
    }
}

// Запускаем тесты
new DatabaseTest();
