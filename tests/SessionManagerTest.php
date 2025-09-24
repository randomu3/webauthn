<?php
/**
 * Тесты для класса SessionManager
 * Проверяют функциональность управления сессиями
 */

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/SessionManager.php';

use WebAuthn\Database;
use WebAuthn\SessionManager;

class SessionManagerTest
{
    private Database $db;
    private SessionManager $sessionManager;
    private array $testResults = [];
    private array $createdSessions = [];
    private array $createdUsers = [];
    
    public function __construct()
    {
        echo "🧪 Запуск тестов SessionManager класса...\n\n";
        
        try {
            $this->db = new Database();
            $this->sessionManager = new SessionManager($this->db);
        } catch (Exception $e) {
            $this->fail("SessionManager initialization", "Не удалось инициализировать SessionManager: " . $e->getMessage());
            return;
        }
        
        $this->runAllTests();
        $this->cleanup();
        $this->printResults();
    }
    
    private function runAllTests(): void
    {
        $this->testInitialization();
        $this->testCreateSession();
        $this->testIsUserLoggedInWithValidSession();
        $this->testIsUserLoggedInWithInvalidSession();
        $this->testIsUserLoggedInWithoutSession();
        $this->testGetCurrentUserId();
        $this->testDestroySession();
        $this->testRegistrationDataFlow();
        $this->testAuthChallengeFlow();
        $this->testSessionPersistence();
        $this->testMultipleSessionsForSameUser();
        $this->testExpiredSessionHandling();
        $this->testSessionDataSafety();
        $this->testEdgeCases();
    }
    
    private function testInitialization(): void
    {
        if ($this->sessionManager instanceof SessionManager) {
            $this->pass("Initialization", "SessionManager инициализирован корректно");
        } else {
            $this->fail("Initialization", "SessionManager должен быть инициализирован корректно");
        }
        
        // Проверяем, что сессия PHP запущена или может быть запущена
        if (session_status() === PHP_SESSION_ACTIVE || session_status() === PHP_SESSION_NONE) {
            $this->pass("PHP session", "PHP сессия в рабочем состоянии");
        } else {
            $this->fail("PHP session", "PHP сессия должна быть в рабочем состоянии");
        }
    }
    
    private function testCreateSession(): void
    {
        $testUserId = 'test_user_' . time() . '_' . rand(1000, 9999);
        
        // Создаем тестового пользователя
        $userHandle = random_bytes(32);
        if (!$this->db->createUser($testUserId, $userHandle)) {
            $this->fail("Create session setup", "Не удалось создать тестового пользователя");
            return;
        }
        $this->createdUsers[] = $testUserId;
        
        try {
            $sessionId = $this->sessionManager->createSession($testUserId);
            $this->createdSessions[] = $sessionId;
            
            if (is_string($sessionId) && strlen($sessionId) === 32) {
                $this->pass("Create session", "Сессия создана с корректным ID");
                
                // Проверяем, что данные сохранены в PHP сессии
                if ($_SESSION['user_id'] === $testUserId && $_SESSION['session_id'] === $sessionId) {
                    $this->pass("Create session PHP data", "Данные сессии сохранены в PHP сессии");
                } else {
                    $this->fail("Create session PHP data", "Данные сессии должны сохраняться в PHP сессии");
                }
            } else {
                $this->fail("Create session", "Session ID должен быть строкой длиной 32 символа");
            }
        } catch (Exception $e) {
            $this->fail("Create session", "Ошибка создания сессии: " . $e->getMessage());
        }
    }
    
    private function testIsUserLoggedInWithValidSession(): void
    {
        if (empty($this->createdSessions)) {
            $this->skip("Valid session check", "Нет созданных сессий");
            return;
        }
        
        // Используем существующую валидную сессию
        $isLoggedIn = $this->sessionManager->isUserLoggedIn();
        
        if ($isLoggedIn === true) {
            $this->pass("Valid session check", "Валидная сессия корректно определяется");
        } else {
            $this->fail("Valid session check", "Валидная сессия должна определяться корректно");
        }
    }
    
    private function testIsUserLoggedInWithInvalidSession(): void
    {
        // Сохраняем текущие данные сессии
        $originalUserId = $_SESSION['user_id'] ?? null;
        $originalSessionId = $_SESSION['session_id'] ?? null;
        
        // Устанавливаем несуществующую сессию
        $_SESSION['user_id'] = 'nonexistent_user';
        $_SESSION['session_id'] = 'nonexistent_session_id';
        
        $isLoggedIn = $this->sessionManager->isUserLoggedIn();
        
        if ($isLoggedIn === false) {
            $this->pass("Invalid session check", "Несуществующая сессия корректно отклоняется");
        } else {
            $this->fail("Invalid session check", "Несуществующая сессия должна отклоняться");
        }
        
        // Восстанавливаем оригинальные данные
        if ($originalUserId !== null) {
            $_SESSION['user_id'] = $originalUserId;
        } else {
            unset($_SESSION['user_id']);
        }
        
        if ($originalSessionId !== null) {
            $_SESSION['session_id'] = $originalSessionId;
        } else {
            unset($_SESSION['session_id']);
        }
    }
    
    private function testIsUserLoggedInWithoutSession(): void
    {
        // Сохраняем текущие данные сессии
        $originalUserId = $_SESSION['user_id'] ?? null;
        $originalSessionId = $_SESSION['session_id'] ?? null;
        
        // Удаляем данные сессии
        unset($_SESSION['user_id'], $_SESSION['session_id']);
        
        $isLoggedIn = $this->sessionManager->isUserLoggedIn();
        
        if ($isLoggedIn === false) {
            $this->pass("No session check", "Отсутствие сессии корректно определяется");
        } else {
            $this->fail("No session check", "Отсутствие сессии должно определяться корректно");
        }
        
        // Восстанавливаем оригинальные данные
        if ($originalUserId !== null) {
            $_SESSION['user_id'] = $originalUserId;
        }
        if ($originalSessionId !== null) {
            $_SESSION['session_id'] = $originalSessionId;
        }
    }
    
    private function testGetCurrentUserId(): void
    {
        if (!empty($this->createdUsers)) {
            $userId = $this->sessionManager->getCurrentUserId();
            
            if ($userId === $this->createdUsers[0]) {
                $this->pass("Get current user ID", "ID текущего пользователя возвращается корректно");
            } else {
                $this->fail("Get current user ID", "ID текущего пользователя должен возвращаться корректно");
            }
        } else {
            $this->skip("Get current user ID", "Нет созданных пользователей");
        }
    }
    
    private function testDestroySession(): void
    {
        if (empty($this->createdSessions)) {
            $this->skip("Destroy session", "Нет созданных сессий");
            return;
        }
        
        $sessionId = $this->createdSessions[0];
        
        try {
            $this->sessionManager->destroySession();
            
            // Проверяем, что сессия удалена из БД
            $session = $this->db->getSession($sessionId);
            
            if ($session === null) {
                $this->pass("Destroy session DB", "Сессия удалена из БД");
            } else {
                $this->fail("Destroy session DB", "Сессия должна быть удалена из БД");
            }
            
            // Удаляем из списка созданных сессий
            $this->createdSessions = array_filter($this->createdSessions, fn($id) => $id !== $sessionId);
            
        } catch (Exception $e) {
            $this->fail("Destroy session", "Ошибка уничтожения сессии: " . $e->getMessage());
        }
    }
    
    private function testRegistrationDataFlow(): void
    {
        $challenge = 'test_challenge_' . time();
        $userId = 'test_reg_user_' . time();
        $userHandle = 'test_reg_handle_' . time();
        
        // Сохраняем данные регистрации
        $this->sessionManager->saveRegistrationData($challenge, $userId, $userHandle);
        
        // Получаем данные регистрации
        $regData = $this->sessionManager->getRegistrationData();
        
        if ($regData && 
            $regData['challenge'] === $challenge && 
            $regData['userId'] === $userId && 
            $regData['userHandle'] === $userHandle) {
            $this->pass("Registration data flow", "Данные регистрации сохраняются и возвращаются корректно");
        } else {
            $this->fail("Registration data flow", "Данные регистрации должны сохраняться и возвращаться корректно");
        }
        
        // Очищаем данные регистрации
        $this->sessionManager->clearRegistrationData();
        $regDataAfterClear = $this->sessionManager->getRegistrationData();
        
        if ($regDataAfterClear === null) {
            $this->pass("Registration data clear", "Данные регистрации корректно очищаются");
        } else {
            $this->fail("Registration data clear", "Данные регистрации должны корректно очищаться");
        }
    }
    
    private function testAuthChallengeFlow(): void
    {
        $challenge = 'test_auth_challenge_' . time();
        
        // Сохраняем challenge аутентификации
        $this->sessionManager->saveAuthChallenge($challenge);
        
        // Получаем challenge аутентификации
        $retrievedChallenge = $this->sessionManager->getAuthChallenge();
        
        if ($retrievedChallenge === $challenge) {
            $this->pass("Auth challenge flow", "Challenge аутентификации сохраняется и возвращается корректно");
        } else {
            $this->fail("Auth challenge flow", "Challenge аутентификации должен сохраняться и возвращаться корректно");
        }
        
        // Очищаем challenge аутентификации
        $this->sessionManager->clearAuthChallenge();
        $challengeAfterClear = $this->sessionManager->getAuthChallenge();
        
        if ($challengeAfterClear === null) {
            $this->pass("Auth challenge clear", "Challenge аутентификации корректно очищается");
        } else {
            $this->fail("Auth challenge clear", "Challenge аутентификации должен корректно очищаться");
        }
    }
    
    private function testSessionPersistence(): void
    {
        $testUserId = 'test_persistence_user_' . time();
        $userHandle = random_bytes(32);
        
        // Создаем тестового пользователя
        if (!$this->db->createUser($testUserId, $userHandle)) {
            $this->fail("Session persistence setup", "Не удалось создать пользователя для теста");
            return;
        }
        $this->createdUsers[] = $testUserId;
        
        try {
            // Создаем сессию
            $sessionId = $this->sessionManager->createSession($testUserId);
            $this->createdSessions[] = $sessionId;
            
            // Проверяем, что сессия существует в БД
            $session = $this->db->getSession($sessionId);
            
            if ($session && $session['user_id'] === $testUserId) {
                $this->pass("Session persistence", "Сессия корректно сохраняется в БД");
            } else {
                $this->fail("Session persistence", "Сессия должна корректно сохраняться в БД");
            }
            
        } catch (Exception $e) {
            $this->fail("Session persistence", "Ошибка теста персистентности: " . $e->getMessage());
        }
    }
    
    private function testMultipleSessionsForSameUser(): void
    {
        $testUserId = 'test_multiple_user_' . time();
        $userHandle = random_bytes(32);
        
        // Создаем тестового пользователя
        if (!$this->db->createUser($testUserId, $userHandle)) {
            $this->fail("Multiple sessions setup", "Не удалось создать пользователя для теста");
            return;
        }
        $this->createdUsers[] = $testUserId;
        
        try {
            // Создаем несколько сессий для одного пользователя
            $sessionId1 = $this->sessionManager->createSession($testUserId);
            
            // Очищаем PHP сессию чтобы создать новую
            unset($_SESSION['user_id'], $_SESSION['session_id']);
            
            $sessionId2 = $this->sessionManager->createSession($testUserId);
            
            $this->createdSessions[] = $sessionId1;
            $this->createdSessions[] = $sessionId2;
            
            if ($sessionId1 !== $sessionId2) {
                $this->pass("Multiple sessions", "Можно создать несколько сессий для одного пользователя");
                
                // Проверяем, что обе сессии существуют в БД
                $session1 = $this->db->getSession($sessionId1);
                $session2 = $this->db->getSession($sessionId2);
                
                if ($session1 && $session2) {
                    $this->pass("Multiple sessions DB", "Несколько сессий корректно сохраняются в БД");
                } else {
                    $this->fail("Multiple sessions DB", "Несколько сессий должны корректно сохраняться в БД");
                }
            } else {
                $this->fail("Multiple sessions", "Разные сессии должны иметь разные ID");
            }
            
        } catch (Exception $e) {
            $this->fail("Multiple sessions", "Ошибка теста множественных сессий: " . $e->getMessage());
        }
    }
    
    private function testExpiredSessionHandling(): void
    {
        $testUserId = 'test_expired_user_' . time();
        $userHandle = random_bytes(32);
        
        // Создаем тестового пользователя
        if (!$this->db->createUser($testUserId, $userHandle)) {
            $this->fail("Expired session setup", "Не удалось создать пользователя для теста");
            return;
        }
        $this->createdUsers[] = $testUserId;
        
        try {
            // Создаем истекшую сессию напрямую в БД
            $expiredSessionId = 'expired_' . bin2hex(random_bytes(8));
            $result = $this->db->createSession($expiredSessionId, $testUserId, -3600); // Истекла час назад
            
            if ($result) {
                // Устанавливаем истекшую сессию в PHP сессии
                $_SESSION['user_id'] = $testUserId;
                $_SESSION['session_id'] = $expiredSessionId;
                
                // Проверяем, что SessionManager не считает пользователя авторизованным
                $isLoggedIn = $this->sessionManager->isUserLoggedIn();
                
                if ($isLoggedIn === false) {
                    $this->pass("Expired session handling", "Истекшие сессии корректно отклоняются");
                } else {
                    $this->fail("Expired session handling", "Истекшие сессии должны отклоняться");
                }
                
                // Очищаем тестовые данные из PHP сессии
                unset($_SESSION['user_id'], $_SESSION['session_id']);
            } else {
                $this->skip("Expired session handling", "Не удалось создать истекшую сессию");
            }
            
        } catch (Exception $e) {
            $this->fail("Expired session handling", "Ошибка теста истекших сессий: " . $e->getMessage());
        }
    }
    
    private function testSessionDataSafety(): void
    {
        // Тест с потенциально опасными данными
        $dangerousData = [
            'xss' => '<script>alert("xss")</script>',
            'sql' => "'; DROP TABLE users; --",
            'null_bytes' => "test\x00null",
            'long_string' => str_repeat('A', 1000)
        ];
        
        foreach ($dangerousData as $type => $data) {
            try {
                $this->sessionManager->saveRegistrationData($data, $data, $data);
                $regData = $this->sessionManager->getRegistrationData();
                
                if ($regData && 
                    $regData['challenge'] === $data && 
                    $regData['userId'] === $data && 
                    $regData['userHandle'] === $data) {
                    $this->pass("Session data safety $type", "Опасные данные ($type) безопасно сохраняются");
                } else {
                    $this->fail("Session data safety $type", "Ошибка безопасного сохранения ($type)");
                }
                
                $this->sessionManager->clearRegistrationData();
                
            } catch (Exception $e) {
                $this->fail("Session data safety $type", "Ошибка при тесте безопасности ($type): " . $e->getMessage());
            }
        }
    }
    
    private function testEdgeCases(): void
    {
        // Тест с пустыми строками
        try {
            $this->sessionManager->saveRegistrationData('', '', '');
            $regData = $this->sessionManager->getRegistrationData();
            
            if ($regData && 
                $regData['challenge'] === '' && 
                $regData['userId'] === '' && 
                $regData['userHandle'] === '') {
                $this->pass("Edge case empty strings", "Пустые строки корректно обрабатываются");
            } else {
                $this->fail("Edge case empty strings", "Пустые строки должны корректно обрабатываться");
            }
            
            $this->sessionManager->clearRegistrationData();
            
        } catch (Exception $e) {
            $this->fail("Edge case empty strings", "Ошибка при тесте пустых строк: " . $e->getMessage());
        }
        
        // Тест множественной очистки
        try {
            $this->sessionManager->clearRegistrationData();
            $this->sessionManager->clearRegistrationData(); // Повторная очистка
            $this->sessionManager->clearAuthChallenge();
            $this->sessionManager->clearAuthChallenge(); // Повторная очистка
            
            $this->pass("Edge case multiple clears", "Множественная очистка не вызывает ошибок");
            
        } catch (Exception $e) {
            $this->fail("Edge case multiple clears", "Ошибка при множественной очистке: " . $e->getMessage());
        }
    }
    
    private function cleanup(): void
    {
        try {
            $pdo = $this->db->getPdo();
            
            // Удаляем тестовые сессии
            foreach ($this->createdSessions as $sessionId) {
                $stmt = $pdo->prepare("DELETE FROM user_sessions WHERE session_id = ?");
                $stmt->execute([$sessionId]);
            }
            
            // Удаляем тестовых пользователей
            foreach ($this->createdUsers as $userId) {
                $stmt = $pdo->prepare("DELETE FROM users WHERE user_id = ?");
                $stmt->execute([$userId]);
            }
            
        } catch (Exception $e) {
            echo "⚠️  Ошибка очистки тестовых данных SessionManager: " . $e->getMessage() . "\n";
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
        
        echo "\n📊 Результаты тестирования SessionManager:\n";
        echo "✅ Пройдено: {$passed}\n";
        echo "❌ Провалено: {$failed}\n";
        echo "⏭️  Пропущено: {$skipped}\n";
        echo "📝 Всего: {$total}\n";
        
        if ($failed > 0) {
            echo "\n❌ ТЕСТЫ SessionManager НЕ ПРОЙДЕНЫ!\n";
            exit(1);
        } else {
            echo "\n🎉 ВСЕ ТЕСТЫ SessionManager ПРОЙДЕНЫ!\n";
        }
    }
}

// Запускаем тесты
new SessionManagerTest();
