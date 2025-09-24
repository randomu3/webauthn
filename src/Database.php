<?php

namespace WebAuthn;

use PDO;
use PDOException;

class Database
{
    private PDO $pdo;

    public function __construct()
    {
        $host = $_ENV['DB_HOST'] ?? 'db';
        $dbname = $_ENV['DB_NAME'] ?? 'webauthn_db';
        $username = $_ENV['DB_USER'] ?? 'webauthn_user';
        $password = $_ENV['DB_PASS'] ?? 'webauthn_pass';

        $dsn = "mysql:host={$host};dbname={$dbname};charset=utf8mb4";

        try {
            $this->pdo = new PDO($dsn, $username, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            throw new \Exception("Database connection failed: " . $e->getMessage());
        }
    }

    public function getPdo(): PDO
    {
        return $this->pdo;
    }

    public function createUser(string $userId, string $userHandle): bool
    {
        try {
            $stmt = $this->pdo->prepare("INSERT INTO users (user_id, user_handle) VALUES (?, ?)");
            return $stmt->execute([$userId, $userHandle]);
        } catch (PDOException $e) {
            return false;
        }
    }

    public function getUser(string $userId): ?array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE user_id = ?");
        $stmt->execute([$userId]);
        $result = $stmt->fetch();
        return $result ?: null;
    }

    public function saveCredential(string $userId, string $credentialId, string $publicKey): bool
    {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO user_credentials (user_id, credential_id, credential_public_key) 
                VALUES (?, ?, ?)
            ");
            return $stmt->execute([$userId, $credentialId, $publicKey]);
        } catch (PDOException $e) {
            return false;
        }
    }

    public function getCredential(string $credentialId): ?array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM user_credentials WHERE credential_id = ?");
        $stmt->execute([$credentialId]);
        $result = $stmt->fetch();
        return $result ?: null;
    }

    public function getUserCredentials(string $userId): array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM user_credentials WHERE user_id = ?");
        $stmt->execute([$userId]);
        return $stmt->fetchAll();
    }

    public function updateCredentialCounter(string $credentialId, int $counter): bool
    {
        try {
            $stmt = $this->pdo->prepare("
                UPDATE user_credentials 
                SET counter = ?, last_used_at = CURRENT_TIMESTAMP 
                WHERE credential_id = ?
            ");
            return $stmt->execute([$counter, $credentialId]);
        } catch (PDOException $e) {
            return false;
        }
    }

    public function createSession(string $sessionId, string $userId, int $expiresInSeconds = 3600): bool
    {
        try {
            $expiresAt = date('Y-m-d H:i:s', time() + $expiresInSeconds);
            $stmt = $this->pdo->prepare("
                INSERT INTO user_sessions (session_id, user_id, expires_at) 
                VALUES (?, ?, ?)
            ");
            return $stmt->execute([$sessionId, $userId, $expiresAt]);
        } catch (PDOException $e) {
            return false;
        }
    }

    public function getSession(string $sessionId): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM user_sessions 
            WHERE session_id = ? AND expires_at > NOW()
        ");
        $stmt->execute([$sessionId]);
        $result = $stmt->fetch();
        return $result ?: null;
    }

    public function deleteSession(string $sessionId): bool
    {
        try {
            $stmt = $this->pdo->prepare("DELETE FROM user_sessions WHERE session_id = ?");
            return $stmt->execute([$sessionId]);
        } catch (PDOException $e) {
            return false;
        }
    }

    public function cleanExpiredSessions(): int
    {
        $stmt = $this->pdo->prepare("DELETE FROM user_sessions WHERE expires_at <= NOW()");
        $stmt->execute();
        return $stmt->rowCount();
    }
}
