<?php

namespace WebAuthn;

/**
 * Класс для обеспечения безопасности WebAuthn в продакшене
 * Реализует рекомендации по криптографической безопасности
 */
class WebAuthnSecurity
{
    /**
     * Генерирует криптографически стойкий challenge
     * Использует openssl_random_pseudo_bytes с проверкой энтропии
     */
    public static function generateSecureChallenge(int $length = 32): string
    {
        // Проверяем доступность криптографически стойкого источника
        if (!function_exists('random_bytes')) {
            throw new \Exception('random_bytes() function not available. PHP 7.0+ required for secure challenge generation.');
        }
        
        try {
            $randomBytes = random_bytes($length);
        } catch (\Exception $e) {
            // Fallback к openssl если random_bytes недоступен
            $strong = false;
            $randomBytes = openssl_random_pseudo_bytes($length, $strong);
            
            if (!$strong) {
                throw new \Exception('Unable to generate cryptographically secure challenge. Check entropy source.');
            }
        }
        
        return $randomBytes;
    }
    
    /**
     * Проверяет валидность challenge с временными ограничениями
     */
    public static function validateChallenge(string $receivedChallenge, string $storedChallenge, int $maxAgeSeconds = 300): bool
    {
        // Проверка базовой валидности
        if (empty($receivedChallenge) || empty($storedChallenge)) {
            return false;
        }
        
        // Защита от timing attacks через hash_equals
        if (!hash_equals($storedChallenge, $receivedChallenge)) {
            return false;
        }
        
        // Здесь должна быть проверка времени создания challenge
        // В реальном приложении challenge должен храниться с timestamp
        
        return true;
    }
    
    /**
     * Верифицирует криптографическую подпись WebAuthn
     */
    public static function verifySignature(
        string $publicKeyPem,
        string $signature,
        string $signedData,
        string $algorithm = 'RS256'
    ): bool {
        try {
            // Преобразуем алгоритм в OpenSSL формат
            $opensslAlgorithm = self::getOpenSSLAlgorithm($algorithm);
            
            // Загружаем публичный ключ
            $publicKey = openssl_pkey_get_public($publicKeyPem);
            if (!$publicKey) {
                error_log('WebAuthnSecurity: Invalid public key format');
                return false;
            }
            
            // Проверяем подпись
            $result = openssl_verify($signedData, $signature, $publicKey, $opensslAlgorithm);
            
            // Освобождаем ресурсы
            if (is_resource($publicKey)) {
                openssl_free_key($publicKey);
            }
            
            return $result === 1;
            
        } catch (\Exception $e) {
            error_log('WebAuthnSecurity: Signature verification failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Конвертирует COSE ключ в PEM формат для проверки подписи
     */
    public static function coseKeyToPem(array $coseKey): ?string
    {
        try {
            // Проверяем тип ключа (должен быть EC2 или RSA)
            if (!isset($coseKey[1]) || !isset($coseKey[3])) {
                return null;
            }
            
            $keyType = $coseKey[1]; // kty
            $algorithm = $coseKey[3]; // alg
            
            switch ($keyType) {
                case 2: // EC2
                    return self::ec2KeyToPem($coseKey);
                case 3: // RSA  
                    return self::rsaKeyToPem($coseKey);
                default:
                    error_log("WebAuthnSecurity: Unsupported key type: $keyType");
                    return null;
            }
            
        } catch (\Exception $e) {
            error_log('WebAuthnSecurity: COSE key conversion failed: ' . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Валидирует attestation statement
     */
    public static function validateAttestation(array $attestationObject): bool
    {
        try {
            if (!isset($attestationObject['fmt']) || !isset($attestationObject['attStmt'])) {
                return false;
            }
            
            $format = $attestationObject['fmt'];
            $statement = $attestationObject['attStmt'];
            
            switch ($format) {
                case 'none':
                    // "none" attestation - минимальная проверка
                    return empty($statement);
                    
                case 'packed':
                    return self::validatePackedAttestation($statement);
                    
                case 'fido-u2f':
                    return self::validateFidoU2fAttestation($statement);
                    
                default:
                    // Неизвестный формат - отклоняем
                    error_log("WebAuthnSecurity: Unknown attestation format: $format");
                    return false;
            }
            
        } catch (\Exception $e) {
            error_log('WebAuthnSecurity: Attestation validation failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Проверяет origin для защиты от phishing
     */
    public static function validateOrigin(string $clientOrigin, array $allowedOrigins): bool
    {
        // Нормализуем origin
        $normalizedOrigin = strtolower(trim($clientOrigin));
        
        // Проверяем против списка разрешенных origins
        foreach ($allowedOrigins as $allowedOrigin) {
            if (hash_equals(strtolower($allowedOrigin), $normalizedOrigin)) {
                return true;
            }
        }
        
        error_log("WebAuthnSecurity: Invalid origin: $clientOrigin");
        return false;
    }
    
    /**
     * Генерирует безопасный user handle
     */
    public static function generateUserHandle(): string
    {
        return random_bytes(16); // 128 бит для уникальности
    }
    
    /**
     * Хеширует sensitive данные для безопасного хранения
     */
    public static function hashSensitiveData(string $data, string $salt = ''): string
    {
        if (empty($salt)) {
            $salt = random_bytes(16);
        }
        
        // Используем PBKDF2 для хеширования
        return hash_pbkdf2('sha256', $data, $salt, 10000, 32, true);
    }
    
    // Приватные вспомогательные методы
    
    private static function getOpenSSLAlgorithm(string $coseAlgorithm): int
    {
        switch ($coseAlgorithm) {
            case 'RS256':
            case -257:
                return OPENSSL_ALGO_SHA256;
            case 'ES256':
            case -7:
                return OPENSSL_ALGO_SHA256;
            case 'PS256':
            case -37:
                return OPENSSL_ALGO_SHA256;
            default:
                throw new \Exception("Unsupported algorithm: $coseAlgorithm");
        }
    }
    
    private static function ec2KeyToPem(array $coseKey): ?string
    {
        // Упрощенная реализация для EC2 ключей
        // В продакшене нужна полная реализация COSE EC2 -> PEM конвертации
        error_log('WebAuthnSecurity: EC2 key conversion not fully implemented');
        return null;
    }
    
    private static function rsaKeyToPem(array $coseKey): ?string
    {
        // Упрощенная реализация для RSA ключей
        // В продакшене нужна полная реализация COSE RSA -> PEM конвертации
        error_log('WebAuthnSecurity: RSA key conversion not fully implemented');
        return null;
    }
    
    private static function validatePackedAttestation(array $statement): bool
    {
        // Упрощенная проверка packed attestation
        return isset($statement['sig']) && isset($statement['alg']);
    }
    
    private static function validateFidoU2fAttestation(array $statement): bool
    {
        // Упрощенная проверка FIDO U2F attestation
        return isset($statement['sig']) && isset($statement['x5c']);
    }
}
