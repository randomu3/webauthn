<?php

namespace WebAuthn;

/**
 * Утилиты для работы с WebAuthn
 */
class WebAuthnHelper
{
    /**
     * Конвертирует base64url в обычный base64
     */
    public static function base64urlDecode(string $data): string
    {
        // Заменяем URL-safe символы обратно
        $data = str_replace(['-', '_'], ['+', '/'], $data);
        
        // Добавляем padding если нужно
        $pad = strlen($data) % 4;
        if ($pad) {
            $data .= str_repeat('=', 4 - $pad);
        }
        
        return base64_decode($data);
    }
    
    /**
     * Конвертирует в base64url
     */
    public static function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    /**
     * Генерирует challenge для WebAuthn
     */
    public static function generateChallenge(): string
    {
        require_once __DIR__ . '/WebAuthnSecurity.php';
        return WebAuthnSecurity::generateSecureChallenge(32);
    }
    
    /**
     * Создает параметры для регистрации WebAuthn
     */
    public static function createRegistrationOptions(string $userId, string $userHandle, array $excludeCredentials = []): array
    {
        $challenge = self::generateChallenge();
        
        $rp = ['name' => $_ENV['WEBAUTHN_RP_NAME'] ?? 'WebAuthn Demo'];
        $rpId = self::getRpId();
        if ($rpId !== null) {
            $rp['id'] = $rpId;
        }
        
        return [
            'rp' => $rp,
            'user' => [
                'id' => self::base64urlEncode($userHandle),
                'name' => 'Device-' . substr($userId, 0, 8),
                'displayName' => 'Device User'
            ],
            'challenge' => self::base64urlEncode($challenge),
            'pubKeyCredParams' => [
                ['type' => 'public-key', 'alg' => -7],   // ES256
                ['type' => 'public-key', 'alg' => -257]  // RS256
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
        ];
    }
    
    /**
     * Создает параметры для аутентификации WebAuthn
     */
    public static function createAuthenticationOptions(array $allowCredentials = []): array
    {
        $challenge = self::generateChallenge();
        
        $options = [
            'challenge' => self::base64urlEncode($challenge),
            'timeout' => 60000,
            'allowCredentials' => $allowCredentials,
            'userVerification' => 'required'
        ];
        
        $rpId = self::getRpId();
        if ($rpId !== null) {
            $options['rpId'] = $rpId;
        }
        
        return $options;
    }
    
    /**
     * Проверяет challenge в ответе WebAuthn
     */
    public static function verifyChallenge(string $clientDataJSON, string $expectedChallenge): bool
    {
        $clientDataJSON = self::base64urlDecode($clientDataJSON);
        $clientData = json_decode($clientDataJSON, true);
        
        if (!$clientData || !isset($clientData['challenge'])) {
            return false;
        }
        
        return $clientData['challenge'] === $expectedChallenge;
    }
    
    /**
     * Генерирует пользователя на основе отпечатка устройства
     */
    public static function generateUserFromDevice(string $deviceId): array
    {
        $userId = substr($deviceId, 0, 16); // Используем первые 16 символов хеша
        $userHandle = hex2bin($userId . str_pad('', 16, '0')); // Дополняем до 16 байт
        
        return [
            'userId' => $userId,
            'userHandle' => $userHandle
        ];
    }
    
    /**
     * Получает корректный RP ID для WebAuthn
     */
    private static function getRpId(): ?string
    {
        // Если задан в переменных окружения - используем его, НО только если это не localhost
        if (!empty($_ENV['WEBAUTHN_RP_ID'])) {
            $envRpId = $_ENV['WEBAUTHN_RP_ID'];
            // Игнорируем localhost из переменных окружения для локальной разработки
            if ($envRpId !== 'localhost' && $envRpId !== '127.0.0.1') {
                return $envRpId;
            }
        }
        
        $host = $_SERVER['HTTP_HOST'] ?? '';
        
        // Если HTTP_HOST не установлен или это localhost/IP - не указываем rpId
        if (empty($host) || 
            $host === 'localhost' || 
            $host === '127.0.0.1' || 
            filter_var($host, FILTER_VALIDATE_IP) !== false ||
            strpos($host, 'localhost:') === 0 ||
            strpos($host, '127.0.0.1:') === 0) {
            return null; // Браузер сам определит корректный rpId
        }
        
        // Для реальных доменов возвращаем хост
        return $host;
    }
}
