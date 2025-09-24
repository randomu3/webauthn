<?php

namespace WebAuthn;

/**
 * Утилиты для работы с устройствами
 */
class DeviceHelper
{
    /**
     * Проверяет, является ли устройство мобильным
     */
    public static function isMobileDevice(string $userAgent = null): bool
    {
        $userAgent = $userAgent ?? $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        $mobilePatterns = [
            '/iPhone/',
            '/iPad/',
            '/iPod/',
            '/Android.*Mobile/',
            '/Android.*Tablet/',
            '/Android/',
            '/BlackBerry/',
            '/Opera Mini/',
            '/IEMobile/',
            '/Mobile/'
        ];
        
        foreach ($mobilePatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Генерирует отпечаток устройства на основе различных параметров
     */
    public static function generateDeviceFingerprint(array $deviceData = []): string
    {
        $components = [
            $deviceData['userAgent'] ?? $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $deviceData['screenWidth'] ?? 'unknown',
            $deviceData['screenHeight'] ?? 'unknown',
            $deviceData['colorDepth'] ?? 'unknown',
            $deviceData['pixelRatio'] ?? 'unknown',
            $deviceData['timezone'] ?? 'unknown',
            $deviceData['platform'] ?? 'unknown',
            $deviceData['hardwareConcurrency'] ?? 'unknown',
            $deviceData['maxTouchPoints'] ?? 'unknown'
        ];
        
        $fingerprint = implode('|', $components);
        return hash('sha256', $fingerprint);
    }
    
    /**
     * Получает информацию об устройстве
     */
    public static function getDeviceInfo(string $userAgent = null): array
    {
        $userAgent = $userAgent ?? $_SERVER['HTTP_USER_AGENT'] ?? '';
        $isMobile = self::isMobileDevice($userAgent);
        
        return [
            'isMobile' => $isMobile,
            'supportsWebAuthn' => true, // Предполагаем поддержку для современных браузеров
            'hasBiometricSupport' => $isMobile,
            'isCompatible' => $isMobile,
            'userAgent' => $userAgent,
            'deviceType' => self::getDeviceType($userAgent),
            'browserName' => self::getBrowserName($userAgent)
        ];
    }
    
    private static function getDeviceType(string $userAgent): string
    {
        if (preg_match('/iPhone/', $userAgent)) {
            return 'iPhone';
        }
        if (preg_match('/iPad/', $userAgent)) {
            return 'iPad';
        }
        if (preg_match('/iPod/', $userAgent)) {
            return 'iPod';
        }
        if (preg_match('/Android.*Mobile/', $userAgent)) {
            return 'Android Phone';
        }
        if (preg_match('/Android.*Tablet/', $userAgent)) {
            return 'Android Tablet';
        }
        if (preg_match('/Android/', $userAgent)) {
            return 'Android Device';
        }
        
        return 'Unknown';
    }
    
    private static function getBrowserName(string $userAgent): string
    {
        if (preg_match('/Chrome/', $userAgent)) {
            return 'Chrome';
        }
        if (preg_match('/Firefox/', $userAgent)) {
            return 'Firefox';
        }
        if (preg_match('/Safari/', $userAgent) && !preg_match('/Chrome/', $userAgent)) {
            return 'Safari';
        }
        if (preg_match('/Edge/', $userAgent)) {
            return 'Edge';
        }
        
        return 'Unknown';
    }
}
