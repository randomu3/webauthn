<?php

namespace WebAuthn;

class DeviceDetector
{
    private string $userAgent;

    public function __construct(string $userAgent = null)
    {
        $this->userAgent = $userAgent ?? $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    public function isMobileDevice(): bool
    {
        // Проверяем на мобильные устройства с поддержкой биометрии
        $mobilePatterns = [
            // iOS устройства
            '/iPhone/',
            '/iPad/',
            '/iPod/',
            
            // Android устройства
            '/Android.*Mobile/',
            '/Android.*Tablet/',
            
            // Windows Mobile
            '/Windows Phone/',
            '/Windows Mobile/',
            
            // Другие мобильные устройства
            '/BlackBerry/',
            '/webOS/',
            '/Opera Mini/',
            '/IEMobile/'
        ];

        foreach ($mobilePatterns as $pattern) {
            if (preg_match($pattern, $this->userAgent)) {
                return true;
            }
        }

        return false;
    }

    public function supportsWebAuthn(): bool
    {
        // Проверяем поддержку WebAuthn по User Agent
        // WebAuthn поддерживается в современных браузерах
        
        // Chrome 67+, Firefox 60+, Safari 14+, Edge 18+
        if (preg_match('/Chrome\/(\d+)/', $this->userAgent, $matches)) {
            return (int)$matches[1] >= 67;
        }
        
        if (preg_match('/Firefox\/(\d+)/', $this->userAgent, $matches)) {
            return (int)$matches[1] >= 60;
        }
        
        if (preg_match('/Safari\/(\d+)/', $this->userAgent, $matches)) {
            // Safari поддержка WebAuthn начиная с iOS 14 и macOS Big Sur
            return preg_match('/Version\/(1[4-9]|[2-9]\d)/', $this->userAgent);
        }
        
        if (preg_match('/Edge\/(\d+)/', $this->userAgent, $matches)) {
            return (int)$matches[1] >= 18;
        }

        // Для неопознанных браузеров предполагаем поддержку
        return true;
    }

    public function hasBiometricSupport(): bool
    {
        // Проверяем на устройства с биометрической поддержкой
        if (!$this->isMobileDevice()) {
            return false;
        }

        // iOS устройства с Touch ID / Face ID
        if (preg_match('/iPhone|iPad|iPod/', $this->userAgent)) {
            // Touch ID появился в iPhone 5s (iOS 7+)
            // Face ID появился в iPhone X (iOS 11+)
            return true;
        }

        // Android устройства с отпечатками пальцев
        if (preg_match('/Android/', $this->userAgent)) {
            // Большинство современных Android устройств поддерживают биометрию
            // Проверяем версию Android (6.0+ для Fingerprint API)
            if (preg_match('/Android (\d+)\.(\d+)/', $this->userAgent, $matches)) {
                $majorVersion = (int)$matches[1];
                return $majorVersion >= 6;
            }
            return true; // Предполагаем поддержку для неопознанных версий
        }

        return false;
    }

    public function getDeviceInfo(): array
    {
        $isMobile = $this->isMobileDevice();
        $supportsWebAuthn = $this->supportsWebAuthn();
        $hasBiometric = $this->hasBiometricSupport();

        return [
            'isMobile' => $isMobile,
            'supportsWebAuthn' => $supportsWebAuthn,
            'hasBiometricSupport' => $hasBiometric,
            'isCompatible' => $isMobile && $supportsWebAuthn && $hasBiometric,
            'userAgent' => $this->userAgent,
            'deviceType' => $this->getDeviceType(),
            'browserName' => $this->getBrowserName()
        ];
    }

    private function getDeviceType(): string
    {
        if (preg_match('/iPhone/', $this->userAgent)) {
            return 'iPhone';
        }
        if (preg_match('/iPad/', $this->userAgent)) {
            return 'iPad';
        }
        if (preg_match('/iPod/', $this->userAgent)) {
            return 'iPod';
        }
        if (preg_match('/Android.*Mobile/', $this->userAgent)) {
            return 'Android Phone';
        }
        if (preg_match('/Android.*Tablet/', $this->userAgent)) {
            return 'Android Tablet';
        }
        if (preg_match('/Android/', $this->userAgent)) {
            return 'Android Device';
        }
        
        return 'Unknown';
    }

    private function getBrowserName(): string
    {
        if (preg_match('/Chrome/', $this->userAgent)) {
            return 'Chrome';
        }
        if (preg_match('/Firefox/', $this->userAgent)) {
            return 'Firefox';
        }
        if (preg_match('/Safari/', $this->userAgent) && !preg_match('/Chrome/', $this->userAgent)) {
            return 'Safari';
        }
        if (preg_match('/Edge/', $this->userAgent)) {
            return 'Edge';
        }
        
        return 'Unknown';
    }

    public static function blockNonMobileDevices(): void
    {
        $detector = new self();
        $deviceInfo = $detector->getDeviceInfo();

        if (!$deviceInfo['isCompatible']) {
            http_response_code(403);
            
            $errorMessage = '';
            if (!$deviceInfo['isMobile']) {
                $errorMessage = 'Доступ разрешен только с мобильных устройств';
            } elseif (!$deviceInfo['supportsWebAuthn']) {
                $errorMessage = 'Ваш браузер не поддерживает WebAuthn';
            } elseif (!$deviceInfo['hasBiometricSupport']) {
                $errorMessage = 'Ваше устройство не поддерживает биометрическую аутентификацию';
            }

            $html = '<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Доступ запрещен</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-align: center;
            padding: 20px;
        }
        .container {
            max-width: 400px;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        h1 {
            font-size: 24px;
            margin-bottom: 20px;
        }
        p {
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .device-info {
            font-size: 12px;
            opacity: 0.7;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 Доступ запрещен</h1>
        <p>' . htmlspecialchars($errorMessage) . '</p>
        <p>Это приложение предназначено для тестирования биометрической аутентификации на мобильных устройствах.</p>
        <div class="device-info">
            Устройство: ' . htmlspecialchars($deviceInfo['deviceType']) . '<br>
            Браузер: ' . htmlspecialchars($deviceInfo['browserName']) . '<br>
            Поддержка WebAuthn: ' . ($deviceInfo['supportsWebAuthn'] ? 'Да' : 'Нет') . '<br>
            Биометрия: ' . ($deviceInfo['hasBiometricSupport'] ? 'Да' : 'Нет') . '
        </div>
    </div>
</body>
</html>';
            
            echo $html;
            exit;
        }
    }
}
