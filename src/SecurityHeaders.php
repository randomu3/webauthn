<?php

namespace WebAuthn;

/**
 * Класс для установки security headers и защиты от атак
 */
class SecurityHeaders
{
    /**
     * Устанавливает все необходимые security headers для продакшена
     */
    public static function setSecurityHeaders(): void
    {
        // Предотвращаем caching sensitive страниц
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
        
        // Content Security Policy для предотвращения XSS
        $csp = "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline' https://code.jquery.com; " .
               "style-src 'self' 'unsafe-inline'; " .
               "img-src 'self' data:; " .
               "connect-src 'self'; " .
               "font-src 'self'; " .
               "object-src 'none'; " .
               "base-uri 'self'; " .
               "form-action 'self'; " .
               "frame-ancestors 'none'";
        header("Content-Security-Policy: $csp");
        
        // X-Frame-Options для защиты от clickjacking
        header('X-Frame-Options: DENY');
        
        // X-Content-Type-Options для предотвращения MIME sniffing
        header('X-Content-Type-Options: nosniff');
        
        // X-XSS-Protection (устаревший, но для совместимости)
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Strict-Transport-Security (только для HTTPS)
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
        
        // Permissions Policy (ранее Feature Policy)
        $permissions = "geolocation=(), microphone=(), camera=(), " .
                      "payment=(), usb=(), magnetometer=(), gyroscope=(), " .
                      "accelerometer=(), ambient-light-sensor=()";
        header("Permissions-Policy: $permissions");
        
        // Content-Type с charset
        header('Content-Type: application/json; charset=utf-8');
    }
    
    /**
     * Проверяет и валидирует HTTPS соединение (отключаемо для development)
     */
    public static function enforceHTTPS(): bool
    {
        // Проверяем настройки окружения
        $httpsRequired = $_ENV['HTTPS_ENFORCEMENT'] ?? 'true';
        $isDevelopment = ($_ENV['APP_ENV'] ?? 'production') === 'development';
        
        // В development режиме можем отключить HTTPS проверку
        if ($isDevelopment && $httpsRequired === 'false') {
            return true; // Пропускаем проверку HTTPS для dev
        }
        
        // Проверяем наличие HTTPS или прокси headers (для Tuna/CloudFlare)
        $isSecure = (
            (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ||
            (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
            (isset($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on') ||
            (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443) ||
            // Для Tuna tunnels и localhost
            (isset($_SERVER['HTTP_HOST']) && (
                strpos($_SERVER['HTTP_HOST'], '.tuna.am') !== false ||
                in_array($_SERVER['HTTP_HOST'], ['localhost', '127.0.0.1']) ||
                str_starts_with($_SERVER['HTTP_HOST'], 'localhost:') ||
                str_starts_with($_SERVER['HTTP_HOST'], '127.0.0.1:')
            ))
        );
        
        if (!$isSecure) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => 'HTTPS required for WebAuthn',
                'message' => 'WebAuthn requires secure context (HTTPS)',
                'debug' => [
                    'https_enforcement' => $httpsRequired,
                    'app_env' => $_ENV['APP_ENV'] ?? 'production',
                    'server_https' => $_SERVER['HTTPS'] ?? 'not set',
                    'forwarded_proto' => $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? 'not set',
                    'host' => $_SERVER['HTTP_HOST'] ?? 'not set',
                    'is_development' => $isDevelopment
                ]
            ]);
            return false;
        }
        
        return true;
    }
    
    /**
     * Валидирует origin для защиты от CSRF
     */
    public static function validateOrigin(): bool
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        
        // Список разрешенных origins для продакшена
        $allowedOrigins = [
            "https://$host",
            "http://localhost",
            "http://127.0.0.1",
            "http://localhost:8080",
            "http://127.0.0.1:8080"
        ];
        
        // Добавляем origins из environment variables
        $envOrigins = $_ENV['ALLOWED_ORIGINS'] ?? '';
        if (!empty($envOrigins)) {
            $additionalOrigins = explode(',', $envOrigins);
            $allowedOrigins = array_merge($allowedOrigins, $additionalOrigins);
        }
        
        if (!empty($origin)) {
            foreach ($allowedOrigins as $allowedOrigin) {
                if (hash_equals(trim($allowedOrigin), $origin)) {
                    return true;
                }
            }
            
            error_log("SecurityHeaders: Invalid origin: $origin");
            http_response_code(403);
            echo json_encode([
                'success' => false,
                'error' => 'Invalid origin',
                'message' => 'Request origin not allowed'
            ]);
            return false;
        }
        
        return true;
    }
}
