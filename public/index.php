<?php
// Главная страница - проверка устройства и перенаправление

// Простая проверка мобильного устройства
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$isMobile = preg_match('/iPhone|iPad|Android/i', $userAgent);

if (!$isMobile) {
    // Показываем страницу для десктопа
    http_response_code(403);
    echo '<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Fingerprint Test</title>
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
            max-width: 500px;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        h1 {
            font-size: 32px;
            margin-bottom: 20px;
        }
        p {
            font-size: 18px;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .devices {
            font-size: 48px;
            margin: 30px 0;
        }
        .info {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            font-size: 14px;
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 WebAuthn Fingerprint Test</h1>
        <div class="devices">📱 ➡️ 👆</div>
        <p><strong>Доступ разрешен только с мобильных устройств</strong></p>
        <p>Это приложение предназначено для тестирования биометрической аутентификации (отпечатки пальцев, Face ID) на мобильных устройствах.</p>
        
        <div class="info">
            <strong>Для тестирования:</strong><br>
            • Откройте на iPhone или Android<br>
            • Убедитесь, что настроена биометрия<br>
            • Используйте HTTPS соединение
        </div>
        
        <div class="info">
            <strong>Ваше устройство:</strong><br>
            ' . htmlspecialchars($userAgent) . '
        </div>
    </div>
</body>
</html>';
    exit;
}

// Если мобильное устройство - перенаправляем на WebAuthn приложение
header('Location: webauthn.html');
exit;
?>