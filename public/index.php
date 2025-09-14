<?php
// Главная страница с автоматическим редиректом на WebAuthn

// Проверка мобильного устройства
function isMobileDevice() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    return preg_match('/iPhone|iPad|iPod|Android|Mobile|BlackBerry|Opera Mini/i', $userAgent);
}

$isMobile = isMobileDevice();
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn - Биометрическая авторизация</title>
    <link rel="stylesheet" href="css/styles.css">
</head>
<body>
    <div class="container">
        <div class="fingerprint">🔐</div>
        <h1>WebAuthn Demo</h1>
        <p class="welcome-text">
            Система биометрической аутентификации<br>
            с использованием отпечатка пальца или Face ID
        </p>

        <?php if ($isMobile): ?>
            <div class="status-card status-success">
                <strong>✅ Мобильное устройство обнаружено</strong>
                <p>Переход к системе авторизации...</p>
            </div>
            <div class="loading" id="redirectMessage">
                Автоматический переход через <span id="countdown">3</span> секунд...
            </div>
            <a href="webauthn.html" class="btn" id="manualLink">
                Перейти к авторизации
            </a>
        <?php else: ?>
            <div class="status-card status-error">
                <strong>❌ Требуется мобильное устройство</strong>
                <p>Данная система предназначена для работы только на мобильных устройствах с поддержкой биометрической аутентификации.</p>
            </div>
            <div class="status-card status-warning">
                <strong>📱 Как получить доступ:</strong>
                <ul style="text-align: left; margin: 10px 0;">
                    <li>Откройте этот сайт на iPhone или Android</li>
                    <li>Убедитесь, что настроена блокировка экрана</li>
                    <li>Разрешите браузеру использовать биометрию</li>
                </ul>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($isMobile): ?>
    <script>
        // Автоматический редирект для мобильных устройств
        let countdown = 3;
        const countdownElement = document.getElementById('countdown');
        
        const timer = setInterval(() => {
            countdown--;
            countdownElement.textContent = countdown;
            
            if (countdown <= 0) {
                clearInterval(timer);
                window.location.href = 'webauthn.html';
            }
        }, 1000);
        
        // Останавливаем таймер при клике на ссылку
        document.getElementById('manualLink').addEventListener('click', () => {
            clearInterval(timer);
        });
    </script>
    <?php endif; ?>
</body>
</html>