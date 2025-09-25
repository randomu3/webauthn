<?php
// Главная страница с системой авторизации

require_once __DIR__ . '/../src/DeviceHelper.php';
use WebAuthn\DeviceHelper;

$isMobile = DeviceHelper::isMobileDevice();
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>НПФ Сургутнефтегаз - Безопасная авторизация</title>
    <link rel="stylesheet" href="css/styles.css">
    <link rel="stylesheet" href="css/npf-theme.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="main-container">
            <!-- Заголовок приложения -->
            <div class="app-header">
                <div class="app-logo">🏢</div>
                <div class="app-title">НПФ Сургутнефтегаз</div>
                <div class="app-subtitle">Личный кабинет<br>Негосударственный пенсионный фонд</div>
            </div>

            <!-- Статус устройства -->
            <div class="device-status <?php echo $isMobile ? 'mobile' : 'desktop'; ?>">
                <?php if ($isMobile): ?>
                    📱 <strong>Мобильное устройство</strong><br>
                    Доступны все функции безопасности
                <?php else: ?>
                    💻 <strong>Настольный компьютер</strong><br>
                    WebAuthn доступен через Tuna tunnel
                <?php endif; ?>
            </div>

            <!-- Демо данные -->
            <div class="demo-info">
                <h4>🧪 Тестовые данные:</h4>
                <p><strong>Логин:</strong> testuser</p>
                <p><strong>Пароль:</strong> password123</p>
                <p><em>Попробуйте "Запомнить меня" для быстрого входа</em></p>
            </div>

            <!-- Табы авторизации (быстрый вход показывается только при наличии remember token) -->
            <div class="auth-tabs" id="authTabs">
                <div class="auth-tab active" data-tab="password">
                    🔐 Логин и пароль
                </div>
                <div class="auth-tab" data-tab="quick" style="display: none;">
                    ⚡ Быстрый вход
                </div>
            </div>

            <!-- Статус сообщения -->
            <div id="status" class="status hidden"></div>

            <!-- Форма входа по логину и паролю -->
            <div id="passwordForm" class="auth-form active">
                <div class="form-group">
                    <label for="username">Логин или Email:</label>
                    <input type="text" id="username" name="username" required 
                           placeholder="Введите логин или email" autocomplete="username">
                </div>

                <div class="form-group">
                    <label for="password">Пароль:</label>
                    <input type="password" id="password" name="password" required 
                           placeholder="Введите пароль" autocomplete="current-password">
                </div>

                <div class="remember-me">
                    <input type="checkbox" id="rememberMe" name="remember_me">
                    <label for="rememberMe">Запомнить меня для быстрого входа</label>
                </div>

                <button type="button" id="loginBtn" class="btn-primary">
                    Войти в систему
                </button>
            </div>

            <!-- Форма быстрого входа (показывается только при наличии remember token) -->
            <div id="quickForm" class="auth-form" style="display: none;">
                <div class="quick-access">
                    <div class="quick-access-title">⚡ Быстрый вход</div>
                    
                    <div id="userWelcome">
                        <p>Добро пожаловать, <span id="userDisplayName"></span>!</p>
                    </div>
                    
                    <div class="pin-input-container">
                        <label>Введите 6-значный PIN код:</label>
                        <div class="pin-input-group">
                            <input type="number" class="pin-digit" maxlength="1" pattern="[0-9]" data-index="0" readonly>
                            <input type="number" class="pin-digit" maxlength="1" pattern="[0-9]" data-index="1" readonly>
                            <input type="number" class="pin-digit" maxlength="1" pattern="[0-9]" data-index="2" readonly>
                            <input type="number" class="pin-digit" maxlength="1" pattern="[0-9]" data-index="3" readonly>
                            <input type="number" class="pin-digit" maxlength="1" pattern="[0-9]" data-index="4" readonly>
                            <input type="number" class="pin-digit" maxlength="1" pattern="[0-9]" data-index="5" readonly>
                        </div>

                        <!-- Мобильная клавиатура -->
                        <div class="mobile-keypad">
                            <button class="keypad-btn" data-digit="1">1</button>
                            <button class="keypad-btn" data-digit="2">2</button>
                            <button class="keypad-btn" data-digit="3">3</button>
                            <button class="keypad-btn" data-digit="4">4</button>
                            <button class="keypad-btn" data-digit="5">5</button>
                            <button class="keypad-btn" data-digit="6">6</button>
                            <button class="keypad-btn" data-digit="7">7</button>
                            <button class="keypad-btn" data-digit="8">8</button>
                            <button class="keypad-btn" data-digit="9">9</button>
                            <button class="keypad-btn special" data-action="clear">⌫</button>
                            <button class="keypad-btn" data-digit="0">0</button>
                            <button class="keypad-btn special" data-action="login">✓</button>
                        </div>
                        
                        <button type="button" id="quickLoginBtn" class="btn-primary" disabled>
                            Войти по PIN
                        </button>
                    </div>

                    <div id="webauthnSection" style="display: none;">
                        <button type="button" id="webauthnBtn" class="btn-secondary">
                            👆 Войти по отпечатку пальца
                        </button>
                    </div>
                </div>

                <button type="button" class="btn-secondary" onclick="switchTab('password')">
                    🔑 Войти через логин и пароль
                </button>
            </div>

            <!-- Debug информация -->
            <div id="debug" class="debug hidden"></div>
        </div>
    </div>

    <script>
        let currentQuickUser = null;
        let currentPin = '';

        $(document).ready(function() {
            // Сначала скрываем быстрый вход (показываем только если есть remember token)
            disableQuickLogin();
            
            // Проверяем remember token при загрузке
            checkRememberToken();
            
            // Настройка обработчиков
            setupEventHandlers();
            
            // Настройка клавиатуры
            setupMobileKeypad();
        });

        function setupEventHandlers() {
            // Переключение табов
            $('.auth-tab').on('click', function() {
                const tab = $(this).data('tab');
                switchTab(tab);
            });
            
            // Обычный вход
            $('#loginBtn').on('click', handleLogin);
            $('#quickLoginBtn').on('click', handleQuickLogin);
            $('#webauthnBtn').on('click', handleWebAuthnLogin);
            
            // Enter для отправки формы
            $('#passwordForm input').on('keypress', function(e) {
                if (e.which === 13) {
                    handleLogin();
                }
            });
        }

        function setupMobileKeypad() {
            $('.keypad-btn').on('click', function() {
                const digit = $(this).data('digit');
                const action = $(this).data('action');
                
                if (digit !== undefined) {
                    addDigitToPin(digit.toString());
                } else if (action === 'clear') {
                    clearLastDigit();
                } else if (action === 'login') {
                    handleQuickLogin();
                }
                
                // Визуальная обратная связь
                $(this).addClass('active');
                setTimeout(() => $(this).removeClass('active'), 150);
            });
        }

        function addDigitToPin(digit) {
            if (currentPin.length < 6) {
                currentPin += digit;
                updatePinDisplay();
                updateQuickLoginButton();
            }
        }

        function clearLastDigit() {
            if (currentPin.length > 0) {
                currentPin = currentPin.slice(0, -1);
                updatePinDisplay();
                updateQuickLoginButton();
            }
        }

        function updatePinDisplay() {
            $('.pin-digit').each(function(index) {
                const $input = $(this);
                if (index < currentPin.length) {
                    $input.val(currentPin[index]).addClass('filled');
                } else {
                    $input.val('').removeClass('filled');
                }
            });
        }

        function updateQuickLoginButton() {
            $('#quickLoginBtn').prop('disabled', currentPin.length !== 6);
        }

        function switchTab(tab) {
            $('.auth-tab').removeClass('active');
            $(`.auth-tab[data-tab="${tab}"]`).addClass('active');
            
            $('.auth-form').removeClass('active');
            $(`#${tab}Form`).addClass('active');
            
            clearStatus();
            
            if (tab === 'quick' && !currentQuickUser) {
                checkRememberToken();
            }
        }

        function checkRememberToken() {
            $.ajax({
                url: 'auth_api.php?action=check-remember',
                method: 'POST',
                contentType: 'application/json',
                success: function(response) {
                    if (response.success && response.quick_login_available) {
                        currentQuickUser = response;
                        enableQuickLogin(response);
                    } else {
                        disableQuickLogin();
                    }
                },
                error: function() {
                    disableQuickLogin();
                }
            });
        }

        function enableQuickLogin(userData) {
            // Показываем таб быстрого входа
            $('.auth-tab[data-tab="quick"]').show();
            $('#authTabs').removeClass('single-tab');
            
            // Показываем форму быстрого входа
            $('#quickForm').show();
            
            // Заполняем данные пользователя
            $('#userWelcome').show();
            $('#userDisplayName').text(userData.display_name || userData.username);
            
            if (userData.webauthn_enabled) {
                $('#webauthnSection').show();
            }
            
            // Автоматически переключаемся на быстрый вход
            switchTab('quick');
            
            showStatus('🚀 Обнаружен сохраненный вход!', 'success');
        }

        function disableQuickLogin() {
            // Скрываем таб быстрого входа
            $('.auth-tab[data-tab="quick"]').hide();
            $('#authTabs').addClass('single-tab');
            
            // Полностью скрываем форму быстрого входа
            $('#quickForm').hide().removeClass('active');
            $('#userWelcome').hide();
            $('#webauthnSection').hide();
            currentQuickUser = null;
            
            // Показываем только форму логина
            $('#passwordForm').show().addClass('active');
            
            // Убеждаемся что активен таб пароля
            $('.auth-tab').removeClass('active');
            $('.auth-tab[data-tab="password"]').addClass('active');
        }

        function handleLogin() {
            const username = $('#username').val().trim();
            const password = $('#password').val().trim();
            const rememberMe = $('#rememberMe').is(':checked');

            if (!username || !password) {
                showStatus('❌ Введите логин и пароль', 'error');
                return;
            }

            setLoading(true);
            showStatus('🔄 Проверка данных...', 'info');

            $.ajax({
                url: 'auth_api.php?action=login',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    username: username,
                    password: password,
                    remember_me: rememberMe
                }),
                success: function(response) {
                    if (response.success) {
                        showStatus('✅ Вход выполнен успешно!', 'success');
                        
                        // Новая логика перенаправления
                        if (response.remember_me_requested) {
                            // Если включено "Запомнить меня"
                            if (response.needs_pin_setup) {
                                // Нужно настроить PIN для быстрого входа
                                setTimeout(() => {
                                    window.location.href = 'setup.html';
                                }, 1000);
                            } else {
                                // PIN уже настроен - идем в dashboard
                                setTimeout(() => {
                                    window.location.href = 'dashboard.html';
                                }, 1000);
                            }
                        } else {
                            // Обычный вход без "Запомнить меня" - сразу в dashboard
                            setTimeout(() => {
                                window.location.href = 'dashboard.html';
                            }, 1000);
                        }
                    } else {
                        showStatus('❌ ' + response.message, 'error');
                    }
                },
                error: function(xhr) {
                    const response = xhr.responseJSON || {};
                    showStatus('❌ ' + (response.message || 'Ошибка входа'), 'error');
                },
                complete: function() {
                    setLoading(false);
                }
            });
        }

        function handleQuickLogin() {
            if (currentPin.length !== 6) {
                showStatus('❌ Введите 6-значный PIN код', 'error');
                return;
            }

            if (!currentQuickUser) {
                showStatus('❌ Сессия истекла', 'error');
                switchTab('password');
                return;
            }

            setLoading(true);
            showStatus('🔄 Проверка PIN...', 'info');

            $.ajax({
                url: 'auth_api.php?action=login-pin',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    user_id: currentQuickUser.user_id,
                    pin: currentPin
                }),
                success: function(response) {
                    if (response.success) {
                        showStatus('✅ Вход по PIN выполнен!', 'success');
                        setTimeout(() => {
                            window.location.href = 'dashboard.html';
                        }, 1000);
                    } else {
                        if (response.error === 'WEBAUTHN_FAILED' || response.security_reset) {
                            // Полный сброс безопасности - перенаправляем на вход
                            showStatus('🔒 ' + response.message, 'error');
                            setTimeout(() => {
                                window.location.href = 'index.php';
                            }, 2000);
                        } else {
                            // Обычная ошибка PIN
                            showStatus('❌ ' + response.error, 'error');
                            clearPin();
                        }
                    }
                },
                error: function(xhr) {
                    const response = xhr.responseJSON || {};
                    
                    if (xhr.status === 400 && response.message && response.message.includes('попыток')) {
                        // Показываем сообщение с количеством попыток
                        showStatus('⚠️ ' + response.message, 'error');
                    } else if (response.security_reset) {
                        // Полный сброс - перенаправляем
                        showStatus('🔒 Безопасность сброшена. Войдите заново.', 'error');
                        setTimeout(() => {
                            window.location.href = 'index.php';
                        }, 2000);
                    } else {
                        showStatus('❌ ' + (response.message || 'Ошибка PIN'), 'error');
                    }
                    
                    clearPin();
                },
                complete: function() {
                    setLoading(false);
                }
            });
        }

        function handleWebAuthnLogin() {
            showStatus('🔐 WebAuthn вход будет интегрирован...', 'info');
            // TODO: Интеграция с WebAuthn API
        }

        function clearPin() {
            currentPin = '';
            updatePinDisplay();
            updateQuickLoginButton();
        }

        function showStatus(message, type = 'info') {
            $('#status')
                .removeClass('hidden success error info')
                .addClass(type)
                .text(message)
                .show();
        }

        function clearStatus() {
            $('#status').addClass('hidden');
        }

        function setLoading(loading) {
            if (loading) {
                $('#loginBtn').prop('disabled', true).text('⏳ Загрузка...');
                $('#quickLoginBtn').prop('disabled', true).text('⏳ Проверка...');
            } else {
                $('#loginBtn').prop('disabled', false).text('Войти в систему');
                updateQuickLoginButton();
                $('#quickLoginBtn').text('Войти по PIN');
            }
        }
    </script>
</body>
</html>