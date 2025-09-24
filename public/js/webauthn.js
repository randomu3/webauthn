// WebAuthn управление авторизацией

// Система логирования для мобильной отладки
const MobileLogger = {
    logs: [],
    maxLogs: 100,
    
    init() {
        this.setupGlobalErrorHandlers();
        this.bindControls();
        this.log('info', 'JS', 'Система логирования инициализирована');
    },
    
    setupGlobalErrorHandlers() {
        // Перехват JavaScript ошибок
        window.addEventListener('error', (event) => {
            this.log('error', 'JS', `Ошибка: ${event.message}\nФайл: ${event.filename}:${event.lineno}:${event.colno}`);
        });
        
        // Перехват Promise ошибок
        window.addEventListener('unhandledrejection', (event) => {
            this.log('error', 'JS', `Promise ошибка: ${event.reason}`);
        });
        
        // Перехват console.error
        const originalConsoleError = console.error;
        console.error = (...args) => {
            this.log('error', 'Console', args.join(' '));
            originalConsoleError.apply(console, args);
        };
        
        // Перехват console.warn
        const originalConsoleWarn = console.warn;
        console.warn = (...args) => {
            this.log('warn', 'Console', args.join(' '));
            originalConsoleWarn.apply(console, args);
        };
        
        // Перехват console.log для важной информации
        const originalConsoleLog = console.log;
        console.log = (...args) => {
            const message = args.join(' ');
            if (message.includes('WebAuthn') || message.includes('error') || message.includes('Error')) {
                this.log('info', 'Console', message);
            }
            originalConsoleLog.apply(console, args);
        };
    },
    
    log(level, source, message) {
        const timestamp = new Date().toLocaleTimeString('ru-RU');
        const logEntry = {
            timestamp,
            level,
            source,
            message: typeof message === 'object' ? JSON.stringify(message, null, 2) : String(message)
        };
        
        this.logs.push(logEntry);
        
        // Ограничиваем количество логов
        if (this.logs.length > this.maxLogs) {
            this.logs.shift();
        }
        
        this.renderLogs();
    },
    
    renderLogs() {
        const container = document.getElementById('debugLogs');
        if (!container) return;
        
        container.innerHTML = this.logs.map(log => `
            <div class="log-entry ${log.level}">
                <span class="log-timestamp">${log.timestamp}</span>
                <span class="log-source">[${log.source}]</span>
                <div>${log.message}</div>
            </div>
        `).join('');
        
        // Автопрокрутка к последнему логу
        container.scrollTop = container.scrollHeight;
    },
    
    clear() {
        this.logs = [];
        this.renderLogs();
        this.log('info', 'System', 'Логи очищены');
    },
    
    bindControls() {
        $(document).ready(() => {
            $('#clearLogsBtn').on('click', () => this.clear());
            
            $('#toggleLogsBtn').on('click', function() {
                const panel = $('.debug-panel');
                panel.toggleClass('collapsed');
                $(this).text(panel.hasClass('collapsed') ? 'Развернуть' : 'Свернуть');
            });
            
            $('#copyLogsBtn').on('click', () => this.copyLogs());
            $('#copyBackendBtn').on('click', () => this.copyBackendErrors());
        });
    },
    
    copyLogs() {
        const logsText = this.logs.map(log => 
            `${log.timestamp} [${log.source}] ${log.message}`
        ).join('\n');
        
        this.copyToClipboard(logsText, 'Логи скопированы в буфер обмена!');
    },
    
    copyBackendErrors() {
        const debugContent = document.getElementById('debugContent');
        if (debugContent && debugContent.textContent) {
            this.copyToClipboard(debugContent.textContent, 'Backend ошибки скопированы!');
        } else {
            this.log('warn', 'System', 'Нет backend ошибок для копирования');
        }
    },
    
    async copyToClipboard(text, successMessage) {
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
                this.log('success', 'System', successMessage);
            } else {
                // Fallback для старых браузеров или HTTP
                const textArea = document.createElement('textarea');
                textArea.value = text;
                textArea.style.position = 'fixed';
                textArea.style.left = '-999999px';
                textArea.style.top = '-999999px';
                document.body.appendChild(textArea);
                textArea.focus();
                textArea.select();
                
                try {
                    document.execCommand('copy');
                    this.log('success', 'System', successMessage);
                } catch (err) {
                    this.log('error', 'System', 'Не удалось скопировать в буфер обмена');
                }
                
                document.body.removeChild(textArea);
            }
        } catch (err) {
            this.log('error', 'System', 'Ошибка при копировании: ' + err.message);
        }
    }
};

// Проверка статуса авторизации
async function checkAuthStatus() {
    try {
        const response = await fetch('/api.php?action=status');
        const data = await response.json();
        
        if (data.success && data.isLoggedIn) {
            showLoggedInState();
        } else {
            showLoggedOutState();
        }
        
        return data;
    } catch (error) {
        console.error('Ошибка проверки авторизации:', error);
        showLoggedOutState();
        return null;
    }
}

// Показать состояние авторизованного пользователя
function showLoggedInState() {
    $('#authButtons').hide();
    $('#loggedInSection').removeClass('hidden').show();
    $('#status').hide();
}

// Показать состояние неавторизованного пользователя
function showLoggedOutState() {
    $('#authButtons').show();
    $('#loggedInSection').addClass('hidden').hide();
}

// Глобальный обработчик ошибок для отладки
window.addEventListener('error', function(event) {
    console.error('Global error caught:', event.error);
    if (event.error && event.error.message && event.error.message.includes('Cannot read properties of null')) {
        console.error('NULL property access error at:', event.filename, ':', event.lineno, ':', event.colno);
        console.error('Stack trace:', event.error.stack);
    }
});

// Проверка устройства (jQuery)
function checkDevice() {
    const userAgent = navigator.userAgent;
    const isMobile = /iPhone|iPad|iPod|Android/i.test(userAgent);
    const supportsWebAuthn = !!window.PublicKeyCredential;
    
    let messages = [];
    
    if (!isMobile) {
        messages.push('❌ Не мобильное устройство');
        $('#deviceCheck').css({
            'background': '#f8d7da',
            'color': '#721c24'
        });
    } else {
        messages.push('✅ Мобильное устройство');
        $('#deviceCheck').css({
            'background': '#d4edda',
            'color': '#155724'
        });
    }
    
    if (!supportsWebAuthn) {
        messages.push('❌ WebAuthn не поддерживается');
    } else {
        messages.push('✅ WebAuthn поддерживается');
    }
    
    $('#deviceInfo').html(messages.join('<br>'));
    
    return isMobile && supportsWebAuthn;
}

// Показать статус (jQuery)
function showStatus(message, type = 'info') {
    const statusElement = $('#status');
    
    statusElement
        .removeClass('success error info hidden')
        .addClass(type)
        .text(message)
        .show();
    
    // Дополнительная проверка для уверенности что элемент видим
    if (statusElement.hasClass('hidden')) {
        statusElement.removeClass('hidden');
    }
    
    console.log('Status shown:', message, 'Type:', type);
}

// Показать debug (jQuery)
function showDebug(data) {
    $('#debugContent').text(JSON.stringify(data, null, 2));
    $('#debugInfo').removeClass('hidden');
}

// Блокировка кнопок
function disableButtons() {
    $('#registerBtn, #loginBtn, #logoutBtn').prop('disabled', true);
}

// Разблокировка кнопок
function enableButtons() {
    $('#registerBtn, #loginBtn, #logoutBtn').prop('disabled', false);
}

// ИСПРАВЛЕННЫЕ функции конвертации base64url
function arrayBufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    // Конвертируем в base64url (без padding + заменяем символы)
    return btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function base64urlToArrayBuffer(base64url) {
    // Конвертируем base64url обратно в обычный base64
    let base64 = base64url
        .replace(/-/g, '+')
        .replace(/_/g, '/');
    
    // Добавляем padding если нужно
    while (base64.length % 4) {
        base64 += '=';
    }
    
    try {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error('Error converting base64url to ArrayBuffer:', error, 'base64url:', base64url);
        throw error;
    }
}

// Регистрация с исправленным base64url (jQuery)
async function register() {
    if (!checkDevice()) {
        showStatus('Устройство не поддерживается', 'error');
        return;
    }
    
    // Блокируем кнопки на время выполнения
    disableButtons();
    
    try {
        showStatus('Получение опций регистрации...', 'info');
        
        // Собираем дополнительные данные устройства для fingerprint
        const deviceData = {
            screenWidth: screen.width,
            screenHeight: screen.height,
            colorDepth: screen.colorDepth,
            pixelRatio: window.devicePixelRatio,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            language: navigator.language,
            platform: navigator.platform,
            cookieEnabled: navigator.cookieEnabled,
            onlineStatus: navigator.onLine,
            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
            maxTouchPoints: navigator.maxTouchPoints || 0,
            userAgent: navigator.userAgent
        };
        
        // Получаем опции с сервера (jQuery)
        MobileLogger.log('info', 'WebAuthn', 'Запрос опций регистрации...');
        const options = await $.ajax({
            url: 'api.php?action=register-options',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ deviceData: deviceData })
        }).fail(function(xhr, status, error) {
            MobileLogger.log('error', 'Backend', `Ошибка при получении опций регистрации: ${xhr.status} ${error}\nОтвет: ${xhr.responseText}`);
        });
        
        console.log('Server options:', options);
        MobileLogger.log('success', 'Backend', `Опции регистрации получены: ${JSON.stringify(options, null, 2)}`);
        
        if (!options.success) {
            MobileLogger.log('error', 'Backend', `Сервер вернул ошибку: ${options.message}`);
            throw new Error(options.message);
        }
        
        // Проверяем, если устройство уже зарегистрировано
        if (options.alreadyRegistered) {
            MobileLogger.log('info', 'WebAuthn', `Устройство уже зарегистрировано: ${options.message}`);
            showStatus('✅ ' + options.message, 'success');
            
            // Используем jQuery для безопасной работы с DOM
            try {
                // Скрываем кнопку регистрации и показываем кнопку входа
                $('#registerBtn').hide();
                $('#loginBtn').show();
                
                // Показываем debug информацию
                showDebug({
                    message: options.message,
                    code: options.code,
                    action: options.action,
                    debug: options.debug
                });
                
                MobileLogger.log('success', 'UI', 'Интерфейс обновлен для уже зарегистрированного устройства');
                
            } catch (uiError) {
                console.error('UI update error in alreadyRegistered handler:', uiError);
                MobileLogger.log('error', 'UI', `Ошибка при обновлении интерфейса: ${uiError.message}`);
                
                // Показываем хотя бы debug информацию
                try {
                    showDebug({
                        message: options.message,
                        code: options.code,
                        action: options.action,
                        debug: options.debug,
                        uiError: uiError.message
                    });
                } catch (debugError) {
                    console.error('Debug show error:', debugError);
                }
            }
            
            // Разблокируем кнопки и завершаем
            enableButtons();
            return; // Выходим из функции, не пытаемся регистрировать
        }
        
        showStatus('Приложите палец к датчику...', 'info');
        
        console.log('Converting options for WebAuthn...');
        console.log('Server options object:', options);
        
        // Проверяем наличие всех необходимых полей
        if (!options.challenge || !options.user || !options.rp) {
            throw new Error('Неполные данные от сервера');
        }
        
        console.log('Converting challenge:', options.challenge);
        console.log('Converting user.id:', options.user.id);
        
        // Конвертируем данные для WebAuthn API с правильным base64url
        const credentialCreationOptions = {
            rp: options.rp,
            user: {
                id: base64urlToArrayBuffer(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName
            },
            challenge: base64urlToArrayBuffer(options.challenge),
            pubKeyCredParams: options.pubKeyCredParams || [
                { type: 'public-key', alg: -7 },
                { type: 'public-key', alg: -257 }
            ],
            timeout: options.timeout || 60000,
            excludeCredentials: (options.excludeCredentials || []).map(cred => ({
                type: cred.type,
                id: base64urlToArrayBuffer(cred.id)
            })),
            authenticatorSelection: options.authenticatorSelection || {
                authenticatorAttachment: 'platform',
                residentKey: 'preferred',
                requireResidentKey: false,
                userVerification: 'required'
            },
            attestation: options.attestation || 'none',
            extensions: options.extensions || { credProps: true }
        };
        
        console.log('WebAuthn options:', credentialCreationOptions);
        
        // Проверяем поддержку WebAuthn
        if (!window.PublicKeyCredential) {
            throw new Error('WebAuthn не поддерживается в этом браузере');
        }
        
        console.log('Calling navigator.credentials.create...');
        MobileLogger.log('info', 'WebAuthn', 'Вызов navigator.credentials.create() - ожидается системный диалог биометрии...');
        
        // Создаем учетные данные
        const credential = await navigator.credentials.create({
            publicKey: credentialCreationOptions
        });
        
        console.log('navigator.credentials.create completed:', credential);
        MobileLogger.log('success', 'WebAuthn', `Credential успешно создан: ${credential ? 'Да' : 'Нет'}`);
        
        console.log('Created credential:', credential);
        
        if (!credential) {
            throw new Error('Не удалось создать учетные данные');
        }
        
        showStatus('Сохранение на сервере...', 'info');
        
        // Отправляем на сервер с правильным base64url
        const verificationData = {
            id: credential.id,
            rawId: arrayBufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: arrayBufferToBase64url(credential.response.clientDataJSON),
                attestationObject: arrayBufferToBase64url(credential.response.attestationObject)
            }
        };
        
        console.log('Sending to server:', verificationData);
        
        // Отправляем через jQuery
        const result = await $.ajax({
            url: 'api.php?action=register-verify',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(verificationData)
        });
        
        console.log('Server response:', result);
        
        if (result.success) {
            showStatus('✅ Регистрация успешна!', 'success');
            // Переключаемся на авторизованное состояние
            setTimeout(() => {
                showLoggedInState();
            }, 2000);
        } else {
            throw new Error(result.message);
        }
        
        showDebug(result);
        
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        MobileLogger.log('error', 'WebAuthn', `Ошибка регистрации: ${error.name} - ${error.message}`);
        
        let errorMessage = 'Неизвестная ошибка';
        let debugInfo = null;
        
        // Обработка специфичных ошибок WebAuthn
        if (error.name === 'NotAllowedError') {
            // Проверяем, поддерживается ли WebAuthn вообще
            if (!window.PublicKeyCredential) {
                MobileLogger.log('error', 'WebAuthn', 'Браузер не поддерживает WebAuthn');
                showStatus('❌ Браузер не поддерживает WebAuthn. Используйте поддерживаемый браузер.', 'error');
                showUnsupportedBrowserHelp();
                return;
            }
            
            // Дополнительная проверка доступности platform authenticator
            if (window.PublicKeyCredential && window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
                window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(available => {
                    if (!available) {
                        MobileLogger.log('error', 'WebAuthn', 'Platform authenticator недоступен');
                        showStatus('❌ Биометрическая аутентификация недоступна на этом устройстве', 'error');
                        showUnsupportedBrowserHelp();
                    } else {
                        MobileLogger.log('info', 'WebAuthn', 'Регистрация отменена пользователем (не ошибка)');
                        showStatus('⚠️ Регистрация отменена пользователем', 'info');
                    }
                }).catch(() => {
                    MobileLogger.log('error', 'WebAuthn', 'Ошибка проверки platform authenticator');
                    showStatus('❌ Невозможно определить поддержку биометрии', 'error');
                    showUnsupportedBrowserHelp();
                });
                return;
            }
            
            MobileLogger.log('info', 'WebAuthn', 'Регистрация отменена пользователем (не ошибка)');
            showStatus('⚠️ Регистрация отменена пользователем', 'info');
            return; // Не показываем это как ошибку
        } else if (error.name === 'InvalidStateError') {
            showStatus('ℹ️ Это устройство уже зарегистрировано для биометрической авторизации. Попробуйте войти вместо регистрации.', 'info');
            return; // Не показываем это как ошибку
        } else if (error.name === 'NotSupportedError') {
            errorMessage = 'WebAuthn не поддерживается на этом устройстве';
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Небезопасный контекст или неверные параметры';
        } else if (error.responseJSON) {
            errorMessage = error.responseJSON.message || errorMessage;
            debugInfo = error.responseJSON.debug || error.responseJSON;
            
            // Специальная обработка для уже зарегистрированного устройства
            if (error.responseJSON.code === 'DEVICE_ALREADY_REGISTERED') {
                errorMessage = '🔒 Это устройство уже зарегистрировано! Используйте кнопку "Войти"';
            }
        } else if (error.message) {
            errorMessage = error.message;
        }
        
        showStatus(`❌ Ошибка: ${errorMessage}`, 'error');
        showDebug({ 
            error: errorMessage,
            errorName: error.name,
            fullError: error,
            debug: debugInfo,
            userAgent: navigator.userAgent
        });
    } finally {
        // Всегда разблокируем кнопки в конце
        enableButtons();
    }
}

// Аутентификация с исправленным base64url (jQuery)
async function login() {
    if (!checkDevice()) {
        showStatus('Устройство не поддерживается', 'error');
        return;
    }
    
    // Блокируем кнопки на время выполнения
    disableButtons();
    
    try {
        showStatus('Получение опций аутентификации...', 'info');
        
        // Получаем опции с сервера (jQuery)
        MobileLogger.log('info', 'WebAuthn', 'Запрос опций авторизации...');
        const options = await $.ajax({
            url: 'api.php?action=auth-options',
            method: 'POST',
            contentType: 'application/json'
        }).fail(function(xhr, status, error) {
            MobileLogger.log('error', 'Backend', `Ошибка при получении опций авторизации: ${xhr.status} ${error}\nОтвет: ${xhr.responseText}`);
            // Создаем кастомную ошибку для правильной обработки
            const customError = new Error('Server error');
            customError.responseJSON = xhr.responseJSON;
            customError.status = xhr.status;
            customError.responseText = xhr.responseText;
            throw customError;
        });
        
        console.log('Auth server options:', options);
        
        if (!options.success) {
            throw new Error(options.message);
        }
        
        showStatus('Приложите палец к датчику...', 'info');
        
        console.log('Converting auth options for WebAuthn...');
        console.log('Server auth options object:', options);
        
        // Проверяем наличие необходимых полей
        if (!options.challenge) {
            throw new Error('Отсутствует challenge от сервера');
        }
        
        console.log('Converting auth challenge:', options.challenge);
        
        // Конвертируем данные для WebAuthn API с правильным base64url
        const credentialRequestOptions = {
            challenge: base64urlToArrayBuffer(options.challenge),
            timeout: options.timeout || 60000,
            rpId: options.rpId,
            allowCredentials: (options.allowCredentials || []).map(cred => ({
                type: cred.type,
                id: base64urlToArrayBuffer(cred.id),
                transports: ['internal'] // Принуждаем к использованию встроенной биометрии
            })),
            userVerification: 'required' // Принуждаем к биометрической проверке
        };
        
        console.log('Auth WebAuthn options:', credentialRequestOptions);
        console.log('allowCredentials count:', credentialRequestOptions.allowCredentials.length);
        console.log('userVerification:', credentialRequestOptions.userVerification);
        
        // Проверяем поддержку WebAuthn
        if (!window.PublicKeyCredential) {
            throw new Error('WebAuthn не поддерживается в этом браузере');
        }
        
        console.log('Calling navigator.credentials.get...');
        MobileLogger.log('info', 'WebAuthn', 'Вызов navigator.credentials.get() - ожидается системный диалог биометрии...');
        MobileLogger.log('info', 'WebAuthn', `Доступные учетные данные: ${credentialRequestOptions.allowCredentials.length}`);
        
        // Получаем assertion
        const assertion = await navigator.credentials.get({
            publicKey: credentialRequestOptions
        });
        
        console.log('navigator.credentials.get completed:', assertion);
        MobileLogger.log('success', 'WebAuthn', `Assertion получен: ${assertion ? 'Да' : 'Нет'}`);
        
        console.log('Got assertion:', assertion);
        
        if (!assertion) {
            throw new Error('Не удалось получить assertion');
        }
        
        showStatus('Проверка на сервере...', 'info');
        
        // Отправляем на сервер с правильным base64url
        const verificationData = {
            id: assertion.id,
            rawId: arrayBufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
                authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
                signature: arrayBufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : null
            }
        };
        
        console.log('Sending auth to server:', verificationData);
        
        // Отправляем через jQuery
        const result = await $.ajax({
            url: 'api.php?action=auth-verify',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(verificationData)
        });
        
        console.log('Auth server response:', result);
        
        if (result.success) {
            showStatus('✅ Вход выполнен успешно!', 'success');
            // Переключаемся на авторизованное состояние
            setTimeout(() => {
                showLoggedInState();
            }, 2000);
        } else {
            throw new Error(result.message);
        }
        
        showDebug(result);
        
    } catch (error) {
        console.error('Ошибка аутентификации:', error);
        MobileLogger.log('error', 'WebAuthn', `Ошибка авторизации: ${error.name} - ${error.message}`);
        
        let errorMessage = 'Неизвестная ошибка';
        let debugInfo = null;
        
        // Обработка специфичных ошибок WebAuthn
        if (error.name === 'NotAllowedError') {
            // Проверяем, поддерживается ли WebAuthn вообще
            if (!window.PublicKeyCredential) {
                MobileLogger.log('error', 'WebAuthn', 'Браузер не поддерживает WebAuthn');
                showStatus('❌ Браузер не поддерживает WebAuthn. Используйте поддерживаемый браузер.', 'error');
                showUnsupportedBrowserHelp();
                return;
            }
            
            // Дополнительная проверка доступности platform authenticator
            if (window.PublicKeyCredential && window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
                window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(available => {
                    if (!available) {
                        MobileLogger.log('error', 'WebAuthn', 'Platform authenticator недоступен');
                        showStatus('❌ Биометрическая аутентификация недоступна на этом устройстве', 'error');
                        showUnsupportedBrowserHelp();
                    } else {
                        MobileLogger.log('info', 'WebAuthn', 'Вход отменен пользователем (не ошибка)');
                        showStatus('⚠️ Вход отменен пользователем', 'info');
                    }
                }).catch(() => {
                    MobileLogger.log('error', 'WebAuthn', 'Ошибка проверки platform authenticator');
                    showStatus('❌ Невозможно определить поддержку биометрии', 'error');
                    showUnsupportedBrowserHelp();
                });
                return;
            }
            
            MobileLogger.log('info', 'WebAuthn', 'Вход отменен пользователем (не ошибка)');
            showStatus('⚠️ Вход отменен пользователем', 'info');
            return; // Не показываем это как ошибку
        } else if (error.name === 'InvalidStateError') {
            errorMessage = 'Нет зарегистрированных устройств';
        } else if (error.name === 'NotSupportedError') {
            errorMessage = 'WebAuthn не поддерживается на этом устройстве';
        } else if (error.name === 'SecurityError') {
            errorMessage = 'Небезопасный контекст или неверные параметры';
        } else if (error.name === 'UnknownError') {
            errorMessage = 'Ошибка аутентификации. Попробуйте снова';
        } else if (error.responseJSON) {
            errorMessage = error.responseJSON.message || errorMessage;
            debugInfo = error.responseJSON.debug || error.responseJSON;
            
            // Специальная обработка для отсутствия учетных данных
            if (error.responseJSON.code === 'NO_CREDENTIALS') {
                errorMessage = '🔐 Сначала зарегистрируйтесь, используя кнопку "Регистрация"';
            }
            // Специальная обработка для уже зарегистрированного устройства
            else if (error.responseJSON.code === 'DEVICE_ALREADY_REGISTERED') {
                errorMessage = '🔒 Это устройство уже зарегистрировано! Используйте кнопку "Войти"';
            }
        } else if (error.responseText) {
            // Попытаемся парсить JSON из responseText
            try {
                const parsedResponse = JSON.parse(error.responseText);
                if (parsedResponse.code === 'NO_CREDENTIALS') {
                    errorMessage = '🔐 Сначала зарегистрируйтесь, используя кнопку "Регистрация"';
                } else {
                    errorMessage = parsedResponse.message || errorMessage;
                }
            } catch (e) {
                errorMessage = 'Ошибка сервера';
            }
        } else if (error.message) {
            errorMessage = error.message;
        }
        
        showStatus(`❌ Ошибка: ${errorMessage}`, 'error');
        showDebug({ 
            error: errorMessage,
            errorName: error.name,
            fullError: error,
            debug: debugInfo,
            userAgent: navigator.userAgent
        });
    } finally {
        // Всегда разблокируем кнопки в конце
        enableButtons();
    }
}

// Функция выхода
async function logout() {
    // Блокируем кнопки на время выполнения
    disableButtons();
    
    try {
        showStatus('Выход из системы...', 'info');
        
        console.log('Sending logout request...');
        
        const response = await fetch('/api.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ action: 'logout' })
        });
        
        console.log('Logout response status:', response.status);
        console.log('Logout response headers:', response.headers);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Logout error response:', errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }
        
        const result = await response.json();
        console.log('Logout result:', result);
        
        if (result.success) {
            showStatus('✅ Вы вышли из системы', 'success');
            showLoggedOutState();
        } else {
            throw new Error(result.message || 'Неизвестная ошибка выхода');
        }
        
    } catch (error) {
        console.error('Ошибка выхода:', error);
        showStatus(`❌ Ошибка выхода: ${error.message}`, 'error');
        showDebug({
            error: error.message,
            fullError: error,
            userAgent: navigator.userAgent
        });
    } finally {
        // Всегда разблокируем кнопки в конце
        enableButtons();
    }
}

// Инициализация (jQuery)
$(document).ready(async function() {
    // Инициализируем систему логирования
    MobileLogger.init();
    
    checkDevice();
    
    // Проверяем статус авторизации при загрузке
    await checkAuthStatus();
    
    $('#registerBtn').on('click', register);
    $('#loginBtn').on('click', login);
    $('#logoutBtn').on('click', logout);
});

// Функция показа помощи при неподдерживаемом браузере
function showUnsupportedBrowserHelp() {
    const userAgent = navigator.userAgent;
    let browserType = 'неизвестный';
    
    if (userAgent.includes('Chrome')) browserType = 'Chrome';
    else if (userAgent.includes('Firefox')) browserType = 'Firefox';
    else if (userAgent.includes('Safari')) browserType = 'Safari';
    else if (userAgent.includes('Edge')) browserType = 'Edge';
    
    const helpMessage = `
        📱 <strong>Инструкция по поддерживаемым браузерам:</strong><br><br>
        
        <strong>✅ Рекомендуемые браузеры для мобильных устройств:</strong><br>
        • <strong>iOS (iPhone/iPad):</strong> Safari 14+ (встроенный браузер)<br>
        • <strong>Android:</strong> Chrome 67+ или Samsung Internet 8+<br><br>
        
        <strong>⚠️ Важно:</strong><br>
        • Используйте <strong>встроенный браузер</strong> вашего устройства<br>
        • Убедитесь, что в настройках включена биометрия (Face ID/Touch ID/отпечаток пальца)<br>
        • Обновите браузер до последней версии<br><br>
        
        <strong>❌ Не поддерживаются:</strong><br>
        • Режим инкогнито/приватный режим<br>
        • Сторонние браузеры на iOS (кроме Safari)<br>
        • Устаревшие версии браузеров<br><br>
        
        <strong>Ваш браузер:</strong> ${browserType}<br>
        <strong>User Agent:</strong> ${userAgent.substring(0, 100)}...
    `;
    
    // Показываем в debug области
    const debugElement = document.getElementById('debug');
    if (debugElement) {
        debugElement.innerHTML = helpMessage;
        debugElement.style.display = 'block';
        debugElement.style.backgroundColor = '#fff3cd';
        debugElement.style.border = '1px solid #ffeaa7';
        debugElement.style.padding = '15px';
        debugElement.style.borderRadius = '8px';
        debugElement.style.marginTop = '10px';
    }
    
    MobileLogger.log('info', 'Help', `Показана помощь по поддерживаемым браузерам. Текущий браузер: ${browserType}`);
}
