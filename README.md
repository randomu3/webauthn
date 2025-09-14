# WebAuthn Fingerprint Test

Простой проект для тестирования биометрической аутентификации (отпечатки пальцев, Face ID) с использованием WebAuthn API.

## 🎯 Описание

Демонстрационное веб-приложение для тестирования WebAuthn на мобильных устройствах. Поддерживает только биометрическую аутентификацию без логинов и паролей.

## ✨ Особенности

- ✅ **Только биометрия** - без логинов, паролей, email
- ✅ **Только мобильные устройства** - автоматическая блокировка десктопов
- ✅ **Простая архитектура** - минимум зависимостей
- ✅ **Docker контейнеризация** - легкий запуск
- ✅ **jQuery + PHP** - понятный код
- ✅ **HTTPS через tuna** - готово для тестирования

## 🏗️ Архитектура

```
/root/otpechatokv2/
├── docker/                    # Docker конфигурация
│   ├── apache/000-default.conf   # Настройки Apache
│   └── mysql/init.sql            # Инициализация БД
├── public/                    # Веб-файлы
│   ├── index.php                 # Главная страница (проверка устройства)
│   ├── webauthn.html            # Основное приложение WebAuthn
│   ├── api.php                  # REST API backend
│   └── styles.css               # Стили
├── src/                      # PHP классы (используются)
│   ├── Database.php             # Работа с БД
│   └── DeviceDetector.php       # Детекция устройств
├── Dockerfile                # Сборка контейнера
├── docker-compose.yml        # Оркестрация сервисов
├── composer.json             # PHP зависимости
└── README.md                 # Документация
```

## 🚀 Полная инструкция по установке и запуску

### Шаг 1: Установка зависимостей

#### Установка Docker (если не установлен)

**Windows (WSL2):**
```bash
# Установка Docker Desktop
# Скачайте с официального сайта: https://www.docker.com/products/docker-desktop/

# Проверка установки
docker --version
docker-compose --version
```

**Linux (Ubuntu/Debian):**
```bash
# Установка Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Установка Docker Compose
sudo apt-get update
sudo apt-get install docker-compose-plugin

# Добавление пользователя в группу docker
sudo usermod -aG docker $USER
newgrp docker
```

#### Установка Tuna (обязательно для HTTPS)

**Windows:**
```bash
# Установка через winget
winget install --id yuccastream.tuna

# Или скачайте с GitHub:
# https://github.com/yuccastream/tuna/releases
```

**Linux/macOS:**
```bash
# Скачайте подходящую версию
curl -L -o tuna https://github.com/yuccastream/tuna/releases/download/v1.0.0/tuna-linux-amd64
chmod +x tuna
sudo mv tuna /usr/local/bin/

# Проверка установки
tuna --version
```

### Шаг 2: Настройка Tuna

#### Регистрация и получение токена

1. **Зарегистрируйтесь на** https://tuna.am
2. **Получите токен** в личном кабинете
3. **Сохраните токен**:

```bash
# Замените YOUR_TOKEN на ваш реальный токен
tuna config save-token YOUR_TOKEN

# Пример:
# tuna config save-token tt_abc123def456ghi789jkl012mno345pqr
```

### Шаг 3: Запуск проекта

#### Клонирование репозитория
```bash
# Клонируйте проект
git clone <your-repo-url>
cd otpechatokv2

# Или если уже скачан
cd /path/to/otpechatokv2
```

#### Запуск Docker контейнеров
```bash
# Запуск в фоновом режиме
docker-compose up -d

# Проверка статуса
docker-compose ps

# Ожидаемый вывод:
# otpechatokv2-web-1  apache2-foreground  Up  0.0.0.0:8080->80/tcp
# otpechatokv2-db-1   mysqld              Up  3306/tcp
```

#### Запуск HTTPS туннеля
```bash
# В новом терминале запустите tuna
tuna http 8080

# Вы увидите что-то вроде:
# INFO[12:53:54] Welcome to Tuna
# INFO[12:53:55] Account: your-email@domain.com (Free)
# INFO[12:53:56] Forwarding https://abc123-178-208-235-88.ru.tuna.am -> 127.0.0.1:8080
```

### Шаг 4: Тестирование на мобильном устройстве

#### Откройте ссылку на мобильном
1. **Скопируйте HTTPS ссылку** из вывода tuna (например: `https://abc123-178-208-235-88.ru.tuna.am`)
2. **Откройте на iPhone или Android** (в Safari или Chrome)
3. **Убедитесь, что включена биометрия** (Touch ID, Face ID, Fingerprint)

#### Процесс тестирования
1. **Проверка устройства** - должен пройти автоматически для мобильных
2. **Регистрация**:
   - Нажмите "Регистрация" 
   - Когда появится запрос биометрии - подтвердите
   - Должно появиться "Регистрация успешна!"
3. **Авторизация**:
   - Нажмите "Вход"
   - Подтвердите биометрию
   - Должно появиться "Добро пожаловать!"

### Шаг 5: Отладка и мониторинг

#### Просмотр логов приложения
```bash
# Логи веб-сервера
docker-compose logs -f web

# Логи базы данных  
docker-compose logs -f db

# Логи Apache (внутри контейнера)
docker-compose exec web tail -f /var/log/apache2/error.log
```

#### Проверка базы данных
```bash
# Подключение к MySQL
docker-compose exec db mysql -u webauthn_user -p webauthn_db

# Пароль: webauthn_pass

# Проверка таблиц
SHOW TABLES;
SELECT * FROM users;
SELECT * FROM user_credentials;
```

#### Мониторинг tuna
```bash
# Логи tuna показывают все HTTP запросы:
# INFO[13:33:04] GET /webauthn.html – 200 OK
# INFO[13:33:12] POST /api.php – 200 OK
```

### Шаг 6: Остановка и очистка

#### Остановка проекта
```bash
# Остановка контейнеров
docker-compose down

# Остановка с удалением volumes (очистка БД)
docker-compose down -v
```

#### Остановка tuna
```bash
# Ctrl+C в терминале с tuna или
pkill tuna
```

## 📱 Поддерживаемые устройства

- **iOS**: iPhone/iPad с Touch ID или Face ID
- **Android**: Устройства с отпечатком пальца (Android 6.0+)

## 🛠️ API Endpoints

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/api.php?action=device-info` | GET | Информация об устройстве |
| `/api.php?action=register-options` | POST | Опции регистрации WebAuthn |
| `/api.php?action=register-verify` | POST | Верификация регистрации |
| `/api.php?action=auth-options` | POST | Опции аутентификации |
| `/api.php?action=auth-verify` | POST | Верификация аутентификации |
| `/api.php?action=logout` | POST | Выход из системы |
| `/api.php?action=status` | GET | Статус аутентификации |

## 📊 База данных

### Таблицы MySQL:

- **`users`** - Пользователи (ID + handle)
- **`user_credentials`** - WebAuthn учетные данные
- **`user_sessions`** - Активные сессии

### Настройки подключения:

- **Host**: `db` (внутри Docker)
- **Database**: `webauthn_db`
- **User**: `webauthn_user`
- **Password**: `webauthn_pass`

## 🔧 Команды для разработки

```bash
# Проверка статуса
docker-compose ps

# Просмотр логов
docker-compose logs -f web

# Перезапуск сервисов
docker-compose restart web

# Подключение к БД
docker-compose exec db mysql -u webauthn_user -p webauthn_db

# Очистка данных
docker-compose down -v
```

## 🐛 Отладка

### Проверка WebAuthn поддержки:

```javascript
console.log('WebAuthn support:', !!window.PublicKeyCredential);
```

### 🚨 Частые проблемы и решения

#### Проблема: "Device not supported"
**Решение:**
```bash
# Проверьте User-Agent вашего устройства
# Откройте Developer Tools → Console
console.log(navigator.userAgent);

# Должен содержать iPhone, iPad или Android
```

#### Проблема: Tuna не запускается
**Решение:**
```bash
# 1. Проверьте токен
tuna config show

# 2. Обновите tuna
winget upgrade yuccastream.tuna

# 3. Проверьте порт 8080
netstat -an | grep 8080
```

#### Проблема: Docker контейнеры не стартуют
**Решение:**
```bash
# 1. Проверьте Docker
docker --version
docker-compose --version

# 2. Освободите порт 8080
docker ps | grep 8080
docker stop $(docker ps -q --filter "expose=8080")

# 3. Пересоберите контейнеры
docker-compose down -v
docker-compose up -d --build
```

#### Проблема: "WebAuthn not supported"
**Решение:**
- ✅ Используйте **HTTPS** (обязательно!)
- ✅ Откройте на **мобильном устройстве**
- ✅ Используйте **Chrome** или **Safari**
- ❌ **HTTP не поддерживается** WebAuthn

#### Проблема: "Challenge mismatch"
**Решение:**
```bash
# Очистите сессии в браузере
# Откройте Developer Tools → Application → Storage → Clear storage

# Перезапустите контейнеры
docker-compose restart web
```

#### Проблема: "Credential not found"
**Решение:**
```bash
# Очистите базу данных
docker-compose exec db mysql -u webauthn_user -pwebauthn_pass webauthn_db -e "
DELETE FROM user_credentials; 
DELETE FROM users; 
DELETE FROM user_sessions;"

# Перерегистрируйтесь заново
```

### 🔍 Детальная отладка

#### Логи в браузере
```javascript
// Откройте Developer Tools → Console
// Включите все уровни логов (Verbose)

// Проверка WebAuthn поддержки
console.log('WebAuthn support:', !!window.PublicKeyCredential);
console.log('Platform authenticator:', 
  await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
```

#### Логи сервера в реальном времени
```bash
# Терминал 1: Docker логи
docker-compose logs -f web

# Терминал 2: Apache логи  
docker-compose exec web tail -f /var/log/apache2/error.log

# Терминал 3: Tuna логи
tuna http 8080
```

#### Проверка API вручную
```bash
# Проверка device-info
curl "https://your-tuna-link.ru.tuna.am/api.php?action=device-info"

# Должен вернуть JSON с device информацией
```

### 📊 Мониторинг производительности

#### Ожидаемые времена ответа
- **GET запросы**: < 100ms
- **Регистрация**: 2-5 секунд (включая биометрию)
- **Авторизация**: 1-3 секунды (включая биометрию)

#### Индикаторы проблем
- ⚠️ **HTTP 500** - проблемы с PHP/MySQL
- ⚠️ **HTTP 403** - блокировка по устройству  
- ⚠️ **Timeout** - проблемы с tuna/Docker

## 🔒 Безопасность

⚠️ **ВНИМАНИЕ**: Это демонстрационный проект!

**В продакшене обязательно:**
- Полная криптографическая верификация WebAuthn
- Правильная обработка CBOR/COSE данных
- Валидные HTTPS сертификаты
- Безопасная конфигурация БД
- Защита от CSRF/XSS атак

## 📦 Технологии

- **Frontend**: HTML5, jQuery 3.7.1, CSS3
- **Backend**: PHP 8.2, MySQL 8.0
- **WebAuthn**: Нативный браузерный API
- **Контейнеризация**: Docker, Docker Compose
- **Веб-сервер**: Apache 2.4
- **Туннелирование**: Tuna для HTTPS

## 📄 Лицензия

MIT License - используйте свободно для обучения и тестирования.

---

**Готово к использованию!** 🎉

Просто запустите `docker-compose up -d` и `tuna http 8080`, затем откройте ссылку на мобильном устройстве.