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

## 🚀 Быстрый запуск

### 1. Запуск Docker контейнеров

```bash
cd /root/otpechatokv2
docker-compose up -d
```

### 2. Запуск HTTPS туннеля

```bash
# Установка tuna (если не установлен)
winget install --id yuccastream.tuna

# Сохранение токена
tuna config save-token tt_4wd704pwo95pi0xdmapgods58fvgwvxs

# Запуск туннеля
tuna http 8080
```

### 3. Тестирование

1. **Откройте ссылку tuna на мобильном устройстве**
2. **Зарегистрируйтесь** через отпечаток пальца
3. **Войдите** через биометрию

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

### Типичные проблемы:

1. **"Device not supported"** - используйте мобильное устройство
2. **"Challenge mismatch"** - проблема с base64url кодированием
3. **"Credential not found"** - перерегистрируйтесь

### Логи в браузере:

Откройте Developer Tools → Console для просмотра debug информации.

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