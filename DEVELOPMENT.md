# WebAuthn Development Guide

## 🚀 Быстрый старт для разработки

### 1. Настройка окружения

```bash
# Копируем development конфигурацию
cp env.development .env

# Запускаем проект
docker-compose up -d

# Ждем инициализации (15 сек)
sleep 15
```

### 2. Доступ к приложению

- **Локально:** http://localhost:8080
- **Tuna tunnel:** https://your-tunnel.tuna.am (для мобильного тестирования)

### 3. Development настройки

```bash
# В env.development:
APP_ENV=development           # Режим разработки
HTTPS_ENFORCEMENT=false      # Отключить HTTPS для localhost
RATE_LIMITING_ENABLED=true   # Смягченные лимиты
VERBOSE_ERRORS=true          # Подробные ошибки
```

## 🔧 Development возможности

### Отключенные для разработки проверки:

1. **HTTPS Enforcement** - работает на HTTP
2. **Строгие Rate Limits** - увеличены лимиты
3. **Production Security Headers** - упрощены
4. **Геолокация** - отключена

### Включенные для тестирования:

1. **Аналитика и аудит** - полный сбор данных
2. **WebAuthn функциональность** - полная поддержка
3. **Device fingerprinting** - активен
4. **Recovery механизмы** - доступны

## 🧪 Тестирование

### Запуск всех тестов:
```bash
docker-compose exec web php tests/run_all_tests.php
```

### Тестирование безопасности:
```bash
docker-compose exec web php tests/SecurityTest.php
```

### Очистка БД для чистого эксперимента:
```bash
# Через PHP скрипт (только данные)
docker-compose exec web php scripts/clean_database.php

# Полный сброс (с пересозданием контейнеров)
./scripts/reset_for_experiment.sh
```

## 📱 Тестирование на мобильных устройствах

### 1. Использование Tuna tunnel:

```bash
# Запуск tunnel
tuna http 8080

# Получите URL вида: https://xxxxx.tuna.am
# Обновите ALLOWED_ORIGINS в env.development
```

### 2. Настройка для Tuna:

```bash
# В env.development добавьте ваш Tuna URL:
ALLOWED_ORIGINS=http://localhost:8080,https://your-tunnel.tuna.am
```

### 3. Тестирование WebAuthn:

1. Откройте `https://your-tunnel.tuna.am` на мобильном
2. Перейдите на `/webauthn.html`
3. Нажмите "Зарегистрироваться"
4. Используйте биометрию (Face ID/Touch ID/Fingerprint)

## 🔍 Отладка

### Логи контейнеров:
```bash
# Web сервер логи
docker-compose logs web

# База данных логи
docker-compose logs db

# Следить за логами в реальном времени
docker-compose logs -f web
```

### Проверка БД:
```bash
# Подключение к БД
docker-compose exec db mysql -u webauthn_user -p webauthn_db

# Проверка таблиц
docker-compose exec web php -r "
require_once '/var/www/html/src/Database.php';
use WebAuthn\Database;
\$db = new Database();
\$pdo = \$db->getPdo();
\$stmt = \$pdo->query('SHOW TABLES');
var_dump(\$stmt->fetchAll(PDO::FETCH_COLUMN));
"
```

### Debug информация в API:
Включите `VERBOSE_ERRORS=true` для получения подробной отладочной информации в ответах API.

## 🛡️ Security в Development

### Что работает:
- ✅ Rate limiting (смягченные лимиты)
- ✅ Origin validation (расширенные origins)
- ✅ WebAuthn crypto security
- ✅ Device analytics
- ✅ Audit logging

### Что отключено:
- ❌ HTTPS enforcement
- ❌ Строгие CSP headers
- ❌ Production rate limits
- ❌ Геолокация API

## 📊 Аналитика в Development

Все аналитические данные собираются в development режиме:

- **Audit Log:** Все действия пользователей
- **Device Analytics:** Анализ устройств
- **Security Incidents:** Инциденты безопасности
- **Session Analytics:** Анализ сессий
- **WebAuthn Analytics:** Метрики аутентификации

## 🔄 Workflow разработки

1. **Сделать изменения в коде**
2. **Запустить тесты:**
   ```bash
   docker-compose exec web php tests/run_all_tests.php
   ```
3. **Очистить БД для чистого теста:**
   ```bash
   docker-compose exec web php scripts/clean_database.php
   ```
4. **Протестировать в браузере/мобильном**
5. **Проверить аналитику:**
   ```bash
   docker-compose exec web php -r "
   require_once '/var/www/html/src/Database.php';
   require_once '/var/www/html/src/AnalyticsManager.php';
   use WebAuthn\Database;
   use WebAuthn\AnalyticsManager;
   \$analytics = new AnalyticsManager(new Database());
   // Ваш код для проверки аналитики
   "
   ```

## 🚨 Известные ограничения Development

1. **WebAuthn требует HTTPS или localhost** - работает только через Tuna tunnel для мобильных
2. **Биометрия недоступна в браузере** - только на реальных мобильных устройствах
3. **Rate limits смягчены** - не отражают production поведение
4. **Debug информация включена** - может содержать чувствительные данные

## 📝 Production Checklist

Перед переносом на продакшен:

- [ ] `APP_ENV=production`
- [ ] `HTTPS_ENFORCEMENT=true`
- [ ] `VERBOSE_ERRORS=false`
- [ ] Настроить реальные Rate Limits
- [ ] Включить все Security Headers
- [ ] Настроить мониторинг
- [ ] Настроить резервное копирование БД
