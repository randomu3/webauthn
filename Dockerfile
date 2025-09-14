FROM php:8.2-apache

# Установка необходимых расширений PHP
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libzip-dev \
    libonig-dev \
    libxml2-dev \
    libsodium-dev \
    unzip \
    git \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd zip pdo pdo_mysql mbstring xml sodium

# Включение mod_rewrite для Apache
RUN a2enmod rewrite
RUN a2enmod ssl
RUN a2enmod headers

# Установка Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Копирование конфигурации Apache
COPY ./docker/apache/000-default.conf /etc/apache2/sites-available/000-default.conf

# Установка рабочей директории
WORKDIR /var/www/html

# Копирование composer.json и composer.lock (если есть)
COPY composer.json composer.lock* ./

# Установка зависимостей
RUN composer install --no-dev --optimize-autoloader

# Копирование исходного кода
COPY . .

# Настройка прав доступа
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

EXPOSE 80

CMD ["apache2-foreground"]
