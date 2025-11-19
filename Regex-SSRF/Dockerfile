FROM composer:2.8.8 AS composer
FROM php:8.3.17-apache-bullseye

RUN apt-get update -y && \
    apt-get install -y git zlib1g-dev libpng-dev openssl libssl-dev redis-server

COPY --from=composer /usr/bin/composer /usr/local/bin/composer

WORKDIR /var/www/html

RUN docker-php-ext-install gd
RUN composer require mpdf/mpdf:8.2.6

COPY index.php /var/www/html/

EXPOSE 80
CMD service redis-server start && apache2-foreground