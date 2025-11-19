FROM composer:2.8.8 AS composer
FROM php:8.1.32-apache-bullseye

RUN apt-get update -y && \
    apt-get install -y git zlib1g-dev libpng-dev openssl libssl-dev libpcap0.8

COPY --from=composer /usr/bin/composer /usr/local/bin/composer

WORKDIR /var/www/html

RUN docker-php-ext-install gd
RUN composer require mpdf/mpdf:8.2.6

COPY index.php /var/www/html/index.php

EXPOSE 80
CMD apache2-foreground
