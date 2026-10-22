FROM composer:2 AS deps
FROM --platform=linux/amd64 php:8.3.35-fpm-bookworm
ARG PHP_VERSION=8.2.30
RUN apt-get update && apt-get install -y php8.1-cli php8.1-mysql
