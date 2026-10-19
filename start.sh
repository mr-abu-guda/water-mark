#!/bin/sh
set -e

# تشغيل PHP-FPM في الخلفية
php-fpm -D

# تشغيل Nginx في المقدمة
nginx -g "daemon off;"