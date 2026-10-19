FROM php:8.2-fpm-alpine

# تثبيت الحزم المطلوبة
RUN apk add --no-cache nginx curl-dev \
    && docker-php-ext-install gd \
    && docker-php-ext-enable gd

# نسخ كود المشروع
WORKDIR /var/www/html
COPY . /var/www/html

# إعداد Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# إعدادات PHP
RUN echo "memory_limit=256M" > /usr/local/etc/php/conf.d/custom.ini \
    && echo "max_execution_time=180" >> /usr/local/etc/php/conf.d/custom.ini \
    && echo "upload_max_filesize=20M" >> /usr/local/etc/php/conf.d/custom.ini \
    && echo "post_max_size=20M" >> /usr/local/etc/php/conf.d/custom.ini

EXPOSE 10000

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]