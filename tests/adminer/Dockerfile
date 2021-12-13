FROM debian:latest

ENV ADMINER_VERSION=4.6.2

#======================================================

ENV HTTP_PORT 80
ENV HTTPS_PORT 443
ENV APACHE_DOCUMENT_ROOT /var/www/
ENV DOMAIN 127.0.0.1

ENV DEBIAN_FRONTEND=noninteractive
RUN \
    apt -y update; \
    apt -y install apache2 php php-mysql wget lsb-release gnupg default-mysql-server default-mysql-client;

RUN \
    sed -i "s/.*mysqli.allow_local_infile.*=.*/mysqli.allow_local_infile = On/g" /etc/php/*/apache2/php.ini; \
    rm -rf /var/www/html/; \
    mkdir -p ${APACHE_DOCUMENT_ROOT}; \
    printf "<VirtualHost *:${HTTP_PORT}>\nServerAdmin webmaster@${DOMAIN}\nServerName ${DOMAIN}\nServerAlias ${DOMAIN}\nDocumentRoot ${APACHE_DOCUMENT_ROOT}\nErrorLog \${APACHE_LOG_DIR}/error.log\nCustomLog \${APACHE_LOG_DIR}/access.log combined\n</VirtualHost>\n" \
    > /etc/apache2/sites-available/${DOMAIN}.conf; \
    printf "# If you just change the port or add more ports here, you will likely also\n# have to change the VirtualHost statement in\n# /etc/apache2/sites-enabled/000-default.conf\n\nListen ${HTTP_PORT}\n\n<IfModule ssl_module>\n    Listen ${HTTPS_PORT}\n</IfModule>\n\n<IfModule mod_gnutls.c>\n    Listen ${HTTPS_PORT}\n</IfModule>\n\n# vim: syntax=apache ts=4 sw=4 sts=4 sr noet\n" \
    > /etc/apache2/ports.conf; \
    printf "ServerTokens Prod\nServerSignature Off\n" >> /etc/apache2/apache2.conf; \
    sed -i "s/AllowOverride None/AllowOverride All/g" /etc/apache2/apache2.conf; \
    a2dissite 000-default.conf; \
    a2ensite ${DOMAIN}.conf; \
    a2enmod rewrite

RUN wget -q https://github.com/vrana/adminer/releases/download/v${ADMINER_VERSION}/adminer-${ADMINER_VERSION}.php -O /var/www/adminer.php

EXPOSE ${HTTP_PORT}
EXPOSE ${HTTPS_PORT}

CMD ["apachectl","-D","FOREGROUND"]
