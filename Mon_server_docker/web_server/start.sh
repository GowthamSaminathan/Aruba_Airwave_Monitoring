#!/usr/bin/env bash
trap 'sh /clean.sh;exit 0' SIGTERM

echo "======== Starting =======" >> /var/log/webserver-log/start_log.txt
date +"%c => %T.%3N" >> /var/log/webserver-log/start_log.txt

uwsgi --ini /webr_api/uwsgi_ini.ini >> /var/log/webserver-log/start_log.txt
service php7.2-fpm start >> /var/log/webserver-log/start_log.txt
service nginx start >> /var/log/webserver-log/start_log.txt

date +"%c => %T.%3N" >> /var/log/webserver-log/start_log.txt
echo "======== End =======" >> /var/log/webserver-log/start_log.txt

while true
do
sleep 1
done
