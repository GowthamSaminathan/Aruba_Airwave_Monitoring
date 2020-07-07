#!/usr/bin/env bash

echo "======= Stoping ====== " >> /var/log/webserver-log/clean_log.txt
date +"%c => %T.%3N" >> /var/log/webserver-log/clean_log.txt

service nginx stop >> /var/log/webserver-log/clean_log.txt
uwsgi --stop /uwsgi.pid >> /var/log/webserver-log/clean_log.txt
service php7.2-fpm stop >> /var/log/webserver-log/clean_log.txt

date +"%c => %T.%3N" >> /var/log/webserver-log/clean_log.txt
echo "======= Done ====== " >> /var/log/webserver-log/clean_log.txt
