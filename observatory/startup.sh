#!/bin/sh

python /observatory/manage.py makemigrations;
python /observatory/manage.py migrate;
python /observatory/manage.py collectstatic --noinput;
gunicorn observatory.wsgi:application --log-level=debug --timeout 120 -w 8 -b :7801
