#!/bin/sh

cd /observatory
python manage.py makemigrations;
python manage.py migrate;
python manage.py collectstatic --noinput;

gunicorn ctobservatory.wsgi:application --log-level=debug --env DJANGO_SETTINGS_MODULE=ctobservatory.settings --timeout 120 -w 8 -b :7801
