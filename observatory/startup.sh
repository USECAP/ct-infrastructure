#!/bin/sh

python manage.py makemigrations;
python manage.py migrate;
python manage.py collectstatic --noinput;
gunicorn observatory.wsgi:application --log-level=debug --timeout 120 -w $NUM_WORKER -b :7801
