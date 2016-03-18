#!/bin/sh

python3 manage.py makemigrations;
python3 manage.py migrate;
python3 manage.py collectstatic --noinput;
gunicorn observatory.wsgi:application --log-level=debug --timeout 120 -w $NUM_WORKER -b :7801
