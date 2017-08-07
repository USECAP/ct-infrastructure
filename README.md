Certificate Transparency Observatory
==

This project contains the following subprojects for running a Certificate Transparency Observatory with the reqiured backend:

0. database: Contains the Dockerfile for a Postgres-database that is set up with the required tables.
0. monitor: Imports certificates out of CT-Logs
0. observatory: Django project for displaying the gathered data
0. analyzer: Python-based script that calculates some KPIs that would otherwise take too long when rendering them live in Django

Getting started
--
This is easy:
```
git clone https://github.com/USECAP/ct-infrastructure.git
cd ct-infrastructure

observatory/certs/create_self_signed_cert.sh

cp observatory/ctobservatory/config.py.template.py observatory/ctobservatory/config.py
sed -i s/secret_key_here/$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)/g observatory/ctobservatory/config.py

docker-compose build
docker-compose up -d
```

Usage
--
When the containers are started the monitor instantly starts collecting certificates that are visible when you visit `http://localhost:7801`.
For testing purposes it is recommended to stop the certificate crawling process via `docker-compose stop ctmonitor` because the resulting database grows very big (up to 60GB).

Parameters for analyzer.py
--
```
usage: python analyzer.py [-h] [-l] [-e] [-u] [-r] [-m] [--t T] [--pg PG] [--es ES]

optional arguments:
  -l          write log file
  -e          enable elasticsearch import
  -u          update expired certs
  -r          update revoked certs (takes veeeery long)
  -m          update metadata certs
  --t=T       time interval between refresh in minutes (default 180)
  --pg=PG     postgres database ip (default localhost)
  --es=ES     elasticsearch database ip (default localhost)
```
