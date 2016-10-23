FROM python:3.5
MAINTAINER SZ

RUN apt-get update && apt-get install -y libpq-dev
COPY ./monitorInPython/requirements.txt /monitor/requirements.txt
RUN pip3 install -r /monitor/requirements.txt

COPY ./monitorInPython /monitor

