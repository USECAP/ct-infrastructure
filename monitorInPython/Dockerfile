FROM python:2.7
MAINTAINER SZ

RUN apt-get update && apt-get install -y libpq-dev
COPY ./monitorInPython/requirements.txt /monitor/requirements.txt
RUN pip install -r /monitor/requirements.txt

COPY ./monitorInPython /monitor

