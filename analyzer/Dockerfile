FROM python:2.7
MAINTAINER CT

RUN apt-get update && apt-get install -y libpq-dev libffi-dev
COPY ./analyzer/requirements.txt /analyzer/requirements.txt
RUN pip install -r /analyzer/requirements.txt

COPY ./analyzer /analyzer

