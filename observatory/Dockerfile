FROM django:python2
MAINTAINER ct

RUN apt-get update && \
    apt-get install -y libpq-dev libffi-dev

COPY ./observatory /observatory

RUN pip install -r /observatory/requirements.txt
