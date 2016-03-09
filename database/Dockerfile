FROM postgres:9.5
MAINTAINER ct

RUN apt-get update && \
    apt-get install -y git gcc wget \
    build-essential libpq-dev postgresql-server-dev-9.5 libtool autoconf automake libcurl4-openssl-dev python ssh

COPY ./database/libx509pq /libx509pq
COPY ./database/certwatch_db /certwatch_db
COPY ./database/config.sh /config.sh

#Compile OPENSSL 1.0.2d
ENV CFLAGS=-fPIC
RUN wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2d.tar.gz && \
    tar xf openssl-1.0.2d.tar.gz && cd openssl-1.0.2d && \
	./config enable-shared enable-md2 && make && make install

#Compile PQ-Library
RUN cd /libx509pq && make && make install && cp libx509pq.so /libx509pq.so

RUN rm -rf libx509pq && rm -rf json-c && rm -rf openssl-1.0.2d

ENV libdir=

RUN chmod 700 -R /var/lib/postgresql/data
