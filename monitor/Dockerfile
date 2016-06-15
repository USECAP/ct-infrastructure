FROM ubuntu:12.04
MAINTAINER christian tiefenau

RUN apt-get update && \
    apt-get install -y git gcc wget \
    build-essential libpq-dev libtool autoconf automake libcurl4-openssl-dev

COPY ./monitor /monitor

#Compile JSON-C
RUN git clone https://github.com/json-c/json-c.git && \
    sed -i -- 's/"json_inttypes.h"/<stdint.h>/' json-c/configure.ac && \
    cd /json-c && sh autogen.sh && ./configure && make && make install && \
    cp /usr/local/lib/libjson-c.so /usr/lib/libjson-c.so.3

RUN cd /monitor && make all && cp ct_monitor /ct-monitor && rm -rf /monitor
