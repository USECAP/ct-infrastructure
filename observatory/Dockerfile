FROM httpd:2.4
MAINTAINER ct

RUN apt-get update && \
    apt-get install -y apache2-dev libpq-dev libffi-dev gcc postgresql-client libpq-dev python python-dev python-pip wget --no-install-recommends

COPY ./observatory /observatory

RUN mv /observatory/observatory.pem /etc/ssl/certs/observatory.pem && \
    mv /observatory/observatory_key.pem /etc/ssl/private/observatory_key.pem && \
    mv /observatory/observatory_chain.pem /etc/ssl/certs/observatory_chain.pem

RUN pip install -r /observatory/requirements.txt

RUN mkdir /static #&& pip install -r /app/requirements.txt

RUN python /observatory/manage.py collectstatic --noinput

RUN wget https://github.com/GrahamDumpleton/mod_wsgi/archive/4.5.0.tar.gz && tar xvfz 4.5.0.tar.gz && \
    cd mod_wsgi-4.5.0 && ./configure --with-apxs=/usr/local/apache2/bin/apxs && make && make install

RUN cp /observatory/httpd.conf /usr/local/apache2/conf/httpd.conf