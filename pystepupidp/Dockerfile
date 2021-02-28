FROM python:3.8-slim-buster

COPY . /app
WORKDIR /app

RUN apt-get update && apt-get install -y \
        xmlsec1 \
        libxmlsec1-openssl \
        && python -m pip install flask \
        && python setup.py install \
        && mkdir -p /etc/pystepupidp

WORKDIR /etc/pystepupidp

RUN rm -rf /app

ENV PYSTEPUPIDP_SETTINGS=/etc/pystepupidp/pystepupidp.cfg

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8080", "pystepupidp:create_app()"]
