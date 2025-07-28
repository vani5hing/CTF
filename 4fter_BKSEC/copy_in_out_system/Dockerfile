FROM ubuntu:24.04@sha256:2e863c44b718727c860746568e1d54afd13b2fa71b160f5cd9058fc436217b30

RUN apt-get update
RUN apt-get install -y socat

WORKDIR /app

COPY ./deploy/flag ./flag
COPY ./deploy/prob ./prob

RUN chmod 755 flag prob

EXPOSE 31313
CMD socat TCP-LISTEN:31313,reuseaddr,fork EXEC:./prob