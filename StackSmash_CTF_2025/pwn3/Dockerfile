FROM ubuntu:22.04

RUN apt-get update && apt-get install -y socat

WORKDIR /app
COPY challenge .

RUN chmod u+s ./love_letter && useradd -m ctf
USER ctf

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/app/love_letter"]

