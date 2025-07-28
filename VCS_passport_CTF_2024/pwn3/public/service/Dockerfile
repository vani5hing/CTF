FROM ubuntu:22.04

RUN useradd -u 1000 user3

RUN apt-get update && apt-get install -y socat

WORKDIR /home/user3/

USER user3

COPY chall .

CMD ["socat", "TCP-LISTEN:9001,reuseaddr,fork", "EXEC:'/home/user3/chall'"]
