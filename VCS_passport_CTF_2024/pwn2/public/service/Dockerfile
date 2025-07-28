FROM ubuntu:24.04

RUN useradd -o -u 1000 user2

RUN apt-get update && apt-get install -y socat

WORKDIR /home/user2/

USER user2

COPY chall .

CMD ["socat", "TCP-LISTEN:9001,reuseaddr,fork", "EXEC:'/home/user2/chall'"]
