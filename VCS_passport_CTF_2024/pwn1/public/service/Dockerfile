FROM ubuntu:24.04

RUN useradd -o -u 1000 user1
RUN apt update && apt install -y socat

WORKDIR /challenge
USER user1
COPY warmup .

CMD ["socat", "TCP-LISTEN:9001,reuseaddr,fork", "EXEC:/challenge/warmup"]
