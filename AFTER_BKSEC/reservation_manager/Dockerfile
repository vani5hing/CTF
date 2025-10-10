FROM ubuntu:24.04@sha256:b59d21599a2b151e23eea5f6602f4af4d7d31c4e236d22bf0b62b86d2e386b8f

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y socat
ENV TERM=linux

RUN groupadd pwn
RUN useradd -g pwn pwn
WORKDIR /home/pwn

ADD prob /home/pwn/
COPY ./flag /home/pwn/

RUN chmod 460 /home/pwn/*
RUN chown pwn:root /home/pwn/*
RUN chmod +x-w /home/pwn/prob
RUN chmod o-rx *

USER pwn

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"./prob"