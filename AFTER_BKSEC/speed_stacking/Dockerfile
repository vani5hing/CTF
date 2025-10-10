FROM ubuntu:22.04@sha256:01a3ee0b5e413cefaaffc6abe68c9c37879ae3cced56a8e088b1649e5b269eee

RUN apt update
RUN apt-get install -y socat adduser

RUN adduser -u 1337 pwn

WORKDIR /home/pwn

COPY ./flag ./flag
COPY ./deploy/chall ./chall
COPY ./deploy/libc.so.6 ./libc.so.6

RUN chmod 644 ./flag
RUN chmod 755 ./chall
RUN export LD_PRELOAD='./libc.so.6'


USER pwn

EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:./chall,stderr
