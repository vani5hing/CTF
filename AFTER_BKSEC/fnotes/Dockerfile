FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt update
RUN apt-get install -y socat

COPY ./deploy/flag /flag
COPY ./deploy/prob /prob
COPY ./deploy/libc.so.6 /libc.so.6

RUN chmod 755 /flag /prob
RUN export LD_PRELOAD='/libc.so.6' 

EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:/prob
