FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt update && apt-get install -y socat
RUN adduser --disabled-login --gecos '' -- "void"

WORKDIR /home/void
USER void

COPY ./deploy/flag ./flag
COPY ./deploy/void ./void

USER root
RUN chmod 444 ./flag
RUN chmod 755 ./void

USER void

EXPOSE 9090
CMD socat TCP-LISTEN:9090,reuseaddr,fork EXEC:./void,stderr