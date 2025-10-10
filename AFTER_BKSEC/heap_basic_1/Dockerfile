FROM ubuntu:20.04@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715

RUN apt update
RUN apt-get install -y socat

RUN adduser pwn

WORKDIR /home/pwn

COPY ./flag ./flag
COPY ./deploy/prob ./prob

RUN chmod 644 ./flag 
RUN chmod 755 ./prob

USER pwn

EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:./prob,stderr