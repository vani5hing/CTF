FROM alpine:3.21 AS builder
WORKDIR /app
RUN wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat

FROM ubuntu:24.04
WORKDIR /app

COPY ./chall chall
COPY flag.txt flag.txt
COPY --from=builder /app/socat .

RUN /usr/sbin/useradd --no-create-home -u 1001 ctf

RUN chmod a+x socat
RUN chmod a+x chall
RUN chmod a-w -R /app

USER ctf

EXPOSE 5000
CMD ["./socat", "tcp-l:5000,reuseaddr,fork", "EXEC:\"./chall\""]
