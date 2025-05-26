FROM ubuntu:22.04

RUN apt update && apt install -y socat netcat-openbsd adduser

RUN adduser --disabled-password --gecos "" ctf

WORKDIR /home/ctf

COPY ./flag.txt ./flag.txt
COPY ./chall ./chall

RUN chmod 644 ./flag.txt && chmod 755 ./chall

USER ctf

EXPOSE 1975

CMD ["socat", "TCP-LISTEN:1975,reuseaddr,fork", "EXEC:/home/ctf/chall"]
