FROM ubuntu:20.04@sha256:8e5c4f0285ecbb4ead070431d29b576a530d3166df73ec44affc1cd27555141b

RUN apt update && apt install -y socat

RUN useradd -m pwn

COPY ./deploy/flag /home/pwn/flag
COPY ./deploy/prob /home/pwn/prob

RUN chown pwn:pwn /home/pwn/flag /home/pwn/prob && \
    chmod 755 /home/pwn/prob && \
    chmod 444 /home/pwn/flag

WORKDIR /home/pwn
USER pwn

EXPOSE 5235
CMD socat TCP-LISTEN:5235,reuseaddr,fork EXEC:/home/pwn/prob
