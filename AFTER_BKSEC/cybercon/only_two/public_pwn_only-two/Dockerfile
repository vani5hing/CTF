FROM ubuntu:22.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential socat && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /chal
COPY . /chal

RUN make && make strip || true

RUN echo "cybercon{SNIP}" > /chal/flag && chmod 444 /chal/flag

RUN chmod 555 /chal/chall

EXPOSE 1000

CMD ["socat", "TCP-LISTEN:1000,reuseaddr,fork", "EXEC:/chal/chall"]

