FROM ubuntu:22.04

WORKDIR /app/

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install socat -y

COPY ./bin/iotcf /app/run
COPY ./bin/flag.txt /app/flag.txt

RUN groupadd --system ctf && \
	useradd -M -d /app -g ctf player && \
	chmod +r /app/flag.txt && \
	chmod +x /app/run

USER player

ENTRYPOINT ["socat", "TCP-LISTEN:10325,reuseaddr,fork", "EXEC:'/app/run',stderr"]
