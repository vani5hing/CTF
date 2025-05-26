FROM ubuntu:22.04

RUN apt-get update -y && apt-get upgrade -y && apt-get install -y socat ncat gcc-multilib && apt-get clean
RUN mkdir /app/ && useradd ctfplayer
ADD bin /app/
RUN chmod 444 /app/flag.txt && chmod +x /app/*

WORKDIR /app
USER ctfplayer

CMD ["socat", "tcp-listen:14311,fork,reuseaddr", "exec:/app/take_control_pwner,stderr"]
