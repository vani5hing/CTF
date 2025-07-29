FROM ubuntu:24.04

RUN apt-get update && \
  apt-get install -y socat && \
  apt-get clean

RUN useradd -md /home/challenge challenge && \
  echo "challenge:challenge" | chpasswd

WORKDIR /challenge
COPY ./chall .
COPY ./flag.txt .

RUN chmod 755 ./chall
RUN chmod a+x ./chall

USER challenge

CMD socat -T 300 -d -d TCP-LISTEN:8088,reuseaddr,fork EXEC:"./chall",pty,raw,echo=0
