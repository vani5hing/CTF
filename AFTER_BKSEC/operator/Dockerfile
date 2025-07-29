FROM ubuntu:22.04@sha256:b6b83d3c331794420340093eb706a6f152d9c1fa51b262d9bf34594887c2c7ac

RUN apt update
RUN apt-get install -y socat 

RUN adduser user

WORKDIR /home/user
USER user

COPY ./deploy/flag ./flag.txt
COPY ./deploy/run.sh ./run.sh
COPY ./deploy/prob ./prob


USER root
RUN chmod 644 ./flag.txt
RUN chmod 755 ./run.sh
RUN chmod 755 ./prob

USER user

EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:./run.sh,stderr
