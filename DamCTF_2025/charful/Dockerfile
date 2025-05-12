FROM --platform=linux/arm ubuntu:24.04
RUN apt-get -y update && apt-get -y --no-install-recommends install build-essential ucspi-tcp
WORKDIR /chal

COPY . .
RUN make

CMD ["/chal/todos"]
