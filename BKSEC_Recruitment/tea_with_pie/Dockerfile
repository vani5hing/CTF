FROM ubuntu:22.04  

# Install dependencies. socat is for networking.
RUN apt-get update && apt-get install -y supervisor socat && apt install -y qemu-user && apt-get clean

RUN useradd -md /home/bksec bksec

# Set working directory.
WORKDIR /home/bksec

COPY libc.so.6 /usr/lib/aarch64-linux-gnu/libc.so.6
COPY ld-linux-aarch64.so.1 /lib/ld-linux-aarch64.so.1

# Copy the flag and binary.
COPY flag.txt .
COPY pwn2 .

# Set permissions.
RUN chown -R bksec:bksec /home/bksec
RUN chmod -R 555 /home/bksec
USER bksec

# Expose the port.
EXPOSE 6035

CMD socat -T 60 -d -d TCP-LISTEN:6035,reuseaddr,fork EXEC:"qemu-aarch64 ./pwn2"
