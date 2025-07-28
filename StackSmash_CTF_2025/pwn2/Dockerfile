FROM ubuntu:24.04

# Update and install necessary packages
RUN apt-get update && apt-get install -y \
    socat \
    dash \
    libc6 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Set dash as the default shell
RUN ln -sf /bin/dash /bin/sh

# Expose the port for the challenge
EXPOSE 1337

# Add a non-root user for the challenge
RUN groupadd -r ctf && useradd -r -g ctf ctf

# Copy the challenge binary and related files
COPY challenge/ /home/ctf/

# Set the working directory
WORKDIR /home/ctf

# Set ownership and permissions
RUN chown -R ctf:ctf /home/ctf && chmod +x /home/ctf/super_jumpio_kart

# Switch to the non-root user
USER ctf

# Command to run the challenge with socat
CMD ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:./super_jumpio_kart"]
