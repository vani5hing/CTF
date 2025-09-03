FROM ubuntu:24.04@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9 AS ubuntu

FROM pwn.red/jail

COPY --from=ubuntu / /srv

RUN mkdir -p /srv/app
COPY chall /srv/app/run
COPY flag.txt /srv/app/flag.txt

# set permissions manually (since --chmod not supported in legacy builder)
RUN chmod 555 /srv/app/run && \
    chmod 444 /srv/app/flag.txt

# DOCKERFILE EDITED