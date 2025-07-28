#!/bin/sh
docker build --tag=super_jumpio_kart .
docker run -it -p 1337:1337 --rm --name=super_jumpio_kart super_jumpio_kart
