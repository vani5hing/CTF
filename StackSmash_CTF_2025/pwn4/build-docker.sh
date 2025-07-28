#!/bin/sh
docker build --tag=refreshments .
docker run -it -p 1337:1337 --rm --name=refreshments refreshments