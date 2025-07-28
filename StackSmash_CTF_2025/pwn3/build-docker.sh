#!/bin/sh
docker build --tag=love_letter .
docker run -it -p 1337:1337 --rm --name=love_letter love_letter