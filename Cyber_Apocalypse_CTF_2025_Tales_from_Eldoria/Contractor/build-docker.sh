#!/bin/sh
docker build --tag=contractor .
docker run -it -p 1337:1337 --rm --name=contractor contractor
