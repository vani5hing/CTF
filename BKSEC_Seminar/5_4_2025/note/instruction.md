# Docker

- Open docker desktop first, then run this command for wsl2.

> Change 2.xx for each version
## Build

```
docker build -t glibc-2.27-env .
```

## Run

```
docker run --rm -it glibc-2.27-env
```

# Compile C file

- Nano && edit file to `tmp.c`
- Run command:
```
gcc ./tmp.c -o tmp
```
- Verify:
```
ldd ./tmp
```

```
ls -l /lib/x86_64-linux-gnu/libc.so.6
```

```
ls -l /lib64/ld-linux-x86-64.so.2
```
# Copy file to local

```
docker ps
```

- copy the container id, example: `f05c61d5518d`

```
docker cp f05c61d5518d:/lib/x86_64-linux-gnu/libc-2.27.so .
```

```
docker cp f05c61d5518d:/lib/x86_64-linux-gnu/ld-2.27.so .
```

```
docker cp f05c61d5518d:/workspace/tmp .
```

```
pwninit
```

then we can work with file normaly.