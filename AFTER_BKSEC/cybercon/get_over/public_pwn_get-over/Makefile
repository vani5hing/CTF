CC=gcc
CFLAGS=-fPIE -pie -fstack-protector-all -O0 -Wl,-z,relro
LDFLAGS=
TARGET=chall

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

strip:
	strip $(TARGET)

clean:
	rm -f $(TARGET)
