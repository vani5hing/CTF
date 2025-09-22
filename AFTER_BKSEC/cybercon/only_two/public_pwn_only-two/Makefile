CC=gcc
CFLAGS=-fPIE -pie -fstack-protector-all -O0 -Wl,-z,relro -Wl,-z,now
LDFLAGS=-Wl,-T,safezone.ld
TARGET=chall

all: $(TARGET)

$(TARGET): main.c safezone.ld
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

strip:
	strip $(TARGET)

clean:
	rm -f $(TARGET)
