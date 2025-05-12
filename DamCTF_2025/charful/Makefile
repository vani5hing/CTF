.SILENT:
OPT=-Os
CFLAGS=-fsigned-char -static

todos: main.o todos.o
	gcc $(CFLAGS) $(OPT) main.o todos.o -o todos
main.o: main.c todos.h
	gcc $(CFLAGS) $(OPT) -c main.c
todos.o: todos.c todos.h
	gcc $(CFLAG) $(OPT) -c todos.c

.PHONY: clean
clean:
	rm -f todos *.o

