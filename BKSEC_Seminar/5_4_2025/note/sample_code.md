# C file

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

long *ptr[105];
int choice, size, index;

void create() {
   scanf("%d", &size);
   scanf("%d", &index);
   ptr[index] = malloc(size);
}

void view() {
   scanf("%d", &index);
   puts(ptr[index]);
}

void edit() {
   scanf("%d", &index);
   read(0, ptr[index], 0x10);
}

void delete() {
   scanf("%d", &index);
   free(ptr[index]);
}

void main() {
   setbuf(stdin, NULL);
   setbuf(stdout, NULL);

   long stackvar = 0;
   printf("here is ur gift: 0x%lx\n", &stackvar);

   while(1) {
      puts("choice:");
      scanf("%d", &choice);
      if(choice == 1) create();
      else if (choice == 2) view();
      else if (choice == 3) edit();
      else if (choice == 4) delete();
      puts("done!");

      if(stackvar > 0) {
         puts("YOU WIN");
         return;
      }
   }
}

```

# Python file

```
from pwn import *

def create(size, index):
	p.sendlineafter(b"choice:\n", b"1")
	p.sendline(f"{size}".encode())
	p.sendline(f"{index}".encode())

def view(index):
	p.sendlineafter(b"choice:\n", b"2")
	p.sendline(f"{index}".encode())

def edit(index, data):
	p.sendlineafter(b"choice:\n", b"3")
	p.send(data)

def delete(index):
	p.sendlineafter(b"choice:\n", b"4")
	p.sendline(f"{index}".encode())

script = '''
b *main
b *create
b *delete
'''

p = gdb.debug("./tmp", gdbscript = script)

create(0x500, 0)
create(0x10, 1)
delete(0)
view(0)

p.interactive()
```