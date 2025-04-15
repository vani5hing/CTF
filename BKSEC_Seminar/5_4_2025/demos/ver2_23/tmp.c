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
   read(0, ptr[index], 0x30);
}

void delete() {
   scanf("%d", &index);
   free(ptr[index]);
}

void main() {
   setbuf(stdin, NULL);
   setbuf(stdout, NULL);

   while(1) {
      puts("choice:");
      scanf("%d", &choice);
      if(choice == 1) create();
      else if (choice == 2) view();
      else if (choice == 3) edit();
      else if (choice == 4) delete();
      puts("done!");
   }
}

