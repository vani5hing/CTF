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

