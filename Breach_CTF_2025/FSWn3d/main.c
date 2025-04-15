#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

char buffer[152];

void win() {
    int fd = memfd_create("payload", 0);
    if (fd == -1) {
        perror("memfd_create");
        exit(1);
    }
    if (write(fd, buffer, 148) != 148) {
        perror("write");
        exit(1);
    }
    char *const args[] = {NULL};
    char *const envp[] = {NULL};
    fexecve(fd, args, envp);
    perror("fexecve");
    exit(1);
}

void vuln() {
    char first_name[28];
    char last_name[28];

    void **hint =
        (void **)((char *)__builtin_frame_address(0) + sizeof(void *));

    printf("Enter your first name: ");
    fgets(first_name, sizeof(first_name), stdin);
    first_name[strcspn(first_name, "\n")] = '\0';

    printf("You entered ");
    printf(first_name);
    printf("\n");

    printf("Enter your last name: ");
    fgets(last_name, sizeof(last_name), stdin);
    last_name[strcspn(last_name, "\n")] = '\0';

    printf("You entered ");
    printf(last_name);
    printf("\n");
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    vuln();
    return 0;
}
