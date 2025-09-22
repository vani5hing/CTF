#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>

static void (*onexit_hook)(const char *msg);
static const char *BINSH = "/bin/sh";

__attribute__((constructor))
static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(60);
    onexit_hook = NULL;
}

__attribute__((noinline, section(".safezone")))
static void safe(const char *msg) {
    puts(msg);
}

__attribute__((noinline, section(".safezone")))
static void win(const char *msg) {
    (void)msg;
    system(BINSH);
}

static void init_hook(void) {
    onexit_hook = safe;
}

static void leak(void) {
    extern int main(void);
    printf("leak: onexit_hook=%p, main=%p\\n", (void*)onexit_hook, (void*)&main);
}

static void partial_write(void) {
    char fmt[0x400];
    ssize_t n;
    puts("format? ");
    n = read(0, fmt, sizeof(fmt)-1);
    if (n <= 0) exit(0);
    fmt[n] = '\\0';
    printf(fmt, &onexit_hook);
    puts("");
}

static void go(void) {
    if (!onexit_hook) init_hook();
    onexit_hook("bye");
}

static void menu(void) {
    while (1) {
        puts("1) leak (print onexit_hook/main)");
        puts("2) write (printf(fmt, &onexit_hook))");
        puts("3) go (call onexit_hook)");
        puts("4) quit");
        printf("> ");
        int c = 0;
        if (scanf("%d%*c", &c) != 1) exit(0);
        switch (c) {
            case 1: leak(); break;
            case 2: partial_write(); break;
            case 3: go(); break;
            case 4: puts("bye"); return;
            default: puts("?"); break;
        }
    }
}

int main(void) {
    menu();
    return 0;
}
