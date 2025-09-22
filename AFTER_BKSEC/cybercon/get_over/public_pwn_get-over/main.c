#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>

static void *slot[4];

__attribute__((constructor))
static void setup(void) {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(60);
}

static void greet(void) {
    puts("You have 4 user-controlled var-args: slot[0..3].");
    puts("Use positional specifiers and %n/%hn wisely.");
}

static void set_slot(void) {
    int idx;
    unsigned long long val;
    printf("index (0-3): ");
    if (scanf("%d", &idx) != 1) exit(1);
    if (idx < 0 || idx > 3) { puts("bad index"); exit(0); }
    printf("hex value (e.g., 0xdeadbeef): ");
    if (scanf("%llx", &val) != 1) exit(1);
    slot[idx] = (void*)val;
    puts("ok");
}

static void say(void) {
    char fmt[0x400];
    ssize_t n;
    puts("format?");
    n = read(0, fmt, sizeof(fmt)-1);
    if (n <= 0) exit(0);
    fmt[n] = '\\0';
    printf(fmt, slot[0], slot[1], slot[2], slot[3]);
    puts("");
}

static void trigger(void) {
    char cmd[0x100];
    puts("cmd?");
    if (!fgets(cmd, sizeof(cmd), stdin)) exit(0);
    char *nl = strchr(cmd, '\\n');
    if (nl) *nl = '\\0';
    printf(cmd);
    puts("");
}

static void menu(void) {
    greet();
    while (1) {
        puts("1) set slot");
        puts("2) say (printf with your format)");
        puts("3) trigger (printf(cmd))");
        puts("4) quit");
        printf("> ");
        int c = 0;
        if (scanf("%d%*c", &c) != 1) exit(0);
        switch (c) {
            case 1: set_slot(); break;
            case 2: say(); break;
            case 3: trigger(); break;
            case 4: puts("bye"); return;
            default: puts("?"); break;
        }
    }
}

int main(void) {
    menu();
    return 0;
}
