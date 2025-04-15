#define _GNU_SOURCE
#include "magic_buddy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#define POOL_SIZE 1024
#define CHUNK_SIZE 0x80

struct buddy state;
uint8_t pool[POOL_SIZE];

char *vault = NULL;

void (*fp)() = NULL;

void safe_notify() { puts("Notification: Your vault is secure."); }

void win() {
    puts("Access granted! Spawning shell...");
    system("/bin/sh");
}

void *vault_functions[2];

void init_app() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    vault_functions[0] = win;
    vault_functions[1] = safe_notify;

    fp = &vault_functions[1];

    uint8_t magic[MAGIC_COOKIE_BYTES];
    if (getrandom(magic, MAGIC_COOKIE_BYTES, 0) != MAGIC_COOKIE_BYTES) {
        perror("getrandom");
        exit(1);
    }
    init_buddy(pool, POOL_SIZE, magic, &state);
}

void menu() {
    puts("========== BankVault Service ==========");
    puts("1. Create Vault Entry");
    puts("2. Edit Vault Entry");
    puts("3. Delete Vault Entry");
    puts("4. Allocate New Vault Entry");
    puts("5. Send Notification");
    puts("6. Exit");
    printf("Your choice: ");
}

void create_vault() {
    if (vault != NULL) {
        puts("Vault entry already exists!");
        return;
    }
    vault = allocate(CHUNK_SIZE, &state);
    if (!vault) {
        puts("Allocation failed.");
        exit(1);
    }
    printf("Enter your vault note (max %d bytes): ", CHUNK_SIZE);
    read(0, vault, CHUNK_SIZE);
}

void edit_vault() {
    if (!vault) {
        puts("No vault entry exists!");
        return;
    }
    printf("Enter new vault note (max %d bytes): ", CHUNK_SIZE);
    read(0, vault, CHUNK_SIZE);
}

void delete_vault() {
    if (!vault) {
        puts("No vault entry exists!");
        return;
    }
    puts("Deleting your vault entry...");
    liberate(vault, CHUNK_SIZE, &state);
}

void allocate_new_vault() {
    vault = allocate(CHUNK_SIZE, &state);
    if (!vault) {
        puts("Allocation failed.");
        exit(1);
    }
    printf("New vault entry allocated at: %p\n", vault);
}

void send_notification() {
    void (*fp2)() = *((void **)fp);
    puts("Sending notification...");
    fp2();
}

int main() {
    char choice[8];
    init_app();

    while (1) {
        menu();
        if (!fgets(choice, sizeof(choice), stdin))
            break;
        switch (atoi(choice)) {
        case 1:
            create_vault();
            break;
        case 2:
            edit_vault();
            break;
        case 3:
            delete_vault();
            break;
        case 4:
            allocate_new_vault();
            break;
        case 5:
            send_notification();
            break;
        case 6:
            puts("Goodbye!");
            exit(0);
        default:
            puts("Invalid choice.");
        }
    }
    return 0;
}
