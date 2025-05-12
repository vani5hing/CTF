#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "todos.h"

char flag[128] = "oh were you looking for a flag? i think i saw one over that way -------------> ";

void read_line(char **buf, size_t *len) {
    ssize_t read = getline(buf, len, stdin);
    if (read < 0) {
        printf("Error reading input\n");
        exit(1);
    }
    if (read > 0 && (*buf)[read-1] == '\n') (*buf)[read-1] = 0;
}

int read_unsigned(char **buf, size_t *len) {
    read_line(buf, len);
    char *end;
    long long result = strtoll(*buf, &end, 10);
    if (result < 0) {
        return -1;
    } else {
        return result;
    }
}

char read_char(char **buf, size_t *len) {
    int result = read_unsigned(buf, len);
    if (result == -1 || result > CHAR_MAX) {
        return -1;
    }
    return result;
}

int main(int argc, const char *argv[]) {
    fgets(flag + strlen(flag), sizeof(flag) - strlen(flag), fopen("flag.txt", "r"));

    for (;;) {
        printf("\n\n");
        printf("1. Add a TODO\n");
        printf("2. Print a TODO\n");
        printf("3. Mark a TODO as completed\n");
        printf("4. Edit a TODO\n");
        printf("5. Check for incomplete TODOs\n");
        printf("6. Exit\n");
        printf("What would you like to do? ");
        fflush(stdout);

        char *buf = NULL;
        size_t len;

        switch (read_char(&buf, &len)) {
            int choice;
            case 1:
                printf("// TODO: ");
                fflush(stdout);
                read_line(&buf, &len);
                add_todo(buf);
                break;
            case 2:
                printf("Which TODO would you like to print? ");
                fflush(stdout);
                choice = read_char(&buf, &len);
                if (choice != -1) print_todo(choice);
                else printf("Invalid input.\n");
                break;
            case 3:
                printf("Which TODO would you like to mark as completed? ");
                fflush(stdout);
                choice = read_char(&buf, &len);
                if (choice != -1) complete_todo(choice);
                else printf("Invalid input.\n");
                break;
            case 4:
                printf("Which TODO would you like to edit? ");
                fflush(stdout);
                choice = read_char(&buf, &len);

                printf("Enter a new name: ");
                fflush(stdout);
                read_line(&buf, &len);

                edit_todo(choice, buf);
                break;
            case 5:
                check_completion();
                break;
            case 6:
                return 0;
            case -1:
                printf("Invalid input.\n");
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}
