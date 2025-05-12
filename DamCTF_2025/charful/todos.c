#include <stdio.h>
#include <string.h>

#include "todos.h"

#define NUM_TODOS 10

struct Todo {
    char name[NAME_LEN + 1];
    int completed;
};

static struct Todo todos[NUM_TODOS];
static int next = 0;

void add_todo(char *name) {
    if (next == NUM_TODOS) {
        printf("Too much to do!\n");
        return;
    }

    struct Todo *todo = &todos[next];
    strncpy(todo->name, name, NAME_LEN);
    todo->name[NAME_LEN] = 0;
    todo->completed = 0;
    printf("Added TODO #%d", next++);
}

void print_todo(char i) {
    if (i < 0 || i >= next) {
        printf("Invalid TODO\n");
        return;
    }

    printf("// TODO: %s%s\n", todos[i].name, todos[i].completed ? " (done!)" : "");
}

void complete_todo(char i) {
    if (i < 0 || i >= next) {
        printf("Invalid TODO\n");
        return;
    }
    todos[i].completed = 1;
}

void edit_todo(char i, char *new_name) {
    if (i < 0 || i >= next) {
        printf("Invalid TODO\n");
        return;
    }

    struct Todo *todo = &todos[i];
    strncpy(todo->name, new_name, NAME_LEN);
    todo->name[NAME_LEN] = 0;
}

void check_completion() {
    char incomplete = -1;
    find_incomplete_todos(&incomplete, 1);
    if (incomplete == -1) {
        printf("You've completed all your TODOs!\n");
    } else {
        printf("You still have to complete TODO #%d!\n", incomplete);
    }
}

// Searches for up to `max` incomplete TODOs and writes their IDs to `out`.
void find_incomplete_todos(char out[], char max) {
    for (char i = 0; i < next; i++) {
        if (!todos[i].completed && max != 0) {
            *out = i;
            max -= 1;
        }
    }
}
