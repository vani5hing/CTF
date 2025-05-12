#define NAME_LEN 50

void add_todo(char *name);
void print_todo(char i);
void complete_todo(char i);
void edit_todo(char i, char *new_name);
void check_completion();
void find_incomplete_todos(char out[], char max);
