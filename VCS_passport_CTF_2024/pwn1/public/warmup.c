#include<stdio.h> 
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include <signal.h>

#define NEW_NOTE 1
#define UPDATE_NOTE 2
#define VIEW_NOTE 3

#define UPDATE_OWNER 1
#define UPDATE_MESSAGE 2
#define UPDATE_STATE 3

#define ERROR_INVALID_ID -1
#define ERROR_INVALID_HEAD -2
#define ERROR_MAX_ID -3
#define ERROR_MALLOC_FAIL -4

#define MAX_MESSAGE 200
#define MAX_ID 50

#define STATE_DONE "DONE"
#define STATE_DOING "DOING"

typedef struct Note{   
    int id;
    char owner[20];
    char *date;
    char *state;
    char *message;
    struct Note *next;
} Note;
int id;
Note *head;

void timeout(){
    exit(0);
}
void init(){
    signal(SIGALRM, timeout);
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}
void win() {
    system("/bin/sh");
}
void logErr(int status){
    if(status == ERROR_INVALID_HEAD){
        puts("[-]Error list head, new note pls!");
    } else if(status == ERROR_INVALID_ID){
        puts("[-]Invalid id");
    } else if (status == ERROR_MAX_ID){
        puts("[-]Max ID");
    } else if (status == ERROR_MALLOC_FAIL){
        puts("[-]Failed to malloc");
    }
}
void Menu(){
    puts("NOTE PROGRAM");
    puts("1.Create new note");
    puts("2.Update note");
    puts("3.View note");
}
int getInt(){
    int buf = 0;
    scanf("%d",&buf);
    getchar(); // remove new line
    return buf;
}
char getchoice(){
    return getInt();
}
int update_note(){
    int update_id = -1;
    char buffer[30];
    Note *tmp;
    if(head == NULL)
        return ERROR_INVALID_HEAD;

    printf("Enter note ID :");
    update_id = getInt();
    if(update_id == -1)
        return ERROR_INVALID_ID;
    
    for(tmp = head;tmp && tmp->id != update_id;tmp = tmp->next);
    if(tmp == NULL || tmp->id != update_id) return ERROR_INVALID_ID;
    // update options
    printf("\nUpdate options: \n1.Update Owner\n2.Update message\n3.Update state\n");
    
    int l = 0;
    printf("Your choice :");
    char c = getchoice();
    switch(c){
        case UPDATE_OWNER:
            printf("Enter new name owner :");
            fgets(buffer,MAX_MESSAGE,stdin);
            l = strlen(buffer);
            memcpy(&tmp->owner,buffer,l);
            break;
        case UPDATE_MESSAGE:
            printf("Enter new message :");
            fgets(buffer,MAX_MESSAGE,stdin);
            l = strlen(buffer);
            if(tmp->message) free(tmp->message);
            tmp->message = malloc(l);
            if(tmp->message == NULL){
                logErr(ERROR_MALLOC_FAIL);
                exit(0);
            }
            memcpy(tmp->message,buffer,l);
            break;
        case UPDATE_STATE:
            printf("is Done?\n1.Yes\n2.No");
            c = getchoice();
            
            if(c == 1) tmp->state = STATE_DONE;
            else if(c == 2) tmp->state = STATE_DOING;
            break;
        default:
            break;
    }    
    
}

int main(){
    init();
    char c;
    Note *tmp;
    head = NULL;
    id = 0;
    time_t t;   
    time(&t);
    char date[100];
    snprintf(date,100,"%s",ctime(&t));

    while(1){
        Menu();
        printf("Your choice :");
        c = getchoice();
        switch (c)
        {
        case NEW_NOTE:
            puts("New note :");
            Note *note = malloc(sizeof(Note));
            
            if(!note){
                logErr(ERROR_MALLOC_FAIL);
                exit(1);
            }
            char message[MAX_MESSAGE];
            memset(message,0,MAX_MESSAGE);
            memset(note,0,sizeof(Note));

            printf("Enter note owner :");
            fgets(note->owner,sizeof(note->owner) - 1,stdin);

            printf("Enter message :");
            fgets(message,MAX_MESSAGE - 1,stdin);

            note->message = malloc(MAX_MESSAGE);
            if(!note->message){
                logErr(ERROR_MALLOC_FAIL);
                exit(1);
            }
            strcpy(note->message,message);
            note->state = STATE_DOING;
            note->id = id;
            note->next = NULL;
            note->date = date;
            id++;
            if (id > MAX_ID) {
                logErr(ERROR_MAX_ID);
                exit(0);
            }
            if(head == NULL){
                head = note;
                printf("New note added, id = %d\n",note->id);
                continue;
            }
            for(tmp = head;tmp->next;tmp = tmp->next);
            tmp->next = note;
            break;
        case UPDATE_NOTE:
            int status = update_note();
            if(status < 0){
                logErr(status);
                continue;
            }
            break;
        case VIEW_NOTE:
            tmp = head;
            puts("All note:");
            for(tmp = head;tmp;tmp = tmp->next){
                puts("===");
                printf("ID : %d\n",tmp->id);
                printf("Note Owner : %s",tmp->owner);
                printf("Note message : %s",tmp->message);
                printf("State : %s\n",tmp->state);
                printf("Program run at : %s\n",tmp->date);
            }
            break;
        default:
            break;
        }
    }
}