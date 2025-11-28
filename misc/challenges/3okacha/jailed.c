#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

int blacklist(char* args) {
    const char* blacklist[] = {
        "flag", "sh", "bin", "cat", 
        "read", "exec", "system", 
        "popen", "eval",
        ";", "|", "&", "$", "`", 
        "(", ")", "<", ">", "*"
    };
    int blacklist_hits = 0;
    for(int i = 0; i < sizeof(blacklist)/sizeof(blacklist[0]); i++) {
        if (strstr(args, blacklist[i]) != NULL) {
            blacklist_hits++;
        }
    }
    return blacklist_hits;
}

int main(){
    char cmd[100];
    int attempts = 0;
    unsetenv("PATH");

    while(attempts < 5)
    {
        printf("user@pwn:~$ ");
        fflush(stdout);

        if (fgets(cmd, sizeof(cmd), stdin) == NULL) {
            break;
        }
        cmd[strcspn(cmd, "\n")] = 0;
        if(strlen(cmd) == 0) continue;
        if(blacklist(cmd)){
            printf("Restricted Command Detected!\n");
            attempts++;
            if(attempts >= 3) {
                printf("Too many incorrect attempts. Lockout initiated.\n");
                sleep(2 * attempts);
            }
            continue;
        }
        attempts = 0;
        system(cmd);
    }
    printf("Maximum attempts reached. Goodbye!\n");
    return 0;
}