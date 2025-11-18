#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setup(void){
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void access(void){

char code[200];
puts("Welcome to the nuclear launch facility.");
printf("To proceed please enter the secret launch code: ");

fgets(code,sizeof(code),stdin);
char *ver = strstr(code,"0rd3r-66");
if(!ver){
	puts("Invalid code.\nBreach detected... Aborting!");
	exit(0);
}
puts("Launch code verified.");
puts("Access granted! You entered the following secret code: ");
printf(ver);
}

void nuke(void){

char c;
char buf[80];
puts("Do you wanna proceed?[Y/N]");
scanf(" %c",&c);
getchar();
if(c != 'Y'){
	puts("Mission aborted...");
	exit(0);
}

printf("Target coordinates identified at: %p\n",buf);
printf("Please enter the instructions: ");
read(0,buf,200);

puts("Instructions received.\nTarget eliminated.");
}

int main(){

setup();
access();
nuke();

return 0;
}
