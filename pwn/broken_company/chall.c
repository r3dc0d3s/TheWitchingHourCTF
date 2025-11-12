#include <stdio.h>
#include <string.h>
#include <stdlib.h>

long access = 0xdeadcafe;

void helper() {
    __asm__(
        "pop %rdi;"
        "ret;"
    );
}

void setup(void){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void portal(void){
	char data[64];
	unsigned int record_size;
	puts("\n=== Employee Database System ===");
	puts("Access granted to internal records.");
        printf("How much data to upload? ");
        scanf("%u", &record_size);
	getchar();

	if ((int)record_size > 64) {
        	puts("ERROR: File size too large!");
        	return;
	}
	puts("Enter employee records:");
        read(0, data, record_size);
        puts("Employee data uploaded successfully!");
	puts("Database updated.");
}

int main(){

char name[16];
char id[100];
setup();

puts("Welcome to our company");
puts("Please enter your name: ");
fgets(name,sizeof(name),stdin);

printf("Welcome %s",name);
puts("To confirm your identity Please enter your ID");
fgets(id,sizeof(id),stdin);
puts("Your badge id is: ");
printf(id);
printf("\n");

if (access == 0xbeefdead) {
	printf("Management credentials verified.\n");
        portal();
}else{
        printf("Standard employee access granted.\n");
}

return 0;
}
