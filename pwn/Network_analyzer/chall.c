#include <stdio.h>
#include <unistd.h>

void setup(void){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void flag(void){
	char flag[57];
	printf("You win! Here is your flag\n");
	FILE *f = fopen("flag.txt","r");
       	if(!f){
		printf("Error opening the flag.\n");
		return;
	}
	if (fgets(flag, sizeof(flag),f)==NULL){
		printf("Error reading the flag\n");
		fclose(f);
		return;
	}
	printf("%s\n",flag);
	fclose(f);
}

int main(){
setup();

char buf[24];
long size;
char buf2[128];
size = 128;

puts("Network Analyzer v1.0");
printf("Enter packet header: ");
read(0,buf,26);

puts("Header accepted.");
printf("Analyzer expects %ld bytes.\n", size);
printf("Send packet body: ");
read(0,buf2,size);

puts("Analyzing packet...\n");
sleep(1);
puts("Scanning for anomalies...\n");
sleep(1);
puts("Packets successfully analyzed! No threat found.\n");

return 0;
}
