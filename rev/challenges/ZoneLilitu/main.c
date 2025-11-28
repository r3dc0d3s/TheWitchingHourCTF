#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#ifdef __linux__
#include <sys/ptrace.h>
#endif

#define PIN_LENGTH   53
#define TOKEN_LENGTH 10

#define DEV_KEY "DEBUG{build_key_only}"

#define USERNAME "LazyBob"

int MASK[5] = {7, 11, 19, 23, 42};

const long S1 = 1716;   
const long S2 = 1834;   

int EQ1_CONSTS[PIN_LENGTH - 4] = {
    42, 169, 174, -9, 202, 227, 160, 34, -125,
    73, 207, -60, -66, 100, 112, 17, 229, 29,
    -66, 184, 63, 162, -40, 13, 25, 124, 212,
    68, -57, -13, -66, 198, 127, 60, -71, 194,
    -33, 8, 121, 246, -58, 146, 34, -29, 153,
    116, 138, -64, 34
};

int ANCHOR1 = 625;
int ANCHOR2 = 30;
int ANCHOR3 = 103;


void random_jitter() {
    int loops = rand() % 1000 + 500;
    volatile int dummy = 0;
    for (int i = 0; i < loops; i++) {
        dummy += (i * 7) ^ (loops - i);
    }

    int sleep_ms = rand() % 50;
    if (sleep_ms > 0) {
        usleep(sleep_ms * 1000);
    }
}

void banner() {
    printf("\n");
    printf("╔═══════════════════════════════════════════╗\n");
    printf("║       Zone01 INTRA ADMIN PANEL v4.2       ║\n");
    printf("║                                           ║\n");
    printf("║        INTERNAL !SECURITY INTERFACE       ║\n");
    printf("║                                           ║\n");
    printf("╚═══════════════════════════════════════════╝\n");
    printf("\n");
}

void stage1_banner() {
    printf("\n");
    printf("[*] Username accepted\n");
    printf("[*] Establishing session channel...\n");
    printf("[*] Validating authentication token...\n");
}

void stage2_banner() {
    printf("\n");
    printf("[*] Token accepted\n");
    printf("[*] Elevating privileges...\n");
    printf("[*] Entering admin password mode...\n\n");
}
int verify_token(char *t) {

    if (strlen(t) != TOKEN_LENGTH)
        return 0;

    int s1 = 0, s2 = 0;
    for (int i = 0; i < TOKEN_LENGTH; i++) {
        if (t[i] < 48 || t[i] > 122) return 0;
        if (i % 2 == 0) s1 += t[i];
        else           s2 += t[i];
    }

    if (s1 != 520) return 0;
    if (s2 != 530) return 0;
    if ((t[2] ^ t[7]) != 23) return 0;

    return 1;
}

int verify_password(char *pin) {

    if (strlen(pin) != PIN_LENGTH)
        return 0;

    if (!strcmp(pin, DEV_KEY)) {
        printf("\n[!] Developer key accepted.\n");
        printf("[!] This is NOT LazyBob's password.\n");
        return 0;
    }
    for (int i = 0; i < PIN_LENGTH; i++) {
        if ((unsigned char)pin[i] < 32 || (unsigned char)pin[i] > 126)
            return 0;
    }

    if (pin[0] != 'C' || pin[1] != 'y' || pin[2] != 'b' || pin[3] != 'e')
        return 0;
    if (pin[4] != 'r' || pin[5] != 'Z' || pin[6] != '{')
        return 0;
    if (pin[PIN_LENGTH - 1] != '}')
        return 0;

    int v[PIN_LENGTH];
    for (int i = 0; i < PIN_LENGTH; i++) {
        v[i] = ((unsigned char)pin[i]) ^ MASK[i % 5];
    }

    long ev = 0, od = 0;
    for (int i = 0; i < PIN_LENGTH; i++) {
        if (i % 2 == 0) ev += v[i];
        else            od += v[i];
    }

    if (ev != S1) return 0;
    if (od != S2) return 0;

    for (int i = 0; i < PIN_LENGTH - 4; i++) {
        if (v[i] + 2 * v[i+1] - 3 * v[i+3] + v[i+4] != EQ1_CONSTS[i])
            return 0;
    }

    if (v[3] * 5 + v[10] != ANCHOR1) return 0;
    if ((v[15] ^ v[32]) != ANCHOR2)  return 0;
    if (v[7] + v[8] + v[9] != ANCHOR3) return 0;

    return 1;
}

int main() {

    char username[64];
    char token[64];
    char password[256];

    srand((unsigned int)(time(NULL) ^ getpid()));
    banner();

    printf("USERNAME: ");
    if (!fgets(username, sizeof(username), stdin)) {
        return 1;
    }
    username[strcspn(username, "\n")] = 0;

    random_jitter();

    if (strcmp(username, USERNAME)) {
        printf("\n[-] Unknown user.\n");
        return 1;
    } else {
	printf("golo lih ykhlini ndkhol w n3tikum lflag\n");
    }

    stage1_banner();
    printf("\nSESSION TOKEN: ");
    if (!fgets(token, sizeof(token), stdin)) {
        return 1;
    }
    token[strcspn(token, "\n")] = 0;

    random_jitter();

    if (!verify_token(token)) {
        printf("\n[-] Session token rejected.\n");
        return 1;
    }

    stage2_banner();
    printf("ADMIN PASSWORD: ");
    if (!fgets(password, sizeof(password), stdin)) {
        return 1;
    }
    password[strcspn(password, "\n")] = 0;

    random_jitter();

    if (verify_password(password)) {
        printf("\n✅ ACCESS GRANTED\n");
        printf("Welcome, LazyBob\n");
        printf("Password (flag): %s\n\n", password);
    } else {
        printf("\n❌ ACCESS DENIED\n");
        printf("Invalid password\n\n");
    }

    return 0;
}

