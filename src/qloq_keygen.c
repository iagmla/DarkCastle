#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include "pki/qloqRSA.c"
#include "keygen/keygen.c"

void keygen_usage() {
    printf("usage: castle-keygen <file prefix>\n");
}

int main(int argc, char *argv[]) {
    //struct termios tp, save;
    //tcgetattr(STDIN_FILENO, &tp);
    //save = tp;
    //tp.c_lflag &= ~ECHO; 
    //tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);
    int psize = 3072;
    if (argc != 2) {
        keygen_usage();
        exit(1);
    }
    char * prefix = argv[1];
    printf("\nGenerating keys...this may take a while...\n");
    //tcsetattr(STDIN_FILENO, TCSANOW, &save);
    qloq_keygen(psize, prefix);
    return 0;
}
