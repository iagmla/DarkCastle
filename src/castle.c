#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include "common/common.c"
#include "pki/qloqRSA.c"
#include "hash/qx.c"
#include "ciphers/zanderfish3_cbc.c"
#include "ciphers/qapla.c"
#include "ciphers/zanderfish4_cbc.c"

/* DarkCastle */
/* by KryptoMagick (Karl Zander) */

void usage() {
    printf("DarkCastle v2.3.0 - by KryptoMagick\n\n");
    printf("Algorithms:\n***********\nzanderfish3      256 bit\nzanderfish4      256 bit\nqapla            256 bit\n\n");
    printf("Usage:\ncastle <algorithm> -e <input file> <output file> <pk file> <sk file>\n");
    printf("castle <algorithm> -d <input file> <output file> <pk file> <sk file>\n");
}

int main(int argc, char *argv[]) {
    int kdf_iters = 100000;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    if (argc != 7) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name, *pkfile_name, *skfile_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    pkfile_name = argv[5];
    skfile_name = argv[6];

    file_present(infile_name);
    file_present(pkfile_name);
    file_present(skfile_name);

    if (strcmp(algorithm, "zanderfish3") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zanderfish3_cbc_encrypt(infile_name, outfile_name, pkfile_name, skfile_name);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zanderfish3_cbc_decrypt(infile_name, outfile_name, pkfile_name, skfile_name);
        }
    }
    else if (strcmp(algorithm, "qapla") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            qapla_encrypt(infile_name, outfile_name, pkfile_name, skfile_name);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            qapla_decrypt(infile_name, outfile_name, pkfile_name, skfile_name);
        }
    }
    else if (strcmp(algorithm, "zanderfish4") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zanderfish4_cbc_encrypt(infile_name, outfile_name, pkfile_name, skfile_name);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zanderfish4_cbc_decrypt(infile_name, outfile_name, pkfile_name, skfile_name);
        }
    }
    printf("\n");
    return 0;
}
