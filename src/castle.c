#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include "pki/qloqRSA.h"
#include "ciphers/uvajda_oneshot.c"
#include "kdf/manja.c"
#include "hash/qx.c"
#include "crypto_funcs.c"
#include "ciphers/zanderfish3_cbc.c"
#include "ciphers/zanderfish3_ofb.c"
#include "ciphers/zanderfish2_cbc.c"
#include "ciphers/zanderfish2_ofb.c"
#include "ciphers/qapla.c"

void usage() {
    printf("DarkCastle v1.667 - by KryptoMagik\n\n");
    printf("Algorithms:\n***********\nqapla            256 bit\nzanderfish2-cbc  256 bit\nzanderfish2-ofb  256 bit\nzanderfish3      256 bit\nzanderfish3-ofb  256 bit\n\n");
    printf("Usage:\ncastle <algorithm> -e <input file> <output file> <public keyfile> <secret keyfile>\n");
    printf("castle <algorithm> -d <input file> <output file> <secret keyfile> <public keyfile>\n");
}

int main(int argc, char *argv[]) {
    int kdf_iterations = 100000;
    int password_len = 256;
    int mask_bytes = 768;

    char *encrypt_symbol = "-e";
    char *decrypt_symbol = "-d";

    int zanderfish2_nonce_length = 16;
    int zanderfish3_nonce_length = 32;
    int qapla_nonce_length = 16;

    int zanderfish_key_length = 32;
    int zanderfish2_key_length = 32;
    int zanderfish3_key_length = 32;
    int qapla_key_length = 32;

    int zanderfish_mac_length = 32;
    int zanderfish2_mac_length = 32;
    int zanderfish3_mac_length = 32;
    int qapla_mac_length = 32;

    int zanderfish2_cbc_bufsize = 131072;
    int zanderfish3_bufsize = 262144;
    int zanderfish2_ofb_bufsize = 262144;
    int zanderfish2_ctr_bufsize = 262144;
    int qapla_bufsize = 262144;

    if (argc != 7) {
        usage();
        return 0;
    }

    FILE *infile, *outfile;
    char *infile_name, *outfile_name, *keyfile1_name, *keyfile2_name;
    char *algorithm = argv[1];
    char *mode = argv[2];
    infile_name = argv[3];
    outfile_name = argv[4];
    keyfile1_name = argv[5];
    keyfile2_name = argv[6];
    if (access(infile_name, F_OK) == -1 ) {
        printf("%s not found\n", infile_name);
        exit(1);
    }
    infile = fopen(infile_name, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fclose(infile);
    struct termios tp, save;
    tcgetattr(STDIN_FILENO, &tp);
    save = tp;
    tp.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);

    unsigned char * passphrase[256];
    printf("Enter secret key passphrase: ");
    scanf("%s", passphrase);
    tcsetattr(STDIN_FILENO, TCSANOW, &save);

    if (strcmp(algorithm, "zanderfish3") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "zanderfish3-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander3_ofb_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander3_ofb_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish3_key_length, zanderfish3_nonce_length, zanderfish3_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, zanderfish3_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-cbc") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_cbc_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_cbc_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_cbc_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_cbc_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "zanderfish2-ofb") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            zander2_ofb_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_ofb_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            zander2_ofb_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, zanderfish2_key_length, zanderfish2_nonce_length, zanderfish2_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, zanderfish2_ofb_bufsize, passphrase);
        }
    }
    else if (strcmp(algorithm, "qapla") == 0) {
        if (strcmp(mode, encrypt_symbol) == 0) {
            qapla_encrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, qapla_bufsize, passphrase);
        }
        else if (strcmp(mode, decrypt_symbol) == 0) {
            qapla_decrypt(keyfile1_name, keyfile2_name, infile_name, outfile_name, qapla_key_length, qapla_nonce_length, qapla_mac_length, kdf_iterations, password_len, keywrap256_ivlen, mask_bytes, qapla_bufsize, passphrase);
        }
    }
    printf("\n");
    return 0;
}
