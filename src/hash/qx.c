#include <stdio.h>

uint32_t qx_c0[16] = {0x923c44fc, 0xf867f0f6, 0xc2e5cc28, 0x8ecebfd4, 0xcb632744, 0x90a142fa, 0xea942e3a, 0x9c70db80, 0xba55d7e1, 0xe3b1f8a2, 0xc60865e0, 0xf8112cc2, 0x93d6b989, 0xc1cf8477, 0x812b7f3c, 0x8c776893};

uint32_t rotateleft32(uint32_t a, uint32_t b) {
    return ((a << b) | (a >> (32 - b)));
}

struct qx_state {
    uint32_t q[16];
    uint32_t t[16];
};

void qx_init(struct qx_state *state) {
    state->q[0] = qx_c0[0];
    state->q[1] = qx_c0[1];
    state->q[2] = qx_c0[2];
    state->q[3] = qx_c0[3];
    state->q[4] = qx_c0[4];
    state->q[5] = qx_c0[5];
    state->q[6] = qx_c0[6];
    state->q[7] = qx_c0[7];
    state->q[8] = qx_c0[8];
    state->q[9] = qx_c0[9];
    state->q[10] = qx_c0[10];
    state->q[11] = qx_c0[11];
    state->q[12] = qx_c0[12];
    state->q[13] = qx_c0[13];
    state->q[14] = qx_c0[14];
    state->q[15] = qx_c0[15];
}

void qx_roundA(struct qx_state *state) {
    state->q[8] += rotateleft32((state->q[7] ^ state->q[4]), 12);
    state->q[6] ^= rotateleft32((state->q[8] + state->q[11]), 7);
    state->q[3] += rotateleft32((state->q[6] ^ state->q[5]), 9);
    state->q[15] ^= rotateleft32((state->q[9] + state->q[10]), 21);
    state->q[10] += rotateleft32((state->q[2] ^ state->q[1]), 12);
    state->q[5] ^= rotateleft32((state->q[10] + state->q[14]), 7);
    state->q[13] += rotateleft32((state->q[3] ^ state->q[0]), 9);
    state->q[12] ^= rotateleft32((state->q[13] + state->q[12]), 21);
    state->q[7] += rotateleft32((state->q[12] ^ state->q[8]), 12);
    state->q[11] ^= rotateleft32((state->q[4] + state->q[6]), 7);
    state->q[2] += rotateleft32((state->q[5] ^ state->q[13]), 9);
    state->q[1] ^= rotateleft32((state->q[1] + state->q[7]), 21);
    state->q[0] += rotateleft32((state->q[14] ^ state->q[3]), 12);
    state->q[14] ^= rotateleft32((state->q[0] + state->q[9]), 7);
    state->q[9] += rotateleft32((state->q[11] ^ state->q[15]), 9);
    state->q[4] ^= rotateleft32((state->q[15] + state->q[2]), 21);
}

void qx_roundB(struct qx_state *state) {
    state->q[1] = rotateleft32((state->q[1] ^ state->q[0]), 15);
    state->q[3] = rotateleft32((state->q[3] ^ state->q[2]), 8);
    state->q[5] = rotateleft32((state->q[5] ^ state->q[4]), 16);
    state->q[7] = rotateleft32((state->q[7] ^ state->q[6]), 24);
    state->q[9] = rotateleft32((state->q[9] ^ state->q[8]), 15);
    state->q[11] = rotateleft32((state->q[11] ^ state->q[10]), 8);
    state->q[13] = rotateleft32((state->q[13] ^ state->q[12]), 16);
    state->q[15] = rotateleft32((state->q[15] ^ state->q[14]), 24);
    state->q[0] = rotateleft32((state->q[0] ^ state->q[1]), 15);
    state->q[2] = rotateleft32((state->q[2] ^ state->q[3]), 8);
    state->q[4] = rotateleft32((state->q[4] ^ state->q[5]), 16);
    state->q[6] = rotateleft32((state->q[6] ^ state->q[7]), 24);
    state->q[8] = rotateleft32((state->q[8] ^ state->q[9]), 15);
    state->q[10] = rotateleft32((state->q[10] ^ state->q[11]), 8);
    state->q[12] = rotateleft32((state->q[12] ^ state->q[13]), 16);
    state->q[14] = rotateleft32((state->q[14] ^ state->q[15]), 24);
}

void qx_rotate_words(struct qx_state *state) {
    state->t[0] = state->q[0];
    state->t[1] = state->q[1];
    state->t[2] = state->q[2];
    state->t[3] = state->q[3];
    state->t[4] = state->q[4];
    state->t[5] = state->q[5];
    state->t[6] = state->q[6];
    state->t[7] = state->q[7];
    state->t[8] = state->q[8];
    state->t[9] = state->q[9];
    state->t[10] = state->q[10];
    state->t[11] = state->q[11];
    state->t[12] = state->q[12];
    state->t[13] = state->q[13];
    state->t[14] = state->q[14];
    state->t[15] = state->q[15];

    state->q[1] = state->t[0];
    state->q[2] = state->t[1];
    state->q[3] = state->t[2];
    state->q[4] = state->t[3];
    state->q[5] = state->t[4];
    state->q[6] = state->t[5];
    state->q[7] = state->t[6];
    state->q[8] = state->t[7];
    state->q[9] = state->t[8];
    state->q[10] = state->t[9];
    state->q[11] = state->t[10];
    state->q[12] = state->t[11];
    state->q[13] = state->t[12];
    state->q[14] = state->t[13];
    state->q[15] = state->t[14];
    state->q[0] = state->t[15];

}

void qx_absorb(struct qx_state *state, uint8_t * block) {
    state->q[0] ^= ((block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3]);
    state->q[1] ^= ((block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7]);
    state->q[2] ^= ((block[8] << 24) + (block[9] << 16) + (block[10] << 8) + block[11]);
    state->q[3] ^= ((block[12] << 24) + (block[13] << 16) + (block[14] << 8) + block[15]);
    state->q[4] ^= ((block[16] << 24) + (block[17] << 16) + (block[18] << 8) + block[19]);
    state->q[5] ^= ((block[20] << 24) + (block[21] << 16) + (block[22] << 8) + block[23]);
    state->q[6] ^= ((block[24] << 24) + (block[25] << 16) + (block[26] << 8) + block[27]);
    state->q[7] ^= ((block[28] << 24) + (block[29] << 16) + (block[30] << 8) + block[31]);
}

void qx_rounds(struct qx_state *state, int rounds) {
    for (int r = 0; r < rounds; r++) {
        qx_roundA(state);
        qx_roundB(state);
        qx_rotate_words(state);
    }
}

void qx_output(struct qx_state * state, uint8_t * digest) {
    digest[0] = (state->q[0] >> 24);
    digest[1] = (state->q[0] >> 16);
    digest[2] = (state->q[0] >> 8);
    digest[3] = state->q[0];
    digest[4] = (state->q[1] >> 24);
    digest[5] = (state->q[1] >> 16);
    digest[6] = (state->q[1] >> 8);
    digest[7] = state->q[1];
    digest[8] = (state->q[2] >> 24);
    digest[9] = (state->q[2] >> 16);
    digest[10] = (state->q[2] >> 8);
    digest[11] = state->q[2];
    digest[12] = (state->q[3] >> 24);
    digest[13] = (state->q[3] >> 16);
    digest[14] = (state->q[3] >> 8);
    digest[15] = state->q[3];
    digest[16] = (state->q[4] >> 24);
    digest[17] = (state->q[4] >> 16);
    digest[18] = (state->q[4] >> 8);
    digest[19] = state->q[4];
    digest[20] = (state->q[5] >> 24);
    digest[21] = (state->q[5] >> 16);
    digest[22] = (state->q[5] >> 8);
    digest[23] = state->q[5];
    digest[24] = (state->q[6] >> 24);
    digest[25] = (state->q[6] >> 16);
    digest[26] = (state->q[6] >> 8);
    digest[27] = state->q[6];
    digest[28] = (state->q[7] >> 24);
    digest[29] = (state->q[7] >> 16);
    digest[30] = (state->q[7] >> 8);
    digest[31] = state->q[7];
}

void qx_hash_file(char * filename, uint8_t *digest) {
    uint8_t key[32] = {1};
    struct qx_state state;
    qx_init(&state);
    int rounds = 64;
    qx_rounds(&state, rounds);
    FILE *infile;
    int blocksize = 32;
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    uint64_t blocks = datalen / blocksize;
    int extra = datalen % blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    for (uint64_t b = 0; b < blocks; b++) {
        uint8_t block[32] = {0};
        if ((b == (blocks - 1)) && (extra != 0)) {
            blocksize = extra;
        }
        fread(&block, 1, blocksize, infile);
        qx_absorb(&state, block);
        qx_rounds(&state, rounds);
    }
    fclose(infile);
    qx_output(&state, digest);
}

void qx_hash_file_offset(char * filename, uint8_t *digest, int offset) {
    uint8_t key[32] = {0};
    struct qx_state state;
    qx_init(&state);
    int rounds = 64;
    qx_absorb(&state, key);
    qx_rounds(&state, rounds);
    FILE *infile;
    int blocksize = 32;
    int bufsize = 32;
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - offset;
    fseek(infile, 0, SEEK_SET);
    uint64_t blocks = datalen / blocksize;
    int extra = datalen % blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    for (uint64_t b = 0; b < blocks; b++) {
        uint8_t block[32] = {0};
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        qx_absorb(&state, block);
        qx_rounds(&state, rounds);
    }
    fclose(infile);
    qx_output(&state, digest);
}

void qx_hmac_file(char * filename, uint8_t * key, uint8_t *digest) {
    struct qx_state state;
    qx_init(&state);
    int rounds = 64;
    qx_absorb(&state, key);
    qx_rounds(&state, rounds);
    FILE *infile;
    int blocksize = 32;
    int bufsize = 32;
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    uint64_t blocks = datalen / blocksize;
    int extra = datalen % blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    for (uint64_t b = 0; b < blocks; b++) {
        uint8_t block[32] = {0};
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        qx_absorb(&state, block);
        qx_rounds(&state, rounds);
    }
    fclose(infile);
    qx_output(&state, digest);
}

void qx_hmac_file_verify(char * filename, uint8_t * key, uint8_t *verify) {
    struct qx_state state;
    qx_init(&state);
    int rounds = 64;
    qx_absorb(&state, key);
    qx_rounds(&state, rounds);
    FILE *infile;
    int blocksize = 32;
    int bufsize = 32;
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - 32;
    fseek(infile, 0, SEEK_SET);
    uint64_t blocks = datalen / blocksize;
    int extra = datalen % blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    for (uint64_t b = 0; b < blocks; b++) {
        uint8_t block[32] = {0};
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        qx_absorb(&state, block);
        qx_rounds(&state, rounds);
    }
    fclose(infile);
    qx_output(&state, verify);
}

void qx_hmac_file_verify_offset(char * filename, uint8_t * key, uint8_t *verify, int offset) {
    struct qx_state state;
    qx_init(&state);
    int rounds = 64;
    qx_absorb(&state, key);
    qx_rounds(&state, rounds);
    FILE *infile;
    int blocksize = 32;
    int bufsize = 32;
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    datalen = datalen - 32 - offset;
    fseek(infile, 0, SEEK_SET);
    uint64_t blocks = datalen / blocksize;
    int extra = datalen % blocksize;
    if (extra != 0) {
        blocks += 1;
    }
    for (uint64_t b = 0; b < blocks; b++) {
        uint8_t block[32] = {0};
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        qx_absorb(&state, block);
        qx_rounds(&state, rounds);
    }
    fclose(infile);
    qx_output(&state, verify);
}


void qx_hmac_file_write(char *filename, uint8_t *key) {
    uint8_t digest[32];
    FILE *outfile;
    qx_hmac_file(filename, key, digest);
    outfile = fopen(filename, "a");
    fwrite(digest, 1, 32, outfile);
    fclose(outfile);
}

int qx_hmac_file_read_verify(char *filename, uint8_t *key) {
    uint8_t digest[32];
    uint8_t verify[32];
    FILE *infile;
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, 0);
    uint64_t mac_pos = datalen - 32;
    datalen = datalen - 32;
    fseek(infile, mac_pos, 0);
    uint64_t pos = ftell(infile);
    fread(verify, 1, 32, infile);
    fclose(infile);
    qx_hmac_file_verify(filename, key, digest);
    if (memcmp(digest, verify, 32) == 0) {
        return 0;
    }
    else {
        return -1;
    }
}

int qx_hmac_file_read_verify_offset(char *filename, uint8_t *key, int offset) {
    uint8_t digest[32];
    uint8_t verify[32];
    FILE *infile;
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    fseek(infile, 0, 0);
    uint64_t mac_pos = datalen - 32 - offset;
    datalen = datalen - 32;
    fseek(infile, mac_pos, 0);
    uint64_t pos = ftell(infile);
    fread(verify, 1, 32, infile);
    fclose(infile);
    qx_hmac_file_verify_offset(filename, key, digest, offset);
    if (memcmp(digest, verify, 32) == 0) {
        return 0;
    }
    else {
        return -1;
    }
}

void qx_kdf(unsigned char *password, int passlen, unsigned char *key, int iters) {
    struct qx_state state;
    int rounds = 64;
    qx_init(&state);
    qx_rounds(&state, rounds);
    int blocklen = 32;
    int blocks = passlen / 32;
    int extra = passlen % 32;
    if (extra != 0) {
        blocks += 1;
    }
    uint8_t block[32] = {0};
    int c = 0;
    for (int i = 0; i < blocks; i++) {
        if ((i == blocks - 1) && (extra != 0)) {
            blocklen = extra;
        }
        uint8_t block[32] = {0};
        for (int x = 0; x < blocklen; x++) {
            block[x] = password[c];
            c += 1;
        }
        qx_absorb(&state, block);
        qx_rounds(&state, rounds);
    }
    for (int i = 0; i < iters; i++) {
        qx_rounds(&state, rounds);
    }
    qx_output(&state, key);
}

void qx_crypt(char * in, char *out, uint8_t * key) {
     uint8_t tmp[32] = {0};
     struct qx_state state;
     qx_init(&state);
     qx_absorb(&state, key);
     int rounds = 1;
     qx_rounds(&state, rounds);
     FILE *infile, *outfile;
     int blocksize = 32;
     int bufsize = 32;
     infile = fopen(in, "rb");
     outfile = fopen(out, "wb");
     fseek(infile, 0, SEEK_END);
     uint64_t datalen = ftell(infile);
     fseek(infile, 0, SEEK_SET);
     uint64_t blocks = datalen / blocksize;
     int extra = datalen % blocksize;
     if (extra != 0) {
         blocks += 1;
     }
     for (int b = 0; b < blocks; b++) {
         uint8_t block[32] = {0};
         fread(block, 1, bufsize, infile);
         if ((b == (blocks - 1)) && (extra != 0)) {
             bufsize = extra;
         }
         qx_absorb(&state, tmp);
         qx_rounds(&state, rounds);
         qx_output(&state, tmp);
         for (int i = 0; i < bufsize; i++) {
             block[i] ^= tmp[i];
         }
         fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}

void sign_hash_write(struct qloq_ctx *Sctx, char *filename) {
    int S_len = 768;
    uint8_t sig[S_len];
    uint8_t h[32];
    uint8_t X[32];
    uint8_t nonce[32];
    BIGNUM *S;
    S = BN_new();
    BIGNUM *H;
    H = BN_new();
    qx_hash_file(filename, h);
    urandom(nonce, 32);
    mypad_encrypt(h, nonce, X);
    BN_bin2bn(X, 32, H);
    sign(Sctx, S, H);
    BN_bn2bin(S, sig);
    FILE *infile;
    infile = fopen(filename, "a");
    fwrite(nonce, 1, 32, infile);
    fwrite(sig, 1, S_len, infile);
    fclose(infile);
}

void verify_sig_read(struct qloq_ctx *Sctx, char *filename) {
    int S_len = 768;
    uint8_t sig[S_len];
    uint8_t X[32];
    uint8_t nonce[32];
    uint8_t h[32];
    BIGNUM *Ssig;
    Ssig = BN_new();
    BIGNUM *S;
    S = BN_new();
    BIGNUM *H;
    H = BN_new();
    FILE *infile;
    qx_hash_file_offset(filename, h, (S_len + 32));
    infile = fopen(filename, "rb");
    fseek(infile, 0, SEEK_END);
    uint64_t datalen = ftell(infile);
    uint64_t pos = datalen - S_len - 32;
    fseek(infile, 0, SEEK_SET);
    fseek(infile, pos, SEEK_SET);
    fread(nonce, 1, 32, infile);
    fread(sig, 1, S_len, infile);
    fclose(infile);
    BN_bin2bn(sig, S_len, Ssig);
    mypad_encrypt(nonce, h, X);
    BN_bin2bn(X, 32, H);

    if (verify(Sctx, Ssig, H) != 0) {
        printf("Error: PK Signature verification failed. Message is not authentic.\n");
        exit(2);
    }
}

