/* QX */
/* by KryptoMagick (Karl Zander) */
/* 256 bit input size / 800 bit state */
/* 256 bit output */
/* 25 rounds */

uint32_t qx_c0[25] = {0x923c44fc, 0xf867f0f6, 0xc2e5cc28, 0x8ecebfd4, 0xcb632744, 0x90a142fa, 0xea942e3a, 0x9c70db80, 0xba55d7e1, 0xe3b1f8a2, 0xc60865e0, 0xf8112cc2, 0x93d6b989, 0xc1cf8477, 0x812b7f3c, 0x8c776893, 0xcea9b7e1, 0xdb51dd82, 0xcf9e6886, 0xc2a7551c, 0xa9e3e82b, 0xe77979d1, 0xead7c4bb, 0xeda04895, 0xbe61724c};

struct qx_state {
    uint32_t q[5][5];
    uint32_t t[5][5];
    uint32_t o[8];
    int rounds;
};

uint32_t qx_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

void qx_init(struct qx_state *state) {
    state->rounds = 25;
    state->q[0][0] = qx_c0[0];
    state->q[0][1] = qx_c0[1];
    state->q[0][2] = qx_c0[2];
    state->q[0][3] = qx_c0[3];
    state->q[0][4] = qx_c0[4];
    state->q[1][0] = qx_c0[5];
    state->q[1][1] = qx_c0[6];
    state->q[1][2] = qx_c0[7];
    state->q[1][3] = qx_c0[8];
    state->q[1][4] = qx_c0[9];
    state->q[2][0] = qx_c0[10];
    state->q[2][1] = qx_c0[11];
    state->q[2][2] = qx_c0[12];
    state->q[2][3] = qx_c0[13];
    state->q[2][4] = qx_c0[14];
    state->q[3][0] = qx_c0[15];
    state->q[3][1] = qx_c0[16];
    state->q[3][2] = qx_c0[17];
    state->q[3][3] = qx_c0[18];
    state->q[3][4] = qx_c0[19];
    state->q[4][0] = qx_c0[20];
    state->q[4][1] = qx_c0[21];
    state->q[4][2] = qx_c0[22];
    state->q[4][3] = qx_c0[23];
    state->q[4][4] = qx_c0[24];
}

void qx_keysetup(struct qx_state *state, uint8_t *key, uint8_t *nonce) {
    qx_init(state);

    state->q[0][0] ^= ((key[0] << 24) + (key[1] << 16) + (key[2] << 8) + key[3]);
    state->q[1][0] ^= ((key[4] << 24) + (key[5] << 16) + (key[6] << 8) + key[7]);
    state->q[2][0] ^= ((key[8] << 24) + (key[9] << 16) + (key[10] << 8) + key[11]);
    state->q[3][0] ^= ((key[12] << 24) + (key[13] << 16) + (key[14] << 8) + key[15]);
    state->q[4][0] ^= ((key[16] << 24) + (key[17] << 16) + (key[18] << 8) + key[19]);
    state->q[0][1] ^= ((key[20] << 24) + (key[21] << 16) + (key[22] << 8) + key[23]);
    state->q[1][1] ^= ((key[24] << 24) + (key[25] << 16) + (key[26] << 8) + key[27]);
    state->q[2][1] ^= ((key[28] << 24) + (key[29] << 16) + (key[30] << 8) + key[31]);
    state->q[3][1] ^= ((nonce[0] << 24) + (nonce[1] << 16) + (nonce[2] << 8) + nonce[3]);
    state->q[4][1] ^= ((nonce[4] << 24) + (nonce[5] << 16) + (nonce[6] << 8) + nonce[7]);
    state->q[0][2] ^= ((nonce[8] << 24) + (nonce[9] << 16) + (nonce[10] << 8) + nonce[11]);
    state->q[1][2] ^= ((nonce[12] << 24) + (nonce[13] << 16) + (nonce[14] << 8) + nonce[15]);

}

void qx_absorb(struct qx_state *state, uint8_t * block) {
    state->q[0][0] ^= ((block[0] << 24) + (block[1] << 16) + (block[2] << 8) + block[3]);
    state->q[1][1] ^= ((block[4] << 24) + (block[5] << 16) + (block[6] << 8) + block[7]);
    state->q[2][2] ^= ((block[8] << 24) + (block[9] << 16) + (block[10] << 8) + block[11]);
    state->q[3][3] ^= ((block[12] << 24) + (block[13] << 16) + (block[14] << 8) + block[15]);
    state->q[4][4] ^= ((block[16] << 24) + (block[17] << 16) + (block[18] << 8) + block[19]);
    state->q[0][1] ^= ((block[20] << 24) + (block[21] << 16) + (block[22] << 8) + block[23]);
    state->q[1][2] ^= ((block[24] << 24) + (block[25] << 16) + (block[26] << 8) + block[27]);
    state->q[2][3] ^= ((block[28] << 24) + (block[29] << 16) + (block[30] << 8) + block[31]);
}

void qx_roundA(struct qx_state *state) { 
    state->q[0][0] += (state->q[1][3] + state->q[3][2]);
    state->q[1][1] += (state->q[2][4] + state->q[4][3]);
    state->q[2][2] += (state->q[3][0] + state->q[0][4]);
    state->q[3][3] += (state->q[4][1] + state->q[1][0]);
    state->q[4][4] += (state->q[0][2] + state->q[2][0]);
}   

void qx_roundB(struct qx_state *state) {
    state->q[3][2] ^= (~qx_rotl(state->q[4][2], 2) & qx_rotl(state->q[0][0], 3));
    state->q[4][3] ^= (~state->q[1][1] & qx_rotl(state->q[0][3], 6));
    state->q[0][4] ^= (~qx_rotl(state->q[1][4], 4) & state->q[2][2]);
    state->q[1][0] ^= (~qx_rotl(state->q[3][3], 11) & qx_rotl(state->q[2][0], 8));
    state->q[2][1] ^= (~state->q[3][1] & state->q[4][4]);
}

void qx_roundC(struct qx_state *state) {
    state->q[4][2] += (state->q[3][2] + state->q[2][3]);
    state->q[0][3] += (state->q[4][3] + state->q[3][4]);
    state->q[1][4] += (state->q[0][4] + state->q[4][0]);
    state->q[2][0] += (state->q[1][0] + state->q[0][1]);
    state->q[3][1] += (state->q[2][1] + state->q[1][2]);
}

void qx_roundD(struct qx_state *state) {
    state->q[2][3] ^= (~qx_rotl(state->q[4][2], 10) & qx_rotl(state->q[1][3], 21));
    state->q[3][4] ^= (~qx_rotl(state->q[0][3], 14) & state->q[2][4]);
    state->q[4][0] ^= (~qx_rotl(state->q[1][4], 28) & qx_rotl(state->q[3][0], 31));
    state->q[0][1] ^= (~qx_rotl(state->q[2][0], 20) & qx_rotl(state->q[4][1], 9));
    state->q[1][2] ^= (~qx_rotl(state->q[3][1], 23) & state->q[0][2]);
}

void qx_roundE(struct qx_state *state) {
    state->q[1][3] += (state->q[2][3] + state->q[0][0]);
    state->q[2][4] += (state->q[3][4] + state->q[1][1]);
    state->q[3][0] += (state->q[4][0] + state->q[2][2]);
    state->q[4][1] += (state->q[0][1] + state->q[3][3]);
    state->q[0][2] += (state->q[1][2] + state->q[4][4]);
}

void qx_rotate_words(struct qx_state *state) {
    state->t[0][0] = state->q[0][0];
    state->t[0][1] = state->q[0][1];
    state->t[0][2] = state->q[0][2];
    state->t[0][3] = state->q[0][3];
    state->t[0][4] = state->q[0][4];
    state->t[1][0] = state->q[1][0];
    state->t[1][1] = state->q[1][1];
    state->t[1][2] = state->q[1][2];
    state->t[1][3] = state->q[1][3];
    state->t[1][4] = state->q[1][4];
    state->t[2][0] = state->q[2][0];
    state->t[2][1] = state->q[2][1];
    state->t[2][2] = state->q[2][2];
    state->t[2][3] = state->q[2][3];
    state->t[2][4] = state->q[2][4];
    state->t[3][0] = state->q[3][0];
    state->t[3][1] = state->q[3][1];
    state->t[3][2] = state->q[3][2];
    state->t[3][3] = state->q[3][3];
    state->t[3][4] = state->q[3][4];
    state->t[4][0] = state->q[4][0];
    state->t[4][1] = state->q[4][1];
    state->t[4][2] = state->q[4][2];
    state->t[4][3] = state->q[4][3];
    state->t[4][4] = state->q[4][4];

    state->q[0][0] = state->t[1][0];
    state->q[0][1] = state->t[1][1];
    state->q[0][2] = state->t[1][2];
    state->q[0][3] = state->t[1][3];
    state->q[0][4] = state->t[1][4];
    state->q[1][0] = state->t[2][0];
    state->q[1][1] = state->t[2][1];
    state->q[1][2] = state->t[2][2];
    state->q[1][3] = state->t[2][3];
    state->q[1][4] = state->t[2][4];
    state->q[2][0] = state->t[3][0];
    state->q[2][1] = state->t[3][1];
    state->q[2][2] = state->t[3][2];
    state->q[2][3] = state->t[3][3];
    state->q[2][4] = state->t[3][4];
    state->q[3][0] = state->t[4][0];
    state->q[3][1] = state->t[4][1];
    state->q[3][2] = state->t[4][2];
    state->q[3][3] = state->t[4][3];
    state->q[3][4] = state->t[4][4];
    state->q[4][0] = state->t[0][4];
    state->q[4][1] = state->t[0][0];
    state->q[4][2] = state->t[0][1];
    state->q[4][3] = state->t[0][2];
    state->q[4][4] = state->t[0][3];
}

void qx_rounds(struct qx_state *state) {
    for (int r = 0; r < state->rounds; r++) {
        qx_roundA(state);
        qx_roundB(state);
        qx_roundC(state);
        qx_roundD(state);
        qx_roundE(state);
        qx_rotate_words(state);
    }
}

void qx_output(struct qx_state *state, uint8_t *digest) {
    state->o[0] = state->q[0][0] ^ state->q[2][4] ^ state->q[4][0];
    state->o[1] = state->q[1][1] ^ state->q[3][0] ^ state->q[0][4];
    state->o[2] = state->q[2][2] ^ state->q[4][1] ^ state->q[1][0];
    state->o[3] = state->q[3][3] ^ state->q[0][2] ^ state->q[2][1];
    state->o[4] = state->q[4][4] ^ state->q[1][3] ^ state->q[3][2];
    state->o[5] = state->q[0][1] ^ state->q[3][4] ^ state->q[4][3];
    state->o[6] = state->q[1][2] ^ state->q[0][3] ^ state->q[2][0];
    state->o[7] = state->q[2][3] ^ state->q[1][4] ^ state->q[3][1];

    digest[0] = (state->o[0] & 0xFF000000) >> 24;
    digest[1] = (state->o[0] & 0x00FF0000) >> 16;
    digest[2] = (state->o[0] & 0x0000FF00) >> 8;
    digest[3] = (state->o[0] & 0x000000FF);
    digest[4] = (state->o[1] & 0xFF000000) >> 24;
    digest[5] = (state->o[1] & 0x00FF0000) >> 16;
    digest[6] = (state->o[1] & 0x0000FF00) >> 8;
    digest[7] = (state->o[1] & 0x000000FF);
    digest[8] = (state->o[2] & 0xFF000000) >> 24;
    digest[9] = (state->o[2] & 0x00FF0000) >> 16;
    digest[10] = (state->o[2] & 0x0000FF00) >> 8;
    digest[11] = (state->o[2] & 0x000000FF);
    digest[12] = (state->o[3] & 0xFF000000) >> 24;
    digest[13] = (state->o[3] & 0x00FF0000) >> 16;
    digest[14] = (state->o[3] & 0x0000FF00) >> 8;
    digest[15] = (state->o[3] & 0x000000FF);
    digest[16] = (state->o[4] & 0xFF000000) >> 24;
    digest[17] = (state->o[4] & 0x00FF0000) >> 16;
    digest[18] = (state->o[4] & 0x0000FF00) >> 8;
    digest[19] = (state->o[4] & 0x000000FF);
    digest[20] = (state->o[5] & 0xFF000000) >> 24;
    digest[21] = (state->o[5] & 0x00FF0000) >> 16;
    digest[22] = (state->o[5] & 0x0000FF00) >> 8;
    digest[23] = (state->o[5] & 0x000000FF);
    digest[24] = (state->o[6] & 0xFF000000) >> 24;
    digest[25] = (state->o[6] & 0x00FF0000) >> 16;
    digest[26] = (state->o[6] & 0x0000FF00) >> 8;
    digest[27] = (state->o[6] & 0x000000FF);
    digest[28] = (state->o[7] & 0xFF000000) >> 24;
    digest[29] = (state->o[7] & 0x00FF0000) >> 16;
    digest[30] = (state->o[7] & 0x0000FF00) >> 8;
    digest[31] = (state->o[7] & 0x000000FF);
}

void qx_hash_file(char * filename, uint8_t *digest) {
    uint8_t key[32] = {1};
    struct qx_state state;
    qx_init(&state);
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
        qx_rounds(&state);
    }
    fclose(infile);
    qx_output(&state, digest);
}

void qx_hash_file_offset(char * filename, uint8_t *digest, int offset) {
    uint8_t key[32] = {0};
    struct qx_state state;
    qx_init(&state);
    qx_absorb(&state, key);
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
        qx_rounds(&state);
    }
    fclose(infile);
    qx_output(&state, digest);
}

void qx_hmac_file(char * filename, uint8_t * key, uint8_t *digest) {
    struct qx_state state;
    qx_init(&state);
    qx_absorb(&state, key);
    qx_rounds(&state);
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
        qx_rounds(&state);
    }
    fclose(infile);
    qx_output(&state, digest);
}

void qx_hmac_file_verify(char * filename, uint8_t * key, uint8_t *verify) {
    struct qx_state state;
    qx_init(&state);
    qx_absorb(&state, key);
    qx_rounds(&state);
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
        qx_rounds(&state);
    }
    fclose(infile);
    qx_output(&state, verify);
}

void qx_hmac_file_verify_offset(char * filename, uint8_t * key, uint8_t *verify, int offset) {
    struct qx_state state;
    qx_init(&state);
    qx_absorb(&state, key);
    qx_rounds(&state);
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
        qx_rounds(&state);
    }
    fclose(infile);
    qx_output(&state, verify);
}

void qx_hmac_file_write(char *filename, uint8_t *key, uint8_t *hmac_hash) {
    uint8_t digest[32];
    FILE *outfile;
    qx_hmac_file(filename, key, digest);
    memcpy(hmac_hash, digest, 32*sizeof(uint8_t));
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
    qx_init(&state);
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
        qx_rounds(&state);
    }
    for (int i = 0; i < iters; i++) {
        qx_rounds(&state);
    }
    qx_output(&state, key);
}

void sign_hash_write(struct qloq_ctx *Sctx, char *filename, uint8_t *hmac_hash) {
    int S_len = 768;
    uint8_t sig[S_len];
    uint8_t X[32];
    uint8_t nonce[32];
    BIGNUM *S;
    S = BN_new();
    BIGNUM *H;
    H = BN_new();
    urandom(nonce, 32);
    mypad_encrypt(hmac_hash, nonce, X);
    BN_bin2bn(X, 32, H);
    sign(Sctx, S, H);
    BN_bn2bin(S, sig);
    FILE *infile;
    infile = fopen(filename, "a");
    fwrite(nonce, 1, 32, infile);
    fwrite(sig, 1, S_len, infile);
    fclose(infile);
}

void verify_sig_read(struct qloq_ctx *Sctx, char *filename, uint8_t *hmac_hash) {
    int S_len = 768;
    uint8_t sig[S_len];
    uint8_t X[32];
    uint8_t nonce[32];
    BIGNUM *Ssig;
    Ssig = BN_new();
    BIGNUM *S;
    S = BN_new();
    BIGNUM *H;
    H = BN_new();
    FILE *infile;
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
    mypad_encrypt(nonce, hmac_hash, X);
    BN_bin2bn(X, 32, H);

    if (verify(Sctx, Ssig, H) != 0) {
        printf("Error: PK Signature verification failed. Message is not authentic.\n");
        exit(2);
    }
}
