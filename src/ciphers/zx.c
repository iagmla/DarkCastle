/* ZX */
/* by KryptoMagick (Karl Zander) */
/* 256 bit block size / 800 bit state */
/* 256 bit key / 128 bit nonce */
/* 25 rounds */

uint32_t zx_c0[25] = {0x923c44fc, 0xf867f0f6, 0xc2e5cc28, 0x8ecebfd4, 0xcb632744, 0x90a142fa, 0xea942e3a, 0x9c70db80, 0xba55d7e1, 0xe3b1f8a2, 0xc60865e0, 0xf8112cc2, 0x93d6b989, 0xc1cf8477, 0x812b7f3c, 0x8c776893, 0xcea9b7e1, 0xdb51dd82, 0xcf9e6886, 0xc2a7551c, 0xa9e3e82b, 0xe77979d1, 0xead7c4bb, 0xeda04895, 0xbe61724c};

struct zx_state {
    uint32_t q[5][5];
    uint32_t t[5][5];
    uint32_t o[8];
    uint8_t digest[32];
    int rounds;
};

uint32_t zx_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t zx_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void zx_roundA(struct zx_state *state) { 
    state->q[0][0] += (state->q[1][3] + state->q[3][2]);
    state->q[1][1] += (state->q[2][4] + state->q[4][3]);
    state->q[2][2] += (state->q[3][0] + state->q[0][4]);
    state->q[3][3] += (state->q[4][1] + state->q[1][0]);
    state->q[4][4] += (state->q[0][2] + state->q[2][0]);
}

void zx_roundB(struct zx_state *state) {
    state->q[3][2] ^= (~zx_rotl(state->q[4][2], 2) & zx_rotl(state->q[0][0], 3));
    state->q[4][3] ^= (~state->q[1][1] & zx_rotl(state->q[0][3], 6));
    state->q[0][4] ^= (~zx_rotl(state->q[1][4], 4) & state->q[2][2]);
    state->q[1][0] ^= (~zx_rotl(state->q[3][3], 11) & zx_rotl(state->q[2][0], 8));
    state->q[2][1] ^= (~state->q[3][1] & state->q[4][4]);
}

void zx_roundC(struct zx_state *state) {
    state->q[4][2] += (state->q[3][2] + state->q[2][3]);
    state->q[0][3] += (state->q[4][3] + state->q[3][4]);
    state->q[1][4] += (state->q[0][4] + state->q[4][0]);
    state->q[2][0] += (state->q[1][0] + state->q[0][1]);
    state->q[3][1] += (state->q[2][1] + state->q[1][2]);
}

void zx_roundD(struct zx_state *state) {
    state->q[2][3] ^= (~zx_rotl(state->q[4][2], 10) & zx_rotl(state->q[1][3], 21));
    state->q[3][4] ^= (~zx_rotl(state->q[0][3], 14) & state->q[2][4]);
    state->q[4][0] ^= (~zx_rotl(state->q[1][4], 28) & zx_rotl(state->q[3][0], 31));
    state->q[0][1] ^= (~zx_rotl(state->q[2][0], 20) & zx_rotl(state->q[4][1], 9));
    state->q[1][2] ^= (~zx_rotl(state->q[3][1], 23) & state->q[0][2]);
}   
    
void zx_roundE(struct zx_state *state) {
    state->q[1][3] += (state->q[2][3] + state->q[0][0]);
    state->q[2][4] += (state->q[3][4] + state->q[1][1]);
    state->q[3][0] += (state->q[4][0] + state->q[2][2]);
    state->q[4][1] += (state->q[0][1] + state->q[3][3]);
    state->q[0][2] += (state->q[1][2] + state->q[4][4]);
}

void zx_rotate_words(struct zx_state *state) {
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

void zx_rounds(struct zx_state *state) {
    for (int r = 0; r < state->rounds; r++) {
        zx_roundA(state);
        zx_roundB(state);
        zx_roundC(state);
        zx_roundD(state);
        zx_roundE(state);
        zx_rotate_words(state);
    }
}

void zx_init(struct zx_state *state) {
    state->rounds = 25;
    memset(state->digest, 0, 32*sizeof(uint8_t));
    state->q[0][0] = zx_c0[0];
    state->q[0][1] = zx_c0[1];
    state->q[0][2] = zx_c0[2];
    state->q[0][3] = zx_c0[3];
    state->q[0][4] = zx_c0[4];
    state->q[1][0] = zx_c0[5];
    state->q[1][1] = zx_c0[6];
    state->q[1][2] = zx_c0[7];
    state->q[1][3] = zx_c0[8];
    state->q[1][4] = zx_c0[9];
    state->q[2][0] = zx_c0[10];
    state->q[2][1] = zx_c0[11];
    state->q[2][2] = zx_c0[12];
    state->q[2][3] = zx_c0[13];
    state->q[2][4] = zx_c0[14];
    state->q[3][0] = zx_c0[15];
    state->q[3][1] = zx_c0[16];
    state->q[3][2] = zx_c0[17];
    state->q[3][3] = zx_c0[18];
    state->q[3][4] = zx_c0[19];
    state->q[4][0] = zx_c0[20];
    state->q[4][1] = zx_c0[21];
    state->q[4][2] = zx_c0[22];
    state->q[4][3] = zx_c0[23];
    state->q[4][4] = zx_c0[24];
}

void zx_keysetup(struct zx_state *state, uint8_t *key, uint8_t *nonce) {
    zx_init(state);

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

void zx_output(struct zx_state *state) {
    state->o[0] = state->q[0][0] ^ state->q[2][4] ^ state->q[4][0];
    state->o[1] = state->q[1][1] ^ state->q[3][0] ^ state->q[0][4];
    state->o[2] = state->q[2][2] ^ state->q[4][1] ^ state->q[1][0];
    state->o[3] = state->q[3][3] ^ state->q[0][2] ^ state->q[2][1];
    state->o[4] = state->q[4][4] ^ state->q[1][3] ^ state->q[3][2];
    state->o[5] = state->q[0][1] ^ state->q[3][4] ^ state->q[4][3];
    state->o[6] = state->q[1][2] ^ state->q[0][3] ^ state->q[2][0];
    state->o[7] = state->q[2][3] ^ state->q[1][4] ^ state->q[3][1];

    state->digest[0] = (state->o[0] & 0xFF000000) >> 24;
    state->digest[1] = (state->o[0] & 0x00FF0000) >> 16;
    state->digest[2] = (state->o[0] & 0x0000FF00) >> 8;
    state->digest[3] = (state->o[0] & 0x000000FF);
    state->digest[4] = (state->o[1] & 0xFF000000) >> 24;
    state->digest[5] = (state->o[1] & 0x00FF0000) >> 16;
    state->digest[6] = (state->o[1] & 0x0000FF00) >> 8;
    state->digest[7] = (state->o[1] & 0x000000FF);
    state->digest[8] = (state->o[2] & 0xFF000000) >> 24;
    state->digest[9] = (state->o[2] & 0x00FF0000) >> 16;
    state->digest[10] = (state->o[2] & 0x0000FF00) >> 8;
    state->digest[11] = (state->o[2] & 0x000000FF);
    state->digest[12] = (state->o[3] & 0xFF000000) >> 24;
    state->digest[13] = (state->o[3] & 0x00FF0000) >> 16;
    state->digest[14] = (state->o[3] & 0x0000FF00) >> 8;
    state->digest[15] = (state->o[3] & 0x000000FF);
    state->digest[16] = (state->o[4] & 0xFF000000) >> 24;
    state->digest[17] = (state->o[4] & 0x00FF0000) >> 16;
    state->digest[18] = (state->o[4] & 0x0000FF00) >> 8;
    state->digest[19] = (state->o[4] & 0x000000FF);
    state->digest[20] = (state->o[5] & 0xFF000000) >> 24;
    state->digest[21] = (state->o[5] & 0x00FF0000) >> 16;
    state->digest[22] = (state->o[5] & 0x0000FF00) >> 8;
    state->digest[23] = (state->o[5] & 0x000000FF);
    state->digest[24] = (state->o[6] & 0xFF000000) >> 24;
    state->digest[25] = (state->o[6] & 0x00FF0000) >> 16;
    state->digest[26] = (state->o[6] & 0x0000FF00) >> 8;
    state->digest[27] = (state->o[6] & 0x000000FF);
    state->digest[28] = (state->o[7] & 0xFF000000) >> 24;
    state->digest[29] = (state->o[7] & 0x00FF0000) >> 16;
    state->digest[30] = (state->o[7] & 0x0000FF00) >> 8;
    state->digest[31] = (state->o[7] & 0x000000FF);
}

void zx_xor_block(struct zx_state *state, uint8_t *block) {
    block[0] ^= state->digest[0];
    block[1] ^= state->digest[1];
    block[2] ^= state->digest[2];
    block[3] ^= state->digest[3];
    block[4] ^= state->digest[4];
    block[5] ^= state->digest[5];
    block[6] ^= state->digest[6];
    block[7] ^= state->digest[7];
    block[8] ^= state->digest[8];
    block[9] ^= state->digest[9];
    block[10] ^= state->digest[10];
    block[11] ^= state->digest[11];
    block[12] ^= state->digest[12];
    block[13] ^= state->digest[13];
    block[14] ^= state->digest[14];
    block[15] ^= state->digest[15];
    block[16] ^= state->digest[16];
    block[17] ^= state->digest[17];
    block[18] ^= state->digest[18];
    block[19] ^= state->digest[19];
    block[20] ^= state->digest[20];
    block[21] ^= state->digest[21];
    block[22] ^= state->digest[22];
    block[23] ^= state->digest[23];
    block[24] ^= state->digest[24];
    block[25] ^= state->digest[25];
    block[26] ^= state->digest[26];
    block[27] ^= state->digest[27];
    block[28] ^= state->digest[28];
    block[29] ^= state->digest[29];
    block[30] ^= state->digest[30];
    block[31] ^= state->digest[31];
}

void zx_encrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    struct qloq_ctx TMPActx;
    struct qloq_ctx TMPBctx;
    load_pkfile(pkfile, &ctx, &TMPActx);
    load_skfile(skfile, &TMPBctx, &Sctx);
    uint8_t key[32];
    uint8_t key_padded[32];
    uint8_t pad_nonce[32];
    uint8_t keyctxt[768];
    urandom(key, 32);
    urandom(pad_nonce, 32);
    BIGNUM *bn_keyptxt;
    BIGNUM *bn_keyctxt;
    bn_keyptxt = BN_new();
    bn_keyctxt = BN_new();
    mypad_encrypt(key, pad_nonce, key_padded);
    BN_bin2bn(key_padded, 32, bn_keyptxt);
    cloak(&ctx, bn_keyctxt, bn_keyptxt);
    BN_bn2bin(bn_keyctxt, keyctxt);

    struct zx_state state;
    int blocklen = 32;
    int bufsize = 32;
    uint8_t nonce[16];
    urandom(nonce, 16);
    zx_keysetup(&state, key, nonce);
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fwrite(pad_nonce, 1, 32, outfile);
    fwrite(keyctxt, 1, 768, outfile);
    fwrite(nonce, 1, 16, outfile);
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    uint32_t blocks = datalen / blocklen;
    int extra = datalen % blocklen;
    int extrabytes = blocklen - (datalen % blocklen);
    if (extra != 0) {
       blocks += 1;
    }
    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[32];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        zx_rounds(&state);
        zx_output(&state);
        zx_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    qx_hmac_file_write(outputfile, kdf_key);
    sign_hash_write(&Sctx, outputfile);
}

void zx_decrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    struct qloq_ctx TMPActx;
    struct qloq_ctx TMPBctx;
    load_pkfile(pkfile, &TMPActx, &Sctx);
    load_skfile(skfile, &ctx, &TMPBctx);
    verify_sig_read(&Sctx, inputfile);
    uint8_t key[32];
    uint8_t key_padded[32];
    uint8_t pad_nonce[32];
    uint8_t keyctxt[768];

    struct zx_state state;
    int blocklen = 32;
    int bufsize = 32;
    uint8_t nonce[16];
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    datalen = datalen - 16 - 768 - 32 - 32 - 768 - 32;
    fseek(infile, 0, SEEK_SET);
    fread(pad_nonce, 1, 32, infile);
    fread(keyctxt, 1, 768, infile);
    fread(nonce, 1, 16, infile);
    uint32_t blocks = datalen / blocklen;
    int extra = datalen % blocklen;
    if (extra != 0) {
       blocks += 1;
    }

    BIGNUM *bn_keyptxt;
    BIGNUM *bn_keyctxt;
    bn_keyptxt = BN_new();
    bn_keyctxt = BN_new();
    BN_bin2bn(keyctxt, 768, bn_keyctxt);
    decloak(&ctx, bn_keyptxt, bn_keyctxt);
    BN_bn2bin(bn_keyptxt, key_padded);
    mypad_decrypt(key_padded, pad_nonce, key);
    fclose(infile);

    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    if (qx_hmac_file_read_verify_offset(inputfile, kdf_key, (768 + 32)) == -1) {
        printf("Error: QX HMAC message is not authentic.\n");
        exit(2);
    }
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fseek(infile, (768 + 16 + 32), SEEK_SET);
    zx_keysetup(&state, key, nonce);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[32];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        zx_rounds(&state);
        zx_output(&state);
        zx_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
