/* Jiyajbe */
/* meaning (I don't understand) in Klingon */
/* by KryptoMagick (Karl Zander) */
/* 256 bit key / 512 bit state / 128 bit nonce */
/* 256 bit output block */
/* 16 rounds */

uint32_t jiyajbe_Q0[4] = {0xed21b71b, 0xe3b4d73a, 0x85f2eb43, 0x9b5240c2};

struct jiyajbe_state {
    uint32_t r[16];
    uint32_t o[8];
    uint32_t y[16];
    int rounds;
};

uint32_t jiyajbe_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t jiyajbe_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void jiyajbe_update(struct jiyajbe_state *state) {
    for (int i = 0; i < state->rounds; i++) {
        state->r[8] ^= jiyajbe_rotl((state->r[10] + state->r[3]), 7);
        state->r[15] += jiyajbe_rotl((state->r[14] ^ state->r[6]), 21);
        state->r[9] += jiyajbe_rotl((state->r[11] ^ state->r[0]), 17);
        state->r[5] += jiyajbe_rotl((state->r[7] ^ state->r[12]), 9);
        state->r[2] ^= jiyajbe_rotl((state->r[2] + state->r[9]), 13);
        state->r[11] += jiyajbe_rotl((state->r[9] ^ state->r[2]), 19);
        state->r[4] ^= jiyajbe_rotl((state->r[4] + state->r[15]), 6);
        state->r[6] ^= jiyajbe_rotl((state->r[6] + state->r[13]), 14);
        state->r[13] += jiyajbe_rotl((state->r[12] ^ state->r[4]), 9);
        state->r[0] ^= jiyajbe_rotl((state->r[0] + state->r[11]), 7);
        state->r[7] += jiyajbe_rotl((state->r[5] ^ state->r[14]), 21);
        state->r[14] += jiyajbe_rotl((state->r[13] + state->r[5]), 14);
        state->r[10] += jiyajbe_rotl((state->r[8] + state->r[1]), 13);
        state->r[3] += jiyajbe_rotl((state->r[1] ^ state->r[10]), 19);
        state->r[12] ^= jiyajbe_rotl((state->r[15] + state->r[7]), 6);
        state->r[1] += jiyajbe_rotl((state->r[3] ^ state->r[8]), 17);
    }

    state->o[0] = state->r[0] ^ state->r[8];
    state->o[1] = state->r[1] ^ state->r[9];
    state->o[2] = state->r[2] ^ state->r[10];
    state->o[3] = state->r[3] ^ state->r[11];
    state->o[4] = state->r[4] ^ state->r[12];
    state->o[5] = state->r[5] ^ state->r[13];
    state->o[6] = state->r[6] ^ state->r[14];
    state->o[7] = state->r[7] ^ state->r[15];

    state->y[0] = state->r[0];
    state->y[1] = state->r[1];
    state->y[2] = state->r[2];
    state->y[3] = state->r[3];
    state->y[4] = state->r[4];
    state->y[5] = state->r[5];
    state->y[6] = state->r[6];
    state->y[7] = state->r[7];
    state->y[8] = state->r[8];
    state->y[9] = state->r[9];
    state->y[10] = state->r[10];
    state->y[11] = state->r[11];
    state->y[12] = state->r[12];
    state->y[13] = state->r[13];
    state->y[14] = state->r[14];
    state->y[15] = state->r[15];

    state->r[0] = state->y[1];
    state->r[1] = state->y[2];
    state->r[2] = state->y[3];
    state->r[3] = state->y[4];
    state->r[4] = state->y[5];
    state->r[5] = state->y[6];
    state->r[6] = state->y[7];
    state->r[7] = state->y[8];
    state->r[8] = state->y[9];
    state->r[9] = state->y[10];
    state->r[10] = state->y[11];
    state->r[11] = state->y[12];
    state->r[12] = state->y[13];
    state->r[13] = state->y[14];
    state->r[14] = state->y[15];
    state->r[15] = state->y[0];

}

void jiyajbe_keysetup(struct jiyajbe_state *state, uint8_t *key, uint8_t *nonce) {
    state->rounds = 16;
    state->r[0] = ((uint32_t)(key[0]) << 24) + ((uint32_t)key[1] << 16) + ((uint32_t)key[2] << 8) + ((uint32_t)key[3]);
    state->r[2] = ((uint32_t)(key[4]) << 24) + ((uint32_t)key[5] << 16) + ((uint32_t)key[6] << 8) + ((uint32_t)key[7]);
    state->r[4] = ((uint32_t)(key[8]) << 24) + ((uint32_t)key[9] << 16) + ((uint32_t)key[10] << 8) + ((uint32_t)key[11]);
    state->r[6] = ((uint32_t)(key[12]) << 24) + ((uint32_t)key[13] << 16) + ((uint32_t)key[14] << 8) + ((uint32_t)key[15]);
    state->r[8] = ((uint32_t)(key[16]) << 24) + ((uint32_t)key[17] << 16) + ((uint32_t)key[18] << 8) + ((uint32_t)key[19]);
    state->r[10] = ((uint32_t)(key[20]) << 24) + ((uint32_t)key[21] << 16) + ((uint32_t)key[22] << 8) + ((uint32_t)key[23]);
    state->r[12] = ((uint32_t)(key[24]) << 24) + ((uint32_t)key[25] << 16) + ((uint32_t)key[26] << 8) + ((uint32_t)key[27]);
    state->r[14] = ((uint32_t)(key[28]) << 24) + ((uint32_t)key[29] << 16) + ((uint32_t)key[30] << 8) + ((uint32_t)key[31]);

    state->r[1] = ((uint32_t)(nonce[0]) << 24) + ((uint32_t)nonce[1] << 16) + ((uint32_t)nonce[2] << 8) + ((uint32_t)nonce[3]);
    state->r[3] = ((uint32_t)(nonce[4]) << 24) + ((uint32_t)nonce[5] << 16) + ((uint32_t)nonce[6] << 8) + ((uint32_t)nonce[7]);
    state->r[5] = ((uint32_t)(nonce[8]) << 24) + ((uint32_t)nonce[9] << 16) + ((uint32_t)nonce[10] << 8) + ((uint32_t)nonce[11]);
    state->r[7] = ((uint32_t)(nonce[12]) << 24) + ((uint32_t)nonce[13] << 16) + ((uint32_t)nonce[14] << 8) + ((uint32_t)nonce[15]);

    state->r[9] = jiyajbe_Q0[0];
    state->r[11] = jiyajbe_Q0[1];
    state->r[13] = jiyajbe_Q0[2];
    state->r[15] = jiyajbe_Q0[3];

}

void jiyajbe_xor_block(struct jiyajbe_state *state, uint8_t *block) {
    block[0] ^= (state->o[0] & 0xFF000000) >> 24;
    block[1] ^= (state->o[0] & 0x00FF0000) >> 16;
    block[2] ^= (state->o[0] & 0x0000FF00) >> 8;
    block[3] ^= (state->o[0] & 0x000000FF);
    block[4] ^= (state->o[1] & 0xFF000000) >> 24;
    block[5] ^= (state->o[1] & 0x00FF0000) >> 16;
    block[6] ^= (state->o[1] & 0x0000FF00) >> 8;
    block[7] ^= (state->o[1] & 0x000000FF);
    block[8] ^= (state->o[2] & 0xFF000000) >> 24;
    block[9] ^= (state->o[2] & 0x00FF0000) >> 16;
    block[10] ^= (state->o[2] & 0x0000FF00) >> 8;
    block[11] ^= (state->o[2] & 0x000000FF);
    block[12] ^= (state->o[3] & 0xFF000000) >> 24;
    block[13] ^= (state->o[3] & 0x00FF0000) >> 16;
    block[14] ^= (state->o[3] & 0x0000FF00) >> 8;
    block[15] ^= (state->o[3] & 0x000000FF);
    block[16] ^= (state->o[4] & 0xFF000000) >> 24;
    block[17] ^= (state->o[4] & 0x00FF0000) >> 16;
    block[18] ^= (state->o[4] & 0x0000FF00) >> 8;
    block[19] ^= (state->o[4] & 0x000000FF);
    block[20] ^= (state->o[5] & 0xFF000000) >> 24;
    block[21] ^= (state->o[5] & 0x00FF0000) >> 16;
    block[22] ^= (state->o[5] & 0x0000FF00) >> 8;
    block[23] ^= (state->o[5] & 0x000000FF);
    block[24] ^= (state->o[6] & 0xFF000000) >> 24;
    block[25] ^= (state->o[6] & 0x00FF0000) >> 16;
    block[26] ^= (state->o[6] & 0x0000FF00) >> 8;
    block[27] ^= (state->o[6] & 0x000000FF);
    block[28] ^= (state->o[7] & 0xFF000000) >> 24;
    block[29] ^= (state->o[7] & 0x00FF0000) >> 16;
    block[30] ^= (state->o[7] & 0x0000FF00) >> 8;
    block[31] ^= (state->o[7] & 0x000000FF);
}

void jiyajbe_encrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct jiyajbe_state state;
    int blocklen = 32;
    int bufsize = 32;
    uint8_t nonce[16];
    urandom(nonce, 16);
    jiyajbe_keysetup(&state, key, nonce);
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
        jiyajbe_update(&state);
        jiyajbe_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    uint8_t kdf_key[32];
    uint8_t hmac_hash[32];
    qx_kdf(key, 32, kdf_key, 10000);
    qx_hmac_file_write(outputfile, kdf_key, hmac_hash);
    sign_hash_write(&Sctx, outputfile, hmac_hash);
}

void jiyajbe_decrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
    struct qloq_ctx ctx;
    struct qloq_ctx Sctx;
    struct qloq_ctx TMPActx;
    struct qloq_ctx TMPBctx;
    load_pkfile(pkfile, &TMPActx, &Sctx);
    load_skfile(skfile, &ctx, &TMPBctx);
    uint8_t hmac_hash[32];
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    fseek(infile, datalen - 768 - 32 - 32, SEEK_SET);
    fread(hmac_hash, 1, 32, infile);
    fclose(infile);

    verify_sig_read(&Sctx, inputfile, hmac_hash);
    uint8_t key[32];
    uint8_t key_padded[32];
    uint8_t pad_nonce[32];
    uint8_t keyctxt[768];

    struct jiyajbe_state state;
    int blocklen = 32;
    int bufsize = 32;
    uint8_t nonce[16];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    datalen = ftell(infile);
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
    jiyajbe_keysetup(&state, key, nonce);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[32];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        jiyajbe_update(&state);
        jiyajbe_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
