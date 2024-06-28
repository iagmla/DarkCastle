/* Nuqvam */
/* meaning (weapon) in Klingon */
/* by KryptoMagick (Karl Zander) */
/* 256 bit key / 512 bit state / 128 bit nonce */
/* 256 bit output block */
/* 16 rounds */

uint32_t nuqvam_Q0[4] = {0xcaf26468, 0xce9637c2, 0xb052d5d9, 0xda2116df};

struct nuqvam_state {
    uint32_t S[4][4];
    uint32_t O[8];
    uint32_t Y[4][4];
    int rounds;
};

uint32_t nuqvam_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

uint32_t nuqvam_rotr(uint32_t a, int b) {
    return ((a >> b) | (a << (32 - b)));
}

void nuqvam_update(struct nuqvam_state *state) {
    for (int i = 0; i < state->rounds; i++) {

        state->S[1][1] += state->S[3][2];
        state->S[2][2] = nuqvam_rotl(state->S[2][2] ^ state->S[1][1], 7);
        state->S[3][3] += state->S[0][3];
        state->S[0][0] = nuqvam_rotl(state->S[0][0] ^ state->S[3][3], 13);
        state->S[2][0] += state->S[1][0];
        state->S[3][1] = nuqvam_rotl(state->S[3][1] ^ state->S[2][0], 29);
        state->S[0][2] += state->S[2][1];
        state->S[1][3] = nuqvam_rotl(state->S[1][3] ^ state->S[0][2], 31);

        state->S[2][1] += state->S[2][0];
        state->S[3][2] = nuqvam_rotl(state->S[3][2] ^ state->S[2][1], 7);
        state->S[0][3] ^= state->S[3][1];
        state->S[1][0] = nuqvam_rotl(state->S[1][0] + state->S[0][3], 13);
        state->S[3][0] += state->S[0][2];   
        state->S[0][1] = nuqvam_rotl(state->S[0][1] ^ state->S[3][0], 29);
        state->S[1][2] ^= state->S[1][3];
        state->S[2][3] = nuqvam_rotl(state->S[2][3] + state->S[1][2], 31);

        state->S[3][1] += state->S[0][1];
        state->S[0][2] = nuqvam_rotl(state->S[0][2] ^ state->S[3][1], 7);
        state->S[1][3] += state->S[1][2];
        state->S[2][0] = nuqvam_rotl(state->S[2][0] ^ state->S[1][3], 13);
        state->S[0][0] += state->S[2][3];
        state->S[1][1] = nuqvam_rotl(state->S[1][1] ^ state->S[0][0], 29);
        state->S[2][2] += state->S[3][0];
        state->S[3][3] = nuqvam_rotl(state->S[3][3] ^ state->S[2][2], 31);

        state->S[2][1] += state->S[1][1];
        state->S[3][2] = nuqvam_rotl(state->S[3][2] ^ state->S[2][1], 7);
        state->S[0][3] ^= state->S[2][2];
        state->S[1][0] = nuqvam_rotl(state->S[1][0] + state->S[0][3], 13);
        state->S[3][0] += state->S[3][3];
        state->S[0][1] = nuqvam_rotl(state->S[0][1] ^ state->S[3][0], 29);
        state->S[1][2] ^= state->S[0][0];
        state->S[2][3] = nuqvam_rotl(state->S[2][3] + state->S[1][2], 31);

        state->Y[0][0] = state->S[0][0];
        state->Y[0][1] = state->S[0][1];
        state->Y[0][2] = state->S[0][2];
        state->Y[0][3] = state->S[0][3];
        state->Y[1][0] = state->S[1][0];
        state->Y[1][1] = state->S[1][1];
        state->Y[1][2] = state->S[1][2];
        state->Y[1][3] = state->S[1][3];
        state->Y[2][0] = state->S[2][0];
        state->Y[2][1] = state->S[2][1];
        state->Y[2][2] = state->S[2][2];
        state->Y[2][3] = state->S[2][3];
        state->Y[3][0] = state->S[3][0];
        state->Y[3][1] = state->S[3][1];
        state->Y[3][2] = state->S[3][2];
        state->Y[3][3] = state->S[3][3];

        state->S[0][0] = state->Y[1][0];
        state->S[0][1] = state->Y[1][1];
        state->S[0][2] = state->Y[1][2];
        state->S[0][3] = state->Y[1][3];
        state->S[1][0] = state->Y[2][0];
        state->S[1][1] = state->Y[2][1];
        state->S[1][2] = state->Y[2][2];
        state->S[1][3] = state->Y[2][3];
        state->S[2][0] = state->Y[3][0];
        state->S[2][1] = state->Y[3][1];
        state->S[2][2] = state->Y[3][2];
        state->S[2][3] = state->Y[3][3];
        state->S[3][0] = state->Y[0][1];
        state->S[3][1] = state->Y[0][2];
        state->S[3][2] = state->Y[0][3];
        state->S[3][3] = state->Y[0][0];
    }

    state->O[0] = state->S[0][0] ^ state->S[2][0];
    state->O[1] = state->S[0][1] ^ state->S[2][1];
    state->O[2] = state->S[0][2] ^ state->S[2][2];
    state->O[3] = state->S[0][3] ^ state->S[2][3];
    state->O[4] = state->S[1][0] ^ state->S[3][0];
    state->O[5] = state->S[1][1] ^ state->S[3][1];
    state->O[6] = state->S[1][2] ^ state->S[3][2];
    state->O[7] = state->S[1][3] ^ state->S[3][3];

}

void nuqvam_keysetup(struct nuqvam_state *state, uint8_t *key, uint8_t *nonce) {
    state->rounds = 16;
    state->S[0][0] = ((uint32_t)(key[0]) << 24) + ((uint32_t)key[1] << 16) + ((uint32_t)key[2] << 8) + ((uint32_t)key[3]);
    state->S[1][1] = ((uint32_t)(key[4]) << 24) + ((uint32_t)key[5] << 16) + ((uint32_t)key[6] << 8) + ((uint32_t)key[7]);
    state->S[2][2] = ((uint32_t)(key[8]) << 24) + ((uint32_t)key[9] << 16) + ((uint32_t)key[10] << 8) + ((uint32_t)key[11]);
    state->S[3][3] = ((uint32_t)(key[12]) << 24) + ((uint32_t)key[13] << 16) + ((uint32_t)key[14] << 8) + ((uint32_t)key[15]);
    state->S[0][1] = ((uint32_t)(key[16]) << 24) + ((uint32_t)key[17] << 16) + ((uint32_t)key[18] << 8) + ((uint32_t)key[19]);
    state->S[1][2] = ((uint32_t)(key[20]) << 24) + ((uint32_t)key[21] << 16) + ((uint32_t)key[22] << 8) + ((uint32_t)key[23]);
    state->S[2][3] = ((uint32_t)(key[24]) << 24) + ((uint32_t)key[25] << 16) + ((uint32_t)key[26] << 8) + ((uint32_t)key[27]);
    state->S[3][0] = ((uint32_t)(key[28]) << 24) + ((uint32_t)key[29] << 16) + ((uint32_t)key[30] << 8) + ((uint32_t)key[31]);

    state->S[0][2] = ((uint32_t)(nonce[0]) << 24) + ((uint32_t)nonce[1] << 16) + ((uint32_t)nonce[2] << 8) + ((uint32_t)nonce[3]);
    state->S[1][3] = ((uint32_t)(nonce[4]) << 24) + ((uint32_t)nonce[5] << 16) + ((uint32_t)nonce[6] << 8) + ((uint32_t)nonce[7]);
    state->S[2][0] = ((uint32_t)(nonce[8]) << 24) + ((uint32_t)nonce[9] << 16) + ((uint32_t)nonce[10] << 8) + ((uint32_t)nonce[11]);
    state->S[3][1] = ((uint32_t)(nonce[12]) << 24) + ((uint32_t)nonce[13] << 16) + ((uint32_t)nonce[14] << 8) + ((uint32_t)nonce[15]);

    state->S[0][3] = nuqvam_Q0[0];
    state->S[1][0] = nuqvam_Q0[1];
    state->S[2][1] = nuqvam_Q0[2];
    state->S[3][2] = nuqvam_Q0[3];

}

void nuqvam_xor_block(struct nuqvam_state *state, uint8_t *block) {
    block[0] ^= (state->O[0] & 0xFF000000) >> 24;
    block[1] ^= (state->O[0] & 0x00FF0000) >> 16;
    block[2] ^= (state->O[0] & 0x0000FF00) >> 8;
    block[3] ^= (state->O[0] & 0x000000FF);
    block[4] ^= (state->O[1] & 0xFF000000) >> 24;
    block[5] ^= (state->O[1] & 0x00FF0000) >> 16;
    block[6] ^= (state->O[1] & 0x0000FF00) >> 8;
    block[7] ^= (state->O[1] & 0x000000FF);
    block[8] ^= (state->O[2] & 0xFF000000) >> 24;
    block[9] ^= (state->O[2] & 0x00FF0000) >> 16;
    block[10] ^= (state->O[2] & 0x0000FF00) >> 8;
    block[11] ^= (state->O[2] & 0x000000FF);
    block[12] ^= (state->O[3] & 0xFF000000) >> 24;
    block[13] ^= (state->O[3] & 0x00FF0000) >> 16;
    block[14] ^= (state->O[3] & 0x0000FF00) >> 8;
    block[15] ^= (state->O[3] & 0x000000FF);
    block[16] ^= (state->O[4] & 0xFF000000) >> 24;
    block[17] ^= (state->O[4] & 0x00FF0000) >> 16;
    block[18] ^= (state->O[4] & 0x0000FF00) >> 8;
    block[19] ^= (state->O[4] & 0x000000FF);
    block[20] ^= (state->O[5] & 0xFF000000) >> 24;
    block[21] ^= (state->O[5] & 0x00FF0000) >> 16;
    block[22] ^= (state->O[5] & 0x0000FF00) >> 8;
    block[23] ^= (state->O[5] & 0x000000FF);
    block[24] ^= (state->O[6] & 0xFF000000) >> 24;
    block[25] ^= (state->O[6] & 0x00FF0000) >> 16;
    block[26] ^= (state->O[6] & 0x0000FF00) >> 8;
    block[27] ^= (state->O[6] & 0x000000FF);
    block[28] ^= (state->O[7] & 0xFF000000) >> 24;
    block[29] ^= (state->O[7] & 0x00FF0000) >> 16;
    block[30] ^= (state->O[7] & 0x0000FF00) >> 8;
    block[31] ^= (state->O[7] & 0x000000FF);
}

void nuqvam_encrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct nuqvam_state state;
    int blocklen = 32;
    int bufsize = 32;
    uint8_t nonce[16];
    urandom(nonce, 16);
    nuqvam_keysetup(&state, key, nonce);
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
        nuqvam_update(&state);
        nuqvam_xor_block(&state, block);
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

void nuqvam_decrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct nuqvam_state state;
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
    nuqvam_keysetup(&state, key, nonce);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[32];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        nuqvam_update(&state);
        nuqvam_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
