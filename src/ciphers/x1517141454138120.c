/* X1517141454138120 */
/* by KryptoMagick (Karl Zander) */
/* 256 bit key / 512 bit state / 64 bit nonce / 64 bit counter */
/* 512 bit output block */
/* 8 rounds */

uint32_t X1517141454138120_Q0[4] = {0x48616220, 0x536f736c, 0x49272d51, 0x75636821};

struct X1517141454138120_state {
    uint32_t S[16];
    uint32_t O[16];
    int rounds;
};

uint32_t X1517141454138120_rotl(uint32_t a, int b) {
    return ((a << b) | (a >> (32 - b)));
}

void X1517141454138120_rnd(struct X1517141454138120_state *state) {

    state->O[0] += state->O[3];
    state->O[5] = X1517141454138120_rotl(state->O[5] ^ state->O[0], 4);
    state->O[10] += state->O[5];
    state->O[15] = X1517141454138120_rotl(state->O[15] ^ state->O[10], 8);

    state->O[6] += state->O[15];
    state->O[11] = X1517141454138120_rotl(state->O[11] ^ state->O[6], 16);
    state->O[12] += state->O[11];
    state->O[1] = X1517141454138120_rotl(state->O[1] ^ state->O[10], 24);

    state->O[8] += state->O[1];
    state->O[13] = X1517141454138120_rotl(state->O[13] ^ state->O[8], 4);
    state->O[2] += state->O[13];
    state->O[7] = X1517141454138120_rotl(state->O[7] ^ state->O[2], 8);

    state->O[14] += state->O[7];
    state->O[3] = X1517141454138120_rotl(state->O[3] ^ state->O[14], 16);
    state->O[4] += state->O[3];
    state->O[9] = X1517141454138120_rotl(state->O[9] ^ state->O[4], 24);

    state->O[0] += state->O[9];
    state->O[8] = X1517141454138120_rotl(state->O[8] ^ state->O[0], 7);
    state->O[12] += state->O[8];
    state->O[4] = X1517141454138120_rotl(state->O[4] ^ state->O[12], 9);

    state->O[5] += state->O[4];
    state->O[13] = X1517141454138120_rotl(state->O[13] ^ state->O[5], 12);
    state->O[1] += state->O[13];
    state->O[9] = X1517141454138120_rotl(state->O[9] ^ state->O[1], 15);

    state->O[10] += state->O[9];
    state->O[2] = X1517141454138120_rotl(state->O[2] ^ state->O[10], 7);
    state->O[6] += state->O[2];
    state->O[14] = X1517141454138120_rotl(state->O[14] ^ state->O[6], 9);

    state->O[15] += state->O[14];
    state->O[7] = X1517141454138120_rotl(state->O[7] ^ state->O[15], 12);
    state->O[11] += state->O[7];
    state->O[3] = X1517141454138120_rotl(state->O[3] ^ state->O[11], 15);

}

void X1517141454138120_state_to_out(struct X1517141454138120_state *state) {
    state->O[0] = state->S[0];
    state->O[1] = state->S[1];
    state->O[2] = state->S[2];
    state->O[3] = state->S[3];
    state->O[4] = state->S[4];
    state->O[5] = state->S[5];
    state->O[6] = state->S[6];
    state->O[7] = state->S[7];
    state->O[8] = state->S[8];
    state->O[9] = state->S[9];
    state->O[10] = state->S[10];
    state->O[11] = state->S[11];
    state->O[12] = state->S[12];
    state->O[13] = state->S[13];
    state->O[14] = state->S[14];
    state->O[15] = state->S[15];
}

void X1517141454138120_add_state(struct X1517141454138120_state *state) {
    state->O[0] += state->S[0];
    state->O[1] += state->S[1];
    state->O[2] += state->S[2];
    state->O[3] += state->S[3];
    state->O[4] += state->S[4];
    state->O[5] += state->S[5];
    state->O[6] += state->S[6];
    state->O[7] += state->S[7];
    state->O[8] += state->S[8];
    state->O[9] += state->S[9];
    state->O[10] += state->S[10];
    state->O[11] += state->S[11];
    state->O[12] += state->S[12];
    state->O[13] += state->S[13];
    state->O[14] += state->S[14];
    state->O[15] += state->S[15];
}

void X1517141454138120_update(struct X1517141454138120_state *state) {
    X1517141454138120_state_to_out(state);
    for (int r = 0; r < state->rounds; r++) {
        X1517141454138120_rnd(state);
    }   
    X1517141454138120_add_state(state);
    state->S[12] += 1;
}

void X1517141454138120_keysetup(struct X1517141454138120_state *state, uint8_t *key, uint8_t *nonce) {
    state->rounds = 8;
    state->S[0] = X1517141454138120_Q0[0];
    state->S[1] = X1517141454138120_Q0[1];
    state->S[2] = X1517141454138120_Q0[2];
    state->S[3] = X1517141454138120_Q0[3];

    state->S[4] = ((uint32_t)(key[0]) << 24) + ((uint32_t)key[1] << 16) + ((uint32_t)key[2] << 8) + ((uint32_t)key[3]);
    state->S[5] ^= ((uint32_t)(key[4]) << 24) + ((uint32_t)key[5] << 16) + ((uint32_t)key[6] << 8) + ((uint32_t)key[7]);
    state->S[6] = ((uint32_t)(key[8]) << 24) + ((uint32_t)key[9] << 16) + ((uint32_t)key[10] << 8) + ((uint32_t)key[11]);
    state->S[7] = ((uint32_t)(key[12]) << 24) + ((uint32_t)key[13] << 16) + ((uint32_t)key[14] << 8) + ((uint32_t)key[15]);
    state->S[8] = ((uint32_t)(key[16]) << 24) + ((uint32_t)key[17] << 16) + ((uint32_t)key[18] << 8) + ((uint32_t)key[19]);
    state->S[9] = ((uint32_t)(key[20]) << 24) + ((uint32_t)key[21] << 16) + ((uint32_t)key[22] << 8) + ((uint32_t)key[23]);
    state->S[10] = ((uint32_t)(key[24]) << 24) + ((uint32_t)key[25] << 16) + ((uint32_t)key[26] << 8) + ((uint32_t)key[27]);
    state->S[11] = ((uint32_t)(key[28]) << 24) + ((uint32_t)key[29] << 16) + ((uint32_t)key[30] << 8) + ((uint32_t)key[31]);

    state->S[12] = 0;
    state->S[13] = 0;

    state->S[14] = ((uint32_t)(nonce[0]) << 24) + ((uint32_t)nonce[1] << 16) + ((uint32_t)nonce[2] << 8) + ((uint32_t)nonce[3]);
    state->S[15] = ((uint32_t)(nonce[4]) << 24) + ((uint32_t)nonce[5] << 16) + ((uint32_t)nonce[6] << 8) + ((uint32_t)nonce[7]);

}

void X1517141454138120_xor_block(struct X1517141454138120_state *state, uint8_t *block) {
    block[0] ^= state->O[0] >> 0;
    block[1] ^= state->O[0] >> 8;
    block[2] ^= state->O[0] >> 16;
    block[3] ^= state->O[0] >> 24;
    block[4] ^= state->O[1] >> 0;
    block[5] ^= state->O[1] >> 8;
    block[6] ^= state->O[1] >> 16;
    block[7] ^= state->O[1] >> 24;
    block[8] ^= state->O[2] >> 0;
    block[9] ^= state->O[2] >> 8;
    block[10] ^= state->O[2] >> 16;
    block[11] ^= state->O[2] >> 24;
    block[12] ^= state->O[3] >> 0;
    block[13] ^= state->O[3] >> 8;
    block[14] ^= state->O[3] >> 16;
    block[15] ^= state->O[3] >> 24;
    block[16] ^= state->O[4] >> 0;
    block[17] ^= state->O[4] >> 8;
    block[18] ^= state->O[4] >> 16;
    block[19] ^= state->O[4] >> 24;
    block[20] ^= state->O[5] >> 0;
    block[21] ^= state->O[5] >> 8;
    block[22] ^= state->O[5] >> 16;
    block[23] ^= state->O[5] >> 24;
    block[24] ^= state->O[6] >> 0;
    block[25] ^= state->O[6] >> 8;
    block[26] ^= state->O[6] >> 16;
    block[27] ^= state->O[6] >> 24;
    block[28] ^= state->O[7] >> 0;
    block[29] ^= state->O[7] >> 8;
    block[30] ^= state->O[7] >> 16;
    block[31] ^= state->O[7] >> 24;
    block[32] ^= state->O[8] >> 0;
    block[33] ^= state->O[8] >> 8;
    block[34] ^= state->O[8] >> 16;
    block[35] ^= state->O[8] >> 24;
    block[36] ^= state->O[9] >> 0;
    block[37] ^= state->O[9] >> 8;
    block[38] ^= state->O[9] >> 16;
    block[39] ^= state->O[9] >> 24;
    block[40] ^= state->O[10] >> 0;
    block[41] ^= state->O[10] >> 8;
    block[42] ^= state->O[10] >> 16;
    block[43] ^= state->O[10] >> 24;
    block[44] ^= state->O[11] >> 0;
    block[45] ^= state->O[11] >> 8;
    block[46] ^= state->O[11] >> 16;
    block[47] ^= state->O[11] >> 24;
    block[48] ^= state->O[12] >> 0;
    block[49] ^= state->O[12] >> 8;
    block[50] ^= state->O[12] >> 16;
    block[51] ^= state->O[12] >> 24;
    block[52] ^= state->O[13] >> 0;
    block[53] ^= state->O[13] >> 8;
    block[54] ^= state->O[13] >> 16;
    block[55] ^= state->O[13] >> 24;
    block[56] ^= state->O[14] >> 0;
    block[57] ^= state->O[14] >> 8;
    block[58] ^= state->O[14] >> 16;
    block[59] ^= state->O[14] >> 24;
    block[60] ^= state->O[15] >> 0;
    block[61] ^= state->O[15] >> 8;
    block[62] ^= state->O[15] >> 16;
    block[63] ^= state->O[15] >> 24;
}

void X1517141454138120_encrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct X1517141454138120_state state;
    int blocklen = 64;
    int bufsize = 64;
    uint8_t nonce[8];
    urandom(nonce, 8);
    X1517141454138120_keysetup(&state, key, nonce);
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fwrite(pad_nonce, 1, 32, outfile);
    fwrite(keyctxt, 1, 768, outfile);
    fwrite(nonce, 1, 8, outfile);
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
        uint8_t block[64];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        X1517141454138120_update(&state);
        X1517141454138120_xor_block(&state, block);
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

void X1517141454138120_decrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct X1517141454138120_state state;
    int blocklen = 64;
    int bufsize = 64;
    uint8_t nonce[8];
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    datalen = ftell(infile);
    datalen = datalen - 8 - 768 - 32 - 32 - 768 - 32;
    fseek(infile, 0, SEEK_SET);
    fread(pad_nonce, 1, 32, infile);
    fread(keyctxt, 1, 768, infile);
    fread(nonce, 1, 8, infile);
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
    fseek(infile, (768 + 8 + 32), SEEK_SET);
    X1517141454138120_keysetup(&state, key, nonce);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[64];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        X1517141454138120_update(&state);
        X1517141454138120_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
