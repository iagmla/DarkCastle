#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int z3blocklen = 32;

int t0 = 0x57bf953b78f054bc;
int t1 = 0x0a78a94e98868e69;

struct zander3_state {
    uint64_t K[80][4];
    uint64_t K2[80][4];
    uint64_t K3[80][4];
    uint64_t K4[80][2];
    uint64_t D[4];
    uint64_t S[4];
    uint64_t last[4];
    uint64_t next[4];
    int rounds;
};

struct z3ksa_state {
    uint64_t r[16];
    uint64_t o;
};

uint64_t zander3_rotl(uint64_t a, int b) {
    return ((a << b) | (a >> (64 - b)));
}

uint64_t zander3_rotr(uint64_t a, int b) {
    return ((a >> b) | (a << (64 - b)));
}

void zander3_F(struct z3ksa_state *state) {
    int r;
    for (r = 0; r < 16; r++) {
        state->r[0] += state->r[6];
        state->r[1] ^= state->r[15];
        state->r[2] = zander3_rotl((state->r[2] ^ state->r[12]), 9);
        state->r[3] += state->r[9];
        state->r[4] ^= state->r[11];
        state->r[5] = zander3_rotr((state->r[5] ^ state->r[10]), 6);
        state->r[6] += state->r[13];
        state->r[7] ^= state->r[8];
        state->r[8] = zander3_rotl((state->r[8] ^ state->r[3]), 11);
        state->r[9] += state->r[1];
        state->r[10] ^= state->r[4];
        state->r[11] = zander3_rotr((state->r[8] ^ state->r[7]), 7);
        state->r[12] += state->r[0];
        state->r[13] ^= state->r[2];
        state->r[14] = zander3_rotl((state->r[14] ^ state->r[0]), 3);
        state->r[15] += state->r[5];

        state->r[15] += state->r[6];
        state->r[2] ^= state->r[15];
        state->r[14] = zander3_rotl((state->r[14] ^ state->r[12]), 9);
        state->r[4] += state->r[9];
        state->r[13] ^= state->r[11];
        state->r[6] = zander3_rotr((state->r[6] ^ state->r[10]), 6);
        state->r[12] += state->r[13];
        state->r[8] ^= state->r[8];
        state->r[11] = zander3_rotl((state->r[11] ^ state->r[3]), 11);
        state->r[10] += state->r[1];
        state->r[1] ^= state->r[4];
        state->r[3] = zander3_rotr((state->r[3] ^ state->r[7]), 7);
        state->r[5] += state->r[0];
        state->r[7] ^= state->r[2];
        state->r[9] = zander3_rotl((state->r[9] ^ state->r[0]), 3);
        state->r[0] += state->r[5];
    }
    state->o = 0;
    for (r = 0; r < 16; r++) {
        state->o ^= state->r[r];
    }
}

void zander3_ksa(struct zander3_state * state, uint8_t * key, int keylen) {
    struct z3ksa_state kstate;
    int c = 0;
    int i;
    int s;
    state->rounds = ((keylen / 4) + ((keylen / 8) + (48 - (keylen / 8))));
    memset(state->K, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(state->K2, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(state->K3, 0, state->rounds*(4*sizeof(uint64_t)));
    memset(state->K4, 0, state->rounds*(2*sizeof(uint64_t)));
    memset(&kstate.r, 0, 16*sizeof(uint64_t));
    memset(&kstate.o, 0, sizeof(uint64_t));

    for (i = 0; i < (keylen / 8); i++) {
        kstate.r[i] = ((uint64_t)key[c] << 56) + ((uint64_t)key[c+1] << 48) + ((uint64_t)key[c+2] << 40) + ((uint64_t)key[c+3] << 32) + ((uint64_t)key[c+4] << 24) + ((uint64_t)key[c+5] << 16) + ((uint64_t)key[c+6] << 8) + (uint64_t)key[c+7];
        c += 8;
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 4; s++) {
            zander3_F(&kstate);
            state->K[i][s] = 0;
            state->K[i][s] = kstate.o;
        }
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 4; s++) {
            zander3_F(&kstate);
            state->K2[i][s] = 0;
            state->K2[i][s] = kstate.o;
        }
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 4; s++) {
            zander3_F(&kstate);
            state->K3[i][s] = 0;
            state->K3[i][s] = kstate.o;
        }
    }
    for (i = 0; i < state->rounds; i++) {
        for (s = 0; s < 2; s++) {
            zander3_F(&kstate);
            state->K4[i][s] = 0;
            state->K4[i][s] = kstate.o;
        }
    }
    for (s = 0; s < 4; s++) {
        zander3_F(&kstate);
        state->D[s] = 0;
        state->D[s] = kstate.o;
    }
}

void zander3_encrypt_block(struct zander3_state * state) {
    int r;
    uint64_t temp;

    for (r = 0; r < state->rounds; r++) {

        state->S[3] += state->K[r][0];
        state->S[1] += state->S[3] + state->K[r][1];
        state->S[0] = zander3_rotl(state->S[0], 18) ^ state->S[2];

        state->S[2] += state->K[r][2];
        state->S[0] += state->S[2] + state->K[r][3];
        state->S[3] = zander3_rotl(state->S[3], 26) ^ state->S[1];

        state->S[1] += state->S[3] + t0;
        state->S[0] += state->S[2] + state->K2[r][0];
        state->S[2] = zander3_rotl(state->S[2], 14) ^ state->S[0];

        state->S[3] += state->K2[r][1];
        state->S[2] += state->S[3];
        state->S[1] = zander3_rotl(state->S[1], 16) ^ state->S[3];

        state->S[0] += state->K2[r][2];
        state->S[1] += state->S[0];
        state->S[3] = zander3_rotl(state->S[3], 34) ^ state->S[2];

        state->S[1] += state->K2[r][3];
        state->S[2] += state->S[3];
        state->S[0] = zander3_rotl(state->S[0], 28) ^ state->S[3];

        state->S[2] += state->S[0];
        state->S[3] += state->S[1];
        state->S[1] = zander3_rotl(state->S[1], 22) ^ state->S[0];

        state->S[3] += state->S[2];
        state->S[0] += state->S[1];
        state->S[2] = zander3_rotl(state->S[2], 46) ^ state->S[1];


        state->S[0] = zander3_rotr(state->S[0], 46);
        state->S[0] += state->S[3];
        state->S[0] ^= state->K4[r][0];

        state->S[1] = zander3_rotr(state->S[1], 34);
        state->S[1] += state->S[2] + t1;
        state->S[1] ^= state->K4[r][1];

        state->S[2] = zander3_rotl(state->S[2], 4);
        state->S[2] ^= state->S[1];

        state->S[3] = zander3_rotl(state->S[3], 6);
        state->S[3] ^= state->S[0];

        state->S[0] += state->K3[r][0];
        state->S[1] += state->K3[r][1];
        state->S[2] += state->K3[r][2];
        state->S[3] += state->K3[r][3];

    }
    state->S[0] += state->D[0];
    state->S[1] += state->D[1];
    state->S[2] += state->D[2];
    state->S[3] += state->D[3];
}

void zander3_decrypt_block(struct zander3_state * state) {
    int r;
    uint64_t temp;

    state->S[3] -= state->D[3];
    state->S[2] -= state->D[2];
    state->S[1] -= state->D[1];
    state->S[0] -= state->D[0];

    for (r = (state->rounds - 1); r != -1; r--) {

        state->S[3] -= state->K3[r][3];
        state->S[2] -= state->K3[r][2];
        state->S[1] -= state->K3[r][1];
        state->S[0] -= state->K3[r][0];

        state->S[3] ^= state->S[0];
        state->S[3] = zander3_rotr(state->S[3], 6);

        state->S[2] ^= state->S[1];
        state->S[2] = zander3_rotr(state->S[2], 4);

        state->S[1] ^= state->K4[r][1];
        state->S[1] -= state->S[2] + t1;
        state->S[1] = zander3_rotl(state->S[1], 34);

        state->S[0] ^= state->K4[r][0];
        state->S[0] -= state->S[3];
        state->S[0] = zander3_rotl(state->S[0], 46);

        temp = state->S[2] ^ state->S[1];
        state->S[2] = zander3_rotr(temp, 46);
        state->S[0] -= state->S[1];
        state->S[3] -= state->S[2];

        temp = state->S[1] ^ state->S[0];
        state->S[1] = zander3_rotr(temp, 22);
        state->S[3] -= state->S[1];
        state->S[2] -= state->S[0];

        temp = state->S[0] ^ state->S[3];
        state->S[0] = zander3_rotr(temp, 28);
        state->S[2] -= state->S[3];
        state->S[1] -= state->K2[r][3];

        temp = state->S[3] ^ state->S[2];
        state->S[3] = zander3_rotr(temp, 34);
        state->S[1] -= state->S[0];
        state->S[0] -= state->K2[r][2];

        temp = state->S[1] ^ state->S[3];
        state->S[1] = zander3_rotr(temp, 16);
        state->S[2] -= state->S[3];
        state->S[3] -= state->K2[r][1];

        temp = state->S[2] ^ state->S[0];
        state->S[2] = zander3_rotr(temp, 14);
        state->S[0] -= state->S[2] + state->K2[r][0];
        state->S[1] -= state->S[3] + t0;


        temp = state->S[3] ^ state->S[1];
        state->S[3] = zander3_rotr(temp, 26);
        state->S[0] -= state->S[2] + state->K[r][3];
        state->S[2] -= state->K[r][2];

        temp = state->S[0] ^ state->S[2];
        state->S[0] = zander3_rotr(temp, 18);
        state->S[1] -= state->S[3] + state->K[r][1];
        state->S[3] -= state->K[r][0];

    }
}

void zander3_load_block(struct zander3_state *state, uint8_t *block) {
    state->S[0] = ((uint64_t)block[0] << 56) + ((uint64_t)block[1] << 48) + ((uint64_t)block[2] << 40) + ((uint64_t)block[3] << 32) + ((uint64_t)block[4] << 24) + ((uint64_t)block[5] << 16) + ((uint64_t)block[6] << 8) + (uint64_t)block[7];
    state->S[1] = ((uint64_t)block[8] << 56) + ((uint64_t)block[9] << 48) + ((uint64_t)block[10] << 40) + ((uint64_t)block[11] << 32) + ((uint64_t)block[12] << 24) + ((uint64_t)block[13] << 16) + ((uint64_t)block[14] << 8) + (uint64_t)block[15];
    state->S[2] = ((uint64_t)block[16] << 56) + ((uint64_t)block[17] << 48) + ((uint64_t)block[18] << 40) + ((uint64_t)block[19] << 32) + ((uint64_t)block[20] << 24) + ((uint64_t)block[21] << 16) + ((uint64_t)block[22] << 8) + (uint64_t)block[23];
    state->S[3] = ((uint64_t)block[24] << 56) + ((uint64_t)block[25] << 48) + ((uint64_t)block[26] << 40) + ((uint64_t)block[27] << 32) + ((uint64_t)block[28] << 24) + ((uint64_t)block[29] << 16) + ((uint64_t)block[30] << 8) + (uint64_t)block[31];
}

void zander3_unload_block(struct zander3_state *state, uint8_t *block) {
    block[0] = (state->S[0] & 0xFF00000000000000) >> 56;
    block[1] = (state->S[0] & 0x00FF000000000000) >> 48;
    block[2] = (state->S[0] & 0x0000FF0000000000) >> 40;
    block[3] = (state->S[0] & 0x000000FF00000000) >> 32;
    block[4] = (state->S[0] & 0x00000000FF000000) >> 24;
    block[5] = (state->S[0] & 0x0000000000FF0000) >> 16;
    block[6] = (state->S[0] & 0x000000000000FF00) >> 8;
    block[7] = (state->S[0] & 0x00000000000000FF);
    block[8] = (state->S[1] & 0xFF00000000000000) >> 56;
    block[9] = (state->S[1] & 0x00FF000000000000) >> 48;
    block[10] = (state->S[1] & 0x0000FF0000000000) >> 40;
    block[11] = (state->S[1] & 0x000000FF00000000) >> 32;
    block[12] = (state->S[1] & 0x00000000FF000000) >> 24;
    block[13] = (state->S[1] & 0x0000000000FF0000) >> 16;
    block[14] = (state->S[1] & 0x000000000000FF00) >> 8;
    block[15] = (state->S[1] & 0x00000000000000FF);
    block[16] = (state->S[2] & 0xFF00000000000000) >> 56;
    block[17] = (state->S[2] & 0x00FF000000000000) >> 48;
    block[18] = (state->S[2] & 0x0000FF0000000000) >> 40;
    block[19] = (state->S[2] & 0x000000FF00000000) >> 32;
    block[20] = (state->S[2] & 0x00000000FF000000) >> 24;
    block[21] = (state->S[2] & 0x0000000000FF0000) >> 16;
    block[22] = (state->S[2] & 0x000000000000FF00) >> 8;
    block[23] = (state->S[2] & 0x00000000000000FF);
    block[24] = (state->S[3] & 0xFF00000000000000) >> 56;
    block[25] = (state->S[3] & 0x00FF000000000000) >> 48;
    block[26] = (state->S[3] & 0x0000FF0000000000) >> 40;
    block[27] = (state->S[3] & 0x000000FF00000000) >> 32;
    block[28] = (state->S[3] & 0x00000000FF000000) >> 24;
    block[29] = (state->S[3] & 0x0000000000FF0000) >> 16;
    block[30] = (state->S[3] & 0x000000000000FF00) >> 8;
    block[31] = (state->S[3] & 0x00000000000000FF);
}

void zander3_load_iv(struct zander3_state *state, uint8_t *iv) {
    state->last[0] = ((uint64_t)iv[0] << 56) + ((uint64_t)iv[1] << 48) + ((uint64_t)iv[2] << 40) + ((uint64_t)iv[3] << 32) + ((uint64_t)iv[4] << 24) + ((uint64_t)iv[5] << 16) + ((uint64_t)iv[6] << 8) + (uint64_t)iv[7];
    state->last[1] = ((uint64_t)iv[8] << 56) + ((uint64_t)iv[9] << 48) + ((uint64_t)iv[10] << 40) + ((uint64_t)iv[11] << 32) + ((uint64_t)iv[12] << 24) + ((uint64_t)iv[13] << 16) + ((uint64_t)iv[14] << 8) + (uint64_t)iv[15];
    state->last[2] = ((uint64_t)iv[16] << 56) + ((uint64_t)iv[17] << 48) + ((uint64_t)iv[18] << 40) + ((uint64_t)iv[19] << 32) + ((uint64_t)iv[20] << 24) + ((uint64_t)iv[21] << 16) + ((uint64_t)iv[22] << 8) + (uint64_t)iv[23];
    state->last[3] = ((uint64_t)iv[24] << 56) + ((uint64_t)iv[25] << 48) + ((uint64_t)iv[26] << 40) + ((uint64_t)iv[27] << 32) + ((uint64_t)iv[28] << 24) + ((uint64_t)iv[29] << 16) + ((uint64_t)iv[30] << 8) + (uint64_t)iv[31];
}

void zander3_cbc_last(struct zander3_state *state) {
    state->S[0] ^= state->last[0];
    state->S[1] ^= state->last[1];
    state->S[2] ^= state->last[2];
    state->S[3] ^= state->last[3];
}

void zander3_cbc_next(struct zander3_state *state) {
    state->last[0] = state->S[0];
    state->last[1] = state->S[1];
    state->last[2] = state->S[2];
    state->last[3] = state->S[3];
}

void zander3_cbc_next_inv(struct zander3_state *state) {
    state->next[0] = state->S[0];
    state->next[1] = state->S[1];
    state->next[2] = state->S[2];
    state->next[3] = state->S[3];
}

void zander3_cbc_last_inv(struct zander3_state *state) {
    state->last[0] = state->next[0];
    state->last[1] = state->next[1];
    state->last[2] = state->next[2];
    state->last[3] = state->next[3];
}

void zanderfish3_cbc_encrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct zander3_state state;
    zander3_ksa(&state, key, 32);
    int blocklen = 32;
    int bufsize = 32;
    uint8_t iv[blocklen];
    urandom(iv, blocklen);
    zander3_load_iv(&state, iv);
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    outfile = fopen(outputfile, "wb");
    fwrite(pad_nonce, 1, 32, outfile);
    fwrite(keyctxt, 1, 768, outfile);
    fwrite(iv, 1, blocklen, outfile);
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
            for (int p = 0; p < extrabytes; p++) {
                block[(blocklen-1-p)] = (uint8_t *)extrabytes;
            }
        }
        fread(block, 1, bufsize, infile);
        zander3_load_block(&state, block);
        zander3_cbc_last(&state);
        zander3_encrypt_block(&state);
        zander3_cbc_next(&state);
        zander3_unload_block(&state, block);
        fwrite(block, 1, blocklen, outfile);
    }
    fclose(infile);
    fclose(outfile);
    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    qx_hmac_file_write(outputfile, kdf_key);
    sign_hash_write(&Sctx, outputfile);
}

void zanderfish3_cbc_decrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct zander3_state state;
    int blocklen = 32;
    uint8_t iv[blocklen];
    FILE *infile, *outfile;
    infile = fopen(inputfile, "rb");
    fseek(infile, 0, SEEK_END);
    uint32_t datalen = ftell(infile);
    datalen = datalen - blocklen - 768 - 32 - 32 - 768 - 32;
    fseek(infile, 0, SEEK_SET);
    fread(pad_nonce, 1, 32, infile);
    fread(keyctxt, 1, 768, infile);
    fread(iv, 1, blocklen, infile);
    zander3_load_iv(&state, iv);
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
    fseek(infile, (768 + blocklen + 32), SEEK_SET);
    zander3_ksa(&state, key, 32);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[32];
        fread(block, 1, blocklen, infile);
        zander3_load_block(&state, block);
        zander3_cbc_next_inv(&state);
        zander3_decrypt_block(&state);
        zander3_cbc_last(&state);
        zander3_cbc_last_inv(&state);
        zander3_unload_block(&state, block);

        if (b == (blocks - 1)) {
            int padcheck = block[blocklen - 1];
            int g = blocklen - 1;
            int count = 0;
            for (int p = 0; p < padcheck; p++) {
                if ((int)block[g] == padcheck) {
                    count += 1;
                }
                g = g - 1;
            }
            if (padcheck == count) {
                blocklen = blocklen - count;
            }
        }
        fwrite(block, 1, blocklen, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
