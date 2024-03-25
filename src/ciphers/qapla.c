#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint64_t Q[2] = {
0x98d57011ef2469a7, 0x0c7e53dd9eb185bc,
};


struct qapla_state {
     uint64_t r[8];
     uint64_t o[4];
     int rounds;
};

void qapla_F(struct qapla_state *state) {
    int i;
    uint64_t x;
    uint64_t y[8];
    for (i = 0; i < 8; i++) {
        y[i] = state->r[i];
    }
    for (i = 0; i < state->rounds; i++) {
        state->r[0] += state->r[7];
        state->r[1] = rotateleft64((state->r[1] ^ state->r[0]), 9);
        state->r[2] += state->r[5];
        state->r[3] = rotateleft64((state->r[3] ^ state->r[2]), 21);
        state->r[4] += state->r[3];
        state->r[5] = rotateleft64((state->r[5] ^ state->r[4]), 12);
        state->r[6] += state->r[1];
        state->r[7] = rotateleft64((state->r[7] ^ state->r[6]), 18);
        state->r[1] += state->r[0];
        state->r[2] = rotateleft64((state->r[2] ^ state->r[7]), 9);
        state->r[3] += state->r[2];
        state->r[4] = rotateleft64((state->r[4] ^ state->r[5]), 21);
        state->r[5] += state->r[4];
        state->r[6] = rotateleft64((state->r[6] ^ state->r[3]), 12);
        state->r[7] += state->r[6];
        state->r[0] = rotateleft64((state->r[0] ^ state->r[1]), 18);
    }
    for (i = 0; i < 8; i++) {
        state->r[i] = state->r[i] + y[i];
    }
    for (i = 0; i < 4; i++) {
        state->o[i] = state->r[i] ^ state->r[(i + 4) & 0x07];
    }
}


void qapla_keysetup(struct qapla_state *state, uint8_t *key, uint8_t *nonce) {
    memset(state->r, 0, 8*(sizeof(uint64_t)));
    int i;
    state->rounds = 20;
    state->r[0] = Q[0];
    state->r[4] = Q[1];
    state->r[1] = ((uint64_t)(key[0]) << 56) + ((uint64_t)key[1] << 48) + ((uint64_t)key[2] << 40) + ((uint64_t)key[3] << 32) + ((uint64_t)key[4] << 24) + ((uint64_t)key[5] << 16) + ((uint64_t)key[6] << 8) + (uint64_t)key[7];
    state->r[3] = ((uint64_t)(key[8]) << 56) + ((uint64_t)key[9] << 48) + ((uint64_t)key[10] << 40) + ((uint64_t)key[11] << 32) + ((uint64_t)key[12] << 24) + ((uint64_t)key[13] << 16) + ((uint64_t)key[14] << 8) + (uint64_t)key[15];
    state->r[2] = ((uint64_t)(key[16]) << 56) + ((uint64_t)key[17] << 48) + ((uint64_t)key[18] << 40) + ((uint64_t)key[19] << 32) + ((uint64_t)key[20] << 24) + ((uint64_t)key[21] << 16) + ((uint64_t)key[22] << 8) + (uint64_t)key[23];
    state->r[5] = ((uint64_t)(key[24]) << 56) + ((uint64_t)key[25] << 48) + ((uint64_t)key[26] << 40) + ((uint64_t)key[27] << 32) + ((uint64_t)key[28] << 24) + ((uint64_t)key[29] << 16) + ((uint64_t)key[30] << 8) + (uint64_t)key[31];

    state->r[6] = ((uint64_t)nonce[0] << 56) + ((uint64_t)nonce[1] << 48) + ((uint64_t)nonce[2] << 40) + ((uint64_t)nonce[3] << 32) + ((uint64_t)nonce[4] << 24) + ((uint64_t)nonce[5] << 16) + ((uint64_t)nonce[6] << 8) + (uint64_t)nonce[7];
    state->r[7] = ((uint64_t)nonce[8] << 56) + ((uint64_t)nonce[9] << 48) + ((uint64_t)nonce[10] << 40) + ((uint64_t)nonce[11] << 32) + ((uint64_t)nonce[12] << 24) + ((uint64_t)nonce[13] << 16) + ((uint64_t)nonce[14] << 8) + (uint64_t)nonce[15];

    for (i = 0; i < 64; i++) {
        qapla_F(state);
    }
}

void qapla_xor_block(struct qapla_state *state, uint8_t *block) {
    block[0] ^= (state->o[0] & 0xFF00000000000000) >> 56;
    block[1] ^= (state->o[0] & 0x00FF000000000000) >> 48;
    block[2] ^= (state->o[0] & 0x0000FF0000000000) >> 40;
    block[3] ^= (state->o[0] & 0x000000FF00000000) >> 32;
    block[4] ^= (state->o[0] & 0x00000000FF000000) >> 24;
    block[5] ^= (state->o[0] & 0x0000000000FF0000) >> 16;
    block[6] ^= (state->o[0] & 0x000000000000FF00) >> 8;
    block[7] ^= (state->o[0] & 0x00000000000000FF);
    block[8] ^= (state->o[1] & 0xFF00000000000000) >> 56;
    block[9] ^= (state->o[1] & 0x00FF000000000000) >> 48;
    block[10] ^= (state->o[1] & 0x0000FF0000000000) >> 40;
    block[11] ^= (state->o[1] & 0x000000FF00000000) >> 32;
    block[12] ^= (state->o[1] & 0x00000000FF000000) >> 24;
    block[13] ^= (state->o[1] & 0x0000000000FF0000) >> 16;
    block[14] ^= (state->o[1] & 0x000000000000FF00) >> 8;
    block[15] ^= (state->o[1] & 0x00000000000000FF);
    block[16] ^= (state->o[2] & 0xFF00000000000000) >> 56;
    block[17] ^= (state->o[2] & 0x00FF000000000000) >> 48;
    block[18] ^= (state->o[2] & 0x0000FF0000000000) >> 40;
    block[19] ^= (state->o[2] & 0x000000FF00000000) >> 32;
    block[20] ^= (state->o[2] & 0x00000000FF000000) >> 24;
    block[21] ^= (state->o[2] & 0x0000000000FF0000) >> 16;
    block[22] ^= (state->o[2] & 0x000000000000FF00) >> 8;
    block[23] ^= (state->o[2] & 0x00000000000000FF);
    block[24] ^= (state->o[3] & 0xFF00000000000000) >> 56;
    block[25] ^= (state->o[3] & 0x00FF000000000000) >> 48;
    block[26] ^= (state->o[3] & 0x0000FF0000000000) >> 40;
    block[27] ^= (state->o[3] & 0x000000FF00000000) >> 32;
    block[28] ^= (state->o[3] & 0x00000000FF000000) >> 24;
    block[29] ^= (state->o[3] & 0x0000000000FF0000) >> 16;
    block[30] ^= (state->o[3] & 0x000000000000FF00) >> 8;
    block[31] ^= (state->o[3] & 0x00000000000000FF);
}

void qapla_encrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct qapla_state state;
    int blocklen = 32;
    int bufsize = 32;
    uint8_t nonce[16];
    urandom(nonce, 16);
    qapla_keysetup(&state, key, nonce);
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
        qapla_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
    uint8_t kdf_key[32];
    qx_kdf(key, 32, kdf_key, 10000);
    qx_hmac_file_write(outputfile, kdf_key);
    sign_hash_write(&Sctx, outputfile);
}

void qapla_decrypt(char *inputfile, char *outputfile, char *pkfile, char *skfile) {
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

    struct qapla_state state;
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
    qapla_keysetup(&state, key, nonce);

    for (uint32_t b = 0; b < blocks; b++) {
        uint8_t block[32];
        if ((b == (blocks - 1)) && (extra != 0)) {
            bufsize = extra;
        }
        fread(block, 1, bufsize, infile);
        qapla_xor_block(&state, block);
        fwrite(block, 1, bufsize, outfile);
    }
    fclose(infile);
    fclose(outfile);
}
