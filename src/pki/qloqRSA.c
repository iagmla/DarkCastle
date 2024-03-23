#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>

struct qloq_ctx {
    BIGNUM *sk;
    BIGNUM *pk;
    BIGNUM *n;
    BIGNUM *M;
};

void cloak(struct qloq_ctx * ctx, BIGNUM *ctxt, const BIGNUM *ptxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *phase1;
    phase1 = BN_new();
    int r0 = BN_mod_exp(phase1, ptxt, ctx->pk, ctx->M, bnctx);
    if (r0 == 0) {
        //printf("cloak: %d\n", r0);
        r0 = BN_mod_exp(phase1, ptxt, ctx->pk, ctx->M, bnctx);
    }
    //printf("cloak: %d\n", r0);
    int r1 = BN_mod_exp(ctxt, phase1, ctx->pk, ctx->n, bnctx);
    if (r1 == 0) {
        //printf("cloak: %d\n", r1);
        r1 = BN_mod_exp(ctxt, phase1, ctx->pk, ctx->n, bnctx);
    }
    //printf("cloak: %d\n", r1);
}

void decloak(struct qloq_ctx * ctx, BIGNUM *ptxt, BIGNUM *ctxt) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *phase1;
    phase1 = BN_new();
    int r0 = BN_mod_exp(phase1, ctxt, ctx->sk, ctx->n, bnctx);
    if (r0 == 0) {
        //printf("decloak: %d\n", r0);
        r0 = BN_mod_exp(phase1, ctxt, ctx->sk, ctx->n, bnctx);
    }
    //printf("decloak: %d\n", r0);
    int r1 = BN_mod_exp(ptxt, phase1, ctx->sk, ctx->M, bnctx);
    if (r1 == 0) {
        //printf("decloak: %d\n", r1);
        r1 = BN_mod_exp(ptxt, phase1, ctx->sk, ctx->M, bnctx);
    }
    //printf("decloak: %d\n", r1);
}

void sign(struct qloq_ctx * ctx, BIGNUM *S, BIGNUM *H) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *phase1;
    phase1 = BN_new();
    int r0 = BN_mod_exp(phase1, H, ctx->sk, ctx->M, bnctx);
    if (r0 == 0) {
        //printf("sign: %d\n", r0);
        r0 = BN_mod_exp(phase1, H, ctx->sk, ctx->M, bnctx);
    }
    //printf("sign: %d\n", r0);
    int r1 = BN_mod_exp(S, phase1, ctx->sk, ctx->n, bnctx);
    if (r1 == 0) {
        //printf("sign: %d\n", r1);
        r1 = BN_mod_exp(S, phase1, ctx->sk, ctx->n, bnctx);
    }
    //printf("sign: %d\n", r1);
}

int verify(struct qloq_ctx * ctx, BIGNUM *S, BIGNUM *H) {
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *phase1;
    BIGNUM *phase2;
    phase1 = BN_new();
    phase2 = BN_new();
    int r0 = BN_mod_exp(phase1, S, ctx->pk, ctx->n, bnctx);
    if (r0 == 0) {
        //printf("verify: %d\n", r0);
        r0 = BN_mod_exp(phase1, S, ctx->pk, ctx->n, bnctx);
    }
    //printf("verify: %d\n", r0);
    int r1 = BN_mod_exp(phase2, phase1, ctx->pk, ctx->M, bnctx);
    if (r1 == 0) {
        //printf("verify: %d\n", r1);
        r1 = BN_mod_exp(phase2, phase1, ctx->pk, ctx->M, bnctx);
    }
    //printf("verify: %d\n", r1);

    if (BN_cmp(phase2, H) == 0) {
        return 0;
    }
    else {
        return 1;
    }
}

void pkg_pk(struct qloq_ctx * ctx, struct qloq_ctx *Sctx, char * prefix) {
    char *pkfilename[256];
    char *pknum[4];
    char *nnum[3];
    char *Mnum[3];
    char *Spknum[4];
    char *Snnum[3];
    char *SMnum[3];
    FILE *pkfile;
    strcpy(pkfilename, prefix);
    strcat(pkfilename, ".pk");
    int pkbytes = BN_num_bytes(ctx->pk);
    int nbytes = BN_num_bytes(ctx->n);
    int Mbytes = BN_num_bytes(ctx->M);
    int Spkbytes = BN_num_bytes(Sctx->pk);
    int Snbytes = BN_num_bytes(Sctx->n);
    int SMbytes = BN_num_bytes(Sctx->M);
    sprintf(pknum, "%d", pkbytes);
    sprintf(nnum, "%d", nbytes);
    sprintf(Mnum, "%d", Mbytes);
    sprintf(Spknum, "%d", Spkbytes);
    sprintf(Snnum, "%d", Snbytes);
    sprintf(SMnum, "%d", SMbytes);
    unsigned char *pk[pkbytes];
    unsigned char *n[nbytes];
    unsigned char *M[Mbytes];
    unsigned char *Spk[Spkbytes];
    unsigned char *Sn[Snbytes];
    unsigned char *SM[SMbytes];
    BN_bn2bin(ctx->pk, pk);
    BN_bn2bin(ctx->n, n);
    BN_bn2bin(ctx->M, M);
    BN_bn2bin(Sctx->pk, Spk);
    BN_bn2bin(Sctx->n, Sn);
    BN_bn2bin(Sctx->M, SM);
    pkfile = fopen(pkfilename, "wb");
    fwrite(pknum, 1, strlen(pknum), pkfile);
    fwrite(pk, 1, pkbytes, pkfile);
    fwrite(nnum, 1, strlen(nnum), pkfile);
    fwrite(n, 1, nbytes, pkfile);
    fwrite(Mnum, 1, strlen(Mnum), pkfile);
    fwrite(M, 1, Mbytes, pkfile);
    fwrite(pknum, 1, strlen(pknum), pkfile);
    fwrite(Spk, 1, Spkbytes, pkfile);
    fwrite(Snnum, 1, strlen(Snnum), pkfile);
    fwrite(Sn, 1, Snbytes, pkfile);
    fwrite(SMnum, 1, strlen(SMnum), pkfile);
    fwrite(SM, 1, SMbytes, pkfile);
    fclose(pkfile);
}

void pkg_sk(struct qloq_ctx * ctx, struct qloq_ctx *Sctx, char * prefix) {
    char *skfilename[256];
    char *sknum[4];
    char *nnum[3];
    char *Mnum[3];
    char *Ssknum[4];
    char *Snnum[3];
    char *SMnum[3];
    FILE *skfile;
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");
    int skbytes = BN_num_bytes(ctx->sk);
    int nbytes = BN_num_bytes(ctx->n);
    int Mbytes = BN_num_bytes(ctx->M);
    int Sskbytes = BN_num_bytes(Sctx->sk);
    int Snbytes = BN_num_bytes(Sctx->n);
    int SMbytes = BN_num_bytes(Sctx->M);
    sprintf(sknum, "%d", skbytes);
    sprintf(nnum, "%d", nbytes);
    sprintf(Mnum, "%d", Mbytes);
    sprintf(Ssknum, "%d", Sskbytes);
    sprintf(Snnum, "%d", Snbytes);
    sprintf(SMnum, "%d", SMbytes);
    unsigned char *sk[skbytes];
    unsigned char *n[nbytes];
    unsigned char *M[Mbytes];
    unsigned char *Ssk[Sskbytes];
    unsigned char *Sn[Snbytes];
    unsigned char *SM[SMbytes];
    BN_bn2bin(ctx->sk, sk);
    BN_bn2bin(ctx->n, n);
    BN_bn2bin(ctx->M, M);
    BN_bn2bin(Sctx->sk, Ssk);
    BN_bn2bin(Sctx->n, Sn);
    BN_bn2bin(Sctx->M, SM);
    skfile = fopen(skfilename, "wb");
    fwrite(sknum, 1, strlen(sknum), skfile);
    fwrite(sk, 1, skbytes, skfile);
    fwrite(nnum, 1, strlen(nnum), skfile);
    fwrite(n, 1, nbytes, skfile);
    fwrite(Mnum, 1, strlen(Mnum), skfile);
    fwrite(M, 1, Mbytes, skfile);
    fwrite(sknum, 1, strlen(Ssknum), skfile);
    fwrite(Ssk, 1, Sskbytes, skfile);
    fwrite(Snnum, 1, strlen(Snnum), skfile);
    fwrite(Sn, 1, Snbytes, skfile);
    fwrite(SMnum, 1, strlen(SMnum), skfile);
    fwrite(SM, 1, SMbytes, skfile);
    fclose(skfile);
}

void pkg_keys(struct qloq_ctx * ctx, char * prefix) {
    char pkfilename[256];
    char skfilename[256];
    char pknum[4];
    char sknum[4];
    char nnum[3];
    char Mnum[3];
    FILE *tmpfile;
    strcpy(pkfilename, prefix);
    strcat(pkfilename, ".pk");
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");
    int pkbytes = BN_num_bytes(ctx->pk);
    int skbytes = BN_num_bytes(ctx->sk);
    int nbytes = BN_num_bytes(ctx->n);
    int Mbytes = BN_num_bytes(ctx->M);
    sprintf(pknum, "%d", pkbytes);
    sprintf(sknum, "%d", skbytes);
    sprintf(nnum, "%d", nbytes);
    sprintf(Mnum, "%d", Mbytes);
    unsigned char pk[pkbytes];
    unsigned char sk[skbytes];
    unsigned char n[nbytes];
    unsigned char M[Mbytes];
    BN_bn2bin(ctx->pk, pk);
    BN_bn2bin(ctx->sk, sk);
    BN_bn2bin(ctx->n, n);
    BN_bn2bin(ctx->M, M);
    tmpfile = fopen(pkfilename, "wb");
    fwrite(pknum, 1, strlen(pknum), tmpfile);
    fwrite(pk, 1, pkbytes, tmpfile);
    fwrite(nnum, 1, strlen(nnum), tmpfile);
    fwrite(n, 1, nbytes, tmpfile);
    fwrite(Mnum, 1, strlen(Mnum), tmpfile);
    fwrite(M, 1, Mbytes, tmpfile);
    fclose(tmpfile);
    tmpfile = fopen(skfilename, "wb");
    fwrite(sknum, 1, strlen(sknum), tmpfile);
    fwrite(sk, 1, skbytes, tmpfile);
    fwrite(nnum, 1, strlen(nnum), tmpfile);
    fwrite(n, 1, nbytes, tmpfile);
    fwrite(Mnum, 1, strlen(Mnum), tmpfile);
    fwrite(M, 1, Mbytes, tmpfile);
    fclose(tmpfile);
}

int pkg_sk_bytes_count(struct qloq_ctx *ctx, struct qloq_ctx *Sctx) {
    int sknum = 4;
    int Ssknum = 4;
    int nnum = 3;
    int Mnum = 3;
    int nbytes = BN_num_bytes(ctx->n);
    int Mbytes = BN_num_bytes(ctx->M);
    int skbytes = BN_num_bytes(ctx->sk);
    int Snbytes = BN_num_bytes(Sctx->n);
    int SMbytes = BN_num_bytes(Sctx->M);
    int Sskbytes = BN_num_bytes(Sctx->sk);
    int total = ((nnum * 2) + (nbytes * 2) + (Mnum * 2) + (Mbytes * 2) + sknum + Ssknum + skbytes + Sskbytes);
    return total;
}

void pkg_sk_bytes(struct qloq_ctx * ctx, struct qloq_ctx *Sctx, unsigned char *keyblob) {
    char *nnum[3];
    char *Mnum[3];
    char *sknum[4];
    char *Snnum[3];
    char *SMnum[3];
    char *Ssknum[4];
    int nbytes = BN_num_bytes(ctx->n);
    sprintf(nnum, "%d", nbytes);
    int Mbytes = BN_num_bytes(ctx->M);
    sprintf(Mnum, "%d", Mbytes);
    int skbytes = BN_num_bytes(ctx->sk);
    sprintf(sknum, "%d", skbytes);
    int Snbytes = BN_num_bytes(Sctx->n);
    sprintf(Snnum, "%d", Snbytes);
    int SMbytes = BN_num_bytes(Sctx->M);
    sprintf(SMnum, "%d", SMbytes);
    int Sskbytes = BN_num_bytes(Sctx->sk);
    sprintf(Ssknum, "%d", Sskbytes);
    unsigned char n[nbytes];
    BN_bn2bin(ctx->n, n);
    unsigned char M[Mbytes];
    BN_bn2bin(ctx->M, M);
    unsigned char sk[skbytes];
    BN_bn2bin(ctx->sk, sk);
    unsigned char Sn[Snbytes];
    BN_bn2bin(Sctx->n, n);
    unsigned char SM[SMbytes];
    BN_bn2bin(Sctx->M, SM);
    unsigned char Ssk[Sskbytes];
    BN_bn2bin(Sctx->sk, Ssk);
    int pos = 0;
    int i;
    unsigned char *_nnum = (unsigned char *)nnum;
    unsigned char *_Mnum = (unsigned char *)Mnum;
    unsigned char *_sknum = (unsigned char *)sknum;
    unsigned char *_Snnum = (unsigned char *)Snnum;
    unsigned char *_SMnum = (unsigned char *)SMnum;
    unsigned char *_Ssknum = (unsigned char *)Ssknum;
    for (i = 0; i < 4; i++) {
        keyblob[pos] = _sknum[i];
        pos += 1;
    }
    for (i = 0; i < skbytes; i++) {
        keyblob[pos] = sk[i];
        pos += 1;
    }
    for (i = 0; i < 3; i++) {
        keyblob[pos] = _nnum[i];
        pos += 1;
    }
    for (i = 0; i < nbytes; i++) {
        keyblob[pos] = n[i];
        pos += 1;
    }
    for (i = 0; i < 3; i++) {
        keyblob[pos] = _Mnum[i];
        pos += 1;
    }
    for (i = 0; i < Mbytes; i++) {
        keyblob[pos] = M[i];
        pos += 1;
    }
    for (i = 0; i < 4; i++) {
        keyblob[pos] = _Ssknum[i];
        pos += 1;
    }
    for (i = 0; i < Sskbytes; i++) {
        keyblob[pos] = Ssk[i];
        pos += 1;
    }
    for (i = 0; i < 3; i++) {
        keyblob[pos] = _Snnum[i];
        pos += 1;
    }
    for (i = 0; i < Snbytes; i++) {
        keyblob[pos] = Sn[i];
        pos += 1;
    }
    for (i = 0; i < 3; i++) {
        keyblob[pos] = _SMnum[i];
        pos += 1;
    }
    for (i = 0; i < SMbytes; i++) {
        keyblob[pos] = SM[i];
        pos += 1;
    }
}

void load_pkfile(char *filename, struct qloq_ctx *ctx, struct qloq_ctx *Sctx) {
    int good = 0;
    BIGNUM *z0;
    z0 = BN_new();
    BN_zero(z0);
    int c = 0;
    while (good == 0) {

        ctx->pk = BN_new();
        ctx->n = BN_new();
        ctx->M = BN_new();
        Sctx->pk = BN_new();
        Sctx->n = BN_new();
        Sctx->M = BN_new();
        int pksize = 4;
        int nsize = 3;
        int Msize = 3;
        int Spksize = 4;
        int Snsize = 3;
        int SMsize = 3;
        unsigned char *pknum[pksize];
        unsigned char *nnum[nsize];
        unsigned char *Mnum[nsize];
        unsigned char *Spknum[pksize];
        unsigned char *Snnum[nsize];
        unsigned char *SMnum[nsize];
        FILE *keyfile;
        keyfile = fopen(filename, "rb");
        fread(pknum, 1, pksize, keyfile);
        //int pkn = atoi(pknum);
        unsigned char pk[1536];
        fread(pk, 1, 1536, keyfile);
        fread(nnum, 1, nsize, keyfile);
        //int nn = atoi(nnum);
        unsigned char n[768];
        fread(n, 1, 768, keyfile);
        fread(Mnum, 1, Msize, keyfile);
        //int Mn = atoi(Mnum);
        unsigned char M[768];
        fread(M, 1, 768, keyfile);

        fread(Spknum, 1, Spksize, keyfile);
        //int Spkn = atoi(Spknum);
        unsigned char Spk[1536];
        fread(Spk, 1, 1536, keyfile);
        fread(Snnum, 1, Snsize, keyfile);
        //int Snn = atoi(Snnum);
        unsigned char Sn[768];
        fread(Sn, 1, 768, keyfile);
        fread(SMnum, 1, SMsize, keyfile);
        //int SMn = atoi(SMnum);
        unsigned char SM[768];
        fread(SM, 1, 768, keyfile);

        fclose(keyfile);
        BN_bin2bn(pk, 1536, ctx->pk);
        BN_bin2bn(n, 768, ctx->n);
        BN_bin2bn(M, 768, ctx->M);
        BN_bin2bn(Spk, 1536, Sctx->pk);
        BN_bin2bn(Sn, 768, Sctx->n);
        BN_bin2bn(SM, 768, Sctx->M);
        if ((BN_cmp(ctx->pk, z0) != 0) && (BN_cmp(ctx->n, z0) != 0) && (BN_cmp(ctx->M, z0) != 0) && (BN_cmp(Sctx->pk, z0) != 0) && (BN_cmp(Sctx->n, z0) != 0) && (BN_cmp(Sctx->M, z0) != 0)) {
            good = 1;
        }
        if (c >= 3) {
            printf("Error: Unable to load public key file\n");
            exit(1);
        }
        c += 1;
}
/*
    const char *n_dec = BN_bn2dec(ctx->n);
    printf("n: %s\n", n_dec);
    const char *M_dec = BN_bn2dec(ctx->M);
    printf("M: %s\n", M_dec);
    const char *pk_dec = BN_bn2dec(ctx->pk);
    printf("pk: %s\n", pk_dec);

    const char *n_dec2 = BN_bn2dec(Sctx->n);
    printf("n: %s\n", n_dec2);
    const char *M_dec2 = BN_bn2dec(Sctx->M);
    printf("M: %s\n", M_dec2);
    const char *pk_dec2 = BN_bn2dec(Sctx->pk);
    printf("pk: %s\n", pk_dec2);
*/

}

void load_skfile(char *filename, struct qloq_ctx *ctx, struct qloq_ctx *Sctx) {
    int good = 0;
    BIGNUM *z0;
    z0 = BN_new();
    BN_zero(z0);
    int c = 0;
    while (good == 0) {
        BIGNUM *chk;
        chk = BN_new();
        ctx->sk = BN_new();
        ctx->n = BN_new();
        ctx->M = BN_new();
        Sctx->sk = BN_new();
        Sctx->n = BN_new();
        Sctx->M = BN_new();
        int sksize = 4;
        int nsize = 3;
        int Msize = 3;
        int Ssksize = 4;
        int Snsize = 3;
        int SMsize = 3;
        unsigned char *sknum[sksize];
        unsigned char *nnum[nsize];
        unsigned char *Mnum[nsize];
        unsigned char *Ssknum[Ssksize];
        unsigned char *Snnum[Snsize];
        unsigned char *SMnum[Snsize];
        FILE *keyfile;
        keyfile = fopen(filename, "rb");
        fread(sknum, 1, sksize, keyfile);
        //int skn = atoi(sknum);
        unsigned char sk[1536];
        fread(sk, 1, 1536, keyfile);
        fread(nnum, 1, nsize, keyfile);
        //int nn = atoi(nnum);
        unsigned char n[768];
        fread(n, 1, 768, keyfile);
        fread(Mnum, 1, Msize, keyfile);
        //int Mn = atoi(Mnum);
        unsigned char M[768];
        fread(M, 1, 768, keyfile);

        fread(Ssknum, 1, Ssksize, keyfile);
        //int Sskn = atoi(Ssknum);
        unsigned char Ssk[1536];
        fread(Ssk, 1, 1536, keyfile);
        fread(Snnum, 1, Snsize, keyfile);
        //int Snn = atoi(Snnum);
        unsigned char Sn[768];
        fread(Sn, 1, 768, keyfile);
        fread(SMnum, 1, SMsize, keyfile);
        //int SMn = atoi(SMnum);
        unsigned char SM[768];
        fread(SM, 1, 768, keyfile);

        fclose(keyfile);
        BN_bin2bn(sk, 1536, ctx->sk);
        BN_bin2bn(n, 768, ctx->n);
        BN_bin2bn(M, 768, ctx->M);
        BN_bin2bn(Ssk, 1536, Sctx->sk);
        BN_bin2bn(Sn, 768, Sctx->n);
        BN_bin2bn(SM, 768, Sctx->M);
        if ((BN_cmp(ctx->sk, z0) != 0) && (BN_cmp(ctx->n, z0) != 0) && (BN_cmp(ctx->M, z0) != 0) && (BN_cmp(Sctx->sk, z0) != 0) && (BN_cmp(Sctx->n, z0) != 0) && (BN_cmp(Sctx->M, z0) != 0)) {
            good = 1;
        }
        if (c >= 3) {
            printf("Error: Unable to load secret key file\n");
            exit(1);
        }
        c += 1;
    }
/*
    const char *sk_dec = BN_bn2dec(ctx->sk);
    printf("sk: %s\n", sk_dec);
    const char *n_dec = BN_bn2dec(ctx->n);
    printf("n: %s\n", n_dec);
    const char *M_dec = BN_bn2dec(ctx->M);
    printf("M: %s\n", M_dec);

    const char *sk_dec2 = BN_bn2dec(Sctx->sk);
    printf("sk: %s\n", sk_dec2);
    const char *n_dec2 = BN_bn2dec(Sctx->n);
    printf("n: %s\n", n_dec2);
    const char *M_dec2 = BN_bn2dec(Sctx->M);
    printf("M: %s\n", M_dec2);
*/
}

void mypad_encrypt(uint8_t * key, uint8_t *nonce, uint8_t *X) {
    for (int i = 0; i < 32; i++) {
        X[i] = key[i] ^ nonce[i];
    }
}

void mypad_decrypt(uint8_t *nonce, uint8_t *X, uint8_t *key) {
    for (int i = 0; i < 32; i++) {
        key[i] = X[i] ^ nonce[i];
    }
}

int keygen(struct qloq_ctx *ctx, int psize) {
    BN_CTX *bnctx = BN_CTX_new();
    BN_CTX_start(bnctx);
    int randstat = 0;
    int good = 1;
    /* Initialize the struct */
    ctx->sk = BN_new();
    ctx->pk = BN_new();
    ctx->n = BN_new();
    ctx->M = BN_new();
    /* Initialize all bignum variables */
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *a;
    BIGNUM *b;
    BIGNUM *s;
    BIGNUM *t;
    BIGNUM *tmp0;
    BIGNUM *tmp1;
    BIGNUM *tmp2;
    BIGNUM *rtmp0;
    BIGNUM *rtmp1;
    BIGNUM *ptxt;
    BIGNUM *ctxt;
    BIGNUM *z1;
    p = BN_new();
    q = BN_new();
    a = BN_new();
    b = BN_new();
    s = BN_new();
    t = BN_new();
    tmp0 = BN_new();
    tmp1 = BN_new();
    tmp2 = BN_new();
    ctxt = BN_new();
    ptxt = BN_new();
    z1 = BN_new();
    /* Set Z1 to equal 1 */
    BN_one(z1);
    /* Generate primes */

    while ((good != 0)) {
        good = 1;
        while (randstat != 1) {
            unsigned seed[524288];
            FILE *randfile;
            randfile = fopen("/dev/urandom", "rb");
            fread(seed, 1, 524288, randfile);
            fclose(randfile);

            RAND_seed(seed, 524288);
            randstat = RAND_status();
        }

        int p_result = BN_generate_prime_ex2(p, psize, 0, NULL, NULL, NULL, bnctx);
        int q_result = BN_generate_prime_ex2(q, psize, 0, NULL, NULL, NULL, bnctx);
        int a_result = BN_generate_prime_ex2(a, psize, 0, NULL, NULL, NULL, bnctx);
        int b_result = BN_generate_prime_ex2(b, psize, 0, NULL, NULL, NULL, bnctx);
        /* Generate the modulus */
        BN_mul(ctx->n, p, q, bnctx);
        /* Generate the mask */
        BN_mul(ctx->M, a, b, bnctx);
        /* Build the totient */
        BN_sub(tmp0, p, z1);
        BN_sub(tmp1, q, z1);
        BN_mul(s, tmp0, tmp1, bnctx);
        BN_sub(tmp0, a, z1);
        BN_sub(tmp1, b, z1);
        BN_mul(tmp2, tmp0 , tmp1, bnctx);
        BN_mul(t, s, tmp2, bnctx);
        /* Generate the public key */
        BN_rand_range(ctx->pk, t);
        BN_gcd(tmp0, ctx->pk, t, bnctx);
        while ((BN_cmp(tmp0, z1) != 0)) {
            BN_rand_range(ctx->pk, t);
            BN_gcd(tmp0, ctx->pk, t, bnctx);
        }
        /* Generate the private key */
        BN_mod_inverse(ctx->sk, ctx->pk, t, bnctx);

        if (BN_cmp(ctx->n, ctx->M) == -1) {
            good = 2;
        }

        BN_set_word(tmp0, 123);
        cloak(ctx, ctxt, tmp0);
        decloak(ctx, ptxt, ctxt);
        sign(ctx, tmp1, ctxt);

        if ((BN_cmp(ptxt, tmp0) == 0) && (good != 2) && (verify(ctx, tmp1, ctxt) == 0)) {
            good = 0;
        }
}
/*
    const char *n_dec = BN_bn2dec(ctx->n);
    printf("n: %s\n", n_dec);
    const char *M_dec = BN_bn2dec(ctx->M);
    printf("M: %s\n", M_dec);
    const char *pk_dec = BN_bn2dec(ctx->pk);
    printf("pk: %s\n", pk_dec);
    const char *sk_dec = BN_bn2dec(ctx->sk);
    printf("sk: %s\n", sk_dec);
*/
    BN_free(p);
    BN_free(q);
    BN_free(a);
    BN_free(b);
    BN_free(s);
    BN_free(t);
    BN_free(tmp0);
    BN_free(tmp1);
    BN_free(tmp2);
    BN_free(ctxt);
    BN_free(ptxt);
    BN_free(z1);
    return good;
}
