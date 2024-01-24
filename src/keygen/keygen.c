#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void qloq_keygen(int psize, char * prefix, unsigned char * passphrase, unsigned char * kdf_salt, int kdf_iterations) {
    struct qloq_ctx ctx;
    int result = keygen(&ctx, psize);
    if (result == 0) {
        printf("QloQ encryption public keys generated successfully.\n");
    }

    struct qloq_ctx Sctx;
    int Sresult = keygen(&Sctx, psize);
    if (Sresult == 0) {
        printf("QloQ signing public keys generated successfully.\n");
    }
    pkg_pk(&ctx, &Sctx, prefix);

    char *skfilename[256];
    strcpy(skfilename, prefix);
    strcat(skfilename, ".sk");

    int total = pkg_sk_bytes_count(&ctx, &Sctx);
    unsigned char *keyblob[total];
    pkg_sk_bytes(&ctx, &Sctx, keyblob);
    zander3_cbc_encrypt_kf(keyblob, total, skfilename, 32, 32, 32, kdf_iterations, 16, 32, passphrase);
}
