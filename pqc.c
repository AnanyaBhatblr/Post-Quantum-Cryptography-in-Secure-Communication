// benchmark.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

void time_diff(clock_t start, clock_t end, const char *label) {
    printf("%s: %.6f seconds\n", label, (double)(end - start) / CLOCKS_PER_SEC);
}

int main() {
    // === PQC ===
    printf("=== Kyber512 (PQC) ===\n");
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    clock_t start = clock();
    OQS_KEM_keypair(kem, pk, sk);
    clock_t end = clock();
    time_diff(start, end, "Kyber KeyGen");

    start = clock();
    OQS_KEM_encaps(kem, ct, ss, pk);
    end = clock();
    time_diff(start, end, "Kyber Encaps");

    start = clock();
    OQS_KEM_decaps(kem, ss, ct, sk);
    end = clock();
    time_diff(start, end, "Kyber Decaps");

    printf("Kyber Public Key Size: %zu bytes\n", kem->length_public_key);
    printf("Kyber Secret Key Size: %zu bytes\n", kem->length_secret_key);
    printf("Kyber Ciphertext Size: %zu bytes\n\n", kem->length_ciphertext);

    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss);

    // === Classical RSA ===
    printf("=== RSA-2048 (Classical) ===\n");
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA *rsa = RSA_new();

    start = clock();
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    end = clock();
    time_diff(start, end, "RSA KeyGen");

    unsigned char msg[] = "benchmark";
    unsigned char enc[256], dec[256];
    int len;

    start = clock();
    len = RSA_public_encrypt(strlen((char *)msg), msg, enc, rsa, RSA_PKCS1_OAEP_PADDING);
    end = clock();
    time_diff(start, end, "RSA Encrypt");

    start = clock();
    RSA_private_decrypt(len, enc, dec, rsa, RSA_PKCS1_OAEP_PADDING);
    end = clock();
    time_diff(start, end, "RSA Decrypt");

    int pub_len = i2d_RSAPublicKey(rsa, NULL);
    int priv_len = i2d_RSAPrivateKey(rsa, NULL);
    printf("RSA Public Key Size: ~%d bytes\n", pub_len);
    printf("RSA Private Key Size: ~%d bytes\n", priv_len);

    RSA_free(rsa);
    BN_free(e);

    return 0;
}

