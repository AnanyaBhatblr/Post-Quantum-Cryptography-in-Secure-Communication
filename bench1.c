#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

void time_diff(clock_t start, clock_t end, const char *label) {
    printf("%s: %.6f\n", label, (double)(end - start) / CLOCKS_PER_SEC);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <plaintext>\n", argv[0]);
        return 1;
    }

    const char *plaintext = argv[1];
    size_t msg_len = strlen(plaintext);
    printf("Plaintext: %s\n", plaintext);

    // === PQC (Kyber512 + AES simulated) ===
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

    uint8_t *ss2 = malloc(kem->length_shared_secret);
    start = clock();
    OQS_KEM_decaps(kem, ss2, ct, sk);
    end = clock();
    time_diff(start, end, "Kyber Decaps");

    int match = memcmp(ss, ss2, kem->length_shared_secret) == 0;
    printf("Kyber Decryption Match: %s\n", match ? "Yes" : "No");

    printf("Kyber Public Key Size: %zu\n", kem->length_public_key);
    printf("Kyber Secret Key Size: %zu\n", kem->length_secret_key);
    printf("Kyber Ciphertext Size: %zu\n", kem->length_ciphertext);

    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss); free(ss2);

    // === Classical RSA ===
    printf("=== RSA-2048 (Classical) ===\n");
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA *rsa = RSA_new();

    start = clock();
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    end = clock();
    time_diff(start, end, "RSA KeyGen");

    unsigned char enc[256], dec[256];
    int len;

    start = clock();
    len = RSA_public_encrypt(msg_len, (unsigned char*)plaintext, enc, rsa, RSA_PKCS1_OAEP_PADDING);
    end = clock();
    time_diff(start, end, "RSA Encrypt");

    start = clock();
    int declen = RSA_private_decrypt(len, enc, dec, rsa, RSA_PKCS1_OAEP_PADDING);
    end = clock();
    time_diff(start, end, "RSA Decrypt");

    dec[declen] = '\0';
    printf("RSA Decrypted Text: %s\n", dec);
    printf("RSA Decryption Match: %s\n", strcmp(plaintext, (char *)dec) == 0 ? "Yes" : "No");

    int pub_len = i2d_RSAPublicKey(rsa, NULL);
    int priv_len = i2d_RSAPrivateKey(rsa, NULL);
    printf("RSA Public Key Size: ~%d\n", pub_len);
    printf("RSA Private Key Size: ~%d\n", priv_len);

    RSA_free(rsa);
    BN_free(e);

    return 0;
}

