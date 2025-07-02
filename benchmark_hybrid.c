#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16

void time_diff(clock_t start, clock_t end, const char *label) {
    printf("%s: %.6f\n", label, (double)(end - start) / CLOCKS_PER_SEC);
}

int aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, const char *plaintext, uint8_t *ciphertext, uint8_t *tag, int plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *ciphertext, uint8_t *tag, char *decrypted, int ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, (unsigned char *)decrypted, &len, ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, tag);
    ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return ret > 0; // success = 1, fail = 0
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <plaintext>\n", argv[0]);
        return 1;
    }

    const char *plaintext = argv[1];
    int msg_len = strlen(plaintext);
    printf("Plaintext: %s\n", plaintext);

    // === PQC KEM (Kyber) + AES-GCM ===
    printf("=== Kyber512 (PQC) + AES-GCM ===\n");
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    clock_t start = clock();
    OQS_KEM_keypair(kem, pk, sk);
    clock_t end = clock();
    time_diff(start, end, "Kyber KeyGen");

    start = clock();
    OQS_KEM_encaps(kem, ct, ss_enc, pk);
    end = clock();
    time_diff(start, end, "Kyber Encaps");

    start = clock();
    OQS_KEM_decaps(kem, ss_dec, ct, sk);
    end = clock();
    time_diff(start, end, "Kyber Decaps");

    // Symmetric AES-GCM encryption
    uint8_t aes_key[32];
    memcpy(aes_key, ss_enc, 32);

    uint8_t iv[AES_IV_SIZE] = {0};  // fixed IV for test
    uint8_t tag[AES_TAG_SIZE];
    uint8_t *cipher = malloc(msg_len + 32);
    char *decrypted = malloc(msg_len + 1);

    start = clock();
    int cipher_len = aes_gcm_encrypt(aes_key, iv, plaintext, cipher, tag, msg_len);
    end = clock();
    time_diff(start, end, "AES-GCM Encrypt");

    start = clock();
    int valid = aes_gcm_decrypt(aes_key, iv, cipher, tag, decrypted, cipher_len);
    end = clock();
    time_diff(start, end, "AES-GCM Decrypt");

    decrypted[msg_len] = '\0';

    printf("AES-GCM Decrypted Text: %s\n", decrypted);
    printf("AES-GCM Decryption Match: %s\n", (valid && strcmp(plaintext, decrypted) == 0) ? "Yes" : "No");

    printf("Kyber Public Key Size: %zu\n", kem->length_public_key);
    printf("Kyber Secret Key Size: %zu\n", kem->length_secret_key);
    printf("Kyber Ciphertext Size: %zu\n", kem->length_ciphertext);

    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec); free(cipher); free(decrypted);
    OQS_KEM_free(kem);

    return 0;
}

