// Compile: gcc client.c -o client -loqs -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 9001
#define AES_KEY_LEN 32
#define MSG_LEN 1024

void handle_errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int aes_encrypt(uint8_t *plaintext, int len, uint8_t *key, uint8_t *iv, uint8_t *tag, uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len1, len2;
    RAND_bytes(iv, 12);  // 96-bit IV for AES-GCM
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len1, plaintext, len);
    EVP_EncryptFinal_ex(ctx, ciphertext + len1, &len2);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return len1 + len2;
}

int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "Failed to initialize KEM.\n");
        return EXIT_FAILURE;
    }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    uint8_t msg[MSG_LEN], ciphertext[MSG_LEN], iv[12], tag[16];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr = {.sin_family = AF_INET, .sin_port = htons(PORT)};
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        handle_errors("connect");
    }

    // Step 1: Receive public key from server
    if (read(sock, pk, kem->length_public_key) != kem->length_public_key) {
        fprintf(stderr, "Failed to receive public key.\n");
        return EXIT_FAILURE;
    }

    // Step 2: Encapsulate and send ciphertext
    OQS_KEM_encaps(kem, ct, ss, pk);
    if (write(sock, ct, kem->length_ciphertext) != kem->length_ciphertext) {
        fprintf(stderr, "Failed to send ciphertext.\n");
        return EXIT_FAILURE;
    }

    printf("Shared secret established.\n");

    // Step 3: Encrypt and send messages
    while (1) {
	    printf("You: ");
	    fgets((char *)msg, MSG_LEN, stdin);
	    msg[strcspn((char *)msg, "\n")] = 0;

	    int clen = aes_encrypt(msg, strlen((char *)msg), ss, iv, tag, ciphertext);
	    uint32_t clen_net = htonl(clen);  // convert length to network byte order

	    write(sock, iv, 12);                     // send IV
	    write(sock, tag, 16);                   // send tag
	    write(sock, &clen_net, sizeof(clen_net)); // send ciphertext length
	    write(sock, ciphertext, clen);          // send ciphertext
    }

    OQS_KEM_free(kem);
    free(pk); free(ct); free(ss);
    return 0;
}

