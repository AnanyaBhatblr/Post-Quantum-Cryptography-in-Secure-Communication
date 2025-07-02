// Compile: gcc server.c -o server -loqs -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 9000
#define AES_KEY_LEN 32
#define MSG_LEN 1024

void handle_errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void aes_decrypt(uint8_t *ciphertext, int len, uint8_t *key, uint8_t *iv, uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen, tmplen;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (EVP_DecryptFinal_ex(ctx, plaintext + outlen, &tmplen) <= 0) {
        printf("Decryption failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    plaintext[outlen + tmplen] = '\0'; // Null-terminate
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "Failed to initialize KEM.\n");
        return EXIT_FAILURE;
    }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    uint8_t buffer[MSG_LEN], plaintext[MSG_LEN], iv[12], tag[16];
    int clen;

    OQS_KEM_keypair(kem, pk, sk);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(PORT)};
    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 1);
    printf("Server waiting on port %d...\n", PORT);
    int client_fd = accept(server_fd, NULL, NULL);

    // Step 1: Send public key to client
    write(client_fd, pk, kem->length_public_key);

    // Step 2: Receive ciphertext from client
    read(client_fd, ct, kem->length_ciphertext);
    OQS_KEM_decaps(kem, ss, ct, sk);
    printf("Shared secret established.\n");

    // Step 3: Receive and decrypt messages
    while (1) {
        // Read IV, tag
        if (read(client_fd, iv, 12) != 12) break;
        if (read(client_fd, tag, 16) != 16) break;

        // Read ciphertext length (sent as 4 bytes from client)
        uint32_t clen_net;
        if (read(client_fd, &clen_net, sizeof(clen_net)) != sizeof(clen_net)) break;
        clen = ntohl(clen_net);

        // Read actual ciphertext
        if (read(client_fd, buffer, clen) != clen) break;

        aes_decrypt(buffer, clen, ss, iv, tag, plaintext);
        printf("Client: %s\n", plaintext);
    }

    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss);
    return 0;
}

