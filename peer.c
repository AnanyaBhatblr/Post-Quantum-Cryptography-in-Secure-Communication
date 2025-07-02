// File: peer.c
// Compile: gcc peer.c -o peer -loqs -lcrypto -lpthread

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT_SELF 9000
#define PORT_PEER 9001
#define AES_KEY_LEN 32
#define MSG_LEN 1024

uint8_t shared_secret_global[AES_KEY_LEN];

void handle_errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void aes_encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *key,
                 uint8_t *ciphertext, uint8_t *iv, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
}

void aes_decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *key,
                 uint8_t *iv, uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        printf("Decryption failed.\n");
    }
    EVP_CIPHER_CTX_free(ctx);
}

void *receiver_thread(void *arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    char buffer[MSG_LEN] = {0};
    uint8_t iv[12], tag[16];
    uint8_t decrypted[MSG_LEN];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT_SELF);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 1);
    new_socket = accept(server_fd, NULL, NULL);

    while (1) {
        read(new_socket, iv, 12);
        read(new_socket, tag, 16);
        int n = read(new_socket, buffer, MSG_LEN);
        aes_decrypt((uint8_t *)buffer, n, shared_secret_global, iv, tag, decrypted);
        printf("[PEER] %s\n", decrypted);
    }
    return NULL;
}

void connect_and_send() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char msg[MSG_LEN];
    uint8_t ciphertext[MSG_LEN], iv[12], tag[16];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT_PEER);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    while (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0);

    while (1) {
        printf("You: ");
        fgets(msg, MSG_LEN, stdin);
        msg[strcspn(msg, "\n")] = 0;
        RAND_bytes(iv, sizeof(iv));
        aes_encrypt((uint8_t *)msg, strlen(msg), shared_secret_global, ciphertext, iv, tag);
        write(sock, iv, 12);
        write(sock, tag, 16);
        write(sock, ciphertext, strlen((char *)ciphertext));
    }
}

void perform_kem_key_exchange(int is_server) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    if (is_server) {
        // Generate keypair and send public key
        OQS_KEM_keypair(kem, pk, sk);
        FILE *f = fopen("pubkey.bin", "wb");
        fwrite(pk, 1, kem->length_public_key, f);
        fclose(f);
        FILE *c = fopen("ct.bin", "rb");
        fread(ct, 1, kem->length_ciphertext, c);
        fclose(c);
        OQS_KEM_decaps(kem, ss, ct, sk);
    } else {
        // Read public key and encapsulate
        FILE *f = fopen("pubkey.bin", "rb");
        fread(pk, 1, kem->length_public_key, f);
        fclose(f);
        OQS_KEM_encaps(kem, ct, ss, pk);
        FILE *c = fopen("ct.bin", "wb");
        fwrite(ct, 1, kem->length_ciphertext, c);
        fclose(c);
    }
    memcpy(shared_secret_global, ss, AES_KEY_LEN);
    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss);
}

int main(int argc, char *argv[]) {
    if (argc != 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
        printf("Usage: %s [server|client]\n", argv[0]);
        return EXIT_FAILURE;
    }
    int is_server = strcmp(argv[1], "server") == 0;
    perform_kem_key_exchange(is_server);

    pthread_t recv_thread;
    pthread_create(&recv_thread, NULL, receiver_thread, NULL);

    sleep(1);  // Let server start first
    connect_and_send();
    return 0;
}
