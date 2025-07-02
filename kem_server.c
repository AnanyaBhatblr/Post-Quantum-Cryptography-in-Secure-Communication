// kem_server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>

#define PORT 12345

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk, sk);

    // Create TCP socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(PORT) };
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 1);

    printf("Server listening on port %d...\n", PORT);
    int client_fd = accept(server_fd, NULL, NULL);

    // Send public key
    send(client_fd, pk, kem->length_public_key, 0);

    // Receive ciphertext
    recv(client_fd, ct, kem->length_ciphertext, 0);

    // Decapsulate
    OQS_KEM_decaps(kem, ss, ct, sk);
    print_hex("Server shared secret", ss, kem->length_shared_secret);

    close(client_fd);
    close(server_fd);
    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss);
    return 0;
}

