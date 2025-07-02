// kem_client.c
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
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    // Connect to server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr = { .sin_family = AF_INET, .sin_port = htons(PORT) };
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    // Receive public key
    recv(sock, pk, kem->length_public_key, 0);

    // Encapsulate
    OQS_KEM_encaps(kem, ct, ss, pk);

    // Send ciphertext
    send(sock, ct, kem->length_ciphertext, 0);

    print_hex("Client shared secret", ss, kem->length_shared_secret);

    close(sock);
    OQS_KEM_free(kem);
    free(pk); free(ct); free(ss);
    return 0;
}

