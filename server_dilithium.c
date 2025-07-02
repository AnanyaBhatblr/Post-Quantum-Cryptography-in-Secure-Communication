#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#define MSG_LEN 256

int main() {
    const char *alg_name = "Dilithium3";

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        fprintf(stderr, "Signature algorithm %s not available.\n", alg_name);
        return 1;
    }

    printf("[Server] Algorithm: %s\n", sig->method_name);
    printf("Public key length: %zu\n", sig->length_public_key);
    printf("Signature length: %zu\n", sig->length_signature);

    // Allocate and load client's public key
    uint8_t *public_key = malloc(sig->length_public_key);
    if (!public_key) {
        fprintf(stderr, "Memory allocation for public key failed.\n");
        return 1;
    }

    FILE *pubf = fopen("client_pub.key", "rb");
    if (!pubf) {
        perror("Failed to open client_pub.key");
        return 1;
    }
    fread(public_key, 1, sig->length_public_key, pubf);
    fclose(pubf);
    printf("[Server] Loaded client's public key from client_pub.key\n");

    // Read signed message
    FILE *msgf = fopen("signed_msg.bin", "rb");
    if (!msgf) {
        perror("[Server] signed_msg.bin not found — run client first?");
        return 1;
    }

    char message[MSG_LEN] = {0};
    size_t sig_len = 0;

    fread(message, 1, MSG_LEN, msgf);
    fread(&sig_len, sizeof(size_t), 1, msgf);

    if (sig_len > sig->length_signature) {
        fprintf(stderr, "[Server] Signature length too large! sig_len = %zu\n", sig_len);
        return 1;
    }

    uint8_t *signature = malloc(sig_len);
    if (!signature) {
        fprintf(stderr, "Signature malloc failed\n");
        return 1;
    }

    fread(signature, 1, sig_len, msgf);
    fclose(msgf);

    printf("[Server] Verifying message: %s\n", message);

    // Verify signature
    OQS_STATUS rc = OQS_SIG_verify(sig,
                                   (uint8_t *)message,
                                   strlen(message),
                                   signature,
                                   sig_len,
                                   public_key);

    if (rc == OQS_SUCCESS) {
        printf("✅ Signature is valid.\n");
    } else {
        printf("❌ Signature is INVALID.\n");
    }

    // Cleanup
    free(public_key);
    free(signature);
    OQS_SIG_free(sig);
    return 0;
}
