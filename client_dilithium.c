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

    printf("[Client] Using algorithm: %s\n", sig->method_name);

    // Allocate keys
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);

    if (!public_key || !secret_key) {
        fprintf(stderr, "Key allocation failed.\n");
        return 1;
    }

    // Generate keypair
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed.\n");
        return 1;
    }

    // Create message
    char message[MSG_LEN] = "Hello from client!";
    size_t sig_len;
    uint8_t *signature = malloc(sig->length_signature);

    if (!signature) {
        fprintf(stderr, "Signature allocation failed.\n");
        return 1;
    }

    // Sign message
    if (OQS_SIG_sign(sig, signature, &sig_len, (uint8_t *)message, strlen(message), secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Signing failed.\n");
        return 1;
    }

    printf("[Client] Message signed. Signature length: %zu\n", sig_len);

    // Save signed message to file
    FILE *msgf = fopen("signed_msg.bin", "wb");
    if (!msgf) {
        perror("Failed to open signed_msg.bin");
        return 1;
    }
    fwrite(message, 1, MSG_LEN, msgf);
    fwrite(&sig_len, sizeof(size_t), 1, msgf);
    fwrite(signature, 1, sig_len, msgf);
    fclose(msgf);
    printf("[Client] Signed message saved to signed_msg.bin\n");

    // Save public key to file
    FILE *pubf = fopen("client_pub.key", "wb");
    if (!pubf) {
        perror("Failed to open client_pub.key");
        return 1;
    }
    fwrite(public_key, 1, sig->length_public_key, pubf);
    fclose(pubf);
    printf("[Client] Public key saved to client_pub.key\n");

    // Cleanup
    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    free(signature);
    return 0;
}

