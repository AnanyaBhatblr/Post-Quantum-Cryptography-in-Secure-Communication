#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#define MSG_LEN 256

int main(int argc, char *argv[]) {
    const char *alg_name = "Dilithium3";

    if (argc < 2) {
        fprintf(stderr, "Usage: %s \"<message_to_sign>\"\n", argv[0]);
        return 1;
    }

    char *message = argv[1];
    size_t msg_len = strlen(message);
    if (msg_len > MSG_LEN) {
        fprintf(stderr, "Message too long (max %d characters).\n", MSG_LEN);
        return 1;
    }

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        fprintf(stderr, "Signature algorithm %s not available.\n", alg_name);
        return 1;
    }

    printf("[Client] Using algorithm: %s\n", sig->method_name);

    // Generate a DIFFERENT (unauthorized) keypair
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    if (!pk || !sk) {
        fprintf(stderr, "Key allocation failed.\n");
        return 1;
    }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed.\n");
        return 1;
    }

    // Sign message using wrong private key
    size_t sig_len;
    uint8_t *signature = malloc(sig->length_signature);
    if (!signature) {
        fprintf(stderr, "Signature allocation failed.\n");
        return 1;
    }

    if (OQS_SIG_sign(sig, signature, &sig_len, (uint8_t *)message, msg_len, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Signing failed.\n");
        return 1;
    }

    printf("[Client] Message signed. Signature length: %zu\n", sig_len);

    // Save fake signed message (overwriting valid one)
    FILE *msgf = fopen("signed_msg.bin", "wb");
    if (!msgf) {
        perror("Failed to open signed_msg.bin");
        return 1;
    }

    fwrite(message, 1, MSG_LEN, msgf);  // Still write full 256 bytes
    fwrite(&sig_len, sizeof(size_t), 1, msgf);
    fwrite(signature, 1, sig_len, msgf);
    fclose(msgf);
    printf("[Client] Signed message saved to signed_msg.bin\n");

    // Do NOT write the public key (use the real client's pub.key)

    // Cleanup
    free(pk);
    free(sk);
    free(signature);
    OQS_SIG_free(sig);

    return 0;
}
