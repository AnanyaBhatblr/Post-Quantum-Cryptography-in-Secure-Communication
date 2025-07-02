#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include <string.h>

int main() {
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_512)) {
        printf("Kyber512 is not enabled.\n");
        return EXIT_FAILURE;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "Error initializing Kyber.\n");
        return EXIT_FAILURE;
    }

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    // Keypair generation
    OQS_KEM_keypair(kem, pk, sk);

    // Encapsulation (sender side)
    OQS_KEM_encaps(kem, ct, ss_enc, pk);

    // Decapsulation (receiver side)
    OQS_KEM_decaps(kem, ss_dec, ct, sk);

    // Verify shared secret match
    printf("Shared secrets match: %s\n",
        (memcmp(ss_enc, ss_dec, kem->length_shared_secret) == 0) ? "YES" : "NO");

    // Cleanup
    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    OQS_KEM_free(kem);
    return EXIT_SUCCESS;
}

