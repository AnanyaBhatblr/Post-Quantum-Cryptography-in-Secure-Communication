import oqs

with oqs.KeyEncapsulation('Kyber512') as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret_enc = kem.encap_secret(public_key)
    shared_secret_dec = kem.decap_secret(ciphertext)

    print("Do shared secrets match?", shared_secret_enc == shared_secret_dec)

