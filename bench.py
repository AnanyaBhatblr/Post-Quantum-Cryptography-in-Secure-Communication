import streamlit as st
import time
import oqs
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import plotly.graph_objects as go

st.set_page_config(layout="centered", page_title="🔐 PQC vs Classical Demo")
st.title("🔐 PQC (Kyber512) vs Classical (RSA-2048) Encryption Demo")

plaintext = st.text_input("🔤 Enter your plaintext message:", "This is a secret!")

if st.button("Encrypt & Analyze") and plaintext:
    st.markdown("---")
    st.subheader("📈 Performance & Decryption Results")

    # ================== PQC (Kyber512) ==================
    st.markdown("### 🔷 PQC: Kyber512")

    kem = oqs.KeyEncapsulation("Kyber512")
    start = time.time()
    public_key = kem.generate_keypair()
    ct, ss_enc = kem.encap_secret(public_key)
    enc_time = time.time() - start

    start = time.time()
    ss_dec = kem.decap_secret(ct)
    dec_time = time.time() - start

    pqc_success = ss_enc == ss_dec

    st.code(base64.b64encode(ct).decode(), language="text")
    st.success("✅ Decryption successful" if pqc_success else "❌ Decryption failed")

    st.write(f"🕒 Encryption Time: `{enc_time:.6f} sec`")
    st.write(f"🕒 Decryption Time: `{dec_time:.6f} sec`")
    st.write(f"🔑 Public Key Size: `{len(public_key)} bytes`")
    st.write(f"📦 Ciphertext Size: `{len(ct)} bytes`")

    # ================== Classical (RSA) ==================
    st.markdown("### 🔶 Classical: RSA-2048")

    rsa_key = RSA.generate(2048)
    rsa_pub = rsa_key.publickey()
    cipher_rsa_enc = PKCS1_OAEP.new(rsa_pub)
    cipher_rsa_dec = PKCS1_OAEP.new(rsa_key)

    start = time.time()
    rsa_cipher = cipher_rsa_enc.encrypt(plaintext.encode())
    rsa_enc_time = time.time() - start

    start = time.time()
    rsa_plain = cipher_rsa_dec.decrypt(rsa_cipher).decode()
    rsa_dec_time = time.time() - start

    rsa_success = (rsa_plain == plaintext)

    st.code(base64.b64encode(rsa_cipher).decode(), language="text")
    st.success("✅ Decryption successful" if rsa_success else "❌ Decryption failed")

    st.write(f"🕒 Encryption Time: `{rsa_enc_time:.6f} sec`")
    st.write(f"🕒 Decryption Time: `{rsa_dec_time:.6f} sec`")
    st.write(f"🔑 Public Key Size: `{len(rsa_pub.export_key())} bytes`")
    st.write(f"📦 Ciphertext Size: `{len(rsa_cipher)} bytes`")

    # ================== Comparison Graph ==================
    st.markdown("### 📊 Time Comparison")

    labels = ["Kyber Encrypt", "Kyber Decrypt", "RSA Encrypt", "RSA Decrypt"]
    times = [enc_time, dec_time, rsa_enc_time, rsa_dec_time]

    fig = go.Figure(go.Bar(
        x=times,
        y=labels,
        orientation='h',
        marker_color=["blue", "lightblue", "orange", "gold"]
    ))

    fig.update_layout(
        xaxis_title="Time (seconds)",
        yaxis_title="Operation",
        height=400
    )

    st.plotly_chart(fig, use_container_width=True)

