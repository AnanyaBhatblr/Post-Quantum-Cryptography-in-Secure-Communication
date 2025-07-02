import streamlit as st
import subprocess
import plotly.graph_objects as go
import re

st.set_page_config(page_title="🔐 PQC vs RSA Benchmark", layout="centered")
st.title("🔐 PQC vs Classical RSA Crypto Benchmark")

plaintext = st.text_input("Enter plaintext to encrypt & compare:", "check")

if st.button("Run Benchmark"):
    with st.spinner("Running benchmark..."):
        try:
            result = subprocess.check_output(["./benchmark2", plaintext], universal_newlines=True)
        except subprocess.CalledProcessError as e:
            st.error(f"❌ Benchmark failed: {e.output}")
            st.stop()

        st.code(result)

        # --- Parse Output ---
        data = {
            "Kyber": {"label": "Kyber512"},
            "RSA": {"label": "RSA-2048"}
        }

        for line in result.splitlines():
            line = line.strip()
            try:
                if "Kyber KeyGen:" in line:
                    data["Kyber"]["KeyGen"] = float(line.split(":")[1])
                elif "Kyber Encaps:" in line:
                    data["Kyber"]["Encaps"] = float(line.split(":")[1])
                elif "Kyber Decaps:" in line:
                    data["Kyber"]["Decaps"] = float(line.split(":")[1])
                elif "AES-GCM Encrypt:" in line:
                    data["Kyber"]["AESEncrypt"] = float(line.split(":")[1])
                elif "AES-GCM Decrypt:" in line:
                    data["Kyber"]["AESDecrypt"] = float(line.split(":")[1])
                elif "Kyber Public Key Size:" in line:
                    data["Kyber"]["PublicKey"] = int(line.split(":")[1])
                elif "Kyber Secret Key Size:" in line:
                    data["Kyber"]["SecretKey"] = int(line.split(":")[1])
                elif "Kyber Ciphertext Size:" in line:
                    data["Kyber"]["Ciphertext"] = int(line.split(":")[1])
                elif "Kyber Encrypted Text:" in line:
                    data["Kyber"]["CipherHex"] = line.split(":")[1].strip()
                elif "Kyber Decrypted Text:" in line:
                    data["Kyber"]["Decrypted"] = line.split(":")[1].strip()
                elif "Kyber Decryption" in line and "Match" in line:
                    data["Kyber"]["Match"] = line.split(":")[1].strip()

                elif "RSA KeyGen:" in line:
                    data["RSA"]["KeyGen"] = float(line.split(":")[1])
                elif "RSA Encrypt:" in line:
                    data["RSA"]["Encrypt"] = float(line.split(":")[1])
                elif "RSA Decrypt:" in line:
                    data["RSA"]["Decrypt"] = float(line.split(":")[1])
                elif "RSA Public Key Size:" in line:
                    data["RSA"]["PublicKey"] = int(re.findall(r"\d+", line)[0])
                elif "RSA Private Key Size:" in line:
                    data["RSA"]["PrivateKey"] = int(re.findall(r"\d+", line)[0])
                elif "RSA Decrypted Text:" in line:
                    data["RSA"]["Decrypted"] = line.split(":")[1].strip()
                elif "RSA Decryption Match:" in line:
                    data["RSA"]["Match"] = line.split(":")[1].strip()
            except Exception as e:
                st.warning(f"⚠️ Could not parse line: `{line}` — {e}")

        # --- Display Decryption Results ---
        st.markdown("### 🔓 Decryption Results")
        col1, col2 = st.columns(2)
        col1.metric("Kyber Decrypted", data["Kyber"].get("Decrypted", ""),
                    delta="✅" if data["Kyber"].get("Match") == "Yes" else "❌")
        col2.metric("RSA Decrypted", data["RSA"].get("Decrypted", ""),
                    delta="✅" if data["RSA"].get("Match") == "Yes" else "❌")

        # --- Kyber Timing (with AES-GCM) ---
        st.markdown("### ⏱️ Kyber + AES Timing")
        fig1 = go.Figure()
        fig1.add_trace(go.Bar(name="Kyber", x=["KeyGen", "Encaps", "Decaps", "AES Encrypt", "AES Decrypt"], y=[
            data["Kyber"].get("KeyGen", 0),
            data["Kyber"].get("Encaps", 0),
            data["Kyber"].get("Decaps", 0),
            data["Kyber"].get("AESEncrypt", 0),
            data["Kyber"].get("AESDecrypt", 0),
        ], marker_color='blue'))
        fig1.update_layout(barmode='group', xaxis_title="Operation", yaxis_title="Time (seconds)")
        st.plotly_chart(fig1, use_container_width=True)

        # --- RSA Timing ---
        st.markdown("### ⏱️ RSA Timing")
        fig2 = go.Figure()
        fig2.add_trace(go.Bar(name="RSA", x=["KeyGen", "Encrypt", "Decrypt"], y=[
            data["RSA"].get("KeyGen", 0),
            data["RSA"].get("Encrypt", 0),
            data["RSA"].get("Decrypt", 0)
        ], marker_color='green'))
        fig2.update_layout(barmode='group', xaxis_title="Operation", yaxis_title="Time (seconds)")
        st.plotly_chart(fig2, use_container_width=True)

        # --- Key & Ciphertext Size Comparison ---
        st.markdown("### 📦 Key & Ciphertext Size Comparison")
        fig3 = go.Figure()
        fig3.add_trace(go.Bar(
            name="Kyber",
            x=["PublicKey", "SecretKey", "Ciphertext"],
            y=[
                data["Kyber"].get("PublicKey", 0),
                data["Kyber"].get("SecretKey", 0),
                data["Kyber"].get("Ciphertext", 0)
            ],
            marker_color="blue"
        ))
        fig3.add_trace(go.Bar(
            name="RSA",
            x=["PublicKey", "PrivateKey", "Ciphertext"],
            y=[
                data["RSA"].get("PublicKey", 0),
                data["RSA"].get("PrivateKey", 0),
                256  # RSA ciphertext fixed at 2048 bits = 256 bytes
            ],
            marker_color="green"
        ))
        fig3.update_layout(barmode='group', xaxis_title="Type", yaxis_title="Size (bytes)")
        st.plotly_chart(fig3, use_container_width=True)

        
