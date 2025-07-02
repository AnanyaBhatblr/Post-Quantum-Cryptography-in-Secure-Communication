import streamlit as st
import subprocess
import socket
import threading
import queue
import re
import time
import pandas as pd
import plotly.graph_objects as go

# Global queue for MITM logs
log_queue = queue.Queue()

# -------------------- MITM Logic -------------------- #
def forward(src, dst, label):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            message = f"[{label}] {data.decode(errors='ignore').strip()}"
            log_queue.put(message)
            dst.sendall(data)
    except Exception as e:
        log_queue.put(f"[{label}] Error: {e}")
    finally:
        try:
            src.close()
            dst.close()
        except:
            pass

def handle_client(client_sock, server_host, server_port):
    log_queue.put("[MITM] New client connected.")
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((server_host, server_port))
        threading.Thread(target=forward, args=(client_sock, server_sock, 'Client->Server'), daemon=True).start()
        threading.Thread(target=forward, args=(server_sock, client_sock, 'Server->Client'), daemon=True).start()
    except Exception as e:
        log_queue.put(f"[MITM] Connection error: {e}")
        client_sock.close()

def mitm_main(client_port, server_host, server_port):
    log_queue.put(f"[MITM] Listening on port {client_port}, forwarding to {server_host}:{server_port}")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', client_port))
    listener.listen(5)
    while True:
        client_sock, _ = listener.accept()
        threading.Thread(target=handle_client, args=(client_sock, server_host, server_port), daemon=True).start()

# -------------------- Streamlit Tabs -------------------- #
st.set_page_config(layout="wide")
tabs = st.tabs(["🏠 Home", "🕵️ MITM Attack", "🔐 Encrypt/Decrypt"])

# -------------------- Home Tab -------------------- #
with tabs[0]:
    st.title("🔒 Post-Quantum Crypto Playground")
    st.markdown("""
    Welcome to the interactive comparison between **Post-Quantum Cryptography (Kyber512 + AES-GCM)** and classical **RSA-2048**. 

    Use the tabs above to:
    - Run a **live MITM attack** and visualize intercepted traffic
    - Benchmark **encryption/decryption performance** for Kyber vs RSA
    """)

# -------------------- MITM Tab -------------------- #
with tabs[1]:
    st.title("🕵️‍♂️ MITM Proxy Monitor with Live Traffic Visualization")
    st.sidebar.header("🛠️ Configuration")
    client_port = st.sidebar.number_input("🔌 MITM Listening Port (Client → MITM)", min_value=1024, max_value=65535, value=9001)
    server_host = st.sidebar.text_input("🌐 Server Host", value="127.0.0.1")
    server_port = st.sidebar.number_input("🔐 Server Port (MITM → Server)", min_value=1024, max_value=65535, value=9000)
    run_attack = st.sidebar.button("🚨 Run MITM Attack")

    log_display = st.empty()
    col1, col2 = st.columns(2)
    bar_chart = col1.empty()
    line_chart = col2.empty()

    if run_attack:
        threading.Thread(target=mitm_main, args=(client_port, server_host, server_port), daemon=True).start()
        st.success(f"MITM Proxy started on port {client_port}, forwarding to {server_host}:{server_port}")

        logs = []
        traffic_stats = {"Client->Server": 0, "Server->Client": 0}
        traffic_over_time = []
        start_time = time.time()

        while True:
            try:
                msg = log_queue.get(timeout=1)
                logs.append(msg)
                if len(logs) > 100:
                    logs = logs[-100:]
                log_display.code("\n".join(logs), language="text")

                if "Client->Server" in msg:
                    traffic_stats["Client->Server"] += 1
                elif "Server->Client" in msg:
                    traffic_stats["Server->Client"] += 1

                now = round(time.time() - start_time, 1)
                total_msgs = sum(traffic_stats.values())
                traffic_over_time.append({"time": now, "messages": total_msgs})
                if len(traffic_over_time) > 50:
                    traffic_over_time = traffic_over_time[-50:]

                df_bar = pd.DataFrame.from_dict(traffic_stats, orient='index', columns=["Count"])
                bar_chart.bar_chart(df_bar)

                df_line = pd.DataFrame(traffic_over_time)
                line_chart.line_chart(df_line.set_index("time"))
            except queue.Empty:
                pass

# -------------------- Benchmark Tab -------------------- #
with tabs[2]:
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

            data = {"Kyber": {"label": "Kyber512"}, "RSA": {"label": "RSA-2048"}}

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

            # Decryption Results
            st.markdown("### 🔓 Decryption Results")
            col1, col2 = st.columns(2)
            col1.metric("Kyber Decrypted", data["Kyber"].get("Decrypted", ""), delta="✅" if data["Kyber"].get("Match") == "Yes" else "❌")
            col2.metric("RSA Decrypted", data["RSA"].get("Decrypted", ""), delta="✅" if data["RSA"].get("Match") == "Yes" else "❌")

            # Kyber Timing
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

            # RSA Timing
            st.markdown("### ⏱️ RSA Timing")
            fig2 = go.Figure()
            fig2.add_trace(go.Bar(name="RSA", x=["KeyGen", "Encrypt", "Decrypt"], y=[
                data["RSA"].get("KeyGen", 0),
                data["RSA"].get("Encrypt", 0),
                data["RSA"].get("Decrypt", 0)
            ], marker_color='green'))
            fig2.update_layout(barmode='group', xaxis_title="Operation", yaxis_title="Time (seconds)")
            st.plotly_chart(fig2, use_container_width=True)

            # Key & Ciphertext Size
            st.markdown("### 📦 Key & Ciphertext Size Comparison")
            fig3 = go.Figure()
            fig3.add_trace(go.Bar(name="Kyber", x=["PublicKey", "SecretKey", "Ciphertext"], y=[
                data["Kyber"].get("PublicKey", 0),
                data["Kyber"].get("SecretKey", 0),
                data["Kyber"].get("Ciphertext", 0)
            ], marker_color="blue"))
            fig3.add_trace(go.Bar(name="RSA", x=["PublicKey", "PrivateKey", "Ciphertext"], y=[
                data["RSA"].get("PublicKey", 0),
                data["RSA"].get("PrivateKey", 0),
                256  # RSA ciphertext
            ], marker_color="green"))
            fig3.update_layout(barmode='group', xaxis_title="Type", yaxis_title="Size (bytes)")
            st.plotly_chart(fig3, use_container_width=True)

            
