import streamlit as st
from streamlit_extras.stylable_container import stylable_container
from streamlit_extras.switch_page_button import switch_page
import socket
import threading
import queue
import subprocess
import time
import pandas as pd
import plotly.graph_objects as go
import re
from datetime import datetime
from scapy.all import sniff, TCP, IP, Raw
import sys
import io
class StreamRedirector(io.TextIOBase):
    def __init__(self, queue):
        self.queue = queue

    def write(self, msg):
        if msg.strip():
            self.queue.put(msg)

    def flush(self):
        pass  # For compatibility

# Queue for intercepted log messages
log_queue = queue.Queue()
log_queue = queue.Queue()
sniffer_thread = None
stop_sniffing = threading.Event()

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            summary = f"""
**--- New Packet Captured ---**  
**Time:** {datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')}  
**Source:** {packet[IP].src}:{packet[TCP].sport}  
**Destination:** {packet[IP].dst}:{packet[TCP].dport}  
**Flags:** {packet[TCP].flags}  
**Sequence:** {packet[TCP].seq}  
**Acknowledgement:** {packet[TCP].ack}  
**Payload (Raw):**  
```
{packet[Raw].load.decode(errors='ignore')}
```
---
"""
            log_queue.put(summary)
        except Exception as e:
            pass
            #log_queue.put(f"Error processing packet: {e}")

def start_sniffing():
    sniff(iface="lo0", prn=packet_callback, store=0, stop_filter=lambda x: stop_sniffing.is_set())

# Forwarding logic between client and server
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

# Handles client connection
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

# --- Sidebar Navigation ---
st.set_page_config(layout="wide")
# --- Set default tab ---
if "tab" not in st.session_state:
    st.session_state.tab = "🏠 Home"

# --- Sync tab value from sidebar ---
tab = st.sidebar.radio("📂 Navigation", 
                       ["🏠 Home", "🕵️ MITM Attack", "📡 Packet Sniffing Attack", "🔐 Encrypt/Decrypt", "🔐 Signature Tabs"],
                       index=["🏠 Home", "🕵️ MITM Attack", "📡 Packet Sniffing Attack", "🔐 Encrypt/Decrypt", "🔐 Signature Tabs"].index(st.session_state.tab),
                       key="tab_radio")

# --- Home Tab ---
if tab == "🏠 Home":
    st.markdown("""
        <style>
        .tile-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            padding-top: 30px;
        }
        .tile {
            background: linear-gradient(135deg, #1f1f1f, #2e2e2e);
            color: #39ff14;
            border: 1px solid #333;
            border-radius: 16px;
            padding: 24px;
            transition: 0.3s;
            font-family: monospace;
            box-shadow: 0 0 20px #0f0;
        }
        .tile:hover {
            background: #000000;
            transform: scale(1.03);
            box-shadow: 0 0 30px #0f0;
        }
        .tile h3 {
            margin-top: 0;
            font-size: 1.5rem;
        }
        .tile p {
            font-size: 0.95rem;
        }
        .main-title {
            font-size: 3.5rem;
            color: #39ff14;
            text-align: center;
            font-family: monospace;
            margin-top: 30px;
            text-shadow: 0 0 20px #0f0;
        }
        </style>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="main-title">COMMUNICATION USING PQC</div>
    """, unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown("""
            <div class="tile">
                <h3>🕵️ MITM Attack</h3>
                <p>Visualize intercepted traffic in real-time between client and server. Monitor data forwarding and explore vulnerabilities.</p>
            </div>
        """, unsafe_allow_html=True)
        if st.button("Launch 🕵️ MITM Attack"):
            st.session_state.tab = "🕵️ MITM Attack"
            st.rerun()


    with col2:
        st.markdown("""
            <div class="tile">
                <h3>📡 Packet Sniffing Attack</h3>
                <p>Live TCP packet sniffer on loopback interface. Watch packets, payloads, and metadata as they traverse the network.</p>
            </div>
        """, unsafe_allow_html=True)
        if st.button("Launch 📡 Packet Sniffing Attack"):
            st.session_state.tab = "📡 Packet Sniffing Attack"
            st.rerun()

    with col3:
        st.markdown("""
            <div class="tile">
                <h3>🔐 Encrypt/Decrypt</h3>
                <p>Compare Kyber512 and RSA performance. Inspect encryption timings, key sizes, ciphertext, and decrypted output.</p>
            </div>
        """, unsafe_allow_html=True)
        if st.button("Launch 🔐 Encrypt/Decrypt"):
            st.session_state.tab = "🔐 Encrypt/Decrypt"
            st.rerun()

    with col4:
        st.markdown("""
            <div class="tile">
                <h3>🔐 Signature Tabs</h3>
                <p>Try out Dilithium digital signatures. Simulate valid and forged clients, and verify authenticity at the server.</p>
            </div>
        """, unsafe_allow_html=True)
        if st.button("Launch 🔐 Signature Tabs"):
            st.session_state.tab = "🔐 Signature Tabs"
            st.rerun()

    st.markdown("""
        <div style="text-align:center; margin-top:40px;">
            <span style="background-color:#111; color:#39ff14; padding:10px 20px; border-radius:8px; font-family:monospace; box-shadow:0 0 10px #0f0;">
                Built for secure comms, visual exploits, and post-quantum experimentation.
            </span>
        </div>
    """, unsafe_allow_html=True)



# --- MITM Attack Tab ---
elif tab == "🕵️ MITM Attack":
    st.title("🕵️‍♂️ MITM Proxy Monitor")

    # Config Inputs (moved from sidebar)
    with st.expander("⚙️ Configuration", expanded=True):
        client_port = st.number_input("🔌 MITM Listening Port (Client → MITM)", min_value=1024, max_value=65535, value=9001)
        server_host = st.text_input("🌐 Server Host", value="127.0.0.1")
        server_port = st.number_input("🔐 Server Port (MITM → Server)", min_value=1024, max_value=65535, value=9000)
        run_attack = st.button("🚨 Run MITM Attack")

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

elif tab == "📡 Packet Sniffing Attack":
    st.title("📡 Live TCP Packet Sniffer (lo0)")
    st.warning("⚠️ Requires root privileges to run.")

    if "sniffing" not in st.session_state:
        st.session_state.sniffing = False

    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶️ Run Sniffer") and not st.session_state.sniffing:
            stop_sniffing.clear()
            st.session_state.sniffing = True
            sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
            sniffer_thread.start()
            st.success("Sniffer started.")

    with col2:
        if st.button("⏹️ Stop Sniffer") and st.session_state.sniffing:
            stop_sniffing.set()
            st.session_state.sniffing = False
            st.warning("Sniffer stopped.")

    # Output area
    st.subheader("📤 Captured Packets")
    output_area = st.empty()

    # Live display loop while sniffing
    if st.session_state.sniffing:
        packet_logs = ""
        for _ in range(100):  # Runs for ~100 seconds, or adjust to your needs
            while not log_queue.empty():
                packet_logs += log_queue.get() + "\n"
            output_area.markdown(packet_logs)
            time.sleep(1)
    
# --- Encrypt/Decrypt Tab ---
elif tab == "🔐 Encrypt/Decrypt":
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

            data = {"Kyber": {}, "RSA": {}}
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

            st.markdown("### 🔓 Decryption Results")
            col1, col2 = st.columns(2)
            col1.metric("Kyber Decrypted", data["Kyber"].get("Decrypted", ""), delta="✅" if data["Kyber"].get("Match") == "Yes" else "❌")
            col2.metric("RSA Decrypted", data["RSA"].get("Decrypted", ""), delta="✅" if data["RSA"].get("Match") == "Yes" else "❌")

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

            st.markdown("### ⏱️ RSA Timing")
            fig2 = go.Figure()
            fig2.add_trace(go.Bar(name="RSA", x=["KeyGen", "Encrypt", "Decrypt"], y=[
                data["RSA"].get("KeyGen", 0),
                data["RSA"].get("Encrypt", 0),
                data["RSA"].get("Decrypt", 0)
            ], marker_color='green'))
            fig2.update_layout(barmode='group', xaxis_title="Operation", yaxis_title="Time (seconds)")
            st.plotly_chart(fig2, use_container_width=True)

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
                256
            ], marker_color="green"))
            fig3.update_layout(barmode='group', xaxis_title="Type", yaxis_title="Size (bytes)")
            st.plotly_chart(fig3, use_container_width=True)



# Utility to run shell commands and capture output
def run_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return output.decode().strip().splitlines()
    except subprocess.CalledProcessError as e:
        return [f"❌ Error occurred:\n{e.output.decode().strip()}"]


# 🧠 Beautifier to format output
def display_output(title, lines):
    st.markdown(f"#### 📤 {title}")
    formatted = "\n".join(lines)
    st.code(formatted, language="bash")  # Terminal-style formatting


# 🔐 Signature Workflow Tabs
if tab == "🔐 Signature Tabs":
    st.title("🔐 Dilithium Signature Verification Demo")
    tab1, tab2, tab3 = st.tabs(["✅ Actual Client", "🚨 Fake Client", "🛡️ Server"])

    # ✅ Actual Client
    with tab1:
        st.subheader("✅ Valid Client Signer")
        msg = st.text_input("Enter message to sign and send:", key="actual_input")

        if st.button("📝 Sign & Send (Valid Client)", key="actual_btn") and msg.strip():
            output_lines = run_command(f"./client_dilithium1 \"{msg}\"")
            display_output("Valid Client Output", output_lines)

    # 🚨 Fake Client
    with tab2:
        st.subheader("🚨 Malicious Client")
        msg = st.text_input("Enter message to sign and send:", key="fake_input")

        if st.button("⚠️ Sign & Send (Fake Client)", key="fake_btn") and msg.strip():
            output_lines = run_command(f"./client_invalid \"{msg}\"")
            display_output("Fake Client Output", output_lines)

    # 🛡️ Server
    with tab3:
        st.subheader("🛡️ Server Verifier")

        if st.button("📥 Receive & Verify Signature", key="server_btn"):
            output_lines = run_command("./server_dilithium")
            display_output("Server Output", output_lines)

            result_block = "\n".join(output_lines).lower()
            if "✅" in result_block or "signature is valid" in result_block:
                st.success("✅ Signature is VALID. The message came from a trusted client.")
            elif "❌" in result_block or "signature is invalid" in result_block:
                st.error("❌ Signature is INVALID. The message may be forged or tampered.")

