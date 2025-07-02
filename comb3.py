import streamlit as st
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

# Queue for intercepted log messages
log_queue = queue.Queue()
sniff_queue = queue.Queue()

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

# Packet sniffer callback
def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')
            src = f"{packet[IP].src}:{packet[TCP].sport}"
            dst = f"{packet[IP].dst}:{packet[TCP].dport}"
            flags = packet[TCP].flags
            seq = packet[TCP].seq
            ack = packet[TCP].ack
            payload = packet[Raw].load.decode(errors='ignore')

            summary = f"""--- New Packet Captured ---\nTime: {timestamp}\nSource: {src}\nDestination: {dst}\nFlags: {flags}\nSequence: {seq}\nAcknowledgement: {ack}\nPayload:\n{payload}\n-------------------------\n"""
            sniff_queue.put(summary)
        except Exception as e:
            sniff_queue.put(f"⚠️ Packet parsing error: {e}")

def start_sniffing():
    try:
        sniff(iface="lo0", prn=packet_callback, store=0, filter="tcp")
    except Exception as e:
        sniff_queue.put(f"❌ Error starting sniffer: {e}")

# --- Sidebar Navigation ---
st.set_page_config(layout="wide")
tab = st.sidebar.radio("📂 Navigation", ["🏠 Home", "🕵️ MITM Attack", "🔐 Encrypt/Decrypt", "📡 Packet Sniffing Attack"])

# --- Home Tab ---
if tab == "🏠 Home":
    st.title("🔒 Secure Communication Simulator")
    st.markdown("""
        Welcome to the **Secure Communication Visualizer**.

        🔐 **Compare classical RSA and post-quantum Kyber512 encryption**  
        🕵️ **Simulate real-time MITM attacks on your network**  
        📊 **Visualize traffic, timings, and encryption stats live**  
        
        Use the sidebar to navigate to features.
    """)

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

# --- Encrypt/Decrypt Tab ---
elif tab == "🔐 Encrypt/Decrypt":
    # existing content unchanged
    pass

# --- Packet Sniffing Attack Tab ---
elif tab == "📡 Packet Sniffing Attack":
    st.title("📡 TCP Packet Sniffing on Loopback Interface")
    st.warning("⚠️ This requires root/admin privileges and works only on `lo0` interface (Mac/Linux).")
    run_sniff = st.button("🚨 Run Packet Sniffer")

    sniff_display = st.empty()

    if run_sniff:
        st.success("Sniffer started on interface `lo0`...")
        threading.Thread(target=start_sniffing, daemon=True).start()

        packets = []
        while True:
            try:
                msg = sniff_queue.get(timeout=1)
                packets.append(msg)
                if len(packets) > 20:
                    packets = packets[-20:]
                sniff_display.code("\n".join(packets), language="text")
            except queue.Empty:
                continue
