import streamlit as st
import socket
import threading
import queue

# Queue for intercepted log messages
log_queue = queue.Queue()

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

# Starts the MITM listener
def mitm_main(client_port, server_host, server_port):
    log_queue.put(f"[MITM] Listening on port {client_port}, forwarding to {server_host}:{server_port}")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', client_port))
    listener.listen(5)

    while True:
        client_sock, _ = listener.accept()
        threading.Thread(target=handle_client, args=(client_sock, server_host, server_port), daemon=True).start()

# ---------------- Streamlit UI ---------------- #
import time
import pandas as pd

st.set_page_config(layout="wide")
st.title("🕵️‍♂️ MITM Proxy Monitor with Live Traffic Visualization")

# Sidebar for configuration
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
    traffic_stats = {
        "Client->Server": 0,
        "Server->Client": 0
    }

    readability_stats = {
        "Readable (ASCII)": 0,
        "Encrypted (Binary)": 0
    }

    message_sizes = []
    traffic_over_time = []


    traffic_over_time = []

    start_time = time.time()

    while True:
        try:
            msg = log_queue.get(timeout=1)
            logs.append(msg)
            if len(logs) > 100:
                logs = logs[-100:]
            log_display.code("\n".join(logs), language="text")

            # Update stats
            if "Client->Server" in msg:
                traffic_stats["Client->Server"] += 1
            elif "Server->Client" in msg:
                traffic_stats["Server->Client"] += 1

            # Time-based stats for line chart
            now = round(time.time() - start_time, 1)
            total_msgs = traffic_stats["Client->Server"] + traffic_stats["Server->Client"]
            traffic_over_time.append({"time": now, "messages": total_msgs})
            if len(traffic_over_time) > 50:
                traffic_over_time = traffic_over_time[-50:]

            # Update bar chart
            df_bar = pd.DataFrame.from_dict(traffic_stats, orient='index', columns=["Count"])
            bar_chart.bar_chart(df_bar)

            # Update line chart
            df_line = pd.DataFrame(traffic_over_time)
            line_chart.line_chart(df_line.set_index("time"))

        except queue.Empty:
            pass
