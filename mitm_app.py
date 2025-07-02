import streamlit as st
import socket
import threading
import queue

# Config - server you're proxying to
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000

# Queue for intercepted log messages
log_queue = queue.Queue()

# Core forwarding logic
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

# Handles new client connection
def handle_client(client_sock):
    log_queue.put("[MITM] New client connected.")
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((SERVER_HOST, SERVER_PORT))
        threading.Thread(target=forward, args=(client_sock, server_sock, 'Client->Server'), daemon=True).start()
        threading.Thread(target=forward, args=(server_sock, client_sock, 'Server->Client'), daemon=True).start()
    except Exception as e:
        log_queue.put(f"[MITM] Connection error: {e}")
        client_sock.close()

# Start MITM listener
def mitm_main(client_port):
    log_queue.put(f"[MITM] Starting MITM Proxy on port {client_port}")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', client_port))
    listener.listen(5)

    while True:
        client_sock, _ = listener.accept()
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()

# ---------------- Streamlit UI ---------------- #
st.set_page_config(layout="wide")
st.title("🕵️‍♂️ MITM Proxy Monitor")

# Sidebar config
st.sidebar.header("Configuration")
client_port = st.sidebar.number_input("Client → MITM Port", min_value=1024, max_value=65535, value=9001)
run_attack = st.sidebar.button("🚨 Run MITM Attack")

log_display = st.empty()

if run_attack:
    # Start MITM listener in background
    threading.Thread(target=mitm_main, args=(client_port,), daemon=True).start()
    st.success(f"MITM Proxy Started on port {client_port}. Connect your client to this port.")

    logs = []

    # Display intercepted logs live
    while True:
        try:
            msg = log_queue.get(timeout=1)
            logs.append(msg)
            if len(logs) > 100:
                logs = logs[-100:]  # Keep only last 100 logs
            log_display.code("\n".join(logs), language="text")
        except queue.Empty:
            pass

