#!/usr/bin/env python3
import socket
import threading

CLIENT_PORT = 9001  # Where the MITM listens (client connects here)
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9000  # Real server port

def forward(src, dst, label):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            print(f"[MITM - {label}] Intercepted: {data.decode(errors='ignore').strip()}")
            
            # Optional: Modify the data before sending
            # if label == 'Client->Server':
            #     data = data.replace(b'hello', b'HACKED')
            
            dst.sendall(data)
    except Exception as e:
        print(f"[MITM - {label}] Error: {e}")
    finally:
        src.close()
        dst.close()

def handle_client(client_sock):
    print("[MITM] New client connected.")
    try:
        # Connect to real server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((SERVER_HOST, SERVER_PORT))

        # Two-way forwarding
        threading.Thread(target=forward, args=(client_sock, server_sock, 'Client->Server')).start()
        threading.Thread(target=forward, args=(server_sock, client_sock, 'Server->Client')).start()
    except Exception as e:
        print(f"[MITM] Connection error: {e}")
        client_sock.close()

def main():
    print("[MITM] Starting MITM Proxy on port", CLIENT_PORT)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('0.0.0.0', CLIENT_PORT))
    listener.listen(5)

    while True:
        client_sock, addr = listener.accept()
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()

if __name__ == "__main__":
    main()

