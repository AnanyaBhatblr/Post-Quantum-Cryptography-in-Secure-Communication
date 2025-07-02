import streamlit as st
import threading
import queue
import time
from datetime import datetime
from scapy.all import sniff, TCP, Raw, IP

# Thread-safe queue for log messages
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

# Streamlit UI
st.title("📡 Live TCP Packet Sniffer (lo0)")
st.warning("⚠️ Requires root privileges to run. Works only on `lo0` interface (macOS/Linux).")

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