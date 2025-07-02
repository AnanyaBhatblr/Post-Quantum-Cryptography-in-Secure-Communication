#!/usr/bin/env python3
from scapy.all import *

def packet_callback(packet):
    """
    This function is called for each captured packet.
    It prints the packet's summary and its raw data.
    """
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        print(f"--- New Packet Captured ---")
        print(f"Time: {datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')}")
        print(f"Source: {packet[IP].src}:{packet[TCP].sport}")
        print(f"Destination: {packet[IP].dst}:{packet[TCP].dport}")
        print(f"Flags: {packet[TCP].flags}")
        print(f"Sequence: {packet[TCP].seq}")
        print(f"Acknowledgement: {packet[TCP].ack}")
        print(f"Payload (Raw):")
        print(packet[Raw].load.decode(errors='ignore'))
        print("-" * 25)
        print("\n")


def main():
    """
    Main function to start sniffing network traffic.
    """
    print("Starting packet sniffing on loopback interface (lo0)...")
    try:
        # Sniff for TCP packets on the loopback interface 'lo0'.
        # You can add a filter to be more specific, e.g., "tcp and port 8080"
        sniff(iface="lo0", prn=packet_callback, store=0)
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please ensure you are running this script with sufficient privileges (e.g., using sudo).")
        print("Also, make sure the interface 'lo0' is correct for your system.")

if __name__ == "__main__":
    main()
