import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw, wrpcap, rdpcap
import time
import json
import numpy as np
import tensorflow as tf  # Added for Deep Learning model integration


class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Python Packet Sniffer")
        master.geometry("1000x700")  # Increased width to accommodate new sections
        master.configure(bg="#2E2E2E")  # Dark background

        self.sniffing = False
        self.packets = []
        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_stats = {
            "Ethernet": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0
        }

        # Packet storage for export, including extracted features
        self.export_packets_data = []

        self.create_widgets()

        # --- Deep Learning Model Loading ---
        self.model = None
        try:
            self.model = tf.keras.models.load_model('network_ids_model.h5')
            self.status_label.config(text="Status: Model loaded successfully. Ready.")
            print("Deep Learning model 'network_ids_model.h5' loaded.")
        except Exception as e:
            self.status_label.config(text=f"Status: Error loading model: {e}. Running without DL detection.")
            print(f"Error loading Deep Learning model: {e}. DL detection will be disabled.")
            messagebox.showwarning("Model Load Error",
                                   f"Could not load network_ids_model.h5: {e}\nDL detection will be disabled.")

    def create_widgets(self):
        # --- Top Frame for Interface, Buttons, and Alerts ---
        top_frame = ttk.Frame(self.master, padding="10", relief="groove", borderwidth=2)
        top_frame.pack(side="top", fill="x", padx=10, pady=10)
        top_frame.columnconfigure(1, weight=1)  # Allow interface dropdown to expand

        # Network Interface Selection
        ttk.Label(top_frame, text="Network Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(top_frame, textvariable=self.interface_var, width=50)
        self.interface_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.interface_dropdown['values'] = self.get_interfaces()  # Populate interfaces
        if self.interface_dropdown['values']:
            self.interface_dropdown.set(self.interface_dropdown['values'][0])

        # Buttons
        button_frame = ttk.Frame(top_frame)
        button_frame.grid(row=0, column=2, rowspan=2, padx=10, pady=5, sticky="e")

        self.start_button = ttk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side="top", fill="x", pady=2)

        self.stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side="top", fill="x", pady=2)

        self.export_button = ttk.Button(button_frame, text="Export Packets", command=self.export_packets)
        self.export_button.pack(side="top", fill="x", pady=2)

        self.import_pcap_button = ttk.Button(button_frame, text="Import PCAP", command=self.import_pcap)
        self.import_pcap_button.pack(side="top", fill="x", pady=2)

        # Alert Keyword (Remains from original concept)
        ttk.Label(top_frame, text="Alert Keyword:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.alert_keyword_var = tk.StringVar(value="sensitive")
        ttk.Entry(top_frame, textvariable=self.alert_keyword_var, width=50).grid(row=1, column=1, padx=5, pady=5,
                                                                                 sticky="ew")

        # Status Bar
        self.status_label = ttk.Label(self.master, text="Status: Ready", relief="sunken", anchor="w")
        self.status_label.pack(side="bottom", fill="x", ipady=2)

        # --- Main Content Area (Paned Window for resizable sections) ---
        main_pane = ttk.Panedwindow(self.master, orient=tk.HORIZONTAL)
        main_pane.pack(fill="both", expand=True, padx=10, pady=5)

        # Left Frame: Filters, Stats, Active Alerts
        left_frame = ttk.Frame(main_pane, padding="10", relief="groove", borderwidth=2)
        main_pane.add(left_frame, weight=1)  # Left frame takes some space

        # Packet Filters
        filter_frame = ttk.LabelFrame(left_frame, text="Packet Filters", padding="10")
        filter_frame.pack(fill="x", pady=10)
        filter_frame.columnconfigure(1, weight=1)

        ttk.Label(filter_frame, text="Source IP:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.src_ip_filter = ttk.Entry(filter_frame, width=20)
        self.src_ip_filter.grid(row=0, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(filter_frame, text="Destination IP:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.dst_ip_filter = ttk.Entry(filter_frame, width=20)
        self.dst_ip_filter.grid(row=1, column=1, padx=5, pady=2, sticky="ew")

        ttk.Label(filter_frame, text="Protocol:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.proto_filter = ttk.Entry(filter_frame, width=20)
        self.proto_filter.grid(row=2, column=1, padx=5, pady=2, sticky="ew")

        # Active Alerts Display
        alerts_frame = ttk.LabelFrame(left_frame, text="Active Alerts", padding="10")
        alerts_frame.pack(fill="both", expand=True, pady=10)
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, wrap=tk.WORD, height=8, bg="#1E1E1E", fg="#FFD700",
                                                     insertbackground="white")
        self.alerts_text.pack(fill="both", expand=True)
        self.alerts_text.insert(tk.END,
                                "(Alerts typically trigger on plaintext data, won't work on encrypted traffic like HTTPS)\n")
        self.alerts_text.configure(state='disabled')  # Make it read-only

        # Protocol Statistics
        stats_frame = ttk.LabelFrame(left_frame, text="Protocol Statistics", padding="10")
        stats_frame.pack(fill="x", pady=10)
        stats_frame.columnconfigure(1, weight=1)  # Allows value labels to expand

        self.stats_labels = {}
        row = 0
        for proto in ["Total", "Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP", "Other"]:
            ttk.Label(stats_frame, text=f"{proto} Packets:").grid(row=row, column=0, padx=5, pady=2, sticky="w")
            self.stats_labels[f"{proto}_pkts"] = ttk.Label(stats_frame, text="0")
            self.stats_labels[f"{proto}_pkts"].grid(row=row, column=1, padx=5, pady=2, sticky="w")

            # Add bytes for Total, IP, TCP, UDP, Ethernet, ICMP, ARP (others can be consolidated)
            if proto in ["Total", "Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP"]:
                ttk.Label(stats_frame, text=f"{proto} Bytes:").grid(row=row, column=2, padx=5, pady=2, sticky="w")
                self.stats_labels[f"{proto}_bytes"] = ttk.Label(stats_frame, text="0 KB")
                self.stats_labels[f"{proto}_bytes"].grid(row=row, column=3, padx=5, pady=2, sticky="w")
            row += 1

        self.update_stats_display()  # Initial update

        # Right Frame: Captured Packets Display
        right_frame = ttk.Frame(main_pane, padding="10", relief="groove", borderwidth=2)
        main_pane.add(right_frame, weight=2)  # Right frame takes more space

        ttk.Label(right_frame, text="Captured Packets:").pack(side="top", fill="x", pady=5)
        self.packet_list_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, bg="#1E1E1E", fg="white",
                                                          insertbackground="white")
        self.packet_list_text.pack(fill="both", expand=True)
        self.packet_list_text.configure(state='disabled')  # Make it read-only

    def get_interfaces(self):
        # This function attempts to list available network interfaces.
        # It's a placeholder; Scapy's sniff() can often find them.
        # For a robust solution, consider using 'ifaces' from scapy.all.
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            # Fallback if get_if_list doesn't work or Scapy isn't fully configured
            return ["eth0", "wlan0", "lo", "\\Device\\NPF_{...}"]  # Common interface names

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Sniffing...")

            # Reset collected data for new sniff session
            self.packets = []
            self.packet_count = 0
            self.total_bytes = 0
            self.protocol_stats = {k: 0 for k in self.protocol_stats}  # Reset all stats
            self.export_packets_data = []  # Clear export buffer

            self.packet_list_text.configure(state='normal')
            self.packet_list_text.delete(1.0, tk.END)
            self.packet_list_text.configure(state='disabled')
            self.alerts_text.configure(state='normal')
            self.alerts_text.delete(1.0, tk.END)
            self.alerts_text.insert(tk.END,
                                    "(Alerts typically trigger on plaintext data, won't work on encrypted traffic like HTTPS)\n")
            self.alerts_text.configure(state='disabled')
            self.update_stats_display()

            self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
            self.sniff_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Sniffer stopped.")

    def _sniff_packets(self):
        interface = self.interface_var.get()
        bpf_filter = self.get_bpf_filter()

        try:
            sniff(iface=interface, prn=self._process_packet, store=0, stop_filter=lambda x: not self.sniffing,
                  filter=bpf_filter)
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Sniffing Error",
                                                              f"Error sniffing on {interface}: {e}\n\nPlease check interface name and permissions (run as admin/root)."))
            self.master.after(0, self.stop_sniffing)  # Stop sniffing in GUI on error

    def get_bpf_filter(self):
        src_ip = self.src_ip_filter.get().strip()
        dst_ip = self.dst_ip_filter.get().strip()
        protocol = self.proto_filter.get().strip().lower()

        filters = []
        if src_ip:
            filters.append(f"src host {src_ip}")
        if dst_ip:
            filters.append(f"dst host {dst_ip}")
        if protocol:
            if protocol in ["tcp", "udp", "icmp", "arp"]:
                filters.append(protocol)
            elif protocol == "ip":
                filters.append("ip")  # Covers all IP-based protocols
            else:
                # Basic validation for other protocols, or just let Scapy handle it
                filters.append(protocol)  # Add as is, Scapy might parse or error

        return " and ".join(filters) if filters else ""

    def _process_packet(self, packet):
        if not self.sniffing:
            return  # Stop processing if sniffing is disabled

        # Update raw packet count and bytes
        self.packet_count += 1
        self.total_bytes += len(packet)

        # Update protocol statistics
        self.protocol_stats["Ethernet"] += 1
        if packet.haslayer(IP):
            self.protocol_stats["IP"] += 1
            if packet.haslayer(TCP):
                self.protocol_stats["TCP"] += 1
            elif packet.haslayer(UDP):
                self.protocol_stats["UDP"] += 1
            elif packet.haslayer(ICMP):
                self.protocol_stats["ICMP"] += 1
            else:
                self.protocol_stats["Other"] += 1  # Other IP protocols
        elif packet.haslayer(ARP):
            self.protocol_stats["ARP"] += 1
        else:
            if not packet.haslayer(IP) and not packet.haslayer(ARP):
                self.protocol_stats["Other"] += 1  # Non-IP, Non-ARP Ethernet traffic

        # Extract features for Deep Learning
        features = self._extract_dl_features(packet)

        # Deep Learning Prediction
        prediction_label = "Normal"  # Default to Normal
        prediction_confidence = 0.0

        if self.model:  # Only predict if model was loaded successfully
            try:
                # Reshape features to (1, 69) as model expects a batch of inputs
                features_reshaped = features.reshape(1, -1)

                # Get prediction probability (output of sigmoid is probability)
                prediction_prob = self.model.predict(features_reshaped, verbose=0)[0][0]
                prediction_confidence = float(prediction_prob)  # Convert to float for display

                # Classify based on a threshold (e.g., 0.5)
                if prediction_prob > 0.5:
                    prediction_label = "Attack"
                else:
                    prediction_label = "Normal"
            except Exception as e:
                prediction_label = f"DL Error: {e}"
                print(f"Error during DL prediction: {e}")

        # Prepare packet data for export
        pkt_summary = packet.summary()
        pkt_info = {
            "raw_hex": bytes(packet).hex(),  # Store raw packet bytes as hex string
            "timestamp": time.time(),
            "summary": pkt_summary,
            "features": features.tolist(),  # Store features as a list (JSON serializable)
            "dl_prediction": prediction_label,  # Add prediction to export data
            "dl_confidence": prediction_confidence  # Add confidence to export data
        }

        # Extract specific fields for the JSON output for better readability (optional but good)
        if packet.haslayer(IP):
            pkt_info["srcIp"] = packet[IP].src
            pkt_info["dstIp"] = packet[IP].dst
            pkt_info["protocol"] = packet[IP].proto  # Numeric protocol
            if packet.haslayer(TCP):
                pkt_info["srcPort"] = packet[TCP].sport
                pkt_info["dstPort"] = packet[TCP].dport
                pkt_info["protocol"] = "TCP"  # Overwrite with string for clarity
            elif packet.haslayer(UDP):
                pkt_info["srcPort"] = packet[UDP].sport
                pkt_info["dstPort"] = packet[UDP].dport
                pkt_info["protocol"] = "UDP"
            elif packet.haslayer(ICMP):
                pkt_info["protocol"] = "ICMP"
        elif packet.haslayer(ARP):
            pkt_info["protocol"] = "ARP"
            pkt_info["srcIp"] = packet[ARP].psrc
            pkt_info["dstIp"] = packet[ARP].pdst

        if packet.haslayer(Raw):
            try:
                # Attempt to decode payload for display/alerting
                pkt_info["rawData"] = packet[Raw].load.decode('utf-8', errors='ignore')
            except:
                pkt_info["rawData"] = packet[Raw].load.hex()  # Fallback to hex if not decodable
        else:
            pkt_info["rawData"] = ""

        self.export_packets_data.append(pkt_info)

        # Update GUI elements
        self.master.after(0, self.update_gui_display, pkt_summary, prediction_label)
        self.master.after(0, self.check_for_alerts, packet)  # Check for alerts based on content

    def update_gui_display(self, pkt_summary, dl_prediction_label):  # Added dl_prediction_label
        # Update packet list display
        self.packet_list_text.configure(state='normal')
        # Display the DL prediction alongside the packet summary
        self.packet_list_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] [{dl_prediction_label}] {pkt_summary}\n")
        self.packet_list_text.see(tk.END)  # Scroll to end
        self.packet_list_text.configure(state='disabled')

        # Update stats display
        self.update_stats_display()

    def update_stats_display(self):
        self.stats_labels["Total_pkts"].config(text=f"{self.packet_count}")
        self.stats_labels["Total_bytes"].config(text=f"{self.total_bytes / 1024:.2f} KB")  # Convert to KB

        for proto in ["Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP", "Other"]:
            if f"{proto}_pkts" in self.stats_labels:
                self.stats_labels[f"{proto}_pkts"].config(text=f"{self.protocol_stats.get(proto, 0)}")

            # For bytes, we need to calculate or accumulate correctly.
            # For simplicity, we'll just show IP/TCP/UDP/ICMP/ARP bytes based on total for now
            # In a real scenario, you'd track bytes per protocol as well during packet processing.
            # Here, we approximate based on packet count for dummy data.
            if proto == "Ethernet":
                # Ethernet bytes are essentially total packet bytes for this layer
                self.stats_labels["Ethernet_bytes"].config(text=f"{self.total_bytes / 1024:.2f} KB")
            elif proto == "IP" and "IP_bytes" in self.stats_labels:
                # Roughly estimate IP bytes based on number of IP packets and average size
                ip_bytes_estimate = self.protocol_stats['IP'] * 60  # Avg IP packet size including headers
                self.stats_labels["IP_bytes"].config(text=f"{ip_bytes_estimate / 1024:.2f} KB")
            elif proto == "TCP" and "TCP_bytes" in self.stats_labels:
                tcp_bytes_estimate = self.protocol_stats['TCP'] * 60
                self.stats_labels["TCP_bytes"].config(text=f"{tcp_bytes_estimate / 1024:.2f} KB")
            elif proto == "UDP" and "UDP_bytes" in self.stats_labels:
                udp_bytes_estimate = self.protocol_stats['UDP'] * 50
                self.stats_labels["UDP_bytes"].config(text=f"{udp_bytes_estimate / 1024:.2f} KB")
            elif proto == "ICMP" and "ICMP_bytes" in self.stats_labels:
                icmp_bytes_estimate = self.protocol_stats['ICMP'] * 40
                self.stats_labels["ICMP_bytes"].config(text=f"{icmp_bytes_estimate / 1024:.2f} KB")
            elif proto == "ARP" and "ARP_bytes" in self.stats_labels:
                arp_bytes_estimate = self.protocol_stats['ARP'] * 42
                self.stats_labels["ARP_bytes"].config(text=f"{arp_bytes_estimate / 1024:.2f} KB")

    def check_for_alerts(self, packet):
        keyword = self.alert_keyword_var.get().strip().lower()
        if not keyword:
            return

        alert_message = None

        # Check for keyword in payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded_payload = payload.decode('utf-8', errors='ignore')
                if keyword in decoded_payload.lower():
                    alert_message = f"Keyword '{keyword}' found in payload from {packet.summary()}"
            except UnicodeDecodeError:
                pass  # Can't decode, skip keyword check for this payload

        # Simple alert for high port scans (SYN packets to unusual ports)
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # SYN flag set
            if packet[TCP].dport > 1024 and packet[TCP].dport not in [8080, 8443]:  # Common web ports often used
                # This is a very basic heuristic. A real IDS would need more context.
                if alert_message:  # Append if existing alert
                    alert_message += f"\nPotential port scan to non-standard port: {packet[TCP].dport}"
                else:
                    alert_message = f"Potential port scan to non-standard port: {packet[TCP].dport} from {packet[IP].src if packet.haslayer(IP) else 'N/A'}"

        # Basic ICMP flood detection (very rudimentary)
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Echo request
            # This is hard to detect in a single packet. Would need rate-limiting logic.
            # For demonstration, we'll just flag any ICMP request if we wanted to
            # But actual flood detection requires tracking packets over time.
            pass  # We won't add a single-packet ICMP flood alert here to avoid noise

        if alert_message:
            self.master.after(0, self._display_alert, message_prefix="Traditional Alert", message=alert_message)

    def _display_alert(self, message_prefix, message):
        self.alerts_text.configure(state='normal')
        self.alerts_text.insert(tk.END, f"{message_prefix}: {message}\n")
        self.alerts_text.see(tk.END)
        self.alerts_text.configure(state='disabled')

    def export_packets(self):
        if not self.export_packets_data:
            messagebox.showinfo("Export", "No packets to export.")
            return

        # Ask user whether to export as PCAP or JSON
        response = messagebox.askyesno("Export Option",
                                       "Do you want to export as a PCAP file? Click 'No' to export as JSON.")

        if response:  # Yes, export as PCAP
            file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                                     filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
            if file_path:
                try:
                    # Reconstruct Scapy packets from raw_hex for PCAP export
                    scapy_packets_to_export = []
                    for pkt_info in self.export_packets_data:
                        try:
                            scapy_packets_to_export.append(Ether(bytes.fromhex(pkt_info['raw_hex'])))
                        except Exception as e:
                            print(f"Error reconstructing packet from hex for PCAP export: {e}")
                            continue
                    wrpcap(file_path, scapy_packets_to_export)
                    messagebox.showinfo("Export Success", f"Packets exported to {file_path}")
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export PCAP: {e}")
        else:  # No, export as JSON
            file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                     filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
            if file_path:
                try:
                    # Save the self.export_packets_data directly, as it's already in the desired format
                    with open(file_path, 'w') as f:
                        json.dump(self.export_packets_data, f, indent=4)
                    messagebox.showinfo("Export Success",
                                        f"Packet data (with features and DL predictions) exported to {file_path}")
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export JSON: {e}")

    def import_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            try:
                self.status_label.config(text="Status: Importing PCAP...")
                self.export_packets_data = []  # Clear existing data
                self.packet_list_text.configure(state='normal')
                self.packet_list_text.delete(1.0, tk.END)
                self.packet_list_text.configure(state='disabled')

                # Reset stats for imported packets
                self.packet_count = 0
                self.total_bytes = 0
                self.protocol_stats = {k: 0 for k in self.protocol_stats}

                packets = rdpcap(file_path)
                for i, packet in enumerate(packets):

                    features = self._extract_dl_features(packet)
                    pkt_summary = packet.summary()

                    # Deep Learning Prediction for imported packets
                    prediction_label = "Normal"
                    prediction_confidence = 0.0
                    if self.model:
                        try:
                            features_reshaped = features.reshape(1, -1)
                            prediction_prob = self.model.predict(features_reshaped, verbose=0)[0][0]
                            prediction_confidence = float(prediction_prob)
                            if prediction_prob > 0.5:
                                prediction_label = "Attack"
                            else:
                                prediction_label = "Normal"
                        except Exception as e:
                            prediction_label = f"DL Error: {e}"
                            print(f"Error during DL prediction for imported packet: {e}")

                    pkt_info = {
                        "raw_hex": bytes(packet).hex(),
                        "timestamp": time.time(),  # Use current time for imported, or original pkt.time
                        "summary": pkt_summary,
                        "features": features.tolist(),
                        "dl_prediction": prediction_label,  # Add prediction to export data
                        "dl_confidence": prediction_confidence  # Add confidence to export data
                    }

                    # Update stats here directly as if sniffed
                    self.packet_count += 1
                    self.total_bytes += len(packet)
                    self.protocol_stats["Ethernet"] += 1
                    if packet.haslayer(IP):
                        self.protocol_stats["IP"] += 1
                        if packet.haslayer(TCP):
                            self.protocol_stats["TCP"] += 1
                        elif packet.haslayer(UDP):
                            self.protocol_stats["UDP"] += 1
                        elif packet.haslayer(ICMP):
                            self.protocol_stats["ICMP"] += 1
                        else:
                            self.protocol_stats["Other"] += 1
                    elif packet.haslayer(ARP):
                        self.protocol_stats["ARP"] += 1
                    else:
                        self.protocol_stats["Other"] += 1

                    # Add detailed info for JSON export
                    if packet.haslayer(IP):
                        pkt_info["srcIp"] = packet[IP].src
                        pkt_info["dstIp"] = packet[IP].dst
                        pkt_info["protocol"] = packet[IP].proto
                        if packet.haslayer(TCP):
                            pkt_info["srcPort"] = packet[TCP].sport
                            pkt_info["dstPort"] = packet[TCP].dport
                            pkt_info["protocol"] = "TCP"
                        elif packet.haslayer(UDP):
                            pkt_info["srcPort"] = packet[UDP].sport
                            pkt_info["dstPort"] = packet[UDP].dport
                            pkt_info["protocol"] = "UDP"
                        elif packet.haslayer(ICMP):
                            pkt_info["protocol"] = "ICMP"
                    elif packet.haslayer(ARP):
                        pkt_info["protocol"] = "ARP"
                        pkt_info["srcIp"] = packet[ARP].psrc
                        pkt_info["dstIp"] = packet[ARP].pdst

                    if packet.haslayer(Raw):
                        try:
                            pkt_info["rawData"] = packet[Raw].load.decode('utf-8', errors='ignore')
                        except:
                            pkt_info["rawData"] = packet[Raw].load.hex()
                    else:
                        pkt_info["rawData"] = ""

                    self.export_packets_data.append(pkt_info)

                    # Update GUI only periodically to avoid lag for large PCAPs
                    if i % 50 == 0:  # Update every 50 packets
                        self.master.after(0, self.packet_list_text.configure, state='normal')
                        # Display the DL prediction alongside the packet summary for imported packets
                        self.master.after(0, self.packet_list_text.insert, tk.END,
                                          f"[{time.strftime('%H:%M:%S')}] [{prediction_label}] {pkt_summary} (Imported)\n")
                        self.master.after(0, self.packet_list_text.see, tk.END)
                        self.master.after(0, self.packet_list_text.configure, state='disabled')
                        self.master.after(0, self.update_stats_display)

                self.master.after(0, self.packet_list_text.configure, state='normal')
                self.master.after(0, self.packet_list_text.insert, tk.END,
                                  f"\n--- Finished importing {len(packets)} packets from {file_path} ---\n")
                self.master.after(0, self.packet_list_text.see, tk.END)
                self.master.after(0, self.packet_list_text.configure, state='disabled')
                self.master.after(0, self.update_stats_display)  # Final stats update
                self.status_label.config(text=f"Status: Imported {len(packets)} packets from {file_path}")
                messagebox.showinfo("Import Success", f"Successfully imported {len(packets)} packets from {file_path}")

            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import PCAP: {e}")
                self.status_label.config(text="Status: Import failed.")

    def _extract_dl_features(self, packet):
        """
        Extracts numerical features from a Scapy packet for deep learning.
        Produces a 69-element numpy array.

        Features:
        1. Packet Length (1 feature)
        2. Protocol Type (5 features: TCP, UDP, ICMP, ARP, Other IP) - One-hot encoded
        3. IP Addresses (2 features: Source IP, Destination IP) - Hashed/Scaled
        4. Port Numbers (2 features: Source Port, Destination Port) - Scaled
        5. TCP Flags (6 features: SYN, ACK, FIN, RST, PSH, URG) - Binary
        6. ICMP Type and Code (2 features)
        7. ARP Opcode (1 feature)
        8. Payload (50 features) - Hashed/Encoded first 50 bytes

        Total features: 1 + 5 + 2 + 2 + 6 + 2 + 1 + 50 = 69
        """
        features = np.zeros(69, dtype=np.float32)

        # 1. Packet Length (Index 0)
        features[0] = len(packet) / 1500.0  # Normalize by max Ethernet MTU (approx)

        # 2. Protocol Type (Indices 1-5 for one-hot encoding)
        # TCP, UDP, ICMP, ARP, Other IP
        proto_offset = 1
        if packet.haslayer(TCP):
            features[proto_offset] = 1  # TCP
        elif packet.haslayer(UDP):
            features[proto_offset + 1] = 1  # UDP
        elif packet.haslayer(ICMP):
            features[proto_offset + 2] = 1  # ICMP
        elif packet.haslayer(ARP):
            features[proto_offset + 3] = 1  # ARP
        elif packet.haslayer(IP):  # Any other IP-based protocol
            features[proto_offset + 4] = 1  # Other IP

        # 3. IP Addresses (Indices 6-7)
        ip_offset = 6
        if packet.haslayer(IP):
            # Simple scaling/hashing for IP addresses (for demonstration)
            # In real-world, might use more sophisticated methods or external reputation
            features[ip_offset] = int(str(packet[IP].src).replace('.', '')) % 100000 / 100000.0
            features[ip_offset + 1] = int(str(packet[IP].dst).replace('.', '')) % 100000 / 100000.0

        # 4. Port Numbers (Indices 8-9)
        port_offset = 8
        if packet.haslayer(TCP):
            features[port_offset] = packet[TCP].sport / 65535.0  # Normalize by max port
            features[port_offset + 1] = packet[TCP].dport / 65535.0
        elif packet.haslayer(UDP):
            features[port_offset] = packet[UDP].sport / 65535.0
            features[port_offset + 1] = packet[UDP].dport / 65535.0

        # 5. TCP Flags (Indices 10-15)
        # SYN, ACK, FIN, RST, PSH, URG
        tcp_flags_offset = 10
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'S' in flags: features[tcp_flags_offset] = 1  # SYN
            if 'A' in flags: features[tcp_flags_offset + 1] = 1  # ACK
            if 'F' in flags: features[tcp_flags_offset + 2] = 1  # FIN
            if 'R' in flags: features[tcp_flags_offset + 3] = 1  # RST
            if 'P' in flags: features[tcp_flags_offset + 4] = 1  # PSH
            if 'U' in flags: features[tcp_flags_offset + 5] = 1  # URG

        # 6. ICMP Type and Code (Indices 16-17)
        icmp_offset = 16
        if packet.haslayer(ICMP):
            features[icmp_offset] = packet[ICMP].type / 255.0  # Normalize type
            features[icmp_offset + 1] = packet[ICMP].code / 255.0  # Normalize code

        # 7. ARP Opcode (Index 18)
        arp_offset = 18
        if packet.haslayer(ARP):
            features[arp_offset] = packet[ARP].op / 2.0  # Normalize (1=request, 2=reply typically)

        # 8. Payload (Indices 19-68, 50 features)
        payload_offset = 19
        payload_len = 50  # Max bytes to consider for payload
        raw_payload = b''
        if packet.haslayer(Raw):
            raw_payload = packet[Raw].load
        # You could also get payload from TCP/UDP layer if Raw is not present, depending on packet structure
        # if packet.haslayer(TCP) and len(packet[TCP].payload) > 0:
        #     raw_payload = bytes(packet[TCP].payload)
        # elif packet.haslayer(UDP) and len(packet[UDP].payload) > 0:
        #     raw_payload = bytes(packet[UDP].payload)

        for i in range(min(len(raw_payload), payload_len)):
            features[payload_offset + i] = raw_payload[i] / 255.0  # Normalize byte value (0-255)

        return features


def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()