import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw, wrpcap, rdpcap
import time
import json
import numpy as np

# Use the scikit-learn and xgboost libraries for a more lightweight solution
# You need to install these: pip install scikit-learn xgboost
# NOTE: You will need to train and save your own XGBoost model file.
# The `network_ids_model.json` file in this code is a placeholder.
try:
    import xgboost as xgb
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    ML_LIBRARIES_AVAILABLE = True
except ImportError:
    ML_LIBRARIES_AVAILABLE = False
    # Use a simpler, placeholder class if XGBoost is not available
    print("Warning: XGBoost and scikit-learn not found. Running in basic mode without ML detection.")

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Python Packet Sniffer")
        master.geometry("1000x700")
        master.configure(bg="#2E2E2E")

        self.sniffing = False
        self.packets = []
        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_stats = {
            "Ethernet": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0
        }

        self.export_packets_data = []

        self.create_widgets()

        # --- Machine Learning Model Loading ---
        self.model = None
        if ML_LIBRARIES_AVAILABLE:
            try:
                # Assuming the user has a pre-trained XGBoost model saved as a JSON file
                self.model = xgb.Booster(model_file='network_ids_model.json')
                self.status_label.config(text="Status: XGBoost model loaded successfully. Ready.")
                print("XGBoost model 'network_ids_model.json' loaded.")
            except Exception as e:
                self.status_label.config(text=f"Status: Error loading model: {e}. Running without ML detection.")
                print(f"Error loading XGBoost model: {e}. ML detection will be disabled.")
                messagebox.showwarning("Model Load Error",
                                       f"Could not load network_ids_model.json: {e}\nML detection will be disabled.")
        else:
            self.status_label.config(text="Status: XGBoost not installed. Running without ML detection.")


    def create_widgets(self):
        # --- Top Frame for Interface, Buttons, and Alerts ---
        top_frame = ttk.Frame(self.master, padding="10", relief="groove", borderwidth=2)
        top_frame.pack(side="top", fill="x", padx=10, pady=10)
        top_frame.columnconfigure(1, weight=1)

        # Network Interface Selection
        ttk.Label(top_frame, text="Network Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttk.Combobox(top_frame, textvariable=self.interface_var, width=50)
        self.interface_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.interface_dropdown['values'] = self.get_interfaces()
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

        # Alert Keyword
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
        main_pane.add(left_frame, weight=1)

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
        self.alerts_text.configure(state='disabled')

        # Protocol Statistics
        stats_frame = ttk.LabelFrame(left_frame, text="Protocol Statistics", padding="10")
        stats_frame.pack(fill="x", pady=10)
        stats_frame.columnconfigure(1, weight=1)

        self.stats_labels = {}
        row = 0
        for proto in ["Total", "Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP", "Other"]:
            ttk.Label(stats_frame, text=f"{proto} Packets:").grid(row=row, column=0, padx=5, pady=2, sticky="w")
            self.stats_labels[f"{proto}_pkts"] = ttk.Label(stats_frame, text="0")
            self.stats_labels[f"{proto}_pkts"].grid(row=row, column=1, padx=5, pady=2, sticky="w")

            if proto in ["Total", "Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP"]:
                ttk.Label(stats_frame, text=f"{proto} Bytes:").grid(row=row, column=2, padx=5, pady=2, sticky="w")
                self.stats_labels[f"{proto}_bytes"] = ttk.Label(stats_frame, text="0 KB")
                self.stats_labels[f"{proto}_bytes"].grid(row=row, column=3, padx=5, pady=2, sticky="w")
            row += 1

        self.update_stats_display()

        # Right Frame: Captured Packets Display
        right_frame = ttk.Frame(main_pane, padding="10", relief="groove", borderwidth=2)
        main_pane.add(right_frame, weight=2)

        ttk.Label(right_frame, text="Captured Packets:").pack(side="top", fill="x", pady=5)
        self.packet_list_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, bg="#1E1E1E", fg="white",
                                                          insertbackground="white")
        self.packet_list_text.pack(fill="both", expand=True)
        self.packet_list_text.configure(state='disabled')

    def get_interfaces(self):
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return ["eth0", "wlan0", "lo", "\\Device\\NPF_{...}"]

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_label.config(text="Status: Sniffing...")

            self.packets = []
            self.packet_count = 0
            self.total_bytes = 0
            self.protocol_stats = {k: 0 for k in self.protocol_stats}
            self.export_packets_data = []

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
            self.master.after(0, self.stop_sniffing)

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
                filters.append("ip")
            else:
                filters.append(protocol)

        return " and ".join(filters) if filters else ""

    def _process_packet(self, packet):
        if not self.sniffing:
            return

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
            if not packet.haslayer(IP) and not packet.haslayer(ARP):
                self.protocol_stats["Other"] += 1

        features = self._extract_ml_features(packet)
        prediction_label = "Normal"
        prediction_confidence = 0.0

        if self.model and ML_LIBRARIES_AVAILABLE:
            try:
                features_reshaped = features.reshape(1, -1)
                d_matrix = xgb.DMatrix(features_reshaped)
                # XGBoost's predict() returns raw scores by default.
                # Use a sigmoid function if your model was trained that way.
                # Assuming 0 is Normal, 1 is Attack.
                prediction_prob = self.model.predict(d_matrix)
                prediction_confidence = float(prediction_prob)

                if prediction_prob > 0.5:
                    prediction_label = "Attack"
                else:
                    prediction_label = "Normal"
            except Exception as e:
                prediction_label = f"ML Error: {e}"
                print(f"Error during ML prediction: {e}")
        else:
            prediction_label = "N/A" # No ML available

        pkt_summary = packet.summary()
        pkt_info = {
            "raw_hex": bytes(packet).hex(),
            "timestamp": time.time(),
            "summary": pkt_summary,
            "features": features.tolist(),
            "ml_prediction": prediction_label,
            "ml_confidence": prediction_confidence
        }

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

        self.master.after(0, self.update_gui_display, pkt_summary, prediction_label)
        self.master.after(0, self.check_for_alerts, packet)

    def update_gui_display(self, pkt_summary, ml_prediction_label):
        self.packet_list_text.configure(state='normal')
        self.packet_list_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] [{ml_prediction_label}] {pkt_summary}\n")
        self.packet_list_text.see(tk.END)
        self.packet_list_text.configure(state='disabled')
        self.update_stats_display()

    def update_stats_display(self):
        self.stats_labels["Total_pkts"].config(text=f"{self.packet_count}")
        self.stats_labels["Total_bytes"].config(text=f"{self.total_bytes / 1024:.2f} KB")

        for proto in ["Ethernet", "IP", "TCP", "UDP", "ICMP", "ARP", "Other"]:
            if f"{proto}_pkts" in self.stats_labels:
                self.stats_labels[f"{proto}_pkts"].config(text=f"{self.protocol_stats.get(proto, 0)}")

            if proto == "Ethernet":
                self.stats_labels["Ethernet_bytes"].config(text=f"{self.total_bytes / 1024:.2f} KB")
            elif proto == "IP" and "IP_bytes" in self.stats_labels:
                ip_bytes_estimate = self.protocol_stats['IP'] * 60
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

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded_payload = payload.decode('utf-8', errors='ignore')
                if keyword in decoded_payload.lower():
                    alert_message = f"Keyword '{keyword}' found in payload from {packet.summary()}"
            except UnicodeDecodeError:
                pass

        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            if packet[TCP].dport > 1024 and packet[TCP].dport not in [8080, 8443]:
                if alert_message:
                    alert_message += f"\nPotential port scan to non-standard port: {packet[TCP].dport}"
                else:
                    alert_message = f"Potential port scan to non-standard port: {packet[TCP].dport} from {packet[IP].src if packet.haslayer(IP) else 'N/A'}"

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

        response = messagebox.askyesno("Export Option",
                                       "Do you want to export as a PCAP file? Click 'No' to export as JSON.")

        if response:
            file_path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                                     filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
            if file_path:
                try:
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
        else:
            file_path = filedialog.asksaveasfilename(defaultextension=".json",
                                                     filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
            if file_path:
                try:
                    with open(file_path, 'w') as f:
                        json.dump(self.export_packets_data, f, indent=4)
                    messagebox.showinfo("Export Success",
                                        f"Packet data (with features and ML predictions) exported to {file_path}")
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to export JSON: {e}")

    def import_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
        if file_path:
            try:
                self.status_label.config(text="Status: Importing PCAP...")
                self.export_packets_data = []
                self.packet_list_text.configure(state='normal')
                self.packet_list_text.delete(1.0, tk.END)
                self.packet_list_text.configure(state='disabled')

                self.packet_count = 0
                self.total_bytes = 0
                self.protocol_stats = {k: 0 for k in self.protocol_stats}

                packets = rdpcap(file_path)
                for i, packet in enumerate(packets):

                    features = self._extract_ml_features(packet)
                    pkt_summary = packet.summary()

                    prediction_label = "Normal"
                    prediction_confidence = 0.0
                    if self.model and ML_LIBRARIES_AVAILABLE:
                        try:
                            features_reshaped = features.reshape(1, -1)
                            d_matrix = xgb.DMatrix(features_reshaped)
                            prediction_prob = self.model.predict(d_matrix)
                            prediction_confidence = float(prediction_prob)
                            if prediction_prob > 0.5:
                                prediction_label = "Attack"
                            else:
                                prediction_label = "Normal"
                        except Exception as e:
                            prediction_label = f"ML Error: {e}"
                            print(f"Error during ML prediction for imported packet: {e}")
                    else:
                        prediction_label = "N/A"

                    pkt_info = {
                        "raw_hex": bytes(packet).hex(),
                        "timestamp": time.time(),
                        "summary": pkt_summary,
                        "features": features.tolist(),
                        "ml_prediction": prediction_label,
                        "ml_confidence": prediction_confidence
                    }

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

                    if i % 50 == 0:
                        self.master.after(0, self.packet_list_text.configure, state='normal')
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
                self.master.after(0, self.update_stats_display)
                self.status_label.config(text=f"Status: Imported {len(packets)} packets from {file_path}")
                messagebox.showinfo("Import Success", f"Successfully imported {len(packets)} packets from {file_path}")

            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import PCAP: {e}")
                self.status_label.config(text="Status: Import failed.")

    def _extract_ml_features(self, packet):
        """
        Extracts numerical features from a Scapy packet.
        This function remains largely the same as the previous version.
        """
        features = np.zeros(69, dtype=np.float32)
        features[0] = len(packet) / 1500.0

        proto_offset = 1
        if packet.haslayer(TCP):
            features[proto_offset] = 1
        elif packet.haslayer(UDP):
            features[proto_offset + 1] = 1
        elif packet.haslayer(ICMP):
            features[proto_offset + 2] = 1
        elif packet.haslayer(ARP):
            features[proto_offset + 3] = 1
        elif packet.haslayer(IP):
            features[proto_offset + 4] = 1

        ip_offset = 6
        if packet.haslayer(IP):
            features[ip_offset] = int(str(packet[IP].src).replace('.', '')) % 100000 / 100000.0
            features[ip_offset + 1] = int(str(packet[IP].dst).replace('.', '')) % 100000 / 100000.0

        port_offset = 8
        if packet.haslayer(TCP):
            features[port_offset] = packet[TCP].sport / 65535.0
            features[port_offset + 1] = packet[TCP].dport / 65535.0
        elif packet.haslayer(UDP):
            features[port_offset] = packet[UDP].sport / 65535.0
            features[port_offset + 1] = packet[UDP].dport / 65535.0

        tcp_flags_offset = 10
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'S' in flags: features[tcp_flags_offset] = 1  # SYN
            if 'A' in flags: features[tcp_flags_offset + 1] = 1  # ACK
            if 'F' in flags: features[tcp_flags_offset + 2] = 1  # FIN
            if 'R' in flags: features[tcp_flags_offset + 3] = 1  # RST
            if 'P' in flags: features[tcp_flags_offset + 4] = 1  # PSH
            if 'U' in flags: features[tcp_flags_offset + 5] = 1  # URG

        icmp_offset = 16
        if packet.haslayer(ICMP):
            features[icmp_offset] = packet[ICMP].type / 255.0
            features[icmp_offset + 1] = packet[ICMP].code / 255.0

        arp_offset = 18
        if packet.haslayer(ARP):
            features[arp_offset] = packet[ARP].op / 2.0

        payload_offset = 19
        if packet.haslayer(Raw):
            payload_bytes = packet[Raw].load
            for i, byte in enumerate(payload_bytes[:50]):
                features[payload_offset + i] = byte / 255.0

        return features

def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
