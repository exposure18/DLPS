import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw, wrpcap, rdpcap, get_if_list
import time
import json
import numpy as np
import tensorflow as tf  # Added for Deep Learning model integration


class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Python Packet Sniffer")
        master.geometry("310x470")  # Adjusted geometry for 320x480 LCD - keeping 310x470 for margin
        master.configure(bg="#000000")  # Dark background

        # --- Configure the main window's grid for two columns ---
        self.master.grid_columnconfigure(0, weight=0)  # Left panel (controls/stats) fixed width
        self.master.grid_columnconfigure(1, weight=1)  # Right panel (packets) expands

        self.master.grid_rowconfigure(0, weight=1)  # Main content area expands vertically
        self.master.grid_rowconfigure(1, weight=0)  # Status bar fixed height

        # --- Sniffer State ---
        self.sniffing = False
        self.packets = []  # Used for raw Scapy packets for export
        self.export_packets_data = []  # Used for structured data for JSON export (includes DL features)
        self.packet_display_buffer = []  # Buffer for live packet display
        self.display_update_interval_ms = 1000  # Update display every 1 second
        self.after_id = None
        self.sniffer_thread = None
        self.stop_sniffer_event = threading.Event()

        # --- Filters ---
        self.src_ip_filter = tk.StringVar(value="")
        self.dst_ip_filter = tk.StringVar(value="")
        self.protocol_filter = tk.StringVar(value="")
        self.alert_keyword_var = tk.StringVar(
            value="sensitive")  # Added from previous, but unused in this version for specific alerts

        # --- Protocol Statistics Counters ---
        self.stats_total_packets = 0
        self.stats_total_bytes = 0
        self.protocol_stats = {
            "Ethernet": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0
        }
        self.protocol_bytes_stats = {
            "Ethernet": 0, "IP": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0
        }

        # --- Deep Learning Model Loading ---
        self.model = None
        self.current_dl_prediction = tk.StringVar(value="Loading Model...")  # Variable to display DL prediction

        self.create_widgets()

        # Load model in a separate thread to prevent GUI freeze
        threading.Thread(target=self._load_dl_model, daemon=True).start()

        self.update_interface_list()

    def _load_dl_model(self):
        try:
            self.model = tf.keras.models.load_model('network_ids_model.h5')
            self.master.after(0, lambda: self.status_label.config(text="Status: Model loaded successfully. Ready."))
            self.master.after(0, lambda: self.current_dl_prediction.set("Model Ready."))
            print("Deep Learning model 'network_ids_model.h5' loaded.")
        except Exception as e:
            self.master.after(0, lambda: self.status_label.config(
                text=f"Status: Error loading model: {e}. Running without DL detection."))
            self.master.after(0, lambda: self.current_dl_prediction.set("DL Error!"))
            print(f"Error loading Deep Learning model: {e}. DL detection will be disabled.")
            self.master.after(0, lambda: messagebox.showwarning("Model Load Error",
                                                                f"Could not load network_ids_model.h5: {e}\nDL detection will be disabled."))

    def create_widgets(self):
        # --- Styling ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#1a1a1a")
        # Even more aggressive font reduction
        style.configure("TLabel", background="#1a1a1a", foreground="#ffffff", font=('Arial', 6))
        style.configure("TButton", background="#333333", foreground="#ffffff", font=('Arial', 7, 'bold'))
        style.map("TButton", background=[('active', '#555555')], foreground=[('active', '#ffffff')])
        style.configure("TCombobox", fieldbackground="#222222", background="#222222", foreground="#ffffff")
        style.map("TCombobox",
                  fieldbackground=[('readonly', '#222222')],
                  selectbackground=[('readonly', '#222222')],
                  selectforeground=[('readonly', '#ffffff')],
                  background=[('readonly', '#222222')],
                  foreground=[('readonly', '#ffffff')])
        self.master.option_add('*TEntry.fieldbackground', '#222222')
        self.master.option_add('*TEntry.foreground', '#ffffff')

        # FIX: Configure the font for TLabelframe.Label directly
        style.configure("TLabelframe.Label", font=('Arial', 7, 'bold'))

        # --- Left Panel Frame (Column 0, Row 0 of master) ---
        left_panel_frame = ttk.Frame(self.master, padding="1", style="TFrame", width=150)
        left_panel_frame.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)
        left_panel_frame.grid_propagate(False)  # Prevent frame from resizing to its contents

        left_panel_frame.grid_columnconfigure(0, weight=1)
        left_panel_frame.grid_rowconfigure(4, weight=1)  # Row 4 (stats/alerts) takes remaining vertical space

        # --- DL Prediction Display (TOP of left panel) ---
        self.dl_prediction_label = ttk.Label(left_panel_frame, textvariable=self.current_dl_prediction,
                                             font=('Arial', 10, 'bold'), anchor='center',
                                             background="#1a1a1a", foreground="#00FF00")  # Default green for 'Normal'
        self.dl_prediction_label.grid(row=0, column=0, sticky="ew", padx=1, pady=2)

        # --- Controls Frame (inside left_panel_frame) ---
        control_frame = ttk.Frame(left_panel_frame, padding="1", relief="groove", borderwidth=1, style="TFrame")
        control_frame.grid(row=1, column=0, sticky="ew", padx=1, pady=1)
        control_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(control_frame, text="Interface:", style="TLabel").grid(row=0, column=0, padx=1, pady=0, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_combobox = ttk.Combobox(control_frame, textvariable=self.interface_var, state="readonly",
                                               font=('Arial', 6))
        self.interface_combobox.grid(row=0, column=1, padx=1, pady=0, sticky="ew")

        # Buttons (Stacked vertically)
        self.start_button = ttk.Button(control_frame, text="Start", command=self.start_sniffing, style="TButton")
        self.start_button.grid(row=1, column=0, columnspan=2, padx=1, pady=0, sticky="ew")
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED,
                                      style="TButton")
        self.stop_button.grid(row=2, column=0, columnspan=2, padx=1, pady=0, sticky="ew")

        self.export_button = ttk.Button(control_frame, text="Export", command=self.export_packets, state=tk.DISABLED,
                                        style="TButton")
        self.export_button.grid(row=3, column=0, columnspan=2, padx=1, pady=0, sticky="ew")
        self.import_button = ttk.Button(control_frame, text="Import", command=self.import_pcap_packets, style="TButton")
        self.import_button.grid(row=4, column=0, columnspan=2, padx=1, pady=0, sticky="ew")

        # --- Filter Inputs (inside left_panel_frame) ---
        filter_frame = ttk.LabelFrame(left_panel_frame, text="Filters", padding="1", style="TFrame")
        filter_frame.grid(row=2, column=0, padx=1, pady=1, sticky="ew")
        filter_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(filter_frame, text="Src IP:", style="TLabel").grid(row=0, column=0, padx=1, pady=0, sticky="w")
        self.src_ip_entry = ttk.Entry(filter_frame, textvariable=self.src_ip_filter, font=('Arial', 6))
        self.src_ip_entry.grid(row=0, column=1, padx=1, pady=0, sticky="ew")

        ttk.Label(filter_frame, text="Dst IP:", style="TLabel").grid(row=1, column=0, padx=1, pady=0, sticky="w")
        self.dst_ip_entry = ttk.Entry(filter_frame, textvariable=self.dst_ip_filter, font=('Arial', 6))
        self.dst_ip_entry.grid(row=1, column=1, padx=1, pady=0, sticky="ew")

        ttk.Label(filter_frame, text="Proto:", style="TLabel").grid(row=2, column=0, padx=1, pady=0, sticky="w")
        self.protocol_combobox = ttk.Combobox(filter_frame, textvariable=self.protocol_filter, state="readonly",
                                              values=["", "IP", "TCP", "UDP", "ICMP", "ARP", "Ether"],
                                              font=('Arial', 6))
        self.protocol_combobox.grid(row=2, column=1, padx=1, pady=0, sticky="ew")
        self.protocol_combobox.set("")

        # Alert Keyword (kept for completeness, though not visually prominent in this compact layout)
        ttk.Label(filter_frame, text="Alert Kw:", style="TLabel").grid(row=3, column=0, padx=1, pady=0, sticky="w")
        ttk.Entry(filter_frame, textvariable=self.alert_keyword_var, font=('Arial', 6)).grid(row=3, column=1, padx=1,
                                                                                             pady=0, sticky="ew")

        # --- Protocol Statistics Display (inside left_panel_frame) ---
        stats_frame = ttk.LabelFrame(left_panel_frame, text="Stats", padding="1", relief="groove", borderwidth=1,
                                     style="TFrame")
        stats_frame.grid(row=3, column=0, sticky="nsew", padx=1,
                         pady=1)  # Changed row to 3 to accommodate DL label and filters
        stats_frame.grid_columnconfigure(1, weight=1)

        self.stats_labels = {}
        row_idx = 0
        # Included Total here now for a more consistent layout
        for protocol in ['Total', 'IP', 'TCP', 'UDP', 'ICMP', 'ARP']:
            ttk.Label(stats_frame, text=f"{protocol}:", style="TLabel").grid(row=row_idx, column=0, padx=1, pady=0,
                                                                             sticky="w")
            self.stats_labels[f'{protocol}_summary'] = ttk.Label(stats_frame, text="0 Pkts / 0 Bytes", style="TLabel",
                                                                 font=('Arial', 6, 'bold'), foreground="#e0e0e0")
            self.stats_labels[f'{protocol}_summary'].grid(row=row_idx, column=1, padx=1, pady=0, sticky="w")
            row_idx += 1

        # --- Captured Packets Display Area (Column 1, Row 0 of master grid) ---
        packet_frame = ttk.Frame(self.master, padding="2", relief="groove", borderwidth=1, style="TFrame")
        packet_frame.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)

        ttk.Label(packet_frame, text="Packets:", font=('Arial', 8, 'bold'), foreground="#63b3ed",
                  background="#1a1a1a").pack(side=tk.TOP, fill=tk.X, pady=1)

        self.packet_text = scrolledtext.ScrolledText(packet_frame, wrap=tk.WORD, bg="#000000", fg="#e2e8f0",
                                                     font=('Consolas', 5), relief="flat")
        self.packet_text.pack(fill=tk.BOTH, expand=True)
        self.packet_text.config(state=tk.DISABLED)

        # --- Status Bar (Row 1 of master grid, spans both columns) ---
        self.status_label = ttk.Label(self.master, text="Status: Ready", style="TLabel", anchor="w", font=('Arial', 7))
        self.status_label.grid(row=1, column=0, columnspan=2, sticky="ew", padx=2, pady=1)

        # --- Color Tag Configuration ---
        self.packet_text.tag_config('tcp', foreground="#FFD700")  # Gold
        self.packet_text.tag_config('udp', foreground="#87CEEB")  # SkyBlue
        self.packet_text.tag_config('icmp', foreground="#FF6347")  # Tomato
        self.packet_text.tag_config('arp', foreground="#DA70D6")  # Orchid
        self.packet_text.tag_config('ether', foreground="#C0C0C0")  # Silver (for pure Ethernet)
        self.packet_text.tag_config('ip', foreground="#98FB98")  # PaleGreen (for general IP)
        self.packet_text.tag_config('normal_dl', foreground="#00FF00", font=('Consolas', 5, 'bold'))  # Green for Normal
        self.packet_text.tag_config('attack_dl', foreground="#FF0000", font=('Consolas', 5, 'bold'))  # Red for Attack
        self.packet_text.tag_config('alert', foreground="#FF0000",
                                    background="#330000")  # Red for alerts, dark red background

    def get_interfaces(self):
        try:
            return get_if_list()
        except Exception:
            return ["eth0", "wlan0", "lo"]  # Fallback

    def update_interface_list(self):
        try:
            interfaces = self.get_interfaces()
            self.interface_combobox['values'] = interfaces
            if interfaces:
                self.interface_var.set(interfaces[0])
            else:
                self.interface_var.set("No interfaces found")
        except Exception as e:
            messagebox.showerror("Error",
                                 f"Could not list interfaces: {e}\nEnsure Npcap/WinPcap is installed on Windows, or run with sudo on Linux.")
            self.interface_combobox['values'] = ["Error loading interfaces"]
            self.interface_var.set("Error loading interfaces")

    def start_sniffing(self):
        interface = self.interface_var.get()
        if not interface or interface == "Error loading interfaces" or interface == "No interfaces found":
            messagebox.showwarning("Warning", "Please select a valid network interface.")
            return

        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.status_label.config(text="Status: Sniffer already running.")
            return

        self.stop_sniffer_event.clear()
        self.packets = []  # Clear raw Scapy packets
        self.export_packets_data = []  # Clear structured export data
        self._clear_display_and_buffers()  # Clears packet_display_buffer and stats
        self.sniffing = True  # Indicate live sniffing is active

        self._set_ui_sniffing_state(True)
        self.status_label.config(text=f"Status: Starting sniffer on {interface}...")

        current_filters = {
            'src_ip': self.src_ip_filter.get().strip(),
            'dst_ip': self.dst_ip_filter.get().strip(),
            'protocol': self.protocol_filter.get().strip()
        }

        self.sniffer_thread = threading.Thread(target=self._run_sniffer, args=(interface, current_filters))
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        self._schedule_display_update()  # Start periodic updates

    def _run_sniffer(self, interface, filters):
        bpf_parts = []
        protocol_filter_val = filters['protocol'].lower()

        if protocol_filter_val:
            proto_map = {'tcp': 'tcp', 'udp': 'udp', 'icmp': 'icmp', 'arp': 'arp', 'ip': 'ip', 'ether': 'ether'}
            if protocol_filter_val in proto_map:
                bpf_parts.append(proto_map[protocol_filter_val])
            else:
                self.master.after(0, lambda: messagebox.showwarning("Filter Warning",
                                                                    f"Unsupported protocol filter: '{filters['protocol']}'. Ignoring protocol filter."))

        if filters['src_ip']:
            if 'ip' not in bpf_parts and 'ether' not in bpf_parts:
                bpf_parts.append('ip')
            bpf_parts.append(f"src host {filters['src_ip']}")

        if filters['dst_ip']:
            if 'ip' not in bpf_parts and 'ether' not in bpf_parts:
                bpf_parts.append('ip')
            bpf_parts.append(f"dst host {filters['dst_ip']}")

        bpf_filter_string = " and ".join(bpf_parts) if bpf_parts else None

        self.master.after(0, lambda: self.status_label.config(
            text=f"Status: Sniffing on {interface} with filter: '{bpf_filter_string if bpf_filter_string else 'None'}'"))

        try:
            sniff(prn=self._process_packet, store=False, iface=interface,
                  stop_filter=lambda p: self.stop_sniffer_event.is_set(),
                  filter=bpf_filter_string, timeout=None)
        except Exception as e:
            error_msg = (f"An error occurred during sniffing: {e}\n\n"
                         "Possible causes:\n"
                         "1. Incorrect interface name.\n"
                         "2. Insufficient permissions (try running script with Administrator/sudo).\n"
                         "3. Npcap/WinPcap not installed (on Windows).\n"
                         f"4. Invalid BPF filter used: '{bpf_filter_string if bpf_filter_string else 'None'}'")
            self.master.after(0, lambda: messagebox.showerror("Sniffing Error", error_msg))
            self.master.after(0, lambda: self.status_label.config(text=f"Status: Error: {e}"))
        finally:
            self.master.after(0, self._reset_ui_after_stop)

    def stop_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.status_label.config(text="Status: Stopping sniffer...")
            self.stop_sniffer_event.set()
            # Give a moment for the thread to stop naturally
            self.master.after(100, self._check_thread_stopped_and_reset_ui)
        else:
            self._reset_ui_after_stop()  # Just reset UI if thread wasn't running

    def _check_thread_stopped_and_reset_ui(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            # Still alive, try again or just force UI reset after a timeout
            self.master.after(500, self._check_thread_stopped_and_reset_ui)
        else:
            self._reset_ui_after_stop()

    def _reset_ui_after_stop(self):
        if self.after_id:
            self.master.after_cancel(self.after_id)
            self.after_id = None

        self._update_display_periodically()  # Ensure any buffered items and stats are shown

        self.sniffing = False  # Update sniffing state
        self._set_ui_sniffing_state(False)

        if not self.status_label.cget("text").startswith("Error:"):
            self.status_label.config(text="Status: Sniffer stopped.")

    def _set_ui_sniffing_state(self, is_sniffing):
        self.start_button.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if is_sniffing else tk.DISABLED)
        self.export_button.config(state=tk.NORMAL if self.packets else tk.DISABLED)  # Enable export if packets exist
        self.import_button.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.interface_combobox.config(state=tk.DISABLED if is_sniffing else "readonly")
        self.src_ip_entry.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.dst_ip_entry.config(state=tk.DISABLED if is_sniffing else tk.NORMAL)
        self.protocol_combobox.config(state=tk.DISABLED if is_sniffing else "readonly")

    def _clear_display_and_buffers(self):
        self.packet_text.config(state=tk.NORMAL)
        self.packet_text.delete(1.0, tk.END)
        self.packet_text.config(state=tk.DISABLED)

        self.packet_display_buffer = []
        self.packets = []  # Clear raw Scapy packets
        self.export_packets_data = []  # Clear structured data for JSON export

        # Reset statistics counters
        self.stats_total_packets = 0
        self.stats_total_bytes = 0
        for proto in self.protocol_stats:  # Use the dict keys for consistency
            self.protocol_stats[proto] = 0
            self.protocol_bytes_stats[proto] = 0
        self._update_protocol_stats_display()

    def _schedule_display_update(self):
        if self.sniffing or self.packet_display_buffer:  # Only schedule if sniffing or there's still a buffer to display
            self.after_id = self.master.after(self.display_update_interval_ms, self._update_display_periodically)

    def _update_display_periodically(self):
        if self.packet_display_buffer:
            self.packet_text.config(state=tk.NORMAL)
            for line_text, line_tags in self.packet_display_buffer:
                self.packet_text.insert(tk.END, line_text, tuple(line_tags))
            self.packet_text.see(tk.END)
            self.packet_text.config(state=tk.DISABLED)
            self.packet_display_buffer = []

        self._update_protocol_stats_display()

        if self.sniffing:  # Continue scheduling only if sniffing is active
            self._schedule_display_update()

    def _bytes_to_human_readable(self, num_bytes):
        for unit in ['Bytes', 'KB', 'MB', 'GB']:
            if num_bytes < 1024.0:
                return f"{num_bytes:.2f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.2f} TB"

    def _update_protocol_stats_display(self):
        self.stats_labels['Total_summary'].config(
            text=f"{self.stats_total_packets} Pkts / {self._bytes_to_human_readable(self.stats_total_bytes)}")

        for proto in ['IP', 'TCP', 'UDP', 'ICMP', 'ARP']:
            packets = self.protocol_stats.get(proto, 0)
            bytes_val = self.protocol_bytes_stats.get(proto, 0)
            self.stats_labels[f'{proto}_summary'].config(
                text=f"{packets} Pkts / {self._bytes_to_human_readable(bytes_val)}")

    def _process_packet(self, packet):
        if not self.sniffing:
            return

        self.packets.append(packet)  # Store raw Scapy packet for PCAP export

        self.stats_total_packets += 1
        packet_len = len(packet)
        self.stats_total_bytes += packet_len

        # Update protocol statistics counters
        self.protocol_stats["Ethernet"] += 1
        self.protocol_bytes_stats["Ethernet"] += packet_len

        protocol_tag = 'ether'  # Default to ether if no higher layer
        packet_info = {
            'timestamp': time.strftime('%H:%M:%S', time.localtime(packet.time)),
            'srcIp': 'N/A', 'dstIp': 'N/A', 'protocol': 'N/A',
            'srcPort': 'N/A', 'dstPort': 'N/A', 'summary': packet.summary(),
            'rawData': '',
            'raw_hex': bytes(packet).hex(),  # Store raw hex for JSON export
            'dl_prediction': "N/A",  # Default for DL
            'dl_confidence': 0.0  # Default for DL confidence
        }

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            packet_info['srcIp'] = ip_layer.src
            packet_info['dstIp'] = ip_layer.dst
            packet_info['protocol'] = ip_layer.proto
            protocol_tag = 'ip'
            self.protocol_stats['IP'] += 1
            self.protocol_bytes_stats['IP'] += packet_len

            if ip_layer.proto == 6:  # TCP
                packet_info['protocol'] = 'TCP'
                if packet.haslayer(TCP):
                    packet_info['srcPort'] = packet[TCP].sport
                    packet_info['dstPort'] = packet[TCP].dport
                protocol_tag = 'tcp'
                self.protocol_stats['TCP'] += 1
                self.protocol_bytes_stats['TCP'] += packet_len
            elif ip_layer.proto == 17:  # UDP
                packet_info['protocol'] = 'UDP'
                if packet.haslayer(UDP):
                    packet_info['srcPort'] = packet[UDP].sport
                    packet_info['dstPort'] = packet[UDP].dport
                protocol_tag = 'udp'
                self.protocol_stats['UDP'] += 1
                self.protocol_bytes_stats['UDP'] += packet_len
            elif ip_layer.proto == 1:  # ICMP
                packet_info['protocol'] = 'ICMP'
                protocol_tag = 'icmp'
                self.protocol_stats['ICMP'] += 1
                self.protocol_bytes_stats['ICMP'] += packet_len
            else:  # Other IP protocols
                self.protocol_stats['Other'] += 1
                self.protocol_bytes_stats['Other'] += packet_len
        elif packet.haslayer(ARP):
            packet_info['protocol'] = 'ARP'
            packet_info['srcIp'] = packet[ARP].psrc if packet[ARP].psrc else 'N/A'
            packet_info['dstIp'] = packet[ARP].pdst if packet[ARP].pdst else 'N/A'
            protocol_tag = 'arp'
            self.protocol_stats['ARP'] += 1
            self.protocol_bytes_stats['ARP'] += packet_len
        else:  # Non-IP, Non-ARP Ethernet traffic
            self.protocol_stats['Other'] += 1
            self.protocol_bytes_stats['Other'] += packet_len

        # Extract Raw data if present for alert keyword searching and JSON export
        if packet.haslayer(Raw):
            try:
                packet_info['rawData'] = packet[Raw].load.decode('utf-8', errors='ignore')
            except Exception:
                packet_info['rawData'] = packet[Raw].load.hex()  # Fallback to hex for binary data

        # --- Deep Learning Prediction ---
        prediction_label = "Normal"
        prediction_confidence = 0.0
        if self.model:  # Only predict if model was loaded successfully
            try:
                features = self._extract_dl_features(packet)
                features_reshaped = features.reshape(1, -1)
                prediction_prob = self.model.predict(features_reshaped, verbose=0)[0][0]
                prediction_confidence = float(prediction_prob)

                if prediction_prob > 0.5:
                    prediction_label = "Attack"
                else:
                    prediction_label = "Normal"
            except Exception as e:
                prediction_label = f"DL Err"  # Keep it short for display
                print(f"Error during DL prediction: {e}")

        packet_info['dl_prediction'] = prediction_label
        packet_info['dl_confidence'] = prediction_confidence
        self.export_packets_data.append(packet_info)  # Store for JSON export

        # Update the prominent DL prediction label
        self.master.after(0, lambda: self._update_dl_display(prediction_label, prediction_confidence))

        # --- Alerting System (basic keyword check) ---
        tags_for_line = [protocol_tag]  # Start with protocol tag
        current_alert_keyword = self.alert_keyword_var.get().strip().lower()
        if current_alert_keyword and current_alert_keyword in packet_info['rawData'].lower():
            tags_for_line.append('alert')  # Add alert tag for highlighting in main packet view

        # Add DL prediction tag for color in packet list
        if prediction_label == "Normal":
            tags_for_line.append('normal_dl')
        elif prediction_label == "Attack":
            tags_for_line.append('attack_dl')

        # --- Add Packet Info to Buffer for display ---
        # Make the line more concise for small screen, include DL prediction
        display_line = (
            f"[{packet_info['timestamp']}] "
            f"[{prediction_label}] "  # Added DL prediction here
            f"{packet_info['srcIp']}:"
            f"{packet_info['srcPort']}"
            f"->{packet_info['dstIp']}:"
            f"{packet_info['dstPort']}"
            f"({packet_info['protocol']})\n"  # Removed full summary to save space
        )
        self.packet_display_buffer.append((display_line, tags_for_line))

    def _update_dl_display(self, prediction_label, confidence):
        self.current_dl_prediction.set(f"DL: {prediction_label} ({confidence * 100:.1f}%)")
        if prediction_label == "Attack":
            self.dl_prediction_label.config(foreground="#FF0000")  # Red for attack
        elif prediction_label == "Normal":
            self.dl_prediction_label.config(foreground="#00FF00")  # Green for normal
        else:  # Error state etc.
            self.dl_prediction_label.config(foreground="#FFA500")  # Orange

    def export_packets(self):
        if not self.packets and not self.export_packets_data:
            messagebox.showinfo("Export", "No packets to export.")
            return

        # Offer choice between JSON and PCAP
        response = messagebox.askyesno("Export Option",
                                       "Do you want to export as a PCAP file? Click 'No' to export as JSON (includes DL features).")

        if response:  # Yes, export as PCAP
            defaultext = ".pcap"
            filetypes = [("PCAP files", "*.pcap"), ("PCAP Next Generation files", "*.pcapng"), ("All files", "*.*")]
            exporter = self._export_to_pcap
            data_to_export = self.packets  # Use raw Scapy packets for PCAP
        else:  # No, export as JSON
            defaultext = ".json"
            filetypes = [("JSON files", "*.json"), ("All files", "*.*")]
            exporter = self._export_to_json
            data_to_export = self.export_packets_data  # Use structured data for JSON

        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        initial_file_name = f"captured_packets_{timestamp_str}{defaultext}"

        file_path = filedialog.asksaveasfilename(
            defaultextension=defaultext,
            filetypes=filetypes,
            initialfile=initial_file_name,
            title="Save Captured Packets"
        )

        if file_path:
            exporter(file_path, data_to_export)
        else:
            self.status_label.config(text="Status: Export cancelled.")

    def _export_to_json(self, file_path, data):
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
            messagebox.showinfo("Export Successful", f"Exported {len(data)} packets to:\n{file_path}")
            self.status_label.config(text=f"Status: Exported {len(data)} packets to JSON.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export packets to JSON: {e}")
            self.status_label.config(text="Status: JSON Export failed.")

    def _export_to_pcap(self, file_path, data):
        try:
            wrpcap(file_path, data)  # 'data' here is self.packets (list of Scapy packets)
            messagebox.showinfo("Export Successful", f"Exported {len(data)} packets to:\n{file_path}")
            self.status_label.config(text=f"Status: Exported {len(data)} packets to PCAP.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export packets to PCAP: {e}")
            self.status_label.config(text="Status: PCAP Export failed.")

    def import_pcap_packets(self):
        if self.sniffing:
            messagebox.showwarning("Warning", "Please stop live sniffing before importing a PCAP file.")
            return

        file_path = filedialog.askopenfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
            title="Open PCAP File"
        )

        if file_path:
            self.status_label.config(text=f"Status: Loading packets from {file_path}...")
            self._clear_display_and_buffers()  # Clears current live data

            try:
                import_thread = threading.Thread(target=self._load_and_process_pcap_thread, args=(file_path,))
                import_thread.daemon = True
                import_thread.start()
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to read PCAP file: {e}")
                self.status_label.config(text="Status: PCAP Import failed.")
        else:
            self.status_label.config(text="Status: PCAP import cancelled.")

    def _load_and_process_pcap_thread(self, file_path):
        try:
            packets_from_pcap = rdpcap(file_path)
            num_packets = len(packets_from_pcap)
            self.master.after(0, lambda: self.status_label.config(
                text=f"Status: Processing {num_packets} packets from PCAP..."))

            # Reset stats and clear display for imported packets
            self.stats_total_packets = 0
            self.stats_total_bytes = 0
            self.protocol_stats = {k: 0 for k in self.protocol_stats}
            self.protocol_bytes_stats = {k: 0 for k in self.protocol_bytes_stats}
            self.packet_text.config(state=tk.NORMAL)
            self.packet_text.delete(1.0, tk.END)
            self.packet_text.config(state=tk.DISABLED)
            self.packets = []  # Clear raw packets for fresh import
            self.export_packets_data = []  # Clear structured data for fresh import

            for i, pkt in enumerate(packets_from_pcap):
                # Simulate packet processing like in _process_packet, but for imported
                self.packets.append(pkt)  # Store raw Scapy packet for PCAP re-export

                self.stats_total_packets += 1
                packet_len = len(pkt)
                self.stats_total_bytes += packet_len

                self.protocol_stats["Ethernet"] += 1
                self.protocol_bytes_stats["Ethernet"] += packet_len

                protocol_tag = 'ether'
                packet_info_for_export = {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.time)),
                    'summary': pkt.summary(),
                    'raw_hex': bytes(pkt).hex(),
                    'dl_prediction': "N/A",
                    'dl_confidence': 0.0
                }

                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    packet_info_for_export['srcIp'] = ip_layer.src
                    packet_info_for_export['dstIp'] = ip_layer.dst
                    packet_info_for_export['ip_protocol'] = ip_layer.proto
                    protocol_tag = 'ip'
                    self.protocol_stats['IP'] += 1
                    self.protocol_bytes_stats['IP'] += packet_len

                    if ip_layer.proto == 6:  # TCP
                        packet_info_for_export['protocol'] = 'TCP'
                        if pkt.haslayer(TCP):
                            packet_info_for_export['srcPort'] = pkt[TCP].sport
                            packet_info_for_export['dstPort'] = pkt[TCP].dport
                        protocol_tag = 'tcp'
                        self.protocol_stats['TCP'] += 1
                        self.protocol_bytes_stats['TCP'] += packet_len
                    elif ip_layer.proto == 17:  # UDP
                        packet_info_for_export['protocol'] = 'UDP'
                        if pkt.haslayer(UDP):
                            packet_info_for_export['srcPort'] = pkt[UDP].sport
                            packet_info_for_export['dstPort'] = pkt[UDP].dport
                        protocol_tag = 'udp'
                        self.protocol_stats['UDP'] += 1
                        self.protocol_bytes_stats['UDP'] += packet_len
                    elif ip_layer.proto == 1:  # ICMP
                        packet_info_for_export['protocol'] = 'ICMP'
                        protocol_tag = 'icmp'
                        self.protocol_stats['ICMP'] += 1
                        self.protocol_bytes_stats['ICMP'] += packet_len
                    else:
                        self.protocol_stats['Other'] += 1
                        self.protocol_bytes_stats['Other'] += packet_len
                elif pkt.haslayer(ARP):
                    packet_info_for_export['protocol'] = 'ARP'
                    packet_info_for_export['srcIp'] = pkt[ARP].psrc if pkt[ARP].psrc else 'N/A'
                    packet_info_for_export['dstIp'] = pkt[ARP].pdst if pkt[ARP].pdst else 'N/A'
                    protocol_tag = 'arp'
                    self.protocol_stats['ARP'] += 1
                    self.protocol_bytes_stats['ARP'] += packet_len
                else:
                    self.protocol_stats['Other'] += 1
                    self.protocol_bytes_stats['Other'] += packet_len

                if pkt.haslayer(Raw):
                    try:
                        packet_info_for_export['rawData'] = pkt[Raw].load.decode('utf-8', errors='ignore')
                    except Exception:
                        packet_info_for_export['rawData'] = pkt[Raw].load.hex()

                # DL Prediction for imported packets
                prediction_label = "N/A"  # Default if model not loaded
                prediction_confidence = 0.0
                if self.model:
                    try:
                        features = self._extract_dl_features(pkt)
                        features_reshaped = features.reshape(1, -1)
                        prediction_prob = self.model.predict(features_reshaped, verbose=0)[0][0]
                        prediction_confidence = float(prediction_prob)
                        if prediction_prob > 0.5:
                            prediction_label = "Attack"
                        else:
                            prediction_label = "Normal"
                    except Exception as e:
                        prediction_label = "DL Err"
                        print(f"Error during DL prediction for imported packet: {e}")

                packet_info_for_export['dl_prediction'] = prediction_label
                packet_info_for_export['dl_confidence'] = prediction_confidence
                self.export_packets_data.append(packet_info_for_export)

                tags_for_line = [protocol_tag]
                if prediction_label == "Normal":
                    tags_for_line.append('normal_dl')
                elif prediction_label == "Attack":
                    tags_for_line.append('attack_dl')

                display_line = (
                    f"[{time.strftime('%H:%M:%S', time.localtime(pkt.time))}] "
                    f"[{prediction_label}] "
                    f"{packet_info_for_export.get('srcIp', 'N/A')}:"
                    f"{packet_info_for_export.get('srcPort', 'N/A')}->"
                    f"{packet_info_for_export.get('dstIp', 'N/A')}:"
                    f"{packet_info_for_export.get('dstPort', 'N/A')}"
                    f"({packet_info_for_export.get('protocol', 'N/A')})\n"
                )
                self.packet_display_buffer.append((display_line, tags_for_line))

                if i % 50 == 0 or i == num_packets - 1:  # Update periodically or at the end
                    self.master.after(0, self._update_display_periodically)
                    self.master.after(0, lambda p=i + 1: self.status_label.config(
                        text=f"Status: Processed {p}/{num_packets} packets from PCAP..."))

            self.master.after(0, self._update_display_periodically)  # Final update
            self.master.after(0,
                              lambda: self.status_label.config(text=f"Status: Loaded {num_packets} packets from PCAP."))
            self.master.after(0, lambda: self.export_button.config(state=tk.NORMAL))
            self.master.after(0, lambda: messagebox.showinfo("Import Success",
                                                             f"Successfully imported {num_packets} packets from {file_path}"))

        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("Import Error", f"Error processing PCAP packets: {e}"))
            self.master.after(0, lambda: self.status_label.config(text="Status: PCAP Import failed during processing."))

    def _extract_dl_features(self, packet):
        """
        Extracts numerical features from a Scapy packet for deep learning.
        Produces a 69-element numpy array.

        Features:
        1. Packet Length (1 feature)
        2. Protocol Type (5 features: TCP, UDP, ICMP, ARP, Other IP) - One-hot encoded
        3. IP Addresses (2 features: Source IP, Destination IP) - Hashed/Scaled
        4. Port Numbers (2 features: Source Port, Destination Port) - Scaled
        5. TCP Flags (6 features: SYN, ACK, FIN, RST, PSH, URG, ECE, CWR) - Binary
        6. ICMP Type and Code (2 features)
        7. ARP Opcode (1 feature)
        8. Payload (50 features) - Hashed/Encoded first 50 bytes

        Total features: 1 + 5 + 2 + 2 + 8 + 2 + 1 + 50 = 71 (Corrected count for TCP flags)
        """
        features = np.zeros(71, dtype=np.float32)  # Adjusted size for 8 TCP flags

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
            try:
                features[ip_offset] = sum(int(x) for x in packet[IP].src.split('.')) / (255 * 4.0)  # Sum and normalize
                features[ip_offset + 1] = sum(int(x) for x in packet[IP].dst.split('.')) / (255 * 4.0)
            except ValueError:  # Handle cases like '0.0.0.0' or invalid IPs gracefully
                pass  # Features remain 0

        # 4. Port Numbers (Indices 8-9)
        port_offset = 8
        if packet.haslayer(TCP):
            features[port_offset] = packet[TCP].sport / 65535.0  # Normalize by max port
            features[port_offset + 1] = packet[TCP].dport / 65535.0
        elif packet.haslayer(UDP):
            features[port_offset] = packet[UDP].sport / 65535.0
            features[port_offset + 1] = packet[UDP].dport / 65535.0

        # 5. TCP Flags (Indices 10-17) - 8 flags: F S R P A U E C
        tcp_flags_offset = 10
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'F' in flags: features[tcp_flags_offset] = 1  # FIN
            if 'S' in flags: features[tcp_flags_offset + 1] = 1  # SYN
            if 'R' in flags: features[tcp_flags_offset + 2] = 1  # RST
            if 'P' in flags: features[tcp_flags_offset + 3] = 1  # PSH
            if 'A' in flags: features[tcp_flags_offset + 4] = 1  # ACK
            if 'U' in flags: features[tcp_flags_offset + 5] = 1  # URG
            # ECE and CWR are newer explicit congestion notification flags
            if 'E' in flags: features[tcp_flags_offset + 6] = 1  # ECE
            if 'C' in flags: features[tcp_flags_offset + 7] = 1  # CWR

        # 6. ICMP Type and Code (Indices 18-19)
        icmp_offset = 18
        if packet.haslayer(ICMP):
            features[icmp_offset] = packet[ICMP].type / 255.0  # Normalize type
            features[icmp_offset + 1] = packet[ICMP].code / 255.0  # Normalize code

        # 7. ARP Opcode (Index 20)
        arp_offset = 20
        if packet.haslayer(ARP):
            features[arp_offset] = packet[ARP].op / 10.0  # Normalize common opcodes (e.g., 1=request, 2=reply)

        # 8. Payload (Indices 21-70) - First 50 bytes
        payload_offset = 21
        if packet.haslayer(Raw):
            payload_bytes = bytes(packet[Raw].load)
            for i in range(min(len(payload_bytes), 50)):
                features[payload_offset + i] = payload_bytes[i] / 255.0  # Normalize byte value

        return features


# --- Main Application Entry Point ---
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()