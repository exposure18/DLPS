import json
import numpy as np
from sklearn.model_selection import train_test_split
from scapy.all import Ether, IP, TCP, UDP, Raw, ARP, ICMP # Import Scapy layers needed to rebuild packets

# IMPORTANT: Import your PacketSnifferApp class from simple_gui_sniffer.py
# Make sure simple_gui_sniffer.py is in the same directory!
from simple_gui_sniffer import PacketSnifferApp

# --- Initialize a dummy PacketSnifferApp instance to access _extract_dl_features ---
# We don't need the GUI to pop up, so we can use a temporary Tkinter root
# or just mock the dependencies if we only need the method.
# For simplicity, let's create a minimal mock or instance for now.
# A more robust way might be to make _extract_dl_features a static method
# or a standalone function, but for now, this works.

# We'll create a dummy Tkinter root for the PacketSnifferApp initialization
# It won't be displayed because we won't call root.mainloop()
import tkinter as tk
dummy_root = tk.Tk()
# Withdraw the window so it doesn't appear
dummy_root.withdraw()
# Create an instance of the app to access the feature extraction method
sniffer_app_instance = PacketSnifferApp(dummy_root)

# --- Function to load JSON and extract features ---
def load_and_extract_features(file_path, label, app_instance):
    print(f"Loading and extracting features from: {file_path}")
    all_features = []
    all_labels = []

    try:
        with open(file_path, 'r') as f:
            packets_data = json.load(f)

        for i, pkt_info in enumerate(packets_data):
            # Reconstruct Scapy packet from raw_hex.
            # This is necessary because _extract_dl_features expects a Scapy packet object.
            try:
                # pkt_info['raw_hex'] contains the full packet bytes in hex string format
                raw_bytes = bytes.fromhex(pkt_info['raw_hex'])
                # Ether() is used as a base layer for raw bytes to be parsed into layers
                packet = Ether(raw_bytes)

                features = app_instance._extract_dl_features(packet)
                if features.shape[0] != 69: # Verify the feature count (as confirmed in Step 1 output)
                    print(f"Warning: Packet {i} from {file_path} has {features.shape[0]} features, expected 69. Skipping.")
                    continue
                all_features.append(features)
                all_labels.append(label)
            except Exception as e:
                print(f"Error processing packet {i} from {file_path}: {e}")
                # Optionally, you can log the packet info that caused the error for debugging
                # print(f"Problematic packet info: {pkt_info}")
                continue # Skip this packet and continue with the next

        print(f"Successfully extracted {len(all_features)} features from {file_path}")
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {file_path}. Is it a valid JSON file?")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    return np.array(all_features), np.array(all_labels)

# --- Main Data Preparation Logic ---
if __name__ == "__main__":
    normal_file = 'normal_traffic_large.json'
    attack_file = 'attack_traffic_large.json'

    # Load and extract features for normal traffic (label = 0)
    X_normal, y_normal = load_and_extract_features(normal_file, 0, sniffer_app_instance)

    # Load and extract features for attack traffic (label = 1)
    X_attack, y_attack = load_and_extract_features(attack_file, 1, sniffer_app_instance)

    # Combine normal and attack data
    if X_normal.size == 0 and X_attack.size == 0:
        print("No data extracted from either file. Cannot proceed.")
        dummy_root.destroy() # Clean up dummy Tkinter root
        exit()

    # Handle cases where one array might be empty due to issues
    if X_normal.size == 0:
        X = X_attack
        y = y_attack
    elif X_attack.size == 0:
        X = X_normal
        y = y_normal
    else:
        X = np.vstack((X_normal, X_attack))
        y = np.concatenate((y_normal, y_attack))

    print(f"\nTotal collected samples: {X.shape[0]}")
    print(f"Total features per sample: {X.shape[1]}")
    print(f"Total labels: {y.shape[0]}")

    # Shuffle and split data into training and testing sets
    # Using a fixed random_state for reproducibility
    # Ensure there's enough data for splitting, especially with stratify
    if X.shape[0] >= 2 and len(np.unique(y)) > 1: # Need at least 2 samples and both classes for stratify
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        print(f"\nTraining set size (X_train): {X_train.shape}")
        print(f"Testing set size (X_test): {X_test.shape}")
        print(f"Training labels size (y_train): {y_train.shape}")
        print(f"Testing labels size (y_test): {y_test.shape}")
    elif X.shape[0] > 0: # If only one class or not enough samples for 20% test
        print("\nWarning: Not enough diverse data for stratified train/test split. Using all data as training set.")
        X_train, y_train = X, y
        X_test, y_test = np.array([]).reshape(0, num_features), np.array([]) # Empty test sets
        print(f"Training set size (X_train): {X_train.shape}")
        print(f"Testing set size (X_test): {X_test.shape}") # Will show (0, 69) if features were determined
    else:
        print("No data to split. X is empty.")
        dummy_root.destroy()
        exit()


    # Save the processed data
    try:
        np.save('X_train.npy', X_train)
        np.save('X_test.npy', X_test)
        np.save('y_train.npy', y_train)
        np.save('y_test.npy', y_test)
        print("\nSuccessfully saved X_train.npy, X_test.npy, y_train.npy, y_test.npy")
    except Exception as e:
        print(f"Error saving processed data: {e}")

    dummy_root.destroy() # Clean up dummy Tkinter root after all operations