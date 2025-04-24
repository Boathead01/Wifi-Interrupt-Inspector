import pyshark
import socket
import numpy as np
import pandas as pd
from collections import defaultdict
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest
from sklearn.naive_bayes import GaussianNB
import signal
import sys

# === Settings ===
INTERFACE = r'\Device\NPF_{B7019BE0-0FD4-46A8-9D11-47280D6240EC}'
MAX_PACKETS = 500
DIST_THRESHOLD = 1_000_000
K = 3

# === Helper Functions ===

def ip_to_int(ip):
    try:
        return int.from_bytes(socket.inet_aton(ip), 'big')
    except socket.error:
        return None

def load_authorized_ips(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# === Load and Train IP KNN Model ===
authorized_ips = load_authorized_ips("authorized ips.txt")
authorized_ip_ints = np.array([[ip_to_int(ip)] for ip in authorized_ips if ip_to_int(ip) is not None])
knn = NearestNeighbors(n_neighbors=K)
knn.fit(authorized_ip_ints)
print("[+] IP Model trained. Monitoring live traffic...\n")

# === FTP Tracking Data ===
attempts = defaultdict(int)
records = []

# === Signal Handler for Graceful Exit ===
def signal_handler(sig, frame):
    print("\n[!] Capture interrupted. Running analysis...\n")
    analyze()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# === Analysis Function ===
def analyze():
    if not records:
        print("[=] No FTP login attempts recorded.")
    else:
        df = pd.DataFrame(records)
        df['attempts'] = df['src_ip'].map(attempts)

        print("\n[*] IPs with more than 3 FTP login attempts:")
        flagged = False
        for ip, count in attempts.items():
            if count > 3:
                print(f"  {ip} -> {count} attempts")
                flagged = True
        if not flagged:
            print("  None. (No brute-force-like behavior)")

        # === Isolation Forest ===
        print("\n[*] Isolation Forest Anomaly Detection:")
        features = df[['dst_port', 'flags', 'attempts']]
        iso = IsolationForest(contamination=0.1, random_state=42)
        df['anomaly'] = iso.fit_predict(features)
        anomalies = df[df['anomaly'] == -1]
        if anomalies.empty:
            print("  No anomalies detected.")
        else:
            print("  Anomalies found:")
            print(anomalies[['src_ip', 'ftp_cmd', 'attempts']].drop_duplicates())

        # === Naive Bayes ===
        print("\n[*] Naive Bayes Classification:")
        df['label'] = df['attempts'].apply(lambda x: 1 if x > 3 else 0)
        nb = GaussianNB()
        nb.fit(features, df['label'])
        df['prediction'] = nb.predict(features)

        predicted = df[df['prediction'] == 1]
        if predicted.empty:
            print("  No suspicious activity predicted.")
        else:
            print("  Naive Bayes flagged:")
            print(predicted[['src_ip', 'ftp_cmd', 'attempts']].drop_duplicates())

# === Packet Processing Function ===
def process_packet(pkt):
    try:
        # === IP Anomaly Detection ===
        if 'IP' in pkt:
            dst_ip = pkt.ip.dst
            dst_ip_int = ip_to_int(dst_ip)
            if dst_ip_int is not None:
                distances, _ = knn.kneighbors([[dst_ip_int]])
                avg_distance = np.mean(distances)
                print(f"\n[IP Monitor] Destination IP: {dst_ip} | Avg Distance: {avg_distance:.2f}")

                if dst_ip in authorized_ips:
                    print("  Status: Authorized")
                else:
                    print("  Status: Unauthorized", end="")
                    if avg_distance > DIST_THRESHOLD:
                        print(" → Anomaly Detected!")
                    else:
                        print(" → Close to known IPs.")

        # === FTP Login Detection ===
        if 'FTP' in pkt and 'IP' in pkt and 'TCP' in pkt:
            ftp_cmd = pkt.ftp.request_command
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            dst_port = int(pkt.tcp.dstport)
            flags = int(pkt.tcp.flags, 16)

            if ftp_cmd in ['USER', 'PASS']:
                attempts[src_ip] += 1
                records.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'flags': flags,
                    'ftp_cmd': ftp_cmd
                })
                print(f"[FTP] {src_ip} → {ftp_cmd} (Attempts: {attempts[src_ip]})")

    except AttributeError:
        pass
    except Exception as e:
        print(f"Error processing packet: {e}")

# === Live Capture ===
print(f"[+] Starting live capture on interface: {INTERFACE}")
cap = pyshark.LiveCapture(interface=INTERFACE)

for i, pkt in enumerate(cap.sniff_continuously()):
    if i >= MAX_PACKETS:
        print(f"\n[!] Reached {MAX_PACKETS} packets. Stopping capture.")
        break
    process_packet(pkt)

# === Final Analysis ===
analyze()
