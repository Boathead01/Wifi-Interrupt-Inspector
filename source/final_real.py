import numpy as np
import subprocess
import sys
import pyshark
import socket
import pandas as pd
from collections import defaultdict
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest
from sklearn.naive_bayes import GaussianNB
import signal
import time

# === SETTINGS for IQ Capture ===
filename = "samples.bin"
sample_rate = 10_000_000
center_freq = 100_000_000
num_samples = 1000 * 2
jam_threshold_db = -60

# === SETTINGS for Live Capture ===
INTERFACE = 'wlan0'
IP_MONITOR_DURATION = 60  # 1 minute
MAX_PACKETS = 1000
DIST_THRESHOLD = 1_000_000
K = 3

# === Jamming Detection ===
def detect_jamming():
    print("🎧 Capturing 1000 samples from HackRF...")
    subprocess.run([
        "hackrf_transfer",
        "-r", filename,
        "-s", str(sample_rate),
        "-f", str(center_freq),
        "-n", str(num_samples)
    ], check=True)
    print("Capture complete.")

    raw = np.fromfile(filename, dtype=np.uint8)
    i_samples = raw[::2] - 127
    q_samples = raw[1::2] - 127
    iq = i_samples + 1j * q_samples
    amplitude = np.abs(iq)
    amp_threshold = np.percentile(amplitude, 95)
    jammed_ratio = np.mean(amplitude > amp_threshold)

    print(f"Amplitude Threshold: {amp_threshold:.2f}")
    print(f"Jammed Sample Ratio: {jammed_ratio:.4f}")

    fft_data = np.fft.fftshift(np.fft.fft(iq))
    fft_power = 20 * np.log10(np.abs(fft_data) + 1e-6)
    freqs = np.fft.fftshift(np.fft.fftfreq(len(iq), d=1/sample_rate)) + center_freq
    above_24ghz = freqs > 2_400_000_000
    jammed_above_24ghz = np.any(fft_power[above_24ghz] > jam_threshold_db)

    if jammed_ratio > 0.05 or jammed_above_24ghz:
        print("Jamming detected. Halting execution.")
        return True
    else:
        print("No jamming detected. Proceeding...")
        return False

# === IP & FTP Brute-force Monitoring ===
attempts = defaultdict(int)
records = []

def ip_to_int(ip):
    try:
        return int.from_bytes(socket.inet_aton(ip), 'big')
    except socket.error:
        return None

def load_authorized_ips(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

authorized_ips = load_authorized_ips("authorized ips.txt")
authorized_ip_ints = np.array([[ip_to_int(ip)] for ip in authorized_ips if ip_to_int(ip) is not None])
knn = NearestNeighbors(n_neighbors=K)
knn.fit(authorized_ip_ints)
print("[+] Authorized IP model trained.\n")

def analyze():
    if not records:
        print("[=] No FTP login attempts recorded.")
        return
    df = pd.DataFrame(records)
    df['attempts'] = df['src_ip'].map(attempts)

    print("\n[*] IPs with more than 3 FTP login attempts:")
    flagged = False
    for ip, count in attempts.items():
        if count > 3:
            print(f"  {ip} -> {count} attempts")
            flagged = True
    if not flagged:
        print("  None.")

    print("\n Isolation Forest Anomaly Detection:")
    features = df[['dst_port', 'flags', 'attempts']]
    iso = IsolationForest(contamination=0.1, random_state=42)
    df['anomaly'] = iso.fit_predict(features)
    anomalies = df[df['anomaly'] == -1]
    if anomalies.empty:
        print("  No anomalies detected.")
    else:
        print("  Anomalies found:")
        print(anomalies[['src_ip', 'ftp_cmd', 'attempts']].drop_duplicates())

    print("\nNaive Bayes Classification:")
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

def signal_handler(sig, frame):
    print("\n Interrupted. Running final analysis...\n")
    analyze()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


if detect_jamming():
    sys.exit(0)


print(f"\n Starting IP monitoring for {IP_MONITOR_DURATION} seconds...\n")
cap = pyshark.LiveCapture(interface='eth0')
start_time = time.time()

for pkt in cap.sniff_continuously():
    if time.time() - start_time > IP_MONITOR_DURATION:
        print("\nIP monitoring done. Starting FTP brute-force monitoring...\n")
        break
    try:
        if 'IP' in pkt:
            dst_ip = pkt.ip.dst
            dst_ip_int = ip_to_int(dst_ip)
            if dst_ip_int is not None:
                distances, _ = knn.kneighbors([[dst_ip_int]])
                avg_distance = np.mean(distances)
                print(f"[IP Monitor] IP: {dst_ip} | Distance: {avg_distance:.2f} | {'Authorized' if dst_ip in authorized_ips else 'Suspicious'}")
    except Exception as e:
        continue


for i, pkt in enumerate(cap.sniff_continuously()):
    if i >= MAX_PACKETS:
        print(f"\n Reached {MAX_PACKETS} packets. Stopping brute-force analysis.")
        break
    try:
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
    except Exception as e:
        print(f"Error processing packet: {e}")

analyze()
