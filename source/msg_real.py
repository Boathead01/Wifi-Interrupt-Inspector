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

# === SETTINGS for Multicast Sender ===
MULTICAST_GROUP = '224.0.0.1'
PORT = 5007

alert_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
alert_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

def send_alert(message):
    alert_sock.sendto(message.encode(), (MULTICAST_GROUP, PORT))
    print("Alert sent via multicast!")

# === Jamming Detection ===
def detect_jamming():
    print("Capturing 1000 samples from HackRF...")
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
        send_alert("ALERT: Jamming detected on the RF spectrum!")
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
print("Authorized IP model trained.\n")

# === Real-time Packet Processing ===
def process_packet(pkt):
    try:
        if 'IP' in pkt:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            dst_ip_int = ip_to_int(dst_ip)

            if dst_ip_int is None:
                return

            distances, _ = knn.kneighbors([[dst_ip_int]])
            avg_distance = np.mean(distances)

            print(f"[IP Monitor] Destination: {dst_ip}")

            if dst_ip not in authorized_ips:
                print("Unauthorized IP detected.")
                if avg_distance > DIST_THRESHOLD:
                    print("Anomalous IP Detected!")
                    send_alert(f"ALERT: Anomalous IP {dst_ip} detected!")
                else:
                    print("Close to known IPs, but still unauthorized.")
            else:
                print("Authorized IP.\n")

        if 'FTP' in pkt and hasattr(pkt.ftp, 'request_command'):
            ftp_cmd = pkt.ftp.request_command
            if ftp_cmd in ['USER', 'PASS']:
                src_ip = pkt.ip.src
                dst_port = int(pkt.tcp.dstport)
                flags = int(pkt.tcp.flags, 16)
                attempts[src_ip] += 1

                records.append({
                    'src_ip': src_ip,
                    'dst_port': dst_port,
                    'flags': flags,
                    'ftp_cmd': ftp_cmd
                })

    except Exception as e:
        print(f"Error: {e}")

def analyze():
    if not records:
        print(" No FTP login attempts recorded.")
        return
    df = pd.DataFrame(records)
    df['attempts'] = df['src_ip'].map(attempts)

    print("\nIPs with more than 3 FTP login attempts:")
    flagged = False
    for ip, count in attempts.items():
        if count > 3:
            print(f"  {ip} -> {count} attempts (Possible Brute-force Attack)")
            flagged = True
    if flagged:
        send_alert("ALERT: Brute-force FTP login attempt detected!")

    print("\nIsolation Forest Anomaly Detection:")
    features = df[['dst_port', 'flags', 'attempts']]
    iso = IsolationForest(contamination=0.1, random_state=42)
    df['anomaly'] = iso.fit_predict(features)
    anomalies = df[df['anomaly'] == -1]
    if not anomalies.empty:
        print("Anomalies found (Possible DDoS or Brute-force Attack):")
        print(anomalies[['src_ip', 'ftp_cmd', 'attempts']].drop_duplicates())
        send_alert("ALERT: Network anomalies detected by Isolation Forest!")

    print("\nNaive Bayes Classification:")
    df['label'] = df['attempts'].apply(lambda x: 1 if x > 3 else 0)
    nb = GaussianNB()
    nb.fit(features, df['label'])
    df['prediction'] = nb.predict(features)
    predicted = df[df['prediction'] == 1]
    if not predicted.empty:
        print( "Naive Bayes flagged suspicious activity:")
        print(predicted[['src_ip', 'ftp_cmd', 'attempts']].drop_duplicates())
        send_alert("ALERT: Naive Bayes flagged suspicious login behavior!")

def signal_handler(sig, frame):
    print("\nInterrupted. Running final analysis...\n")
    analyze()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# === Main Execution ===
if __name__ == "__main__":
    jammed = detect_jamming()
    if not jammed:
        print("Starting live traffic monitoring...\n")
        capture = pyshark.LiveCapture(interface=INTERFACE)
        capture.sniff(timeout=IP_MONITOR_DURATION)
        for pkt in capture.sniff_continuously(packet_count=MAX_PACKETS):
            process_packet(pkt)
        analyze()
