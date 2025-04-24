import pandas as pd
import pyshark
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import NearestNeighbors
import numpy as np
import socket
import datetime
import RPi.GPIO as GPIO
import time

# --- Buzzer Setup ---
BUZZER_PIN = 17 # GPIO17 (Physical pin 11)
GPIO.setmode(GPIO.BCM)
GPIO.setup(BUZZER_PIN, GPIO.OUT)

def activate_buzzer(duration=2):
    GPIO.output(BUZZER_PIN, GPIO.HIGH)
    time.sleep(duration)
    GPIO.output(BUZZER_PIN, GPIO.LOW)

# --- Step 1: Jamming Detection ---
print("Checking for jamming...")
try:
    df_jam = pd.read_csv('logged_data.csv')
    threshold = 2.5e9  # 2.5 GHz

    if 'Frequency' in df_jam.columns:
        jammed = df_jam[df_jam['Frequency'] > threshold]
        if not jammed.empty:
            print("Jamming detected! Activating buzzer and halting system.")
            activate_buzzer()
            GPIO.cleanup()
            exit()
        else:
            print("No jamming detected. Proceeding to IP check...\n")
    else:
        print("'Frequency' column not found in CSV.")
        GPIO.cleanup()
        exit()
except FileNotFoundError:
    print("logged_data.csv not found.")
    GPIO.cleanup()
    exit()
except Exception as e:
    print(f"Jamming detection error: {e}")
    GPIO.cleanup()
    exit()

# --- Helper Functions ---
def ip_to_int(ip):
    return int.from_bytes(socket.inet_aton(ip), 'big')

def load_authorized_ips(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# --- IP Anomaly Detector Class ---
class IPAnomalyDetector:
    def __init__(self, k=3, dist_threshold=1_000_000):
        self.k = k
        self.dist_threshold = dist_threshold
        self.known_ips = []
        self.knn = None

    def train(self):
        if len(self.known_ips) >= 2:
            authorized_ip_ints = np.array([[ip_to_int(ip)] for ip in self.known_ips])
            self.knn = NearestNeighbors(n_neighbors=self.k)
            self.knn.fit(authorized_ip_ints)

    def is_anomalous(self, ip):
        if len(self.known_ips) < 2:
            return False
        test_ip_int = np.array([[ip_to_int(ip)]])
        if ip in self.known_ips:
            return False
        distances, _ = self.knn.kneighbors(test_ip_int)
        avg_distance = np.mean(distances)
        return avg_distance > self.dist_threshold

# --- Load PCAP and Setup ---
print("Loading PCAP file...")
cap = pyshark.FileCapture('bruteforce.pcap', display_filter='ftp')
attempts = defaultdict(int)
records = []

AUTHORIZED_FILE = "authorized ips.txt"
authorized_ips = load_authorized_ips(AUTHORIZED_FILE)
detector = IPAnomalyDetector()
detector.known_ips.extend(authorized_ips)
detector.train()

# --- Step 2: Monitor IPs for 1 Minute ---
print("Monitoring authorized IPs for 1 minute...\n")
start_time = datetime.datetime.now()
for pkt in cap:
    try:
        if 'FTP' in pkt and 'IP' in pkt and 'TCP' in pkt:
            ftp_cmd = pkt.ftp.request_command
            src_ip = pkt.ip.src
            if (datetime.datetime.now() - start_time).total_seconds() > 60:
                break
            if src_ip in authorized_ips:
                print(f"Authorized IP Activity: {src_ip} - Command: {ftp_cmd}")
    except:
        continue

print("\n1-minute authorized IP monitoring complete.\nProceeding to brute-force and DDoS analysis...\n")

# --- Step 3: Full Analysis ---
cap.close()
cap = pyshark.FileCapture('bruteforce.pcap', display_filter='ftp')
for pkt in cap:
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
    except:
        continue

cap.close()
df = pd.DataFrame(records)

# --- Step 4: ML-Based Analysis ---
if df.empty:
    print("No FTP login attempts found.")
else:
    df['attempts'] = df['src_ip'].map(attempts)

    print("IPs with more than 3 login attempts (Brute-force):")
    flagged = False
    for ip, count in attempts.items():
        if count > 3:
            print(f"{ip} → {count} attempts")
            flagged = True
    if not flagged:
        print("No brute-force-like behavior (<= 3 attempts).")

    # Isolation Forest
    print("\nIsolation Forest:")
    features = df[['dst_port', 'flags', 'attempts']]
    iso = IsolationForest(contamination=0.1, random_state=42)
    df['anomaly'] = iso.fit_predict(features)
    anomalies = df[df['anomaly'] == -1]
    if anomalies.empty:
        print("No anomalies detected.")
    else:
        print("Anomalies:")
        print(anomalies[['src_ip', 'ftp_cmd', 'attempts']].drop_duplicates())

    # Naive Bayes
    print("\nNaive Bayes Prediction:")
    df['label'] = df['attempts'].apply(lambda x: 1 if x > 3 else 0)
    nb = GaussianNB()
    nb.fit(features, df['label'])
    df['prediction'] = nb.predict(features)
    predicted = df[df['prediction'] == 1]
    if predicted.empty:
        print("No suspicious activity predicted.")
    else:
        print("Predicted suspicious activity:")
        print(predicted[['src_ip', 'ftp_cmd', 'attempts']].drop_duplicates())

    # KNN IP Anomaly Detection
    print("\nKNN IP Anomaly Detection:")
    all_ips = df['src_ip'].unique()
    for test_ip in all_ips:
        if test_ip in authorized_ips:
            print(f"{test_ip} is authorized.")
        else:
            print(f"{test_ip} is unauthorized.")
            if detector.is_anomalous(test_ip):
                print(f"  Anomaly Detected for {test_ip}!")
            else:
                print(f"  Unauthorized, but not anomalous.")

# --- Cleanup GPIO ---
GPIO.cleanup()
