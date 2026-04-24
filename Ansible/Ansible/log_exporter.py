import time, json, os, pickle
import numpy as np
import pandas as pd
import requests
import threading
from datetime import datetime
from prometheus_client import start_http_server, Counter, Gauge

ai_attacks = Counter('ai_attacks_detected_total', 'Attacks Detected by AI', ['type'])
ai_normal = Counter('ai_normal_traffic_total', 'Normal Traffic Detected by AI')
attack_intensity = Gauge('ai_attack_intensity', 'Current Attack Intensity')

LOG_FILE = "/var/log/suricata/eve.json"
MODEL_PATH = "/opt/model.pkl" 
SCALER_PATH = "/opt/scaler.pkl"
ANSIBLE_API_URL = "http://172.16.1.55:5000/trigger_mitigation"

CLASS_MAP = {0: 'DDos', 1: 'Normal Traffic', 2: 'Port Scan'}
FEATURE_NAMES = [
    'src_port', 'dest_port', 'pkts_toserver', 'pkts_toclient', 
    'bytes_toserver', 'bytes_toclient', 'flow_duration', 'proto_encoded'
]
active_blocks = set()

def trap_and_block(attacker_ip):
    if attacker_ip in active_blocks or ":" in attacker_ip: return
    active_blocks.add(attacker_ip)
    attack_intensity.set(100)
    try:
        requests.post(ANSIBLE_API_URL, json={"ip": attacker_ip}, timeout=5)
    except:
        pass
    def release_block():
        time.sleep(35)
        attack_intensity.set(0)
        active_blocks.remove(attacker_ip)
    threading.Thread(target=release_block).start()

def extract_features(data):
    try:
        if data.get('event_type') not in ['flow', 'alert']: return None
        flow = data.get('flow', {})
        proto_str = data.get('proto', 'TCP').upper()
        proto_map = {'ICMP': 0, 'TCP': 1, 'UDP': 2}
        proto_encoded = float(proto_map.get(proto_str, 1))
        current_timestamp_str = data.get('timestamp', '')
        current_ts = datetime.fromisoformat(current_timestamp_str.replace('Z', '+00:00'))
        if 'age' in flow:
            flow_duration = float(flow['age'])
        elif 'start' in flow:
            start_ts = datetime.fromisoformat(flow['start'].replace('Z', '+00:00'))
            flow_duration = max(0.0, (current_ts - start_ts).total_seconds())
        else:
            flow_duration = 0.0

        return [
            float(data.get('src_port', 0)),
            float(data.get('dest_port', 0)),
            float(flow.get('pkts_toserver', 0)),
            float(flow.get('pkts_toclient', 0)),
            float(flow.get('bytes_toserver', 0)),
            float(flow.get('bytes_toclient', 0)),
            float(flow_duration),
            proto_encoded
        ]
    except:
        return None

def follow(thefile):
    thefile.seek(0, 2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

if __name__ == '__main__':
    start_http_server(8000, addr='0.0.0.0')
    attack_intensity.set(0)
    try:
        with open(MODEL_PATH, 'rb') as f: model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f: scaler = pickle.load(f)
        print("✅ System Ready.")
    except Exception as e:
        model = None
        scaler = None
    while True:
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r") as logfile:
                    for line in follow(logfile):
                        try:
                            data = json.loads(line)
                            if data.get("event_type") == "stats": continue
                            features = extract_features(data)
                            if features and model and scaler:
                                features_df = pd.DataFrame([features], columns=FEATURE_NAMES)
                                features_scaled = scaler.transform(features_df)
                                prediction = model.predict(features_scaled)[0]
                                label = CLASS_MAP.get(prediction, "Normal Traffic")
                                if label != 'Normal Traffic':
                                    ai_attacks.labels(type=label).inc()
                                    attacker_ip = data.get('src_ip')
                                    if attacker_ip: trap_and_block(attacker_ip)
                                    print(f"🚨 {label}: {attacker_ip}")
                                else:
                                    ai_normal.inc()
                                    attack_intensity.set(0)
                        except: continue
            except: time.sleep(2)
        else:
            time.sleep(2)