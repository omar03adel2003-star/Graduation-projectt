import json, hashlib, time

SECRET_KEY = "ShadowNetX_2026_Secret"
INPUT_FILE = "/var/log/suricata/eve.json"
OUTPUT_FILE = "/home/sara/watermarked_eve.json"

def run_watermark():
    print("Starting Watermarking Module...")
    with open(INPUT_FILE, "r") as fin:
        fin.seek(0, 2)
        while True:
            line = fin.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                log_data = json.loads(line)
                if log_data.get("event_type") == "alert":
                    signature = hashlib.sha256((line.strip() + SECRET_KEY))
                    log_data["watermark"] = signature
                    with open(OUTPUT_FILE, "a") as fout:
                        fout.write(json.dumps(log_data) + "\n")
            except:
                continue

if __name__ == "__main__":
    run_watermark()
