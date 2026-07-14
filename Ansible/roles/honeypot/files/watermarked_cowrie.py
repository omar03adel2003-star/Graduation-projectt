import json
import hmac
import hashlib
import time
import os

SECRET_KEY = b'ShadowNetX_Secret_2026'
INPUT_LOG = '/home/sara/live_cowrie.json'
OUTPUT_LOG = '/opt/cowrie/var/log/cowrie/watermarked_cowrie.json'

def add_watermark(log_entry):
    try:
        data = json.loads(log_entry)
        base_string = json.dumps(data, sort_keys=True)
        signature = hmac.new(SECRET_KEY, base_string.encode(), hashlib.sha256).hexdigest()
        data['watermark'] = signature
        return json.dumps(data)
    except:
        return None

def process_logs():
    if not os.path.exists(INPUT_LOG):
        return
    with open(INPUT_LOG, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            watermarked = add_watermark(line)
            if watermarked:
                with open(OUTPUT_LOG, 'a') as out:
                    out.write(watermarked + '\n')

if __name__ == "__main__":
    process_logs()
