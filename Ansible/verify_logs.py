import json
import hmac
import hashlib
import os

SECRET_KEY = b'ShadowNetX_Secret_2026'
WATERMARKED_LOG = '/opt/cowrie/var/log/cowrie/watermarked_cowrie.json'

def verify_log_file():
    if not os.path.exists(WATERMARKED_LOG):
        print(f"[-] Error: {WATERMARKED_LOG} not found!")
        return

    print(f"[*] Starting Integrity Verification on: {WATERMARKED_LOG}\n" + "-"*60)
    tampered_count = 0
    total_count = 0

    with open(WATERMARKED_LOG, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total_count += 1
            try:
                data = json.loads(line)
                original_watermark = data.get('watermark', None)
                
                if not original_watermark:
                    print(f"[!] Line {line_num}: Missing Watermark!")
                    tampered_count += 1
                    continue

                data_copy = data.copy()
                if 'watermark' in data_copy:
                    del data_copy['watermark']
                base_string = json.dumps(data_copy, sort_keys=True)
                calculated_signature = hmac.new(SECRET_KEY, base_string.encode(), hashlib.sha256).hexdigest()

                if calculated_signature != original_watermark:
                    print(f"[-] TAMPERED LOG DETECTED at line {line_num}!!!")
                    print(f"    Expected: {calculated_signature}")
                    print(f"    Found:    {original_watermark}\n")
                    tampered_count += 1
            except:
                print(f"[!] Line {line_num}: Failed to parse JSON.")
                tampered_count += 1

    print("-"*60)
    if tampered_count == 0:
        print(f"[+] SUCCESS: All {total_count} logs are VERIFIED. Data Integrity is 100% Secure.")
    else:
        print(f"[-] WARNING: Detection complete. Found {tampered_count} compromised logs out of {total_count}!")

if __name__ == '__main__':
    verify_log_file()
