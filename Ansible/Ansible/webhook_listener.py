from flask import Flask, request, jsonify
import os
import threading
import time

app = Flask(__name__)

INVENTORY = "/home/sara/grad-proj/inventory.ini"
TRAP_PLAYBOOK = "/home/sara/grad-proj/trap_attacker.yml"
BLOCK_PLAYBOOK = "/home/sara/grad-proj/block_attacker.yml"

def run_mitigation(attacker_ip):
    os.system(f"ansible-playbook -i {INVENTORY} {TRAP_PLAYBOOK} --extra-vars 'target_ip={attacker_ip}'")
    time.sleep(30)
    os.system(f"ansible-playbook -i {INVENTORY} {BLOCK_PLAYBOOK} --extra-vars 'target_ip={attacker_ip}'")

@app.route('/trigger_mitigation', methods=['POST'])
def trigger():
    data = request.json
    attacker_ip = data.get('ip')
    
    if not attacker_ip:
        return jsonify({"error": "No IP provided"}), 400
    
    threading.Thread(target=run_mitigation, args=(attacker_ip,)).start()
    
    return jsonify({"status": "Mitigation triggered successfully", "ip": attacker_ip}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)