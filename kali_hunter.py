import os
import re
import json
from datetime import datetime

LOG_PATH = "/var/log/audit/audit.log"
OUTPUT_JSON = "alerts.json"

def parse_audit_time(event_id):
    try:
        # Correctly split the ID by the colon character and grab the first element (e.g., 1793997843.281)
        epoch_str = event_id.split(':')[0]
        epoch_float = float(epoch_str)
        
        # Convert the true kernel epoch timestamp directly into local human-readable time
        return datetime.fromtimestamp(epoch_float).strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        # Fallback metric (should not hit if split functions cleanly)
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def hunt_threats():
    if not os.path.exists(LOG_PATH):
        print("[-] Error: Cannot find Auditd logs. Run script with sudo.")
        return

    events = {}
    alerts = []
    
    with open(LOG_PATH, "r") as log_file:
        for line in log_file.readlines():
            match_id = re.search(r'audit\((\d+\.\d+:\d+)\)', line)
            if not match_id:
                continue
            
            event_id = match_id.group(1)
            if event_id not in events:
                events[event_id] = {"key": "", "arguments": []}
            
            if 'key="mitre_t1059"' in line:
                events[event_id]["key"] = "mitre_t1059"
            elif 'key="mitre_t1222"' in line:
                events[event_id]["key"] = "mitre_t1222"
                
            args = re.findall(r'a\d+="(.*?)"', line)
            if args:
                events[event_id]["arguments"].extend(args)

    for ev_id, data in events.items():
        if not data["key"]:
            continue
            
        full_command = " ".join(data["arguments"])
        full_command_lower = full_command.lower()
        
        if "kali_hunter" in full_command_lower or "ausearch" in full_command_lower:
            continue

        alert_entry = None
        # Extract the true chronological time of the execution event
        attack_timestamp = parse_audit_time(ev_id)

        # Parse Command Line Shell Threats (T1059.004)
        if data["key"] == "mitre_t1059" and full_command:
            
            # Signature C: Log Tampering & Service Disabling (T1562.001)
            if any(cmd in full_command_lower for cmd in ["auditd", "auditctl"]) and any(act in full_command_lower for act in ["stop", "disable", "kill", "status", "-s"]):
                alert_entry = {
                    "timestamp": attack_timestamp,
                    "alert_type": "Security Service Impairment (Log Tampering)",
                    "details": f"Attempted to stop or disable security monitoring: {full_command}",
                    "mitre_tactic": "Defense Evasion",
                    "mitre_id": "T1562.001"
                }
            
            # Signature A: System Account/Network Discovery Traps
            elif "passwd" in full_command_lower or "ip address" in full_command_lower:
                alert_entry = {
                    "timestamp": attack_timestamp,
                    "alert_type": "Suspicious Shell Command",
                    "details": f"Command executed: {full_command}",
                    "mitre_tactic": "Discovery / Execution",
                    "mitre_id": "T1059.004"
                }
                
            # Signature B: Network Tools
            elif any(cmd in full_command_lower for cmd in ["nmap", "ss", "netstat", "lsof"]):
                if "debian-sa1" in full_command_lower or "libexec/sysstat" in full_command_lower:
                    pass 
                else:
                    alert_entry = {
                        "timestamp": attack_timestamp,
                        "alert_type": "Network Infrastructure Reconnaissance",
                        "details": f"Network scanning tool used: {full_command}",
                        "mitre_tactic": "Discovery",
                        "mitre_id": "T1049 / T1046"
                    }

        # Parse Permission Traps (T1222)
        elif data["key"] == "mitre_t1222":
            alert_entry = {
                "timestamp": attack_timestamp,
                "alert_type": "Unauthorized File Modification Attempt",
                "details": "Changes detected on /etc/passwd attributes or content",
                "mitre_tactic": "Defense Evasion / Persistence",
                "mitre_id": "T1222"
            }

        if alert_entry and alert_entry not in alerts:
            alerts.append(alert_entry)

    if alerts:
        with open(OUTPUT_JSON, "w") as jf:
            json.dump(alerts, jf, indent=4)
        print(f"[🚨 SUCCESS] Threats identified! {len(alerts)} alerts exported.")
    else:
        if os.path.exists(OUTPUT_JSON):
            os.remove(OUTPUT_JSON)
        print("[*] Scan complete. No active threats detected.")

if __name__ == "__main__":
    hunt_threats()
