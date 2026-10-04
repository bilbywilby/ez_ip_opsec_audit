cat << 'EOF' > ~/opsec_audit.py
#!/usr/bin/env python3
import os
import subprocess
import sys

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"

def main():
    # Atomic directory initialization
    log_dir = os.path.expanduser("~/opsec_audit_logs")
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print(f"[+] Created {log_dir}")

    # Git State Capture
    repo_path = os.path.expanduser("~/pixel-terminal-master")
    commit_hash = run_cmd(f"git -C {repo_path} rev-parse HEAD")
    
    # Tac-based Reverse Audit (Captures latest changes first)
    audit_file = os.path.join(repo_path, "lib/monitor.sh")
    if os.path.exists(audit_file):
        # Using tac to read the file in reverse to identify tail-end injections
        reversed_content = run_cmd(f"tac {audit_file}")
        
        with open(os.path.join(log_dir, "monitor_reverse.log"), "w") as f:
            f.write(f"Commit: {commit_hash}\n")
            f.write("-" * 40 + "\n")
            f.write(reversed_content)
        print(f"[+] Reverse audit written to {log_dir}/monitor_reverse.log")

    print(f"[✓] OPSEC Audit Complete. Hash: {commit_hash}")

if __name__ == "__main__":
    main()
EOF
chmod +x ~/opsec_audit.py
python3 ~/opsec_audit.py
