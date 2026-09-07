import json
import time
import random
import paramiko
import os
import argparse

def load_profiles(config_path):
    with open(config_path, 'r') as f:
        data = json.load(f)
    return data['profiles']

def simulate_attack(host, port, username, password, profile, max_retries=3):
    print(f"Simulating attack with profile: {profile['name']}")
    
    for attempt in range(1, max_retries + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        channel = None
        try:
            # Cowrie accepts any password; allow higher banner_timeout and auth_timeout
            client.connect(
                hostname=host, 
                port=port, 
                username=username, 
                password=password, 
                timeout=15, 
                banner_timeout=20,
                auth_timeout=15
            )
            
            # Interactive shell
            channel = client.invoke_shell()
            time.sleep(0.5)
            
            for cmd in profile['commands']:
                print(f"[{profile['name']}] Executing: {cmd}")
                channel.send(cmd + "\n")
                
                # Wait based on delay range
                delay = random.uniform(profile['delay_range'][0], profile['delay_range'][1])
                time.sleep(delay)
                
                # Clear buffer
                if channel.recv_ready():
                    channel.recv(2048)
                    
            # Graceful session exit
            channel.send("exit\n")
            time.sleep(0.5)
            return True
            
        except Exception as e:
            if attempt < max_retries:
                wait_time = attempt * 2
                print(f"Connection attempt {attempt} failed ({e}). Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                print(f"Failed to connect or execute after {max_retries} attempts: {e}")
                return False
        finally:
            if channel:
                try: channel.close()
                except Exception: pass
            try: client.close()
            except Exception: pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Automated Attack Generator for Honeypot')
    parser.add_argument('--config', type=str, default='configs/attack_profiles.json', help='Path to attack profiles JSON')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Honeypot host')
    parser.add_argument('--port', type=int, default=2223, help='Honeypot SSH port')
    parser.add_argument('--sessions', type=int, default=5, help='Number of attack sessions to simulate')
    
    args = parser.parse_args()
    
    profiles = load_profiles(args.config)
    
    for i in range(args.sessions):
        profile = random.choice(profiles)
        # Random username and password
        user = random.choice(['root', 'admin', 'user', 'guest'])
        password = random.choice(['123456', 'password', 'admin', 'root', '1234'])
        
        print(f"--- Session {i+1}/{args.sessions} ---")
        simulate_attack(args.host, args.port, user, password, profile)
        time.sleep(1.5)
