import subprocess
import os
import argparse

def collect_logs(container_name, dest_path):
    # Docker path to cowrie.json
    source_path = f"{container_name}:/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
    
    print(f"Collecting logs from {source_path} to {dest_path}")
    
    # We will try without sudo first, but note that docker might require sudo depending on setup
    # If the user doesn't have passwordless sudo, a python subprocess will block if it prompts for password.
    # So we'll try docker first. We'll use sudo if docker fails. 
    try:
        # Try standard docker cp first
        subprocess.run(['docker', 'cp', source_path, dest_path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("Successfully collected logs via docker cp.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            # Fallback to sudo docker cp on Linux systems where non-root lacks docker socket access
            subprocess.run(['sudo', '-n', 'docker', 'cp', source_path, dest_path], check=True)
            print("Successfully collected logs via sudo docker cp.")
        except Exception as e:
            print(f"Warning: Could not copy logs from Docker container '{container_name}'.")
            if os.path.exists(dest_path):
                print(f"Proceeding with existing log file at {dest_path}")
            else:
                print(f"Error details: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Collect Cowrie Logs')
    parser.add_argument('--container', type=str, default='cowrie-project', help='Cowrie docker container name')
    parser.add_argument('--dest', type=str, default='data/raw/cowrie.json', help='Destination path for collected logs')
    
    args = parser.parse_args()
    
    os.makedirs(os.path.dirname(args.dest), exist_ok=True)
    collect_logs(args.container, args.dest)
