import json
import argparse
import os

def parse_logs(input_file, output_file):
    sessions = {}
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} does not exist.")
        return

    print(f"Parsing logs from {input_file}...")
    with open(input_file, 'r') as f:
        for line in f:
            if not line.strip():
                continue
            
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
                
            session_id = event.get('session')
            if not session_id:
                continue
                
            if session_id not in sessions:
                sessions[session_id] = []
                
            sessions[session_id].append(event)
            
    print(f"Parsed {len(sessions)} unique sessions.")
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(sessions, f, indent=4)
    print(f"Saved parsed sessions to {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse Cowrie Logs')
    parser.add_argument('--input', type=str, default='data/raw/cowrie.json', help='Path to raw cowrie.json')
    parser.add_argument('--output', type=str, default='data/parsed/sessions.json', help='Path to save grouped sessions')
    
    args = parser.parse_args()
    parse_logs(args.input, args.output)
