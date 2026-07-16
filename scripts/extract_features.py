import json
import csv
import argparse
from datetime import datetime
import os

def extract_features(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} does not exist.")
        return
        
    with open(input_file, 'r') as f:
        sessions = json.load(f)
        
    features_list = []
    
    for session_id, events in sessions.items():
        features = {
            'session_id': session_id,
            'login_attempts': 0,
            'commands_executed': 0,
            'unique_commands': 0,
            'wget_curl_chmod_usage': 0,
            'shell_spawn': 0,
            'session_duration': 0,
            'failed_commands': 0,
            'downloads': 0
        }
        
        commands = set()
        start_time = None
        end_time = None
        
        for event in events:
            event_id = event.get('eventid')
            ts_str = event.get('timestamp')
            
            if ts_str:
                try:
                    # e.g., "2023-01-01T12:00:00.000000Z"
                    dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    if not start_time or dt < start_time:
                        start_time = dt
                    if not end_time or dt > end_time:
                        end_time = dt
                except Exception:
                    pass
            
            if event_id == 'cowrie.login.success' or event_id == 'cowrie.login.failed':
                features['login_attempts'] += 1
                
            elif event_id == 'cowrie.command.input':
                features['commands_executed'] += 1
                cmd = event.get('input', '').strip()
                commands.add(cmd)
                
                if 'wget' in cmd or 'curl' in cmd or 'chmod' in cmd:
                    features['wget_curl_chmod_usage'] = 1
                    
            elif event_id == 'cowrie.command.failed':
                features['failed_commands'] += 1
                
            elif event_id == 'cowrie.session.file_download':
                features['downloads'] += 1
                
            elif event_id == 'cowrie.client.size': # Usually indicates interactive shell
                features['shell_spawn'] = 1
                
        features['unique_commands'] = len(commands)
        
        if start_time and end_time:
            features['session_duration'] = (end_time - start_time).total_seconds()
            
        features_list.append(features)
        
    print(f"Extracted features for {len(features_list)} sessions.")
    
    if features_list:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        keys = features_list[0].keys()
        with open(output_file, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(features_list)
        print(f"Saved behavioral features to {output_file}")
    else:
        print("No features extracted.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract Behavioral Features')
    parser.add_argument('--input', type=str, default='data/parsed/sessions.json', help='Path to parsed sessions.json')
    parser.add_argument('--output', type=str, default='data/parsed/behavior_features.csv', help='Path to save features CSV')
    
    args = parser.parse_args()
    extract_features(args.input, args.output)
