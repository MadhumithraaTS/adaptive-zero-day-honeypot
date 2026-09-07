import subprocess
import os
import sys
import argparse

def run_step(step_name, command):
    print(f"\n{'='*60}")
    print(f"Running step: {step_name}")
    print(f"{'='*60}")
    try:
        # Use sys.executable to ensure we use the active Python environment
        subprocess.run([sys.executable, *command], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running {step_name}: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Adaptive Zero-Day Honeypot Pipeline')
    parser.add_argument('--sessions', type=int, default=1800, help='Number of attack sessions to simulate')
    parser.add_argument('--skip-attack', action='store_true', help='Skip synthetic attack simulation')
    parser.add_argument('--skip-collect', action='store_true', help='Skip Docker log collection')
    
    args = parser.parse_args()
    
    print("Starting Adaptive Zero-Day Honeypot Data & ML Preprocessing Pipeline...")
    
    # Ensure standard directory structure
    os.makedirs('data/raw', exist_ok=True)
    os.makedirs('data/parsed', exist_ok=True)
    os.makedirs('data/processed', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    # 1. Attack Generator (Simulation)
    if not args.skip_attack:
        run_step("Attack Automation", ["scripts/attack_generator.py", "--sessions", str(args.sessions)])
    else:
        print("\nSkipping Attack Simulation (--skip-attack set)")
        
    # 2. Collect Logs
    if not args.skip_collect and not args.skip_attack:
        run_step("Log Collection", ["scripts/collect_logs.py"])
    else:
        print("\nSkipping Log Collection")
        
    # 3. Parse Logs
    run_step("Log Parsing", ["scripts/parse_logs.py"])
    
    # 4. Extract Features & Sequences
    run_step("Feature Extraction", [
        "scripts/extract_features.py", 
        "--input", "data/parsed/sessions.json",
        "--output", "data/parsed/behavior_features.csv",
        "--details", "data/parsed/session_details.json"
    ])
    
    # 5. Preprocess Dataset & Persist Scaler
    run_step("Dataset Generation & Normalization", [
        "scripts/preprocess_dataset.py",
        "--input", "data/parsed/behavior_features.csv",
        "--output", "data/processed/model_input.csv",
        "--mapping", "data/processed/session_mapping.csv",
        "--scaler", "models/scaler.joblib"
    ])
        
    print(f"\n{'='*60}")
    print(" Pipeline completed successfully!")
    print(" Outputs Generated:")
    print("  • ML Input Features:     data/processed/model_input.csv")
    print("  • Session Mapping:       data/processed/session_mapping.csv")
    print("  • Fitted Scaler:         models/scaler.joblib")
    print("  • Session Sequences:     data/parsed/session_details.json")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()

