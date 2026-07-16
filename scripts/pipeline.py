import subprocess
import os
import sys

def run_step(step_name, command):
    print(f"\n{'='*50}")
    print(f"Running step: {step_name}")
    print(f"{'='*50}")
    try:
        # Use sys.executable to ensure we use the virtual environment's Python
        subprocess.run([sys.executable, *command], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running {step_name}: {e}")
        exit(1)

def main():
    print("Starting Adaptive Zero-Day Honeypot Pipeline...")
    
    # Ensure directories exist
    os.makedirs('data/raw', exist_ok=True)
    os.makedirs('data/parsed', exist_ok=True)
    os.makedirs('data/processed', exist_ok=True)
    
    # 1. Run Attack Generator
    # Note: We simulate 5 sessions by default
    run_step("Attack Automation", ["scripts/attack_generator.py", "--sessions", "5"])
    
    # 2. Collect Logs
    run_step("Log Collection", ["scripts/collect_logs.py"])
    
    # 3. Parse Logs
    run_step("Log Parsing", ["scripts/parse_logs.py"])
    
    # 4. Extract Features
    run_step("Feature Extraction", ["scripts/extract_features.py"])
    
    # 5. Preprocess Dataset
    run_step("Dataset Generation", ["scripts/preprocess_dataset.py"])
    
    print("\nPipeline completed successfully!")
    print("Final ML-ready dataset: data/processed/model_input.csv")

if __name__ == '__main__':
    main()
