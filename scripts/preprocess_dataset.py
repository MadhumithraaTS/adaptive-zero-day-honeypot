import pandas as pd
import argparse
import os

def preprocess(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} does not exist.")
        return
        
    print(f"Loading features from {input_file}...")
    df = pd.read_csv(input_file)
    
    if df.empty:
        print("Dataset is empty. No preprocessing needed.")
        return
        
    # Drop session_id as it's not a feature for ML
    if 'session_id' in df.columns:
        df = df.drop(columns=['session_id'])
        
    # Fill missing values with 0
    df = df.fillna(0)
    
    # Normalize numerical columns (min-max scaling as an example)
    cols_to_normalize = ['login_attempts', 'commands_executed', 'unique_commands', 'session_duration', 'failed_commands', 'downloads']
    
    for col in cols_to_normalize:
        if col in df.columns:
            min_val = df[col].min()
            max_val = df[col].max()
            if max_val > min_val:
                df[col] = (df[col] - min_val) / (max_val - min_val)
            else:
                df[col] = 0.0
                
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"Preprocessed dataset saved to {output_file}")
    print("Dataset shape:", df.shape)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Preprocess Dataset')
    parser.add_argument('--input', type=str, default='data/parsed/behavior_features.csv', help='Path to features CSV')
    parser.add_argument('--output', type=str, default='data/processed/model_input.csv', help='Path to save final ML-ready CSV')
    
    args = parser.parse_args()
    preprocess(args.input, args.output)
