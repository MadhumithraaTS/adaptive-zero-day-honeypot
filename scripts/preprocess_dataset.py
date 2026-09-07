import pandas as pd
import argparse
import os

try:
    import joblib
    def save_model(obj, path): joblib.dump(obj, path)
    def load_model(path): return joblib.load(path)
except ImportError:
    import pickle
    def save_model(obj, path):
        with open(path, 'wb') as f: pickle.dump(obj, f)
    def load_model(path):
        with open(path, 'rb') as f: return pickle.load(f)

from sklearn.preprocessing import MinMaxScaler

# Feature columns matching UNSW-NB15 benchmark for DEC model evaluation.
FEATURE_COLS = [
    'dur', 'proto', 'service', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'tcprtt', 'synack', 'ackdat', 'ct_srv_src',
    'ct_state_ttl', 'ct_dst_ltm', 'ct_src_ltm', 'ct_srv_dst'
]

def preprocess(input_file, output_file, mapping_file='data/processed/session_mapping.csv', scaler_path='models/scaler.joblib', fit_scaler=True):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} does not exist.")
        return
        
    print(f"Loading features from {input_file}...")
    df = pd.read_csv(input_file)
    
    if df.empty:
        print("Dataset is empty. No preprocessing needed.")
        return
        
    # 1. Save Session Mapping (Metadata Lookup)
    mapping_cols = ['session_id', 'src_ip', 'src_port', 'auth_success']
    available_mapping_cols = [c for c in mapping_cols if c in df.columns]
    mapping_df = df[available_mapping_cols].copy()
    mapping_df.insert(0, 'row_index', range(len(mapping_df)))
    
    os.makedirs(os.path.dirname(mapping_file), exist_ok=True)
    mapping_df.to_csv(mapping_file, index=False)
    print(f"Saved session metadata mapping to {mapping_file}")

    # 2. Extract and sanitize feature columns
    # Select available numerical feature columns for scaling; keep 'service' string separate if present
    NUMERIC_COLS = [c for c in FEATURE_COLS if c != 'service']

    feature_df = pd.DataFrame()
    for col in NUMERIC_COLS:
        if col in df.columns:
            feature_df[col] = df[col]
        else:
            feature_df[col] = 0.0
            
    feature_df = feature_df.fillna(0.0)

    # 3. Scaler Fitting / Transformation
    os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
    
    if fit_scaler or not os.path.exists(scaler_path):
        print("Fitting and saving new MinMaxScaler...")
        scaler = MinMaxScaler()
        normalized_data = scaler.fit_transform(feature_df)
        save_model(scaler, scaler_path)
        print(f"Saved scaler to {scaler_path}")
    else:
        print(f"Loading existing scaler from {scaler_path}...")
        scaler = load_model(scaler_path)
        normalized_data = scaler.transform(feature_df)

    normalized_df = pd.DataFrame(normalized_data, columns=NUMERIC_COLS)
    if 'service' in FEATURE_COLS and 'service' in df.columns:
        normalized_df.insert(2, 'service', df['service'])
    if 'attack_cat' in df.columns:
        normalized_df['attack_cat'] = df['attack_cat']
    if 'label' in df.columns:
        normalized_df['label'] = df['label']
    
    # 4. Save Final ML-Ready Dataset
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    normalized_df.to_csv(output_file, index=False)
    print(f"Preprocessed dataset saved to {output_file}")
    print(f"Dataset shape: {normalized_df.shape}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Preprocess Dataset and Persist Scaler')
    parser.add_argument('--input', type=str, default='data/parsed/behavior_features.csv', help='Path to features CSV')
    parser.add_argument('--output', type=str, default='data/processed/model_input.csv', help='Path to save final ML-ready CSV')
    parser.add_argument('--mapping', type=str, default='data/processed/session_mapping.csv', help='Path to save session mapping CSV')
    parser.add_argument('--scaler', type=str, default='models/scaler.joblib', help='Path to save/load MinMaxScaler')
    parser.add_argument('--no-fit', action='store_true', help='Use existing scaler without refitting')
    
    args = parser.parse_args()
    preprocess(args.input, args.output, args.mapping, args.scaler, fit_scaler=not args.no_fit)

