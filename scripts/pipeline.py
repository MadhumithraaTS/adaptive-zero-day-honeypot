import subprocess
import os
import sys
import argparse

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# The saved DEC artifacts need this interpreter's pandas/scikit-learn/TensorFlow versions.
DEFAULT_DEC_PYTHON = os.path.join(
    REPO_ROOT, 'ml', 'cowrie_dec_integration_skeleton', '.venv-dec-smoke', 'Scripts', 'python.exe'
)

def run_step(step_name, command, python_executable=None):
    print(f"\n{'='*60}")
    print(f"Running step: {step_name}")
    print(f"{'='*60}")
    try:
        # Use the active environment unless a step needs a different runtime.
        subprocess.run([python_executable or sys.executable, *command], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running {step_name}: {e}")
        sys.exit(1)
    except OSError as e:
        print(f"Error running {step_name}: could not start {python_executable or sys.executable}: {e}")
        sys.exit(1)

def resolve_cluster_python(cluster_python=None):
    """DEC interpreter: the explicit --cluster-python, else the project's DEC environment. Never sys.executable."""
    path = cluster_python or DEFAULT_DEC_PYTHON
    return path if os.path.isfile(path) else None

def build_paths(output_dir=None):
    """Output locations: the tracked data/ and models/ paths by default, or a separate run directory."""
    if output_dir is None:
        return {
            'raw': 'data/raw/cowrie.json',
            'sessions': 'data/parsed/sessions.json',
            'features': 'data/parsed/behavior_features.csv',
            'details': 'data/parsed/session_details.json',
            'model_input': 'data/processed/model_input.csv',
            'mapping': 'data/processed/session_mapping.csv',
            'aux_scaler': 'models/scaler.joblib',
            'dec_results': 'data/processed/dec_results.csv',
        }
    return {
        'raw': os.path.join(output_dir, 'raw', 'cowrie.json'),
        'sessions': os.path.join(output_dir, 'parsed', 'sessions.json'),
        'features': os.path.join(output_dir, 'parsed', 'behavior_features.csv'),
        'details': os.path.join(output_dir, 'parsed', 'session_details.json'),
        'model_input': os.path.join(output_dir, 'processed', 'model_input.csv'),
        'mapping': os.path.join(output_dir, 'processed', 'session_mapping.csv'),
        'aux_scaler': os.path.join(output_dir, 'models', 'scaler.joblib'),
        'dec_results': os.path.join(output_dir, 'processed', 'dec_results.csv'),
    }

def planned_outputs(paths, collect, preprocess):
    keys = ['sessions', 'features', 'details', 'dec_results']
    if collect:
        keys.insert(0, 'raw')
    if preprocess:
        keys += ['model_input', 'mapping', 'aux_scaler']
    return [paths[key] for key in keys]

def existing_outputs(outputs):
    return [path for path in outputs if os.path.exists(path)]

def main():
    parser = argparse.ArgumentParser(description='Adaptive Zero-Day Honeypot Pipeline')
    parser.add_argument('--sessions', type=int, default=1800, help='Number of attack sessions to simulate')
    parser.add_argument('--skip-attack', action='store_true', help='Skip synthetic attack simulation')
    parser.add_argument('--skip-collect', action='store_true', help='Skip Docker log collection')
    parser.add_argument('--attack-username', help='Use this SSH username for simulated sessions')
    parser.add_argument('--attack-password', help='Use this SSH password for simulated sessions')
    parser.add_argument(
        '--cluster-python',
        help='Python executable for DEC clustering (default: ml/cowrie_dec_integration_skeleton/'
             '.venv-dec-smoke/Scripts/python.exe; the main .venv cannot load the saved DEC artifacts)'
    )
    parser.add_argument(
        '--output-dir',
        help='Write every pipeline output under this directory instead of the tracked data/ and models/ paths'
    )
    parser.add_argument(
        '--raw-input',
        help='Parse this existing Cowrie JSON log instead of collecting a new one (disables log collection)'
    )
    parser.add_argument(
        '--skip-preprocess',
        action='store_true',
        help='Skip the auxiliary MinMaxScaler/model_input.csv step; DEC does not use it'
    )
    parser.add_argument(
        '--allow-overwrite',
        action='store_true',
        help='Allow replacing existing output files, including the tracked baseline under data/ and models/'
    )

    args = parser.parse_args()

    if (args.attack_username is None) != (args.attack_password is None):
        parser.error('--attack-username and --attack-password must be provided together')
    cluster_python = resolve_cluster_python(args.cluster_python)
    if cluster_python is None:
        if args.cluster_python:
            parser.error(f'--cluster-python does not point to a file: {args.cluster_python}')
        parser.error(f'DEC interpreter not found at {DEFAULT_DEC_PYTHON}; pass --cluster-python')
    if args.raw_input and not os.path.isfile(args.raw_input):
        parser.error(f'--raw-input does not point to a file: {args.raw_input}')

    paths = build_paths(args.output_dir)
    collect = not args.skip_collect and not args.skip_attack and not args.raw_input
    raw_log = args.raw_input or paths['raw']

    # Refuse before any attack, collection or write if outputs already exist.
    outputs = planned_outputs(paths, collect, not args.skip_preprocess)
    existing = existing_outputs(outputs)
    if existing and not args.allow_overwrite:
        print("Error: refusing to overwrite existing pipeline outputs:", file=sys.stderr)
        for path in existing:
            print(f"  {path}", file=sys.stderr)
        print("Use --output-dir with a new directory, or pass --allow-overwrite to replace them.", file=sys.stderr)
        sys.exit(2)

    print("Starting Adaptive Zero-Day Honeypot Data & ML Preprocessing Pipeline...")
    print(f"DEC interpreter: {cluster_python}")

    for path in outputs:
        os.makedirs(os.path.dirname(path), exist_ok=True)

    # 1. Attack Generator (Simulation)
    if not args.skip_attack:
        attack_command = ["scripts/attack_generator.py", "--sessions", str(args.sessions)]
        if args.attack_username is not None:
            attack_command.extend([
                "--username", args.attack_username,
                "--password", args.attack_password
            ])
        run_step("Attack Automation", attack_command)
    else:
        print("\nSkipping Attack Simulation (--skip-attack set)")

    # 2. Collect Logs
    if collect:
        run_step("Log Collection", ["scripts/collect_logs.py", "--dest", paths['raw']])
    else:
        print(f"\nSkipping Log Collection (parsing {raw_log})")

    # 3. Parse Logs
    run_step("Log Parsing", ["scripts/parse_logs.py", "--input", raw_log, "--output", paths['sessions']])

    # 4. Extract Features & Sequences
    run_step("Feature Extraction", [
        "scripts/extract_features.py",
        "--input", paths['sessions'],
        "--output", paths['features'],
        "--details", paths['details']
    ])

    # 5. Auxiliary MinMax preprocessing (model_input.csv). DEC does not use this
    #    scaler; it loads its own saved StandardScaler from its artifacts directory.
    if not args.skip_preprocess:
        run_step("Auxiliary MinMax Preprocessing (not used by DEC)", [
            "scripts/preprocess_dataset.py",
            "--input", paths['features'],
            "--output", paths['model_input'],
            "--mapping", paths['mapping'],
            "--scaler", paths['aux_scaler']
        ])
    else:
        print("\nSkipping auxiliary MinMax preprocessing (--skip-preprocess set)")

    # 6. DEC Clustering (saved artifacts; no refitting)
    run_step("DEC Clustering", [
        "ml/cowrie_dec_integration_skeleton/scripts/run_dec_evaluation.py",
        paths['features'],
        "--output", paths['dec_results']
    ], python_executable=cluster_python)

    print(f"\n{'='*60}")
    print(" Pipeline completed successfully!")
    print(" Outputs Generated:")
    print(f"  • Session Sequences:     {paths['details']}")
    print(f"  • DEC Feature Input:     {paths['features']}")
    print(f"  • DEC Cluster Results:   {paths['dec_results']}")
    if not args.skip_preprocess:
        print(f"  • Auxiliary ML Input:    {paths['model_input']}")
        print(f"  • Session Mapping:       {paths['mapping']}")
        print(f"  • Auxiliary MinMaxScaler (not used by DEC): {paths['aux_scaler']}")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
