import json
import argparse
import os
import sys
import tempfile


class LogParseError(Exception):
    """Raised when the raw log cannot be parsed into a valid, non-empty sessions file."""


def _write_json_atomic(output_file, payload):
    # Write to a temporary file first so a failed write never replaces or truncates an existing output.
    directory = os.path.dirname(output_file) or "."
    temporary = None
    try:
        os.makedirs(directory, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{os.path.basename(output_file)}.", suffix=".tmp", dir=directory)
        os.close(descriptor)
        with open(temporary, 'w') as f:
            json.dump(payload, f, indent=4)
        os.replace(temporary, output_file)
        temporary = None
    except OSError as exc:
        raise LogParseError(f"Could not write {output_file}: {exc}") from exc
    finally:
        if temporary and os.path.exists(temporary):
            os.remove(temporary)


def parse_logs(input_file, output_file):
    if not os.path.isfile(input_file):
        raise LogParseError(f"{input_file} does not exist.")

    sessions = {}
    print(f"Parsing logs from {input_file}...")
    try:
        with open(input_file, 'r') as f:
            for line_number, line in enumerate(f, start=1):
                if not line.strip():
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LogParseError(f"Malformed JSON on line {line_number} of {input_file}: {exc}") from exc
                if not isinstance(event, dict):
                    raise LogParseError(f"Line {line_number} of {input_file} is not a JSON object.")

                session_id = event.get('session')
                if not session_id:
                    continue
                if not isinstance(session_id, str):
                    raise LogParseError(f"Line {line_number} of {input_file} has a non-string session ID: {session_id!r}")

                if session_id not in sessions:
                    sessions[session_id] = []

                sessions[session_id].append(event)
    except (OSError, UnicodeDecodeError) as exc:
        raise LogParseError(f"Could not read {input_file}: {exc}") from exc

    if not sessions:
        raise LogParseError(f"No session events found in {input_file}.")

    print(f"Parsed {len(sessions)} unique sessions.")

    _write_json_atomic(output_file, sessions)

    # Confirm the written file is a readable sessions object with the expected count.
    try:
        with open(output_file, 'r') as f:
            written = json.load(f)
    except (OSError, ValueError) as exc:
        raise LogParseError(f"Written output {output_file} could not be read back: {exc}") from exc
    if not isinstance(written, dict) or len(written) != len(sessions):
        raise LogParseError(f"Written output {output_file} does not contain the {len(sessions)} parsed sessions.")

    print(f"Saved parsed sessions to {output_file}")
    return len(sessions)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse Cowrie Logs')
    parser.add_argument('--input', type=str, default='data/raw/cowrie.json', help='Path to raw cowrie.json')
    parser.add_argument('--output', type=str, default='data/parsed/sessions.json', help='Path to save grouped sessions')

    args = parser.parse_args()
    try:
        parse_logs(args.input, args.output)
    except LogParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if os.path.exists(args.output):
            print(f"Error: existing {args.output} was not updated by this run.", file=sys.stderr)
        sys.exit(1)
