import subprocess
import os
import sys
import argparse

def _sudo_fallback_available():
    # Windows `sudo` is a different tool that rejects `-n`; the fallback only applies to POSIX docker setups.
    return os.name != 'nt'

def _describe_failure(exc):
    if isinstance(exc, FileNotFoundError):
        return f"command not found ({exc.filename or exc})"
    if isinstance(exc, subprocess.CalledProcessError):
        detail = exc.stderr.decode(errors='replace').strip() if isinstance(exc.stderr, bytes) else (exc.stderr or '').strip()
        return f"exit status {exc.returncode}" + (f": {detail}" if detail else "")
    return str(exc)

def collect_logs(container_name, dest_path):
    """Copy cowrie.json out of the container. Returns True only if a non-empty snapshot was copied."""
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
    except (subprocess.CalledProcessError, FileNotFoundError) as docker_error:
        failures = [f"docker cp failed: {_describe_failure(docker_error)}"]
        copied = False
        if _sudo_fallback_available():
            try:
                # Fallback to sudo docker cp on Linux systems where non-root lacks docker socket access
                subprocess.run(['sudo', '-n', 'docker', 'cp', source_path, dest_path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print("Successfully collected logs via sudo docker cp.")
                copied = True
            except Exception as sudo_error:
                failures.append(f"sudo -n docker cp fallback failed: {_describe_failure(sudo_error)}")
        if not copied:
            # A pre-existing file at dest_path is stale, so it must not be reported as a fresh snapshot.
            print(f"Error: Could not copy logs from Docker container '{container_name}'.", file=sys.stderr)
            for failure in failures:
                print(f"  {failure}", file=sys.stderr)
            if os.path.exists(dest_path):
                print(f"Error: {dest_path} was not refreshed; it is a stale earlier snapshot.", file=sys.stderr)
            return False

    if not os.path.isfile(dest_path):
        print(f"Error: Snapshot missing after copy: {dest_path}", file=sys.stderr)
        return False
    if os.path.getsize(dest_path) == 0:
        print(f"Error: Snapshot is empty: {dest_path}", file=sys.stderr)
        return False
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Collect Cowrie Logs')
    parser.add_argument('--container', type=str, default='cowrie-project', help='Cowrie docker container name')
    parser.add_argument('--dest', type=str, default='data/raw/cowrie.json', help='Destination path for collected logs')

    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.dest) or ".", exist_ok=True)
    sys.exit(0 if collect_logs(args.container, args.dest) else 1)
