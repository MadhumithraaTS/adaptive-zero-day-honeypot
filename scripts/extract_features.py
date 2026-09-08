import json
import csv
import argparse
from datetime import datetime
import os
import math

RECON_KEYWORDS = ['whoami', 'uname', 'id', 'pwd', 'ls', 'cat /etc/passwd', 'cat /etc/issue', 'hostname', 'w', 'ps', 'ifconfig', 'ip a']
PRIV_ESC_KEYWORDS = ['sudo', 'su', '/etc/shadow', 'id_rsa', 'chmod 777', 'chmod +s', 'crontab']
NETWORK_KEYWORDS = ['wget', 'curl', 'scp', 'nc', 'tftp', 'ftp', 'ssh', 'ping']
EVASION_KEYWORDS = ['rm ', 'history -c', 'unset HISTFILE', 'HISTSIZE=0', 'kill', 'killall']

PROTO_MAP = {'ssh': 1, 'telnet': 2, 'http': 3, 'ftp': 4, 'tcp': 5, 'udp': 6}
SERVICE_MAP = {22: 'ssh', 23: 'telnet', 80: 'http', 443: 'https',
               21: 'ftp', 2222: 'ssh', 2223: 'ssh'}

DPKT_EVENT_IDS = {
    'cowrie.client.version',
    'cowrie.client.kex',
    'cowrie.login.success',
    'cowrie.login.failed',
    'cowrie.client.size',
    'cowrie.session.params',
    'cowrie.command.success',
    'cowrie.command.failed',
    'cowrie.log.closed',
}


def encode_proto(proto_str: str) -> int:
    return PROTO_MAP.get(proto_str.lower(), 0) if proto_str else 0


def calculate_std_dev(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(variance)


def extract_features(input_file, output_file, details_output=None):
    if not os.path.exists(input_file):
        print(f"Error: {input_file} does not exist.")
        return

    with open(input_file, 'r') as f:
        sessions = json.load(f)

    features_list = []
    session_details = {}

    # State counters for cross-session connection metrics (ct_* features)
    src_ip_counts = {}
    dst_ip_counts = {}
    srv_src_counts = {}
    srv_dst_counts = {}

    for session_id, events in sessions.items():
        first_evt = events[0] if events else {}
        ip_src = first_evt.get('src_ip', '127.0.0.1')
        ip_dst = first_evt.get('dst_ip', '172.18.0.2')
        port_dst = first_evt.get('dst_port', 2222)
        srv_name = SERVICE_MAP.get(port_dst, 'ssh')

        src_ip_counts[ip_src] = src_ip_counts.get(ip_src, 0) + 1
        dst_ip_counts[ip_dst] = dst_ip_counts.get(ip_dst, 0) + 1
        srv_src_key = f"{ip_src}:{srv_name}"
        srv_src_counts[srv_src_key] = srv_src_counts.get(srv_src_key, 0) + 1
        srv_dst_key = f"{ip_dst}:{srv_name}"
        srv_dst_counts[srv_dst_key] = srv_dst_counts.get(srv_dst_key, 0) + 1

    for session_id, events in sessions.items():
        src_ip = "127.0.0.1"
        src_port = 0
        auth_success = 0
        commands = []
        unique_commands = set()
        cmd_timestamps = []
        dpkt_timestamps = []
        start_time = None
        end_time = None
        downloads = 0
        failed_commands = 0
        shell_spawn = 0
        login_attempts = 0

        recon_count = 0
        priv_esc_count = 0
        network_count = 0
        evasion_count = 0

        dst_ip = ""
        dst_port = 0
        protocol_str = "ssh"
        duration_ms_direct = None
        tty_size_bytes = 0
        spkts = 0
        dpkts = 0
        sbytes = 0

        # Ground truth labels attached during session generation
        attack_cat = "normal"
        label = 0

        kex_time = None
        auth_time = None
        first_cmd_time = None

        for event in events:
            event_id = event.get('eventid', '')
            ts_str = event.get('timestamp')

            if 'attack_cat' in event and attack_cat == "normal":
                attack_cat = event['attack_cat']
            if 'label' in event and label == 0:
                label = event['label']

            if 'src_ip' in event and src_ip == "127.0.0.1":
                src_ip = event['src_ip']
            if 'src_port' in event and src_port == 0:
                src_port = event['src_port']
            if 'dst_ip' in event and not dst_ip:
                dst_ip = event['dst_ip']
            if 'dst_port' in event and dst_port == 0:
                dst_port = event['dst_port']
            if 'protocol' in event and protocol_str == "ssh":
                protocol_str = event['protocol']

            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                    if not start_time or dt < start_time:
                        start_time = dt
                    if not end_time or dt > end_time:
                        end_time = dt

                    if event_id == 'cowrie.client.kex' and not kex_time:
                        kex_time = dt
                    elif event_id in ['cowrie.login.success', 'cowrie.login.failed'] and not auth_time:
                        auth_time = dt
                    elif event_id == 'cowrie.command.input' and not first_cmd_time:
                        first_cmd_time = dt
                except Exception:
                    pass

            if event_id == 'cowrie.session.closed':
                raw_ms = event.get('duration_ms')
                if raw_ms is not None:
                    try:
                        duration_ms_direct = float(raw_ms)
                    except (ValueError, TypeError):
                        pass

            if event_id == 'cowrie.log.closed':
                raw_size = event.get('size')
                if raw_size is not None:
                    try:
                        tty_size_bytes += int(raw_size)
                    except (ValueError, TypeError):
                        pass

            if event_id == 'cowrie.login.success':
                login_attempts += 1
                auth_success = 1
            elif event_id == 'cowrie.login.failed':
                login_attempts += 1

            elif event_id == 'cowrie.command.input':
                cmd = event.get('input', '').strip()
                commands.append(cmd)
                unique_commands.add(cmd)

                spkts += 1
                sbytes += len(cmd.encode('utf-8'))

                if ts_str:
                    try:
                        cmd_timestamps.append(
                            datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                        )
                    except Exception:
                        pass

                cmd_lower = cmd.lower()
                if any(kw in cmd_lower for kw in RECON_KEYWORDS):
                    recon_count += 1
                if any(kw in cmd_lower for kw in PRIV_ESC_KEYWORDS):
                    priv_esc_count += 1
                if any(kw in cmd_lower for kw in NETWORK_KEYWORDS):
                    network_count += 1
                if any(kw in cmd_lower for kw in EVASION_KEYWORDS):
                    evasion_count += 1

            elif event_id == 'cowrie.command.failed':
                failed_commands += 1

            elif event_id == 'cowrie.session.file_download':
                downloads += 1

            elif event_id == 'cowrie.client.size':
                shell_spawn = 1

            if event_id in DPKT_EVENT_IDS:
                dpkts += 1
                if ts_str:
                    try:
                        dpkt_timestamps.append(
                            datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                        )
                    except Exception:
                        pass

        # ------------------------------------------------------------------ #
        # Session duration & timing metrics
        # ------------------------------------------------------------------ #
        if duration_ms_direct is not None:
            session_duration = duration_ms_direct / 1000.0
        elif start_time and end_time:
            session_duration = (end_time - start_time).total_seconds()
        else:
            session_duration = 0.0

        dur = round(session_duration, 6)
        proto = protocol_str.lower()
        service = SERVICE_MAP.get(dst_port, f"port_{dst_port}" if dst_port else "ssh")

        dbytes = tty_size_bytes
        rate = round((sbytes + dbytes) / session_duration, 4) if session_duration > 0 else 0.0
        sttl = 64
        dttl = 64
        sload = round((sbytes * 8) / session_duration, 4) if session_duration > 0 else 0.0
        dload = round((dbytes * 8) / session_duration, 4) if session_duration > 0 else 0.0

        # --- 13. sinpkt ---
        sinpkt = 0.0
        src_intervals = []
        if len(cmd_timestamps) > 1:
            src_intervals = [
                (cmd_timestamps[i] - cmd_timestamps[i - 1]).total_seconds()
                for i in range(1, len(cmd_timestamps))
            ]
            sinpkt = round(sum(src_intervals) / len(src_intervals), 6)

        # --- 14. dinpkt ---
        dinpkt = 0.0
        dst_intervals = []
        if len(dpkt_timestamps) > 1:
            dst_intervals = [
                (dpkt_timestamps[i] - dpkt_timestamps[i - 1]).total_seconds()
                for i in range(1, len(dpkt_timestamps))
            ]
            dinpkt = round(sum(dst_intervals) / len(dst_intervals), 6)

        # --- 15. sjit (Source Jitter) & 16. djit (Destination Jitter) ---
        sjit = round(calculate_std_dev(src_intervals), 6)
        djit = round(calculate_std_dev(dst_intervals), 6)

        # --- 17. tcprtt (SSH Handshake Round-Trip Time) ---
        tcprtt = 0.0
        if start_time and kex_time:
            tcprtt = round((kex_time - start_time).total_seconds(), 6)

        # --- 18. synack (SYN-to-SYN/ACK timing proxy) ---
        synack = round(tcprtt * 0.45, 6) if tcprtt > 0 else 0.0

        # --- 19. ackdat (ACK-to-Data timing proxy) ---
        ackdat = 0.0
        if auth_time and first_cmd_time:
            ackdat = round(max(0.0, (first_cmd_time - auth_time).total_seconds()), 6)

        # --- 20-24. Connection Count Telemetry Features ---
        ct_src_ltm = src_ip_counts.get(src_ip, 1)
        ct_dst_ltm = dst_ip_counts.get(dst_ip, 1)
        srv_name_clean = SERVICE_MAP.get(dst_port, 'ssh')
        ct_srv_src = srv_src_counts.get(f"{src_ip}:{srv_name_clean}", 1)
        ct_srv_dst = srv_dst_counts.get(f"{dst_ip}:{srv_name_clean}", 1)
        ct_state_ttl = 1 if sttl == 64 and dttl == 64 else 0

        # ------------------------------------------------------------------ #
        # Assemble complete 24 UNSW-NB15 feature vector + labels
        # ------------------------------------------------------------------ #
        features = {
            'session_id': session_id,
            'src_ip': src_ip,
            'src_port': src_port,

            # --- 24 UNSW-NB15 Features ---
            'dur': dur,
            'proto': proto,
            'service': service,
            'spkts': spkts,
            'dpkts': dpkts,
            'sbytes': sbytes,
            'dbytes': dbytes,
            'rate': rate,
            'sttl': sttl,
            'dttl': dttl,
            'sload': sload,
            'dload': dload,
            'sinpkt': sinpkt,
            'dinpkt': dinpkt,
            'sjit': sjit,
            'djit': djit,
            'tcprtt': tcprtt,
            'synack': synack,
            'ackdat': ackdat,
            'ct_srv_src': ct_srv_src,
            'ct_state_ttl': ct_state_ttl,
            'ct_dst_ltm': ct_dst_ltm,
            'ct_src_ltm': ct_src_ltm,
            'ct_srv_dst': ct_srv_dst,

            # --- Ground Truth Labels ---
            'attack_cat': attack_cat,
            'label': label
        }

        features_list.append(features)

        session_details[session_id] = {
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': protocol_str,
            'auth_success': auth_success,
            'commands': commands,
            'session_duration': session_duration,
            'features': features
        }

    print(f"Extracted 24 UNSW-NB15 features + ground-truth labels for {len(features_list)} sessions.")

    if features_list:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        keys = features_list[0].keys()
        with open(output_file, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(features_list)
        print(f"Saved 24-feature dataset + labels to {output_file}")

        if details_output:
            os.makedirs(os.path.dirname(details_output), exist_ok=True)
            with open(details_output, 'w') as f:
                json.dump(session_details, f, indent=4)
            print(f"Saved session sequence details to {details_output}")
    else:
        print("No features extracted.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Extract 24 UNSW-NB15 Features + Ground-Truth Labels')
    parser.add_argument('--input', type=str, default='data/parsed/sessions.json',
                        help='Path to parsed sessions.json')
    parser.add_argument('--output', type=str, default='data/parsed/behavior_features.csv',
                        help='Path to save features CSV')
    parser.add_argument('--details', type=str, default='data/parsed/session_details.json',
                        help='Path to save raw sequence details')

    args = parser.parse_args()
    extract_features(args.input, args.output, args.details)
