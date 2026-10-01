"""
parse_cowrie_log.py
--------------------
Parses a Cowrie text log (cowrie.log / all_logs.json) into two outputs:
  1. cowrie_events.json  — flat list of structured events (one per log line)
  2. attacker_profiles.json — one aggregated profile per source IP

Usage:
    python parse_cowrie_log.py <input_log_file>

Example:
    python parse_cowrie_log.py all_logs.json
"""

import re
import json
import sys
from collections import defaultdict
from datetime import datetime

# ── Regex patterns for each event type ───────────────────────────────────────

PATTERNS = {
    "new_connection": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}) "
        r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
        r"(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+) "
        r"\((?P<dst_ip>[\d.]+):(?P<dst_port>\d+)\) \[session: (?P<session>[a-f0-9]+)\]"
    ),
    "login_attempt": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}) "
        r"\[HoneyPotSSHTransport,\d+,(?P<src_ip>\d+\.\d+\.\d+\.\d+)\] "
        r"login attempt \[b'(?P<username>[^']+)'/b'(?P<password>[^']+)'\] "
        r"(?P<result>succeeded|failed)"
    ),
    "command": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}) "
        r"\[HoneyPotSSHTransport,\d+,(?P<src_ip>\d+\.\d+\.\d+\.\d+)\] "
        r"CMD: (?P<command>.+)"
    ),
    "connection_lost": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}) "
        r"\[HoneyPotSSHTransport,\d+,(?P<src_ip>\d+\.\d+\.\d+\.\d+)\] "
        r"Connection lost after (?P<duration>[\d.]+) seconds"
    ),
    "file_download": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}) "
        r"\[HoneyPotSSHTransport,\d+,(?P<src_ip>\d+\.\d+\.\d+\.\d+)\] "
        r".*(?:Downloading|download|wget|curl|tftp).* (?P<url>https?://\S+|ftp://\S+)"
    ),
    "sftp_open": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}) "
        r"\[HoneyPotSSHTransport,\d+,(?P<src_ip>\d+\.\d+\.\d+\.\d+)\] "
        r"SFTP openFile: b'(?P<filename>[^']+)'"
    ),
    "new_session_sftp": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}) "
        r"\[cowrie\.ssh\.factory\.CowrieSSHFactory\] New connection: "
        r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)"
    ),
}


def parse_timestamp(ts_str):
    """Convert timestamp string to ISO format string."""
    try:
        dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S+%f")
        return dt.isoformat()
    except Exception:
        return ts_str


def parse_log(filepath):
    events = []
    
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            matched = False
            for event_type, pattern in PATTERNS.items():
                m = pattern.search(line)
                if m:
                    data = m.groupdict()
                    event = {
                        "event_type": event_type,
                        "timestamp": data.get("timestamp", ""),
                        "src_ip": data.get("src_ip", ""),
                    }
                    # Add event-specific fields
                    if event_type == "new_connection":
                        event["session"] = data.get("session", "")
                        event["src_port"] = data.get("src_port", "")
                    elif event_type == "login_attempt":
                        event["username"] = data.get("username", "")
                        event["password"] = data.get("password", "")
                        event["result"] = data.get("result", "")
                    elif event_type == "command":
                        event["command"] = data.get("command", "").strip()
                    elif event_type == "connection_lost":
                        event["duration_seconds"] = float(data.get("duration", 0))
                    elif event_type == "file_download":
                        event["url"] = data.get("url", "")
                    elif event_type == "sftp_open":
                        event["filename"] = data.get("filename", "")

                    events.append(event)
                    matched = True
                    break

    return events


def build_profiles(events):
    """Aggregate events into one profile per source IP."""
    profiles = defaultdict(lambda: {
        "src_ip": "",
        "first_seen": "",
        "last_seen": "",
        "total_events": 0,
        "sessions": [],
        "login_attempts": [],
        "successful_logins": 0,
        "failed_logins": 0,
        "commands": [],
        "file_downloads": [],
        "sftp_files": [],
        "total_duration_seconds": 0.0,
        "connection_count": 0,
    })

    for event in events:
        ip = event.get("src_ip", "")
        if not ip:
            continue

        p = profiles[ip]
        p["src_ip"] = ip
        p["total_events"] += 1

        ts = event.get("timestamp", "")
        if ts:
            if not p["first_seen"] or ts < p["first_seen"]:
                p["first_seen"] = ts
            if not p["last_seen"] or ts > p["last_seen"]:
                p["last_seen"] = ts

        etype = event.get("event_type")

        if etype == "new_connection":
            p["connection_count"] += 1
            session = event.get("session", "")
            if session and session not in p["sessions"]:
                p["sessions"].append(session)

        elif etype == "login_attempt":
            attempt = {
                "username": event.get("username", ""),
                "password": event.get("password", ""),
                "result": event.get("result", ""),
                "timestamp": ts,
            }
            p["login_attempts"].append(attempt)
            if event.get("result") == "succeeded":
                p["successful_logins"] += 1
            else:
                p["failed_logins"] += 1

        elif etype == "command":
            p["commands"].append({
                "command": event.get("command", ""),
                "timestamp": ts,
            })

        elif etype == "connection_lost":
            p["total_duration_seconds"] += event.get("duration_seconds", 0.0)

        elif etype == "file_download":
            p["file_downloads"].append(event.get("url", ""))

        elif etype == "sftp_open":
            p["sftp_files"].append(event.get("filename", ""))

    # Compute derived features for ML
    for ip, p in profiles.items():
        cmd_count = len(p["commands"])
        duration = p["total_duration_seconds"]
        p["command_count"] = cmd_count
        p["intensity"] = round(cmd_count / duration, 4) if duration > 0 else 0.0
        p["unique_usernames"] = len(set(a["username"] for a in p["login_attempts"]))
        p["unique_passwords"] = len(set(a["password"] for a in p["login_attempts"]))
        p["login_attempt_count"] = len(p["login_attempts"])
        p["has_file_activity"] = len(p["file_downloads"]) > 0 or len(p["sftp_files"]) > 0

    return dict(profiles)


def main():
    if len(sys.argv) < 2:
        print("Usage: python parse_cowrie_log.py <log_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    print(f"[*] Parsing: {filepath}")

    events = parse_log(filepath)
    print(f"[+] Parsed {len(events)} events")

    profiles = build_profiles(events)
    print(f"[+] Built {len(profiles)} attacker profiles")

    # Write flat events
    with open("cowrie_events.json", "w") as f:
        json.dump(events, f, indent=2)
    print("[+] Saved: cowrie_events.json")

    # Write profiles
    with open("attacker_profiles.json", "w") as f:
        json.dump(list(profiles.values()), f, indent=2)
    print("[+] Saved: attacker_profiles.json")

    # Quick summary
    print("\n── Summary ──────────────────────────────")
    print(f"  Unique IPs:        {len(profiles)}")
    total_logins = sum(p["login_attempt_count"] for p in profiles.values())
    total_cmds   = sum(p["command_count"] for p in profiles.values())
    total_files  = sum(1 for p in profiles.values() if p["has_file_activity"])
    print(f"  Total login attempts: {total_logins}")
    print(f"  Total commands:       {total_cmds}")
    print(f"  IPs with file activity: {total_files}")
    print("─────────────────────────────────────────")


if __name__ == "__main__":
    main()
