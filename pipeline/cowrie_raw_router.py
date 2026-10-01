import json
import argparse
import logging
from datetime import datetime

RAW_LOG_FILE = "/var/ossec/logs/cowrie_raw.log"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DANGEROUS_COMMANDS = [
    "wget", "curl", "chmod", "rm", "nc", "nmap", "python",
    "perl", "bash", "sh", "cat /etc/passwd", "cat /etc/shadow",
    "uname", "whoami", "id", "ifconfig", "ip addr", "ps",
    "kill", "pkill", "dd", "mkfs", "iptables", "crontab"
]

def get_command_severity(command):
    cmd = command.lower().strip()
    for dangerous in DANGEROUS_COMMANDS:
        if dangerous in cmd:
            return "HIGH"
    if len(cmd) > 100:
        return "MEDIUM"
    return "LOW"

def route_raw_logs(log_path, limit=None, dry_run=False):
    with open(log_path) as f:
        data = json.load(f)

    log.info(f"Loaded {len(data)} raw events")

    if limit:
        data = data[:limit]
        log.info(f"Limited to first {limit} events")

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    written = 0

    with open(RAW_LOG_FILE, 'a') as f:
        for event in data:
            src_ip = event.get("src_ip", "unknown")
            eventid = event.get("eventid", "unknown")
            command = event.get("command", "")
            timestamp = event.get("timestamp", datetime.utcnow().isoformat())
            severity = get_command_severity(command)
            counts[severity] += 1

            payload = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "eventid": eventid,
                "command": command,
                "severity": severity
            }

            line = "COWRIE_RAW: " + json.dumps(payload) + "\n"

            if dry_run:
                if written < 5:
                    log.info(f"[DRY RUN] {line.strip()}")
            else:
                f.write(line)
            written += 1

    log.info(f"Done. {written} events written.")
    log.info(f"Command severity breakdown: HIGH={counts['HIGH']}, MEDIUM={counts['MEDIUM']}, LOW={counts['LOW']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', required=True)
    parser.add_argument('--limit', type=int, default=None, help='Max events to send (default: all)')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    route_raw_logs(args.log, limit=args.limit, dry_run=args.dry_run)
