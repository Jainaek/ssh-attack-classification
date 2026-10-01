#!/usr/bin/env python3
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

LOG_FILE = "/var/ossec/logs/cowrie_alerts.log"

RULES = {
    'BOT_LOW': 110101, 'BOT_MEDIUM': 110103, 'BOT_HIGH': 110104, 'BOT_CRITICAL': 110105,
    'HUMAN_LOW': 110102, 'HUMAN_HIGH': 110106, 'HUMAN_CRITICAL': 110107
}

LEVELS = {
    'BOT_LOW': 8, 'BOT_MEDIUM': 11, 'BOT_HIGH': 13, 'BOT_CRITICAL': 15,
    'HUMAN_LOW': 10, 'HUMAN_HIGH': 13, 'HUMAN_CRITICAL': 15
}

def parse_log():
    alerts = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('COWRIE:'):
                    continue
                try:
                    json_str = line[len('COWRIE:'):].strip()
                    d = json.loads(json_str)
                    tier = d.get('severity', '')
                    alerts.append({
                        'ip':        d.get('src_ip', ''),
                        'type':      d.get('classification', ''),
                        'tier':      tier,
                        'hits':      int(d.get('total_hits', 0)),
                        'dur':       float(d.get('duration_mins', 0)),
                        'intensity': float(d.get('intensity', 0)),
                        'level':     LEVELS.get(tier, 0),
                        'rule':      RULES.get(tier, 0)
                    })
                except Exception:
                    continue
    except FileNotFoundError:
        print(f"Log file not found: {LOG_FILE}")
    except Exception as e:
        print(f"Error reading log: {e}")
    return alerts

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/alerts':
            data = parse_log()
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress request logs

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8888), Handler)
    print("Cowrie alert server running on http://localhost:8888/alerts")
    print(f"Reading from: {LOG_FILE}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
