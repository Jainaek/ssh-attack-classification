import os
import json
import random

JSON_DIR = '/media/sf_shared/archive/json_log/json_log/'
ip_events = {}

for fname in sorted(os.listdir(JSON_DIR)):
    fpath = os.path.join(JSON_DIR, fname)
    with open(fpath, errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                ip = e.get('src_ip')
                if ip:
                    if ip not in ip_events:
                        ip_events[ip] = []
                    ip_events[ip].append(e)
            except:
                continue

MALWARE_COMMANDS = ['wget','curl','chmod +x','rm -rf','/bin/sh','bash -i','python -c','perl -e','nc ','ncat','tftp','base64 -d','>/dev/','mkfifo','nohup']
COMMON_USERNAMES = {'root','admin','ubuntu','user','test','guest','oracle','pi','vagrant'}

profiles = {}
for ip, events in ip_events.items():
    commands = [e.get('input','') for e in events if e.get('input')]
    login_failed = sum(1 for e in events if e.get('eventid') == 'cowrie.login.failed')
    login_success = sum(1 for e in events if e.get('eventid') == 'cowrie.login.success')
    downloads = sum(1 for e in events if e.get('eventid') == 'cowrie.session.file_download')
    malware_cmds = sum(1 for c in commands if any(m in c for m in MALWARE_COMMANDS))
    usernames = set(e.get('username','') for e in events if e.get('username'))
    lateral = sum(1 for e in events if e.get('eventid') == 'cowrie.direct-tcpip.request')
    recon = sum(1 for e in events if e.get('eventid') in ['cowrie.client.version','cowrie.session.params'])
    hits = len(events)

    if downloads > 0 or malware_cmds > 0:
        attack_type = 'Malware Deployment'
    elif lateral > 0:
        attack_type = 'Lateral Movement'
    elif login_success > 0 and len(commands) > 0 and malware_cmds == 0:
        attack_type = 'Post-Exploitation'
    elif login_success > 0 and login_failed < 20:
        attack_type = 'Credential Stuffing'
    elif login_failed > 0 and len(usernames & COMMON_USERNAMES) >= 3:
        attack_type = 'Dictionary Attack'
    elif login_failed > 10 and login_success == 0:
        attack_type = 'Brute Force'
    elif recon > 0:
        attack_type = 'Reconnaissance'
    else:
        attack_type = 'Brute Force'

    profiles[ip] = {'attack_type': attack_type, 'hits': hits, 'events': events}

by_type = {}
for ip, p in profiles.items():
    t = p['attack_type']
    if t not in by_type:
        by_type[t] = []
    by_type[t].append(ip)

print("Available attack types:")
for t, ips in by_type.items():
    print(f"  {t}: {len(ips)} IPs")

targets = {
    'Malware Deployment': 8,
    'Brute Force': 6,
    'Reconnaissance': 5,
    'Dictionary Attack': 5,
    'Post-Exploitation': 5,
    'Credential Stuffing': 4,
    'Lateral Movement': 3
}

selected_ips = []
for attack_type, count in targets.items():
    available = by_type.get(attack_type, [])
    picked = random.sample(available, min(count, len(available)))
    selected_ips += picked
    print(f"Picked {len(picked)} from {attack_type}")

subset_events = []
for ip in selected_ips:
    subset_events += profiles[ip]['events']

print(f"\nTotal IPs: {len(selected_ips)}")
print(f"Total events: {len(subset_events)}")
print(f"\n{'IP':<20} {'Type':<25} {'Hits':>6}")
print("-" * 55)
for ip in selected_ips:
    p = profiles[ip]
    print(f"{ip:<20} {p['attack_type']:<25} {p['hits']:>6}")

with open('/media/sf_shared/subset_dir/subset_ndjson.json', 'w') as f:
    for event in subset_events:
        f.write(json.dumps(event) + '\n')

print(f"\nSaved directly as NDJSON to subset_dir. Ready for pipeline.")