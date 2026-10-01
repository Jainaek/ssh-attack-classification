# SSH Attack Classification Framework

A lightweight monitoring system that classifies SSH attackers from a Cowrie honeypot, enriches each one with an attack type and severity score, and sends a single consolidated alert per attacker to the Wazuh SIEM.

Final-year BSc Computer Science project, Covenant University, 2026.
**Title:** *Development of a Lightweight Monitoring System for Automated Classification of SSH Attacks Using a Honeypot Generated Dataset*
**Author:** Jaina Chukwufumnanya Ekome

## The problem

A honeypot exposed to the internet produces hundreds of thousands of raw events. Analysts cannot read them all, so important activity gets buried (alert fatigue). This project groups events by attacker, classifies each attacker, and raises one prioritised alert per attacker.

## How it works

Five stages:

1. **Collection:** a Cowrie medium-interaction SSH honeypot logs attacker activity as JSON.
2. **Aggregation and classification:** a Python bridge script groups events by source IP and extracts three features: total hits, session duration and attack intensity. A Random Forest classifier labels each attacker as `BOT` or `HUMAN`.
3. **Enrichment:** a rule-based classifier assigns one of seven attack types and a composite severity score (Low, Medium, High, Critical).
4. **SIEM integration:** consolidated alerts are written to a log file. Wazuh reads them using custom decoders and rules (rule IDs 110100 to 110306).
5. **Visualisation:** a standalone HTML SOC dashboard loads Wazuh's `alerts.json` and shows stat cards, charts, a filterable alert feed and a per-attacker detail view. It needs no server or installation.

Attack types: Malware Deployment, Reconnaissance, Brute Force, Post-Exploitation, Credential Stuffing, Dictionary Attack, Lateral Movement.

## Results

Data came from a Cowrie honeypot run on an internet-facing server for six weeks.

| Metric | Value |
| --- | --- |
| Raw events processed | 524,184 |
| Consolidated alerts (unique attacker IPs) | 1,811 |
| Alert reduction | 99.65% |
| Random Forest accuracy | 89% |
| Macro F1 | 0.79 |
| BOT F1 / precision / recall | 0.94 / 0.95 / 0.93 |
| HUMAN F1 / precision / recall | 0.65 / 0.60 / 0.70 |

The test set had 352 BOT and 60 HUMAN sessions. HUMAN results rest on a small sample and should not be generalised. Class imbalance was handled with `class_weight="balanced"`.

Attack type distribution: Malware Deployment 68%, Reconnaissance 18%, Brute Force 7%, Post-Exploitation 4%, Credential Stuffing 1%, Dictionary Attack 1%, Lateral Movement 1%.

## Repository layout

```
pipeline/      Bridge script, dataset preparation, training and evaluation scripts
wazuh/         Custom Wazuh decoders and rules (XML)
experiments/   SMOTE and K-Means experiments
results/       Saved evaluation metrics (JSON)
dashboard/     Standalone SOC dashboard (HTML)
```

## Requirements

- Python 3 with scikit-learn
- Wazuh 4.x, running in a VirtualBox VM
- Ubuntu 20.04 or higher (VM) and Windows 10 or higher (host)
- Any modern web browser for the dashboard
- 8 GB RAM minimum, 16 GB recommended

## Setup

1. Copy the files in `wazuh/` into the Wazuh manager's decoder and rule directories (`/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/`), then restart the manager.
2. Run the bridge script in `pipeline/` on your Cowrie logs to produce the consolidated alert file that Wazuh monitors.
3. Export Wazuh's `alerts.json` and open the dashboard HTML in a browser, then load that file.

## Data

Raw honeypot logs and trained models are not included. The logs contain real attacker IP addresses and captured credentials. To reproduce the results, deploy your own Cowrie honeypot and retrain the classifier with the scripts in `pipeline/`.

## Limitations

- One source IP is treated as one attacker, which fails behind NAT, VPNs or rotating botnet nodes.
- Only three features are used.
- Attack types come from fixed keyword rules.
- Data comes from a honeypot, so attacker behaviour may differ on live systems.
- Processing is batch only, not streaming.

This is a proof of concept, not a production tool.
