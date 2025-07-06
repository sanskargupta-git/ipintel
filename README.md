# 🌐 IPIntel – Malicious IP Checker (Offline Threat Intel)

**IPIntel** is a fast CLI tool to check if IP addresses are suspicious, blacklisted, or geo-located to flagged countries using offline simulated threat feeds.

## ✅ Features

- Accepts single IP or file of IPs
- Checks against a blacklist (simulated)
- Flags suspicious countries (e.g. RU, CN, IR)
- Optional report output to file

## 🛠️ Usage

```bash
python ipintel.py -i 45.33.32.156
python ipintel.py -f ips.txt -o report.csv
