import argparse

# Simulated malicious IPs (can be replaced with real feeds)
blacklist = {
    "45.33.32.156": "Known C2 Server",
    "103.21.244.0": "Botnet IP",
    "185.107.56.231": "Phishing Host",
    "198.51.100.13": "Abuse Spam Source"
}

flagged_countries = ["RU", "CN", "KP", "IR", "SY"]

# Simulated IP → country mapping
ip_country = {
    "45.33.32.156": "US",
    "103.21.244.0": "IN",
    "185.107.56.231": "NL",
    "198.51.100.13": "RU",
    "8.8.8.8": "US"
}

def check_ip(ip):
    print(f"🔍 Checking: {ip}")
    if ip in blacklist:
        print(f"  ⚠️ BLACKLISTED: {blacklist[ip]}")
    else:
        print("  ✅ Not found in blacklist.")

    country = ip_country.get(ip, "Unknown")
    print(f"  🌍 Country: {country}")
    if country in flagged_countries:
        print(f"  🚩 Suspicious country: {country}")

def process_inputs(ip_list, output=None):
    results = []
    for ip in ip_list:
        print("-" * 40)
        check_ip(ip)
        results.append(ip)

    if output:
        with open(output, "w") as f:
            for ip in ip_list:
                result = "BLACKLISTED" if ip in blacklist else "CLEAN"
                f.write(f"{ip},{result},{ip_country.get(ip, 'Unknown')}\n")
        print(f"\n📁 Results saved to: {output}")

def main():
    parser = argparse.ArgumentParser(description="🌐 IPIntel – Malicious IP Checker")
    parser.add_argument("-i", "--ip", help="Single IP to check")
    parser.add_argument("-f", "--file", help="File with list of IPs")
    parser.add_argument("-o", "--output", help="Optional output report file")
    args = parser.parse_args()

    ip_list = []

    if args.ip:
        ip_list.append(args.ip.strip())
    if args.file:
        with open(args.file, "r") as f:
            ip_list.extend([line.strip() for line in f if line.strip()])

    if not ip_list:
        print("❌ No IPs provided.")
        return

    process_inputs(ip_list, args.output)

if __name__ == "__main__":
    main()
