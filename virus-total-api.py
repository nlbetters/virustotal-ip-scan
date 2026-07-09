import csv
import ipaddress
import time
from datetime import datetime

import requests


from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

API_KEY_FILE = BASE_DIR / "api_key.txt"
IP_FILE = BASE_DIR / "ips.txt"
OUTPUT_FILE = BASE_DIR / "results.csv"

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Public VirusTotal API is limited. (says its 4/min but its actually faster.) [max = 500/day]
REQUEST_DELAY = 0.01


def read_api_key():
    try:
        with open(API_KEY_FILE, "r", encoding="utf-8") as file:
            api_key = file.read().strip()

        if not api_key:
            raise ValueError("API key file is empty.")

        return api_key

    except FileNotFoundError:
        raise SystemExit(f"Missing {API_KEY_FILE}. Create it and paste your VirusTotal API key inside.")


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def read_ips():
    try:
        with open(IP_FILE, "r", encoding="utf-8") as file:
            ips = []

            for line in file:
                ip = line.strip()

                if not ip or ip.startswith("#"):
                    continue

                if is_valid_ip(ip):
                    ips.append(ip)
                else:
                    print(f"[SKIPPED] Invalid IP: {ip}")

        # Removes duplicates while keeping original order
        return list(dict.fromkeys(ips))

    except FileNotFoundError:
        raise SystemExit(f"Missing {IP_FILE}. Create it and add one IP per line.")


def check_ip(ip, api_key):
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    url = VT_URL.format(ip=ip)

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            return response.json()

        if response.status_code == 429:
            print(f"[RATE LIMIT] VirusTotal rate limit hit for {ip}. Waiting 60 seconds...")
            time.sleep(60)
            return check_ip(ip, api_key)

        print(f"[ERROR] {ip} returned status {response.status_code}")
        return None

    except requests.RequestException as error:
        print(f"[ERROR] Request failed for {ip}: {error}")
        return None


def parse_result(ip, data):
    if not data:
        return {
            "ip": ip,
            "status": "error_or_not_found",
            "malicious": "",
            "suspicious": "",
            "harmless": "",
            "undetected": "",
            "reputation": "",
            "country": "",
            "as_owner": "",
            "network": "",
            "last_analysis_date": "",
            "virustotal_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
        }

    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    last_analysis_date = attributes.get("last_analysis_date", "")

    if last_analysis_date:
        last_analysis_date = datetime.fromtimestamp(last_analysis_date).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "ip": ip,
        "status": "ok",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation", ""),
        "country": attributes.get("country", ""),
        "as_owner": attributes.get("as_owner", ""),
        "network": attributes.get("network", ""),
        "last_analysis_date": last_analysis_date,
        "virustotal_link": f"https://www.virustotal.com/gui/ip-address/{ip}"
    }


def save_results(results):
    fieldnames = [
        "ip",
        "status",
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "reputation",
        "country",
        "as_owner",
        "network",
        "last_analysis_date",
        "virustotal_link"
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def main():
    api_key = read_api_key()
    ips = read_ips()

    if not ips:
        print("No valid IPs found in ips.txt.")
        return

    print(f"Loaded {len(ips)} IPs.")
    print("Starting VirusTotal checks...\n")

    results = []

    for index, ip in enumerate(ips, start=1):
        print(f"[{index}/{len(ips)}] Checking {ip}...")

        data = check_ip(ip, api_key)
        result = parse_result(ip, data)
        results.append(result)

        if index < len(ips):
            time.sleep(REQUEST_DELAY)

    save_results(results)

    print(f"\nDone. Results saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()