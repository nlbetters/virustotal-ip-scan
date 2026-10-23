import argparse
import csv
import ipaddress
import os
import time
from datetime import datetime
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent

API_KEY_FILE = BASE_DIR / "api_key.txt"
IP_FILE = BASE_DIR / "ips.txt"
OUTPUT_FILE = BASE_DIR / "results.csv"

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# free api keys get 4 requests/min (500/day), so 15s between calls keeps you under it.
# premium keys can go way faster, just pass --delay 0
REQUEST_DELAY = 15.0


def read_api_key(key_file=API_KEY_FILE):
    # env var wins so you dont have to keep a key file around at all
    env_key = os.environ.get("VT_API_KEY", "").strip()
    if env_key:
        return env_key

    try:
        with open(key_file, "r", encoding="utf-8") as file:
            api_key = file.read().strip()

        if not api_key:
            raise SystemExit(f"{key_file} is empty. Paste your VirusTotal API key inside.")

        return api_key

    except FileNotFoundError:
        raise SystemExit(
            f"No API key found. Set VT_API_KEY or create {key_file} "
            "(copy api_key.example.txt) and paste your key inside."
        )


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def read_ips(ip_file=IP_FILE):
    try:
        with open(ip_file, "r", encoding="utf-8") as file:
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
        raise SystemExit(f"Missing {ip_file}. Create it and add one IP per line.")


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


def save_results(results, output_file=OUTPUT_FILE):
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

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def parse_args():
    parser = argparse.ArgumentParser(description="check a list of ips against virustotal and save the results to csv")
    parser.add_argument("--ips", type=Path, default=IP_FILE, help="file with one ip per line (default: ips.txt)")
    parser.add_argument("--out", type=Path, default=OUTPUT_FILE, help="csv to write results to (default: results.csv)")
    parser.add_argument("--key-file", type=Path, default=API_KEY_FILE, help="file holding your api key (default: api_key.txt)")
    parser.add_argument("--delay", type=float, default=REQUEST_DELAY, help="seconds to wait between requests (default: 15, safe for free keys)")
    return parser.parse_args()


def main():
    args = parse_args()
    api_key = read_api_key(args.key_file)
    ips = read_ips(args.ips)

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
            time.sleep(args.delay)

    save_results(results, args.out)

    print(f"\nDone. Results saved to {args.out}")


if __name__ == "__main__":
    main()