# VirusTotal Bulk IP Checker

A small Python tool that checks a list of IP addresses against the [VirusTotal API](https://docs.virustotal.com/reference/ip-info) and exports the results to a CSV you can open in Excel.

I built it to speed up a repetitive task: looking up dozens of IPs one at a time in the VirusTotal web UI. Instead, you drop them in a text file, run one command, and get a spreadsheet with detection counts, reputation, country, AS owner and a direct link for each IP.

## Features

- Validates every line and skips anything that isn't a real IPv4/IPv6 address
- Removes duplicate IPs while keeping the original order
- Waits and retries automatically when VirusTotal returns a rate limit (HTTP 429)
- Default request delay stays inside the free API tier (4 requests/min)
- Outputs one row per IP with `malicious`, `suspicious`, `harmless`, `undetected`, `reputation`, `country`, `as_owner`, `network`, last analysis date and a VirusTotal link

## Setup

Requires Python 3.9+.

```bash
python3 -m venv .venv
source .venv/bin/activate        # on windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### API key

Get a free API key from your VirusTotal account settings, then either:

- set it as an environment variable:

  ```bash
  export VT_API_KEY=your_key_here
  ```

- or copy `api_key.example.txt` to `api_key.txt` and paste your key in. `api_key.txt` is gitignored so it never gets committed.

## Usage

Put your IPs in `ips.txt`, one per line (lines starting with `#` are ignored):

```txt
8.8.8.8
1.1.1.1
24.54.233.14
```

Then run:

```bash
python3 vt_ip_scan.py
```

Results are written to `results.csv`.

### Options

| Flag | Default | Description |
|---|---|---|
| `--ips` | `ips.txt` | File with one IP per line |
| `--out` | `results.csv` | Where to write the CSV |
| `--key-file` | `api_key.txt` | File holding your API key (ignored if `VT_API_KEY` is set) |
| `--delay` | `15` | Seconds between requests. Use `0` with a premium key. |

Example with a premium key and custom files:

```bash
python3 vt_ip_scan.py --ips suspicious.txt --out report.csv --delay 0
```

## Notes

The free VirusTotal API allows 4 requests per minute and 500 per day, so a list of 100 IPs takes about 25 minutes at the default delay. Never commit your API key; each user should use their own.

## License

MIT
