# VirusTotal Bulk IP Checker

This program checks a list of IP addresses against VirusTotal using the VirusTotal API and exports the results to a CSV file.

## Setup

Sign into VirusTotal using your TekSynap account.

Go to your VirusTotal settings/API key page and copy your private API key.

Create a file named:

```txt
api_key.txt
```

Paste only your API key into that file. Do not add quotes or extra text.

Example:

```txt
your_api_key_here
```

## Add IP Addresses

Insert the IP addresses into `ips.txt`, one IP per line, with no separating commas.

Example:

```txt
24.54.233.14
8.8.8.8
1.1.1.1
```

## Run the Program

Open a terminal in the project folder and run:

```bash
python main.py
```

or simply press the run button in VS Code

## Output

After the script finishes, the results will be saved to:

```txt
results.csv
```

Open `results.csv` in Excel to review the VirusTotal results.

## Notes

Do not share your `api_key.txt` file or commit it to GitHub. Each user should use their own VirusTotal API key.

## Recommended: Use a Virtual Environment

It is safest to create a Python virtual environment before running the program. This keeps the required Python package separate from your system-wide Python installation.

This program requires the `requests` package.

- install this in your .venv by using
> `pip install requests`
in the temrinal