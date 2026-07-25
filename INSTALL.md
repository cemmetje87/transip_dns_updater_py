# Installation

## Requirements

- Python 3.8 or newer
- A TransIP account with an API key pair (private key)

## 1. Clone the repository

```bash
git clone https://github.com/cemmetje87/transip_dns_updater_py.git
cd transip_dns_updater_py
```

## 2. Create a virtual environment

On Debian/Ubuntu and other PEP 668 managed systems, do not install into the system Python. Use a venv instead:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Configure credentials

Copy your TransIP private key into the project directory:

```bash
scp your_host:path/to/private.key ./private.key
chmod 600 private.key
```

Create a `config.ini` from this template:

```ini
[config]
username = your_transip_username
private_key_path = ./private.key
# domain =               # Optional. If omitted, the first domain is used.
recordname = @
recordtype = A
ip_url = https://ipecho.net/plain
```

`config.ini` and `private.key` are `.gitignore`d and must never be committed.

## 5. Run the updater

```bash
source .venv/bin/activate
python3 main.py
```

### Options

- `--dry-run` — show what would be changed without updating.
- `--list` — list the DNS records for the selected domain and exit.

## Automating with cron

After verifying the updater works, add it to your crontab, for example every 5 minutes:

```cron
*/5 * * * * cd /path/to/transip_dns_updater_py && /path/to/transip_dns_updater_py/.venv/bin/python main.py >> /var/log/transip_dns_updater.log 2>&1
```

Make sure the `config.ini` and `private.key` paths are readable by the cron user.
