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

Or install the project directly:

```bash
pip install -e .
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
# domain = example.com    # Optional. If omitted, the first domain is used.
recordname = @
recordtype = A
ip_services = https://ipecho.net/plain,https://ifconfig.me/ip,https://api.ipify.org,https://checkip.amazonaws.com

# Retry behavior for transient failures (HTTP 408/425/429/5xx and network errors).
max_retries = 3
retry_backoff = 1.0
retry_max_delay = 30.0
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
- `-v` — enable debug logging.

## 6. Run tests

```bash
source .venv/bin/activate
pytest
```

## 7. Legacy variant for constrained / ARM systems

If your device cannot build or install `cryptography` (common on older ARMv7 NAS devices such as Marvell Armada XP systems), use the legacy updater:

```bash
# Only requests is required; no python-transip / cryptography
python3 -m venv .venv
source .venv/bin/activate
pip install requests

./transip_updater_legacy.py --list
./transip_updater_legacy.py --dry-run
```

Requirements for the legacy script:
- Python 3.8+
- `requests`
- The `openssl` CLI binary installed on the device
- The same `config.ini` and `private.key` used by `main.py`

The legacy script uses the `openssl` CLI to RSA-SHA512-sign the TransIP authentication request and talks to the TransIP REST API directly.

## 8. Automating with cron

After verifying the updater works, add it to your crontab, for example every 5 minutes:

```cron
*/5 * * * * cd /path/to/transip_dns_updater_py && /path/to/transip_dns_updater_py/.venv/bin/python main.py >> /var/log/transip_dns_updater.log 2>&1
```

For the legacy variant:

```cron
*/5 * * * * cd /path/to/transip_dns_updater_py && /path/to/transip_dns_updater_py/.venv/bin/python transip_updater_legacy.py >> /var/log/transip_dns_updater.log 2>&1
```

Make sure the `config.ini` and `private.key` paths are readable by the cron user.
