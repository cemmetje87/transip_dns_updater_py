# TransIP DNS Updater (Python)

Python port of the TransIP dynamic DNS updater. It fetches your current public IP
address and updates a DNS record in your TransIP account when the IP changes.

## Features

- Updates a configurable TransIP DNS record (`@` A record by default).
- Falls back through multiple public IP discovery services if one fails.
- Validates discovered IPs before touching DNS.
- Logs to stderr with timestamps.
- Supports `--dry-run` and `--list` modes.
- Unit tested with mocked API calls.

## Compatibility & Reliability

- Runs on any machine with Python 3.8 or newer. Dependencies are only the standard library plus `requests` and `python-transip`.
- Retries transient failures (HTTP 408/425/429/5xx and network errors) with exponential backoff and jitter, on both the public IP discovery services and the TransIP API calls. Non-retryable errors (401/403/404, invalid data) fail fast.
- Fails over across multiple public IP discovery services when one is exhausted.
- Retry behavior is configurable via `max_retries`, `retry_backoff`, and `retry_max_delay` in `config.ini`.

## Quick start

See [INSTALL.md](INSTALL.md) for detailed setup instructions.

```bash
git clone https://github.com/cemmetje87/transip_dns_updater_py.git
cd transip_dns_updater_py
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# copy your TransIP private key and create config.ini
cp /path/to/private.key ./private.key
chmod 600 private.key
# edit config.ini with your username

python3 main.py
```

## Usage

```text
python3 main.py [-h] [--list] [--dry-run] [--config CONFIG] [-v]
```

| Option | Description |
|--------|-------------|
| `--list` | List DNS records for the selected domain and exit. |
| `--dry-run` | Show what would be updated without making changes. |
| `--config CONFIG` | Path to config file (default: `config.ini`). |
| `-v`, `--verbose` | Enable debug logging. |

## Configuration

Example `config.ini`:

```ini
[config]
username = your_transip_username
private_key_path = ./private.key
# domain = example.com   # Optional. Uses first domain if omitted.
recordname = @
recordtype = A
ip_services = https://ipecho.net/plain,https://ifconfig.me/ip,https://api.ipify.org,https://checkip.amazonaws.com
max_retries = 3
retry_backoff = 1.0
retry_max_delay = 30.0
```

`config.ini` and `private.key` are `.gitignore`d and must never be committed.

## Testing

```bash
source .venv/bin/activate
pytest
```

## License

MIT
