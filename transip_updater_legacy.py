#!/usr/bin/env python3
"""TransIP DNS updater — legacy / low-dependency variant.

This version does not depend on `python-transip` or `cryptography`. It uses:
- `requests` for HTTP
- the `openssl` CLI for RSA-SHA512 signing of the authentication request

Intended for constrained systems (e.g. ARMv7 NAS devices) where building the
`cryptography` crate is slow, impossible, or undesirable.

Compatible with the same `config.ini` format as `main.py`.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import ipaddress
import json
import logging
import os
import random
import secrets
import stat
import string
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests


DEFAULT_IP_SERVICES = [
    "https://ipecho.net/plain",
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
]

TRANSIP_API_URL = "https://api.transip.nl/v6"

RETRYABLE_HTTP_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF = 1.0
DEFAULT_MAX_DELAY = 30.0

DEFAULT_CONFIG = """\
[config]
# TransIP login username (same as the account that owns the private key below).
username =

# Path to the TransIP private key downloaded from the control panel.
private_key_path = ./private.key

# Domain to update. If left empty, the first domain in the TransIP account is used.
domain =

# DNS record name and type to update.
recordname = @
recordtype = A

# Comma-separated list of services used to discover the current public IP.
ip_services = https://ipecho.net/plain,https://ifconfig.me/ip,https://api.ipify.org,https://checkip.amazonaws.com

# Retry behavior for transient failures (HTTP 408/425/429/5xx and network errors).
max_retries = 3
retry_backoff = 1.0
retry_max_delay = 30.0

# Set to true if your API key should be usable from any IP (not only whitelisted ones).
# Default is false to match the python-transip library behavior.
global_key = false
"""

logger = logging.getLogger(__name__)


@dataclass
class RetrySettings:
    max_retries: int = DEFAULT_MAX_RETRIES
    base_delay: float = DEFAULT_BACKOFF
    max_delay: float = DEFAULT_MAX_DELAY


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def read_config(path: Path) -> dict[str, str]:
    if not path.exists():
        path.write_text(DEFAULT_CONFIG)
        print(f"Created default config at {path}. Please fill it in and rerun.", file=sys.stderr)
        sys.exit(1)

    parser = configparser.ConfigParser()
    parser.read(path)
    return {k: v.strip() for k, v in parser["config"].items()}


def retry_settings(config: dict[str, str]) -> RetrySettings:
    def _int(key: str, default: int) -> int:
        raw = config.get(key)
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            logger.warning("Invalid %s value %r; using default %s", key, raw, default)
            return default

    def _float(key: str, default: float) -> float:
        raw = config.get(key)
        if not raw:
            return default
        try:
            return float(raw)
        except ValueError:
            logger.warning("Invalid %s value %r; using default %s", key, raw, default)
            return default

    return RetrySettings(
        max_retries=max(1, _int("max_retries", DEFAULT_MAX_RETRIES)),
        base_delay=max(0.0, _float("retry_backoff", DEFAULT_BACKOFF)),
        max_delay=max(0.0, _float("retry_max_delay", DEFAULT_MAX_DELAY)),
    )


# ---------------------------------------------------------------------------
# Retry / backoff
# ---------------------------------------------------------------------------


def is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, requests.exceptions.HTTPError):
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        return status in RETRYABLE_HTTP_CODES
    return isinstance(
        exc,
        (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            ConnectionError,
            TimeoutError,
            OSError,
        ),
    )


def retry_call(
    fn: Callable[[], object],
    *,
    settings: RetrySettings,
    label: str,
    sleep: Callable[[float], None] = time.sleep,
) -> object:
    last_exc: BaseException | None = None
    for attempt in range(1, settings.max_retries + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if not is_retryable(exc) or attempt == settings.max_retries:
                break
            delay = min(settings.base_delay * (2 ** (attempt - 1)), settings.max_delay)
            delay += random.uniform(0, max(delay * 0.1, 0.25))
            logger.debug(
                "%s failed (attempt %d/%d): %s; retrying in %.2fs",
                label, attempt, settings.max_retries, exc, delay,
            )
            sleep(delay)
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Public IP discovery
# ---------------------------------------------------------------------------


def validate_public_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid IP address") from exc
    return value


def get_public_ip(
    services: list[str],
    *,
    timeout: int = 30,
    settings: RetrySettings | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    settings = settings or RetrySettings()
    errors: list[str] = []
    for url in services:
        def attempt(url: str = url) -> str:
            logger.debug("Trying IP discovery service: %s", url)
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return validate_public_ip(response.text.strip())

        try:
            return retry_call(attempt, settings=settings, label=f"IP service {url}", sleep=sleep)  # type: ignore[return-value]
        except Exception as exc:  # noqa: BLE001
            logger.debug("IP service %s failed: %s", url, exc)
            errors.append(f"{url}: {exc}")

    raise RuntimeError(f"Could not discover public IP from any service. Errors: {'; '.join(errors)}")


# ---------------------------------------------------------------------------
# Credentials / client
# ---------------------------------------------------------------------------


def check_private_key_permissions(path: Path) -> None:
    mode = path.stat().st_mode
    if mode & stat.S_IRWXG or mode & stat.S_IRWXO:
        logger.warning(
            "Private key %s has overly broad permissions (%o). "
            "Consider running: chmod 600 %s",
            path,
            stat.S_IMODE(mode),
            path,
        )


def sign_body(body: str, private_key_path: str) -> str:
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha512", "-sign", private_key_path],
            input=body.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"openssl signing failed: {exc.stderr.decode(errors='replace').strip()}"
        ) from exc
    except FileNotFoundError as exc:
        raise RuntimeError("openssl CLI not found; it is required by the legacy updater") from exc
    return base64.b64encode(result.stdout).decode()


class TransIPLegacyClient:
    def __init__(
        self,
        *,
        username: str,
        private_key_path: str,
        api_url: str = TRANSIP_API_URL,
        label: str = "transip_dns_updater_legacy",
        global_key: bool = True,
        settings: RetrySettings | None = None,
    ) -> None:
        self.username = username
        self.private_key_path = private_key_path
        self.api_url = api_url.rstrip("/")
        self.label = label
        self.global_key = global_key
        self.settings = settings or RetrySettings()
        self._token: str | None = None

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: dict[str, object] | None = None,
        label: str = "API request",
    ) -> requests.Response:
        if self._token is None:
            self._authenticate()

        url = f"{self.api_url}{path}"
        headers = {"Authorization": f"Bearer {self._token}"}
        logger.debug("%s %s", method, url)

        def do_request() -> requests.Response:
            response = requests.request(method, url, headers=headers, json=json_data, timeout=30)
            response.raise_for_status()
            return response

        return retry_call(do_request, settings=self.settings, label=label)  # type: ignore[return-value]

    @staticmethod
    def _generate_nonce(length: int = 32) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _authenticate(self) -> None:
        body_dict = {
            "login": self.username,
            "nonce": self._generate_nonce(32),
            "read_only": False,
            "global_key": self.global_key,
        }
        body = json.dumps(body_dict, separators=(",", ":"), ensure_ascii=False)
        signature = sign_body(body, self.private_key_path)

        logger.debug("Requesting TransIP access token")
        response = requests.post(
            f"{self.api_url}/auth",
            data=body,
            headers={"Signature": signature, "Content-Type": "application/json"},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        self._token = data.get("token")
        if not self._token:
            raise RuntimeError("TransIP authentication response did not contain a token")

    def list_domains(self) -> list[dict[str, object]]:
        response = self._request("GET", "/domains", label="List domains")
        return response.json().get("domains", [])

    def list_dns_entries(self, domain_name: str) -> list[dict[str, object]]:
        response = self._request(
            "GET",
            f"/domains/{domain_name}/dns",
            label=f"List DNS entries for {domain_name}",
        )
        return response.json().get("dnsEntries", [])

    def update_dns_entry(self, domain_name: str, entry: dict[str, object]) -> None:
        self._request(
            "PATCH",
            f"/domains/{domain_name}/dns",
            json_data=entry,
            label=f"Update DNS entry for {domain_name}",
        )


# ---------------------------------------------------------------------------
# Logic
# ---------------------------------------------------------------------------


def find_record(
    entries: list[dict[str, object]],
    record_name: str,
    record_type: str,
) -> dict[str, object]:
    for entry in entries:
        if entry.get("name") == record_name and entry.get("type") == record_type:
            return entry
    raise LookupError(f"No {record_name} {record_type} record found")


def select_domain_name(
    client: TransIPLegacyClient,
    configured_domain: str | None,
) -> str:
    if configured_domain:
        logger.debug("Using configured domain: %s", configured_domain)
        return configured_domain

    domains = client.list_domains()
    if not domains:
        raise RuntimeError("No domains found in the TransIP account.")

    domain_name = str(domains[0]["name"])
    logger.debug("No domain configured; using first domain: %s", domain_name)
    return domain_name


def update_root_dns_entry(
    public_ip: str,
    client: TransIPLegacyClient,
    config: dict[str, str],
    *,
    dry_run: bool = False,
) -> bool:
    logger.info("Public IP address is: %s", public_ip)

    record_name = config.get("recordname", "@") or "@"
    record_type = (config.get("recordtype", "A") or "A").upper()

    domain_name = select_domain_name(client, config.get("domain"))
    logger.info("Selected domain name is: %s", domain_name)

    dns_entries = client.list_dns_entries(domain_name)
    current_record = find_record(dns_entries, record_name, record_type)

    logger.info(
        "%s %s DNS entry selected: %s %s %s %s",
        record_name,
        record_type,
        current_record.get("name"),
        current_record.get("expire"),
        current_record.get("type"),
        current_record.get("content"),
    )

    current_content = str(current_record.get("content", ""))
    if current_content == public_ip:
        logger.info("Current public IP is equal to DNS root entry, exiting...")
        return False

    logger.info(
        "Current public IP (%s) differs from DNS content (%s). %s...",
        public_ip,
        current_content,
        "Would update" if dry_run else "Updating",
    )
    if dry_run:
        return True

    updated_entry = dict(current_record)
    updated_entry["content"] = public_ip
    client.update_dns_entry(domain_name, updated_entry)
    logger.info("DNS entry updated successfully.")
    return True


def list_records(client: TransIPLegacyClient, config: dict[str, str]) -> None:
    domain_name = select_domain_name(client, config.get("domain"))
    logger.info("Selected domain name is: %s", domain_name)

    for entry in client.list_dns_entries(domain_name):
        print(f"{entry.get('name')}\t{entry.get('expire')}\t{entry.get('type')}\t{entry.get('content')}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_ip_services(config_value: str | None) -> list[str]:
    if not config_value:
        return list(DEFAULT_IP_SERVICES)
    services = [url.strip() for url in config_value.split(",") if url.strip()]
    return services or list(DEFAULT_IP_SERVICES)


def parse_bool(value: str | None, default: bool) -> bool:
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def generate_nonce(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update a TransIP DNS record with the current public IP (legacy / openssl variant).")
    parser.add_argument("--list", action="store_true", help="List DNS records for the selected domain and exit.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed without updating.")
    parser.add_argument("--config", default="config.ini", help="Path to config.ini.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    return parser.parse_args(argv)


def create_client(config: dict[str, str], settings: RetrySettings) -> TransIPLegacyClient:
    username = config.get("username") or os.environ.get("TRANSIP_USERNAME")
    if not username:
        raise ValueError("TransIP username is required (set in config.ini or TRANSIP_USERNAME env var).")

    private_key_path = Path(config.get("private_key_path") or "./private.key")
    if not private_key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")

    check_private_key_permissions(private_key_path)

    return TransIPLegacyClient(
        username=username,
        private_key_path=str(private_key_path),
        global_key=parse_bool(config.get("global_key"), False),
        settings=settings,
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    config_path = Path(args.config)
    try:
        config = read_config(config_path)
        settings = retry_settings(config)
        client = create_client(config, settings)

        if args.list:
            list_records(client, config)
            return 0

        services = parse_ip_services(config.get("ip_services") or config.get("ip_url"))
        public_ip = get_public_ip(services, settings=settings)
        updated = update_root_dns_entry(public_ip, client, config, dry_run=args.dry_run)
        return 0 if (updated or not args.dry_run) else 0
    except Exception as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
