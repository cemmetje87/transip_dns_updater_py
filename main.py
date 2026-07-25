#!/usr/bin/env python3
"""TransIP DNS root-record updater.

Python port of the original Go updater. Fetches the current public IPv4 address
and updates a configurable TransIP DNS record when it differs.
"""

from __future__ import annotations

import argparse
import configparser
import ipaddress
import logging
import os
import random
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeVar

import requests
import transip
from transip import exceptions as transip_exceptions
from transip.v6.objects import DnsEntry


DEFAULT_IP_SERVICES = [
    "https://ipecho.net/plain",
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
]

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
# max_retries = total attempts per call, retry_backoff = base delay in seconds
# (doubled each attempt, plus jitter), retry_max_delay = cap on the delay.
max_retries = 3
retry_backoff = 1.0
retry_max_delay = 30.0
"""

logger = logging.getLogger(__name__)

RETRYABLE_HTTP_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF = 1.0
DEFAULT_MAX_DELAY = 30.0

T = TypeVar("T")


@dataclass
class RetrySettings:
    max_retries: int = DEFAULT_MAX_RETRIES
    base_delay: float = DEFAULT_BACKOFF
    max_delay: float = DEFAULT_MAX_DELAY


def is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, transip_exceptions.TransIPHTTPError):
        return exc.response_code in RETRYABLE_HTTP_CODES
    if isinstance(exc, requests.exceptions.HTTPError):
        return exc.response is not None and exc.response.status_code in RETRYABLE_HTTP_CODES
    return isinstance(
        exc,
        (
            transip_exceptions.TransIPIOError,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            ConnectionError,
            TimeoutError,
            OSError,
        ),
    )


def retry_call(
    fn: Callable[[], T],
    *,
    settings: RetrySettings,
    label: str,
    sleep: Callable[[float], None] = time.sleep,
    retryable: Callable[[BaseException], bool] = is_retryable,
) -> T:
    for attempt in range(1, settings.max_retries + 1):
        try:
            return fn()
        except Exception as exc:
            if not retryable(exc) or attempt == settings.max_retries:
                raise
            delay = min(settings.base_delay * 2 ** (attempt - 1), settings.max_delay)
            delay += random.uniform(0, delay * 0.1)
            logger.debug(
                "%s failed (attempt %d/%d): %s; retrying in %.2fs",
                label,
                attempt,
                settings.max_retries,
                exc,
                delay,
            )
            sleep(delay)
    raise AssertionError("unreachable")


def retry_settings(config: dict[str, str]) -> RetrySettings:
    return RetrySettings(
        max_retries=max(1, _parse_config_int(config, "max_retries", DEFAULT_MAX_RETRIES)),
        base_delay=max(0.0, _parse_config_float(config, "retry_backoff", DEFAULT_BACKOFF)),
        max_delay=max(0.0, _parse_config_float(config, "retry_max_delay", DEFAULT_MAX_DELAY)),
    )


def _parse_config_int(config: dict[str, str], key: str, default: int) -> int:
    raw = config.get(key)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("Invalid %s value %r; using default %s", key, raw, default)
        return default


def _parse_config_float(config: dict[str, str], key: str, default: float) -> float:
    raw = config.get(key)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("Invalid %s value %r; using default %s", key, raw, default)
        return default


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
    if settings is None:
        settings = RetrySettings()
    errors: list[str] = []
    for url in services:
        def attempt(url: str = url) -> str:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            return validate_public_ip(response.text.strip())

        try:
            logger.debug("Trying IP discovery service: %s", url)
            return retry_call(attempt, settings=settings, label=f"IP service {url}", sleep=sleep)
        except requests.RequestException as exc:
            logger.debug("IP service %s failed: %s", url, exc)
            errors.append(f"{url}: {exc}")
        except ValueError as exc:
            logger.debug("IP service %s returned invalid IP: %s", url, exc)
            errors.append(f"{url}: {exc}")

    raise RuntimeError(f"Could not discover public IP from any service. Errors: {'; '.join(errors)}")


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


def find_record(entries: list[DnsEntry], record_name: str, record_type: str) -> DnsEntry:
    for entry in entries:
        if entry.name == record_name and entry.type == record_type:
            return entry
    raise LookupError(f"No {record_name} {record_type} record found")


def select_domain_name(
    client: transip.TransIP,
    configured_domain: str | None,
    *,
    settings: RetrySettings | None = None,
) -> str:
    if configured_domain:
        logger.debug("Using configured domain: %s", configured_domain)
        return configured_domain

    if settings is None:
        settings = RetrySettings()
    domains = retry_call(client.domains.list, settings=settings, label="List domains")
    if not domains:
        raise RuntimeError("No domains found in the TransIP account.")

    domain_name = domains[0].name
    logger.debug("No domain configured; using first domain: %s", domain_name)
    return domain_name


def update_root_dns_entry(
    public_ip: str,
    client: transip.TransIP,
    config: dict[str, str],
    dry_run: bool = False,
    *,
    settings: RetrySettings | None = None,
) -> bool:
    if settings is None:
        settings = RetrySettings()
    logger.info("Public IP address is: %s", public_ip)

    record_name = config.get("recordname", "@") or "@"
    record_type = (config.get("recordtype", "A") or "A").upper()

    domain_name = select_domain_name(client, config.get("domain"), settings=settings)
    logger.info("Selected domain name is: %s", domain_name)

    domain = retry_call(lambda: client.domains.get(domain_name), settings=settings, label=f"Get domain {domain_name}")
    dns_entries = retry_call(domain.dns.list, settings=settings, label=f"List DNS entries for {domain_name}")
    current_record = find_record(dns_entries, record_name, record_type)

    logger.info(
        "%s %s DNS entry selected: %s %s %s %s",
        record_name,
        record_type,
        current_record.name,
        current_record.expire,
        current_record.type,
        current_record.content,
    )

    if current_record.content == public_ip:
        logger.info("Current public IP is equal to DNS root entry, exiting...")
        return False

    logger.info(
        "Current public IP (%s) differs from DNS content (%s). %s...",
        public_ip,
        current_record.content,
        "Would update" if dry_run else "Updating",
    )
    if dry_run:
        return True

    current_record.content = public_ip
    retry_call(current_record.update, settings=settings, label=f"Update {record_name} {record_type} record")
    logger.info("DNS entry updated successfully.")
    return True


def list_records(client: transip.TransIP, config: dict[str, str], *, settings: RetrySettings | None = None) -> None:
    if settings is None:
        settings = RetrySettings()
    domain_name = select_domain_name(client, config.get("domain"), settings=settings)
    logger.info("Selected domain name is: %s", domain_name)

    domain = retry_call(lambda: client.domains.get(domain_name), settings=settings, label=f"Get domain {domain_name}")
    dns_entries = retry_call(domain.dns.list, settings=settings, label=f"List DNS entries for {domain_name}")
    for entry in dns_entries:
        print(f"{entry.name}\t{entry.expire}\t{entry.type}\t{entry.content}")


def create_client(config: dict[str, str]) -> transip.TransIP:
    username = config.get("username") or os.environ.get("TRANSIP_USERNAME")
    if not username:
        raise ValueError("TransIP username is required (set in config.ini or TRANSIP_USERNAME env var).")

    private_key_path = Path(config.get("private_key_path") or "./private.key")
    if not private_key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")

    check_private_key_permissions(private_key_path)

    try:
        return transip.TransIP(
            login=username,
            private_key_file=str(private_key_path),
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to create TransIP client: {exc}") from exc


def parse_ip_services(config_value: str | None) -> list[str]:
    if not config_value:
        return list(DEFAULT_IP_SERVICES)
    services = [url.strip() for url in config_value.split(",") if url.strip()]
    return services or list(DEFAULT_IP_SERVICES)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update a TransIP DNS record with the current public IP.")
    parser.add_argument("--list", action="store_true", help="List DNS records for the selected domain and exit.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed without updating.")
    parser.add_argument("--config", default="config.ini", help="Path to config.ini.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    config_path = Path(args.config)
    try:
        config = read_config(config_path)
        settings = retry_settings(config)
        client = create_client(config)

        if args.list:
            list_records(client, config, settings=settings)
            return 0

        services = parse_ip_services(config.get("ip_services") or config.get("ip_url"))
        public_ip = get_public_ip(services, settings=settings)
        updated = update_root_dns_entry(public_ip, client, config, dry_run=args.dry_run, settings=settings)
        return 0 if (updated or not args.dry_run) else 0
    except Exception as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
