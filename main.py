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
import stat
import sys
from pathlib import Path
from typing import Any

import requests
import transip
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
ip_services = https://ipecho.net/plain
"""

logger = logging.getLogger(__name__)


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


def get_public_ip(services: list[str], timeout: int = 30) -> str:
    errors: list[str] = []
    for url in services:
        try:
            logger.debug("Trying IP discovery service: %s", url)
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            candidate = response.text.strip()
            return validate_public_ip(candidate)
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


def select_domain_name(client: transip.TransIP, configured_domain: str | None) -> str:
    if configured_domain:
        logger.debug("Using configured domain: %s", configured_domain)
        return configured_domain

    domains = client.domains.list()
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
) -> bool:
    logger.info("Public IP address is: %s", public_ip)

    record_name = config.get("recordname", "@") or "@"
    record_type = (config.get("recordtype", "A") or "A").upper()

    domain_name = select_domain_name(client, config.get("domain"))
    logger.info("Selected domain name is: %s", domain_name)

    domain = client.domains.get(domain_name)
    dns_entries = domain.dns.list()
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
    current_record.update()
    logger.info("DNS entry updated successfully.")
    return True


def list_records(client: transip.TransIP, config: dict[str, str]) -> None:
    domain_name = select_domain_name(client, config.get("domain"))
    logger.info("Selected domain name is: %s", domain_name)

    domain = client.domains.get(domain_name)
    for entry in domain.dns.list():
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
        client = create_client(config)

        if args.list:
            list_records(client, config)
            return 0

        services = parse_ip_services(config.get("ip_services") or config.get("ip_url"))
        public_ip = get_public_ip(services)
        updated = update_root_dns_entry(public_ip, client, config, dry_run=args.dry_run)
        return 0 if (updated or not args.dry_run) else 0
    except Exception as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
