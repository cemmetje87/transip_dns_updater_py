#!/usr/bin/env python3
"""TransIP DNS root-record updater.

Python port of the original Go updater.

Reads config.ini for TransIP credentials and the record to update, fetches the
public IPv4 address, then updates the selected A record (by default the root
'@' record) of the first TransIP domain when it differs.
"""

import argparse
import configparser
import os
import sys
from pathlib import Path

import requests
import transip
from transip.v6.objects import DnsEntry


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

# Service used to discover the current public IPv4 address.
ip_url = https://ipecho.net/plain
"""


def read_config(path: Path) -> dict[str, str]:
    if not path.exists():
        path.write_text(DEFAULT_CONFIG)
        print(f"Created default config at {path}. Please fill it in and rerun.")
        sys.exit(1)

    parser = configparser.ConfigParser()
    parser.read(path)
    return {k: v.strip() for k, v in parser["config"].items()}


def get_public_ip(url: str) -> str:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.text.strip()


def find_root_record(entries: list[DnsEntry], record_name: str, record_type: str) -> DnsEntry:
    for entry in entries:
        if entry.name == record_name and entry.type == record_type:
            return entry
    raise LookupError(f"No {record_name} {record_type} record found")


def update_root_dns_entry(public_ip: str, config: dict[str, str], dry_run: bool = False) -> None:
    print(f"Public IP address is: {public_ip}")

    domain_name = config.get("domain")
    record_name = config.get("recordname", "@")
    record_type = config.get("recordtype", "A")

    client = _create_client(config)

    if not domain_name:
        domains = client.domains.list()
        if not domains:
            print("No domains found in the TransIP account.")
            sys.exit(1)
        domain_name = domains[0].name

    print(f"Selected domain name is: {domain_name}")

    domain = client.domains.get(domain_name)
    dns_entries = domain.dns.list()
    current_record = find_root_record(dns_entries, record_name, record_type)

    print(f"{record_name} {record_type} DNS entry selected: {current_record.name} {current_record.expire} {current_record.type} {current_record.content}")

    if current_record.content != public_ip:
        print(f"Current public IP is different, {'would update' if dry_run else 'updating'}...")
        if dry_run:
            return
        current_record.content = public_ip
        current_record.update()
    else:
        print("Current public IP is equal to DNS root entry, exiting...")


def list_records(config: dict[str, str]) -> None:
    client = _create_client(config)
    domains = client.domains.list()
    if not domains:
        print("No domains found in the TransIP account.")
        return

    domain_name = config.get("domain") or domains[0].name
    print(f"Selected domain name is: {domain_name}")

    domain = client.domains.get(domain_name)
    for entry in domain.dns.list():
        print(f"{entry.name} {entry.expire} {entry.type} {entry.content}")


def _create_client(config: dict[str, str]) -> transip.TransIP:
    username = config.get("username") or os.environ.get("TRANSIP_USERNAME")
    private_key_path = config.get("private_key_path") or "./private.key"

    if not username:
        print("TransIP username is required (set in config.ini or TRANSIP_USERNAME env var).")
        sys.exit(1)

    private_key_path = Path(private_key_path)
    if not private_key_path.exists():
        print(f"Private key not found: {private_key_path}")
        sys.exit(1)

    return transip.TransIP(
        login=username,
        private_key_file=str(private_key_path),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Update a TransIP DNS record with the current public IP.")
    parser.add_argument("--list", action="store_true", help="List DNS records for the selected domain and exit.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed without updating.")
    parser.add_argument("--config", default="config.ini", help="Path to config.ini.")
    args = parser.parse_args()

    config_path = Path(args.config)
    config = read_config(config_path)

    if args.list:
        list_records(config)
        return

    ip_url = config.get("ip_url", "https://ipecho.net/plain")
    public_ip = get_public_ip(ip_url)
    update_root_dns_entry(public_ip, config, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
