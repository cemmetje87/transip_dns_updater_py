from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

import main


def make_record(name: str, type_: str, content: str, expire: int = 3600) -> SimpleNamespace:
    return SimpleNamespace(name=name, type=type_, content=content, expire=expire, update=MagicMock())


class TestGetPublicIp:
    @patch("main.requests.get")
    def test_returns_first_valid_ip(self, mock_get):
        mock_get.return_value.text = "  1.2.3.4  \n"
        mock_get.return_value.raise_for_status = MagicMock()
        assert main.get_public_ip(["https://example.com"]) == "1.2.3.4"

    @patch("main.requests.get")
    def test_tries_fallback_on_failure(self, mock_get):
        good = MagicMock(text="5.6.7.8\n")
        good.raise_for_status = MagicMock()
        mock_get.side_effect = [
            requests.RequestException("service down"),
            good,
        ]
        assert main.get_public_ip(["https://bad", "https://good"]) == "5.6.7.8"

    @patch("main.requests.get")
    def test_raises_when_all_services_fail(self, mock_get):
        mock_get.side_effect = requests.RequestException("service down")
        with pytest.raises(RuntimeError, match="Could not discover public IP"):
            main.get_public_ip(["https://bad"])

    @patch("main.requests.get")
    def test_raises_on_invalid_ip(self, mock_get):
        mock_get.return_value.text = "not-an-ip"
        mock_get.return_value.raise_for_status = MagicMock()
        with pytest.raises(RuntimeError, match="Could not discover public IP"):
            main.get_public_ip(["https://bad"])


class TestValidatePublicIp:
    def test_valid_ipv4(self):
        assert main.validate_public_ip("1.2.3.4") == "1.2.3.4"

    def test_valid_ipv6(self):
        assert main.validate_public_ip("2001:db8::1") == "2001:db8::1"

    def test_invalid(self):
        with pytest.raises(ValueError, match="not a valid IP address"):
            main.validate_public_ip("not-an-ip")


class TestFindRecord:
    def test_finds_record(self):
        entries = [
            make_record("www", "A", "1.1.1.1"),
            make_record("@", "A", "2.2.2.2"),
        ]
        found = main.find_record(entries, "@", "A")
        assert found.name == "@"

    def test_missing_record_raises(self):
        entries = [make_record("www", "A", "1.1.1.1")]
        with pytest.raises(LookupError, match="No @ A record found"):
            main.find_record(entries, "@", "A")


class TestSelectDomainName:
    def test_uses_configured_domain(self):
        client = MagicMock()
        assert main.select_domain_name(client, "example.com") == "example.com"
        client.domains.list.assert_not_called()

    def test_uses_first_domain_when_not_configured(self):
        client = MagicMock()
        client.domains.list.return_value = [SimpleNamespace(name="first.nl")]
        assert main.select_domain_name(client, None) == "first.nl"

    def test_raises_when_no_domains(self):
        client = MagicMock()
        client.domains.list.return_value = []
        with pytest.raises(RuntimeError, match="No domains found"):
            main.select_domain_name(client, None)


class TestUpdateRootDnsEntry:
    def test_no_update_when_ip_matches(self):
        client = MagicMock()
        domain = client.domains.get.return_value
        record = make_record("@", "A", "1.2.3.4")
        domain.dns.list.return_value = [record]
        client.domains.list.return_value = [SimpleNamespace(name="example.com")]

        updated = main.update_root_dns_entry("1.2.3.4", client, {})
        assert updated is False
        record.update.assert_not_called()

    def test_updates_when_ip_differs(self):
        client = MagicMock()
        domain = client.domains.get.return_value
        record = make_record("@", "A", "1.2.3.4")
        domain.dns.list.return_value = [record]
        client.domains.list.return_value = [SimpleNamespace(name="example.com")]

        updated = main.update_root_dns_entry("5.6.7.8", client, {})
        assert updated is True
        assert record.content == "5.6.7.8"
        record.update.assert_called_once()

    def test_dry_run_does_not_update(self):
        client = MagicMock()
        domain = client.domains.get.return_value
        record = make_record("@", "A", "1.2.3.4")
        domain.dns.list.return_value = [record]
        client.domains.list.return_value = [SimpleNamespace(name="example.com")]

        updated = main.update_root_dns_entry("5.6.7.8", client, {}, dry_run=True)
        assert updated is True
        record.update.assert_not_called()


class TestParseIpServices:
    def test_defaults_when_empty(self):
        services = main.parse_ip_services(None)
        assert services == main.DEFAULT_IP_SERVICES

    def test_splits_comma_separated(self):
        services = main.parse_ip_services("https://a, https://b")
        assert services == ["https://a", "https://b"]

    def test_legacy_ip_url_key(self):
        services = main.parse_ip_services("https://legacy")
        assert services == ["https://legacy"]


class TestMain:
    @patch("main.create_client")
    @patch("main.get_public_ip")
    @patch("main.update_root_dns_entry")
    def test_main_runs_update(
        self,
        mock_update,
        mock_get_ip,
        mock_create_client,
        tmp_path: Path,
    ):
        config_path = tmp_path / "config.ini"
        config_path.write_text(
            "[config]\nusername = test\nprivate_key_path = ./private.key\n"
        )
        mock_get_ip.return_value = "1.2.3.4"
        mock_update.return_value = True

        code = main.main(["--config", str(config_path)])
        assert code == 0
        mock_update.assert_called_once()

    @patch("main.create_client")
    def test_main_returns_error_on_failure(self, mock_create_client, tmp_path: Path):
        config_path = tmp_path / "config.ini"
        config_path.write_text("[config]\n")
        mock_create_client.side_effect = ValueError("missing username")

        code = main.main(["--config", str(config_path)])
        assert code == 1
