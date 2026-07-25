from __future__ import annotations

import json
import secrets
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests

import transip_updater_legacy as legacy


class TestSignBody:
    @patch("transip_updater_legacy.subprocess.run")
    def test_signs_body_with_openssl(self, mock_run):
        mock_run.return_value = SimpleNamespace(stdout=b"signed", stderr=b"", returncode=0)
        signature = legacy.sign_body('{"x":1}', "/key.pem")
        mock_run.assert_called_once()
        args = mock_run.call_args
        assert args.kwargs["input"] == b'{"x":1}'
        assert args.args[0] == ["openssl", "dgst", "-sha512", "-sign", "/key.pem"]
        assert signature == "c2lnbmVk"  # base64 of b"signed"

    @patch("transip_updater_legacy.subprocess.run")
    def test_raises_on_openssl_failure(self, mock_run):
        mock_run.side_effect = subprocess_called_process_error("bad key")
        with pytest.raises(RuntimeError, match="openssl signing failed"):
            legacy.sign_body("body", "/key.pem")


def subprocess_called_process_error(stderr: str):
    import subprocess
    return subprocess.CalledProcessError(1, ["openssl"], stderr=stderr.encode())


class TestRetryCall:
    def test_success_first_attempt(self):
        sleeps = []
        fn = MagicMock(return_value="ok")
        assert legacy.retry_call(fn, settings=legacy.RetrySettings(max_retries=1), label="t", sleep=lambda d: sleeps.append(d)) == "ok"
        assert sleeps == []

    def test_retryable_then_success(self):
        sleeps = []
        fn = MagicMock(side_effect=[requests.exceptions.ConnectionError("boom"), "ok"])
        assert legacy.retry_call(fn, settings=legacy.RetrySettings(max_retries=3), label="t", sleep=lambda d: sleeps.append(d)) == "ok"
        assert len(sleeps) == 1
        assert fn.call_count == 2

    def test_non_retryable_immediate(self):
        fn = MagicMock(side_effect=ValueError("bad"))
        with pytest.raises(ValueError, match="bad"):
            legacy.retry_call(fn, settings=legacy.RetrySettings(max_retries=3), label="t", sleep=lambda d: None)
        assert fn.call_count == 1


class TestTransIPLegacyClient:
    @patch("transip_updater_legacy.requests.post")
    @patch("transip_updater_legacy.sign_body")
    def test_authenticate_and_list_domains(self, mock_sign, mock_post):
        mock_sign.return_value = "fake_signature"
        mock_post.return_value = SimpleNamespace(
            json=lambda: {"token": "abc123"},
            raise_for_status=MagicMock(),
        )

        client = legacy.TransIPLegacyClient(
            username="user",
            private_key_path="/key.pem",
            settings=legacy.RetrySettings(max_retries=1),
        )

        # list_domains should trigger authentication
        with patch("transip_updater_legacy.requests.request") as mock_request:
            mock_request.return_value = SimpleNamespace(
                json=lambda: {"domains": [{"name": "example.com"}]},
                raise_for_status=MagicMock(),
            )
            domains = client.list_domains()

        assert domains == [{"name": "example.com"}]
        assert client._token == "abc123"

        # Verify auth call
        mock_post.assert_called_once()
        auth_url = mock_post.call_args.args[0]
        assert auth_url.endswith("/auth")
        auth_headers = mock_post.call_args.kwargs["headers"]
        assert auth_headers["Signature"] == "fake_signature"
        assert auth_headers["Content-Type"] == "application/json"
        auth_body = json.loads(mock_post.call_args.kwargs["data"])
        assert auth_body["login"] == "user"
        assert auth_body["read_only"] is False
        assert auth_body["global_key"] is True
        assert "nonce" in auth_body

    @patch("transip_updater_legacy.requests.post")
    @patch("transip_updater_legacy.sign_body")
    def test_list_dns_entries(self, mock_sign, mock_post):
        mock_sign.return_value = "sig"
        mock_post.return_value = SimpleNamespace(
            json=lambda: {"token": "tok"},
            raise_for_status=MagicMock(),
        )
        client = legacy.TransIPLegacyClient(
            username="user",
            private_key_path="/key.pem",
            settings=legacy.RetrySettings(max_retries=1),
        )

        with patch("transip_updater_legacy.requests.request") as mock_request:
            mock_request.return_value = SimpleNamespace(
                json=lambda: {
                    "dnsEntries": [
                        {"name": "@", "type": "A", "content": "1.2.3.4", "expire": 3600},
                    ]
                },
                raise_for_status=MagicMock(),
            )
            entries = client.list_dns_entries("example.com")

        assert len(entries) == 1
        assert entries[0]["content"] == "1.2.3.4"
        method, url = mock_request.call_args.args[:2]
        assert method == "GET"
        assert url.endswith("/domains/example.com/dns")

    @patch("transip_updater_legacy.requests.post")
    @patch("transip_updater_legacy.sign_body")
    def test_update_dns_entry(self, mock_sign, mock_post):
        mock_sign.return_value = "sig"
        mock_post.return_value = SimpleNamespace(
            json=lambda: {"token": "tok"},
            raise_for_status=MagicMock(),
        )
        client = legacy.TransIPLegacyClient(
            username="user",
            private_key_path="/key.pem",
            settings=legacy.RetrySettings(max_retries=1),
        )

        entry = {"name": "@", "type": "A", "content": "5.6.7.8", "expire": 3600}
        with patch("transip_updater_legacy.requests.request") as mock_request:
            mock_request.return_value = SimpleNamespace(
                json=lambda: {},
                raise_for_status=MagicMock(),
            )
            client.update_dns_entry("example.com", entry)

        method, url = mock_request.call_args.args[:2]
        assert method == "PATCH"
        assert url.endswith("/domains/example.com/dns")
        assert mock_request.call_args.kwargs["json"] == entry


class TestFindRecord:
    def test_finds_record(self):
        entries = [
            {"name": "www", "type": "A", "content": "1.1.1.1"},
            {"name": "@", "type": "A", "content": "2.2.2.2"},
        ]
        found = legacy.find_record(entries, "@", "A")
        assert found["content"] == "2.2.2.2"

    def test_missing_raises(self):
        with pytest.raises(LookupError, match="No @ A record found"):
            legacy.find_record([{"name": "www", "type": "A"}], "@", "A")


class TestSelectDomainName:
    def test_uses_configured_domain(self):
        client = MagicMock()
        assert legacy.select_domain_name(client, "example.com") == "example.com"
        client.list_domains.assert_not_called()

    def test_uses_first_domain(self):
        client = MagicMock()
        client.list_domains.return_value = [{"name": "first.nl"}]
        assert legacy.select_domain_name(client, None) == "first.nl"

    def test_raises_when_empty(self):
        client = MagicMock()
        client.list_domains.return_value = []
        with pytest.raises(RuntimeError, match="No domains found"):
            legacy.select_domain_name(client, None)


class TestUpdateRootDnsEntry:
    def test_no_update_when_ip_matches(self):
        client = MagicMock()
        client.list_dns_entries.return_value = [{"name": "@", "type": "A", "content": "1.2.3.4", "expire": 3600}]

        updated = legacy.update_root_dns_entry("1.2.3.4", client, {})
        assert updated is False
        client.update_dns_entry.assert_not_called()

    def test_updates_when_ip_differs(self):
        client = MagicMock()
        client.list_domains.return_value = [{"name": "example.com"}]
        client.list_dns_entries.return_value = [{"name": "@", "type": "A", "content": "1.2.3.4", "expire": 3600}]

        updated = legacy.update_root_dns_entry("5.6.7.8", client, {})
        assert updated is True
        client.update_dns_entry.assert_called_once()
        args = client.update_dns_entry.call_args.args
        assert args[0] == "example.com"
        assert args[1]["content"] == "5.6.7.8"

    def test_dry_run_does_not_update(self):
        client = MagicMock()
        client.list_dns_entries.return_value = [{"name": "@", "type": "A", "content": "1.2.3.4", "expire": 3600}]

        updated = legacy.update_root_dns_entry("5.6.7.8", client, {}, dry_run=True)
        assert updated is True
        client.update_dns_entry.assert_not_called()


class TestParseBool:
    def test_truthy_values(self):
        assert legacy.parse_bool("true", False) is True
        assert legacy.parse_bool("1", False) is True
        assert legacy.parse_bool("yes", False) is True
        assert legacy.parse_bool("on", False) is True

    def test_falsy_values_and_default(self):
        assert legacy.parse_bool("false", True) is False
        assert legacy.parse_bool("0", True) is False
        assert legacy.parse_bool("", True) is True
        assert legacy.parse_bool(None, True) is True


class TestGetPublicIp:
    @patch("transip_updater_legacy.requests.get")
    def test_returns_first_valid_ip(self, mock_get):
        mock_get.return_value.text = "  1.2.3.4  \n"
        mock_get.return_value.raise_for_status = MagicMock()
        assert legacy.get_public_ip(["https://x"], settings=legacy.RetrySettings(max_retries=1)) == "1.2.3.4"

    @patch("transip_updater_legacy.requests.get")
    def test_falls_back_on_failure(self, mock_get):
        good = MagicMock(text="5.6.7.8\n")
        good.raise_for_status = MagicMock()
        mock_get.side_effect = [requests.RequestException("down"), good]
        assert legacy.get_public_ip(["https://bad", "https://good"], settings=legacy.RetrySettings(max_retries=1)) == "5.6.7.8"
