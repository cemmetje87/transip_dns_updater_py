from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests
from transip.exceptions import TransIPHTTPError

import main


def make_record(name: str, type_: str, content: str, expire: int = 3600) -> SimpleNamespace:
    return SimpleNamespace(name=name, type=type_, content=content, expire=expire, update=MagicMock())


class TestGetPublicIp:
    @patch("main.requests.get")
    def test_returns_first_valid_ip(self, mock_get):
        mock_get.return_value.text = "  1.2.3.4  \n"
        mock_get.return_value.raise_for_status = MagicMock()
        assert main.get_public_ip(["https://example.com"], settings=main.RetrySettings(max_retries=1)) == "1.2.3.4"

    @patch("main.requests.get")
    def test_tries_fallback_on_failure(self, mock_get):
        good = MagicMock(text="5.6.7.8\n")
        good.raise_for_status = MagicMock()
        mock_get.side_effect = [
            requests.RequestException("service down"),
            good,
        ]
        assert (
            main.get_public_ip(["https://bad", "https://good"], settings=main.RetrySettings(max_retries=1))
            == "5.6.7.8"
        )

    @patch("main.requests.get")
    def test_raises_when_all_services_fail(self, mock_get):
        mock_get.side_effect = requests.RequestException("service down")
        with pytest.raises(RuntimeError, match="Could not discover public IP"):
            main.get_public_ip(["https://bad"], settings=main.RetrySettings(max_retries=1))

    @patch("main.requests.get")
    def test_raises_on_invalid_ip(self, mock_get):
        mock_get.return_value.text = "not-an-ip"
        mock_get.return_value.raise_for_status = MagicMock()
        with pytest.raises(RuntimeError, match="Could not discover public IP"):
            main.get_public_ip(["https://bad"], settings=main.RetrySettings(max_retries=1))

    @patch("main.requests.get")
    def test_retries_same_service_on_transient_error(self, mock_get):
        good = MagicMock(text="1.2.3.4\n")
        good.raise_for_status = MagicMock()
        mock_get.side_effect = [
            requests.exceptions.ConnectionError("boom"),
            requests.exceptions.ConnectionError("boom"),
            good,
        ]
        result = main.get_public_ip(
            ["https://flaky"],
            settings=main.RetrySettings(max_retries=3),
            sleep=lambda d: None,
        )
        assert result == "1.2.3.4"
        assert mock_get.call_count == 3


class TestIsRetryable:
    def test_transip_http_error_retryable_code(self):
        assert main.is_retryable(TransIPHTTPError(response_code=503)) is True

    def test_transip_http_error_non_retryable_codes(self):
        assert main.is_retryable(TransIPHTTPError(response_code=401)) is False
        assert main.is_retryable(TransIPHTTPError(response_code=404)) is False

    def test_requests_network_errors(self):
        assert main.is_retryable(requests.exceptions.ConnectionError()) is True
        assert main.is_retryable(requests.exceptions.Timeout()) is True

    def test_requests_http_error_depends_on_status(self):
        bad_gateway = requests.exceptions.HTTPError(response=SimpleNamespace(status_code=502))
        assert main.is_retryable(bad_gateway) is True
        not_found = requests.exceptions.HTTPError(response=SimpleNamespace(status_code=404))
        assert main.is_retryable(not_found) is False
        assert main.is_retryable(requests.exceptions.HTTPError()) is False

    def test_builtin_os_errors(self):
        assert main.is_retryable(ConnectionError()) is True
        assert main.is_retryable(TimeoutError()) is True
        assert main.is_retryable(OSError()) is True

    def test_non_retryable_errors(self):
        assert main.is_retryable(ValueError()) is False
        assert main.is_retryable(LookupError()) is False


class TestRetryCall:
    def test_success_on_first_attempt(self):
        sleeps = []
        fn = MagicMock(return_value="ok")
        result = main.retry_call(
            fn,
            settings=main.RetrySettings(),
            label="test",
            sleep=lambda d: sleeps.append(d),
        )
        assert result == "ok"
        assert sleeps == []
        assert fn.call_count == 1

    def test_retryable_error_then_success(self):
        sleeps = []
        fn = MagicMock(side_effect=[requests.exceptions.ConnectionError("boom"), "ok"])
        result = main.retry_call(
            fn,
            settings=main.RetrySettings(),
            label="test",
            sleep=lambda d: sleeps.append(d),
        )
        assert result == "ok"
        assert len(sleeps) == 1
        assert fn.call_count == 2

    def test_non_retryable_error_raised_immediately(self):
        sleeps = []
        fn = MagicMock(side_effect=ValueError("bad"))
        with pytest.raises(ValueError, match="bad"):
            main.retry_call(
                fn,
                settings=main.RetrySettings(),
                label="test",
                sleep=lambda d: sleeps.append(d),
            )
        assert sleeps == []
        assert fn.call_count == 1

    def test_transip_http_error_retried_by_code(self):
        sleeps = []
        fn = MagicMock(side_effect=[TransIPHTTPError(response_code=503), "ok"])
        result = main.retry_call(
            fn,
            settings=main.RetrySettings(),
            label="test",
            sleep=lambda d: sleeps.append(d),
        )
        assert result == "ok"
        assert len(sleeps) == 1
        assert fn.call_count == 2

    def test_transip_http_error_not_retried_by_code(self):
        sleeps = []
        fn = MagicMock(side_effect=TransIPHTTPError(response_code=401))
        with pytest.raises(TransIPHTTPError):
            main.retry_call(
                fn,
                settings=main.RetrySettings(),
                label="test",
                sleep=lambda d: sleeps.append(d),
            )
        assert sleeps == []
        assert fn.call_count == 1

    def test_exhausts_retries_and_reraises_last_error(self):
        sleeps = []
        err = requests.exceptions.ConnectionError("always down")
        fn = MagicMock(side_effect=err)
        with pytest.raises(requests.exceptions.ConnectionError) as excinfo:
            main.retry_call(
                fn,
                settings=main.RetrySettings(max_retries=3),
                label="test",
                sleep=lambda d: sleeps.append(d),
            )
        assert excinfo.value is err
        assert fn.call_count == 3
        assert len(sleeps) == 2

    def test_backoff_increases_between_attempts(self):
        sleeps = []
        fn = MagicMock(side_effect=requests.exceptions.ConnectionError("boom"))
        with pytest.raises(requests.exceptions.ConnectionError):
            main.retry_call(
                fn,
                settings=main.RetrySettings(max_retries=3, base_delay=1.0, max_delay=30.0),
                label="test",
                sleep=lambda d: sleeps.append(d),
            )
        assert len(sleeps) == 2
        assert sleeps[0] >= 1.0
        assert sleeps[1] >= 2.0


class TestRetrySettings:
    def test_parses_valid_values(self):
        settings = main.retry_settings(
            {"max_retries": "5", "retry_backoff": "0.5", "retry_max_delay": "10"}
        )
        assert settings.max_retries == 5
        assert settings.base_delay == 0.5
        assert settings.max_delay == 10.0

    def test_invalid_values_fall_back_to_defaults(self):
        settings = main.retry_settings({"max_retries": "bogus", "retry_backoff": "x"})
        assert settings.max_retries == main.DEFAULT_MAX_RETRIES
        assert settings.base_delay == main.DEFAULT_BACKOFF

    def test_missing_keys_use_defaults(self):
        assert main.retry_settings({}) == main.RetrySettings()

    def test_values_are_clamped(self):
        assert main.retry_settings({"max_retries": "0"}).max_retries == 1
        assert main.retry_settings({"retry_max_delay": "-3"}).max_delay == 0.0


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
