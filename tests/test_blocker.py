"""Pruebas del bloqueador automático de IPs (iptables)."""
import subprocess
from unittest.mock import MagicMock

from blocker import IpBlocker


def _blocker(**overrides):
    defaults = dict(
        enabled=True,
        min_severity="high",
        whitelist=["192.168.1.1"],
        duration_seconds=3600,
    )
    defaults.update(overrides)
    return IpBlocker(**defaults)


def test_should_block_false_when_disabled():
    blocker = _blocker(enabled=False)
    assert blocker.should_block("1.2.3.4", "high") is False


def test_should_block_false_for_whitelisted_ip():
    blocker = _blocker()
    assert blocker.should_block("192.168.1.1", "high") is False


def test_should_block_false_for_loopback():
    blocker = _blocker()
    assert blocker.should_block("127.0.0.1", "high") is False


def test_should_block_false_below_severity_threshold():
    blocker = _blocker(min_severity="high")
    assert blocker.should_block("1.2.3.4", "medium") is False


def test_should_block_true_for_malicious_ip_above_threshold():
    blocker = _blocker(min_severity="medium")
    assert blocker.should_block("1.2.3.4", "high") is True


def test_should_block_false_when_ip_is_none():
    blocker = _blocker()
    assert blocker.should_block(None, "high") is False


def test_block_invokes_iptables_and_returns_true_on_success():
    runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
    blocker = _blocker(runner=runner)

    result = blocker.block("1.2.3.4", reason="port scan")

    assert result is True
    runner.assert_called_once()
    called_args = runner.call_args.args[0]
    assert called_args == ["iptables", "-I", "INPUT", "-s", "1.2.3.4", "-j", "DROP"]


def test_block_returns_false_when_iptables_fails():
    runner = MagicMock(
        return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
    )
    blocker = _blocker(runner=runner)

    assert blocker.block("1.2.3.4", reason="port scan") is False


def test_block_returns_false_when_iptables_not_found():
    runner = MagicMock(side_effect=FileNotFoundError("no iptables"))
    blocker = _blocker(runner=runner)

    assert blocker.block("1.2.3.4", reason="port scan") is False


def test_unblock_invokes_iptables_delete_rule():
    runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
    blocker = _blocker(runner=runner)

    assert blocker.unblock("1.2.3.4") is True
    called_args = runner.call_args.args[0]
    assert called_args == ["iptables", "-D", "INPUT", "-s", "1.2.3.4", "-j", "DROP"]


def test_expires_at_adds_duration_to_now():
    blocker = _blocker(duration_seconds=3600)
    assert blocker.expires_at(now=1000.0) == 4600.0
