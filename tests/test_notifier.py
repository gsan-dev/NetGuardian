"""Pruebas del sistema de notificaciones (Telegram/Discord)."""
from unittest.mock import MagicMock, patch

from notifier import Notifier


def _alert(severity="high", source_ip="10.0.0.5", port=22, reason="scan"):
    return {"severity": severity, "source_ip": source_ip, "port": port, "reason": reason}


def test_notify_skips_when_below_severity_threshold():
    notifier = Notifier(
        telegram_bot_token="t", telegram_chat_id="c", min_severity="high"
    )
    with patch("notifier.requests.post") as mock_post:
        sent = notifier.notify(_alert(severity="low"))

    assert sent is False
    mock_post.assert_not_called()


def test_notify_sends_telegram_when_enabled():
    notifier = Notifier(
        telegram_bot_token="t", telegram_chat_id="c", min_severity="medium"
    )
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()

    with patch("notifier.requests.post", return_value=mock_response) as mock_post:
        sent = notifier.notify(_alert())

    assert sent is True
    mock_post.assert_called_once()
    call_url = mock_post.call_args.args[0]
    assert "api.telegram.org/bott/sendMessage" in call_url


def test_notify_sends_discord_when_enabled():
    notifier = Notifier(
        discord_webhook_url="https://discord.example/webhook", min_severity="medium"
    )
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()

    with patch("notifier.requests.post", return_value=mock_response) as mock_post:
        sent = notifier.notify(_alert())

    assert sent is True
    mock_post.assert_called_once_with(
        "https://discord.example/webhook",
        json={"content": notifier._format_message(_alert())},
        timeout=10,
    )


def test_notify_respects_cooldown_per_source_ip():
    notifier = Notifier(
        telegram_bot_token="t", telegram_chat_id="c", min_severity="low", cooldown_seconds=60
    )
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()

    with patch("notifier.requests.post", return_value=mock_response) as mock_post:
        first = notifier.notify(_alert(), now=1000.0)
        second = notifier.notify(_alert(), now=1010.0)  # dentro del cooldown
        third = notifier.notify(_alert(), now=1070.0)  # cooldown ya pasó

    assert first is True
    assert second is False
    assert third is True
    assert mock_post.call_count == 2


def test_notify_returns_false_when_no_channel_configured():
    notifier = Notifier(min_severity="low")
    sent = notifier.notify(_alert())
    assert sent is False


def test_notify_handles_request_exception_gracefully():
    import requests

    notifier = Notifier(telegram_bot_token="t", telegram_chat_id="c", min_severity="low")

    with patch("notifier.requests.post", side_effect=requests.RequestException("boom")):
        sent = notifier.notify(_alert())

    assert sent is False
