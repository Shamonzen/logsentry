import urllib.request
from pathlib import Path
from urllib.error import URLError

import pytest

from logsentry import notify, store
from logsentry.cli import main, poll
from logsentry.engine import Engine
from logsentry.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = Path(__file__).parent.parent / "config" / "rules.yaml"
URL = "https://ntfy.example.test/logsentry-topic"


class FakeResponse:
    def close(self):
        pass


@pytest.fixture
def sent(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        return FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return requests


def alerts_from(tmp_path, fixture):
    log = tmp_path / "auth.log"
    log.write_bytes((FIXTURES / fixture).read_bytes())
    seen = []
    poll(store.connect(tmp_path / "t.db"), Engine.from_config(CONFIG), {"sshd": log}, seen.append)
    return seen


def test_poll_hands_every_alert_to_the_callback(tmp_path):
    alerts = alerts_from(tmp_path, "auth_bruteforce.log")
    assert {a.rule_id for a in alerts} == {"ssh_bruteforce", "password_spray"}


def test_high_alert_is_pushed(tmp_path, sent):
    (alert,) = [a for a in alerts_from(tmp_path, "auth_success_after_fail.log")]
    assert alert.severity == Severity.HIGH
    notify.push(URL, alert)
    (request,) = sent
    assert (request.full_url, request.get_method()) == (URL, "POST")
    assert request.get_header("Title") == "LogSentry HIGH: success_after_failures"
    assert request.get_header("Priority") == "high"
    assert alert.summary in request.data.decode()


def test_medium_alert_is_not_pushed(tmp_path, sent):
    for alert in alerts_from(tmp_path, "auth_bruteforce.log"):
        assert alert.severity == Severity.MEDIUM
        notify.push(URL, alert)
    assert sent == []


def test_push_failure_is_reported_not_raised(tmp_path, monkeypatch, capsys):
    def down(request, timeout):
        raise URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", down)
    (alert,) = alerts_from(tmp_path, "auth_success_after_fail.log")
    notify.push(URL, alert)
    assert "ntfy push failed" in capsys.readouterr().err


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y", "ntfy.sh/topic"])
def test_tail_rejects_non_web_url(monkeypatch, tmp_path, url):
    monkeypatch.setenv("LOGSENTRY_NTFY_URL", url)
    with pytest.raises(SystemExit) as exc:
        main(["tail", "--sshd", str(tmp_path / "auth.log")])
    assert exc.value.code == 2
