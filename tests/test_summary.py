import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import URLError

import pytest

from logsentry import summary
from logsentry.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = Path(__file__).parent.parent / "config" / "rules.yaml"
URL = "https://ntfy.example.test/topic"


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


def db_with(tmp_path, *fixtures):
    db = tmp_path / "logsentry.db"
    for name in fixtures:
        main(["ingest", str(FIXTURES / name), "--source", "sshd", "--config", str(CONFIG),
              "--db", str(db)])  # fmt: skip
    return db


def test_day_with_a_high_alert(tmp_path, capsys, sent):
    db = db_with(tmp_path, "auth_bruteforce.log", "auth_success_after_fail.log")
    capsys.readouterr()
    assert summary.run(db, 24, URL) == 0
    (request,) = sent
    assert request.get_header("Title") == "LogSentry: 3 alerts in 24 hours"
    assert request.get_header("Priority") == "default"
    assert request.data.decode().splitlines() == [
        "1 x SSH login after repeated failures (HIGH)",  # most severe first
        "1 x SSH brute force (MEDIUM)",
        "1 x SSH password spray (MEDIUM)",
        "1 HIGH: check them on the dashboard.",
    ]
    assert capsys.readouterr().out.startswith("LogSentry: 3 alerts in 24 hours\n")


def test_day_without_high_is_low_priority(tmp_path, sent):
    db = db_with(tmp_path, "auth_bruteforce.log")
    summary.run(db, 24, URL)
    assert sent[0].get_header("Priority") == "low"
    assert sent[0].data.decode().endswith("Nothing serious: no HIGH alerts.")


def test_alerts_older_than_the_window_are_left_out(tmp_path, sent):
    db = db_with(tmp_path, "auth_bruteforce.log")
    summary.run(db, 24, URL, now=datetime.now(UTC) + timedelta(days=2))
    assert sent[0].get_header("Title") == "LogSentry: all quiet"
    assert sent[0].data.decode() == "No alerts in the last 24 hours."


def test_no_database_yet_is_all_quiet(tmp_path, sent):
    assert summary.run(tmp_path / "none.db", 24, URL) == 0
    assert sent[0].get_header("Title") == "LogSentry: all quiet"


def test_without_url_it_only_prints(tmp_path, capsys, sent):
    assert summary.run(db_with(tmp_path, "auth_bruteforce.log"), 24, None) == 0
    assert sent == []
    assert "2 alerts" in capsys.readouterr().out


def test_failed_push_exits_1(tmp_path, monkeypatch, capsys):
    def down(request, timeout):
        raise URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", down)
    assert summary.run(tmp_path / "none.db", 24, URL) == 1
    assert "ntfy push failed" in capsys.readouterr().err


def test_cli_reads_url_from_env_file(tmp_path, monkeypatch, sent):
    monkeypatch.delenv("LOGSENTRY_NTFY_URL", raising=False)
    env = tmp_path / "logsentry.env"
    env.write_text(f"LOGSENTRY_NTFY_URL={URL}\n")
    argv = ["summary", "--db", str(tmp_path / "none.db"), "--env-file", str(env)]
    assert main(argv) == 0
    assert sent[0].full_url == URL


@pytest.mark.parametrize(("extra", "env"), [(["--hours", "0"], None), ([], "file:///etc/passwd")])
def test_cli_rejects_bad_input(tmp_path, monkeypatch, extra, env):
    if env:
        monkeypatch.setenv("LOGSENTRY_NTFY_URL", env)
    with pytest.raises(SystemExit) as exc:
        main(["summary", "--db", str(tmp_path / "none.db"), *extra])
    assert exc.value.code == 2
