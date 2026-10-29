import shutil
import urllib.request
from pathlib import Path
from urllib.error import URLError

import pytest

from logsentry import doctor, notify, store
from logsentry.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = Path(__file__).parent.parent / "config" / "rules.yaml"


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


@pytest.fixture
def server(tmp_path, monkeypatch):
    """A healthy install: logs present, alerts stored, no systemd (as on the CI runner)."""
    monkeypatch.setattr(shutil, "which", lambda name: None)
    (tmp_path / "auth.log").write_text("")
    (tmp_path / "access.log").write_text("")
    db = tmp_path / "logsentry.db"
    main(["ingest", str(FIXTURES / "auth_success_after_fail.log"), "--source", "sshd",
          "--config", str(CONFIG), "--db", str(db)])  # fmt: skip
    return tmp_path


def argv(tmp, *extra):
    return ["doctor", "--sshd", str(tmp / "auth.log"), "--nginx", str(tmp / "access.log"),
            "--config", str(CONFIG), "--db", str(tmp / "logsentry.db"),
            "--env-file", str(tmp / "logsentry.env"), *extra]  # fmt: skip


def test_healthy_install_passes(server, capsys, sent):
    (server / "logsentry.env").write_text("LOGSENTRY_NTFY_URL=https://ntfy.example.test/t\n")
    assert main(argv(server)) == 0
    out = capsys.readouterr().out
    assert "Alerts: 1 stored, 1 of them HIGH" in out
    assert "Rules: 6 detections enabled" in out
    assert "test notification sent" in out
    assert out.rstrip().endswith("All good.")
    assert sent[0].full_url == "https://ntfy.example.test/t"


def test_missing_ssh_log_fails(server, capsys):
    (server / "auth.log").unlink()
    assert main(argv(server)) == 1
    assert "[FAIL] SSH log" in capsys.readouterr().out


def test_missing_web_log_only_warns(server, capsys):
    (server / "access.log").unlink()
    assert main(argv(server)) == 0
    assert "[WARN] Web log" in capsys.readouterr().out


def test_broken_config_fails(server, capsys):
    bad = server / "rules.yaml"
    bad.write_text("cooldown_seconds: [not a number\n")
    assert main([*argv(server), "--config", str(bad)]) == 1
    assert "[FAIL] Rules" in capsys.readouterr().out


def test_no_database_yet_only_warns(server, capsys):
    (server / "logsentry.db").unlink()
    assert main(argv(server)) == 0
    assert "[WARN] Alerts: no database yet" in capsys.readouterr().out


def test_phone_off_only_warns(server, capsys, sent):
    assert main(argv(server)) == 0
    assert "[WARN] Phone alerts: off" in capsys.readouterr().out
    assert sent == []


def test_failed_test_push_fails(server, capsys, monkeypatch):
    def down(request, timeout):
        raise URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", down)
    (server / "logsentry.env").write_text("LOGSENTRY_NTFY_URL=https://ntfy.example.test/t\n")
    assert main(argv(server)) == 1
    assert "[FAIL] Phone alerts: test notification failed" in capsys.readouterr().out


def test_unreadable_settings_say_use_sudo_not_off(tmp_path, monkeypatch):
    def denied(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(notify, "read_env_file", denied)
    status, message = doctor.check_phone(None, tmp_path / "logsentry.env")
    assert status == doctor.WARN and "sudo" in message and "off" not in message


def test_env_file_parsing(tmp_path):
    env = tmp_path / "e"
    env.write_text('# comment\n\nLOGSENTRY_NTFY_URL="https://ntfy.sh/x=y"\nOTHER = 1\n')
    assert notify.read_env_file(env) == {"LOGSENTRY_NTFY_URL": "https://ntfy.sh/x=y", "OTHER": "1"}
    assert notify.read_env_file(tmp_path / "missing") == {}


def test_stopped_service_fails(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/systemctl")

    class Result:
        stdout = "inactive\n"

    monkeypatch.setattr(doctor.subprocess, "run", lambda *a, **k: Result())
    status, message = doctor.check_service()
    assert status == doctor.FAIL and "inactive" in message


def fake_systemctl(monkeypatch, answers):
    monkeypatch.setattr(doctor, "systemctl", lambda *args: answers[args[0]])


def test_armed_timer_shows_next_run(monkeypatch):
    fake_systemctl(monkeypatch, {"is-active": "active", "show": "Tue 2026-10-27 08:00:00 EDT"})
    assert doctor.check_timer() == (
        doctor.OK,
        "Daily summary: next one Tue 2026-10-27 08:00:00 EDT",
    )


def test_inactive_timer_only_warns(monkeypatch):
    fake_systemctl(monkeypatch, {"is-active": "inactive"})
    status, message = doctor.check_timer()
    assert status == doctor.WARN and "inactive" in message and "install.sh" in message


def test_no_systemd_timer_only_warns(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert doctor.check_timer()[0] == doctor.WARN


def test_db_counts(tmp_path):
    store.connect(tmp_path / "e.db").close()
    assert doctor.check_db(tmp_path / "e.db") == (doctor.OK, "Alerts: none yet (that's good)")
