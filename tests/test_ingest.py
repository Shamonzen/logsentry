import json
from pathlib import Path

from logsentry import store
from logsentry.cli import main, poll
from logsentry.engine import Engine
from logsentry.ingest import read_new_lines

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = Path(__file__).parent.parent / "config" / "rules.yaml"


def read_and_save(conn, path):
    lines, inode, offset = read_new_lines(conn, path)
    store.set_offset(conn, str(path), inode, offset)
    return lines


def test_resumes_from_saved_offset_and_waits_for_partial_lines(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    log = tmp_path / "auth.log"
    log.write_bytes(b"one\ntwo\nhal")
    assert read_and_save(conn, log) == ["one\n", "two\n"]
    with log.open("ab") as f:
        f.write(b"f\nthree\n")
    assert read_and_save(conn, log) == ["half\n", "three\n"]
    assert read_and_save(conn, log) == []


def test_rotation_and_truncation_restart_from_zero(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    log = tmp_path / "auth.log"
    log.write_bytes(b"old line one\nold line two\n")
    read_and_save(conn, log)
    log.rename(tmp_path / "auth.log.1")
    log.write_bytes(b"new\n")  # new inode, shorter than the saved offset
    assert read_and_save(conn, log) == ["new\n"]
    log.write_bytes(b"x\n")  # truncated in place (copytruncate)
    assert read_and_save(conn, log) == ["x\n"]


def test_missing_file_is_skipped(tmp_path):
    assert read_new_lines(store.connect(tmp_path / "t.db"), tmp_path / "nope.log") is None


def test_restart_does_not_alert_twice(tmp_path):
    db, log = tmp_path / "t.db", tmp_path / "auth.log"
    log.write_bytes((FIXTURES / "auth_bruteforce.log").read_bytes())
    files = {"sshd": log}
    first = poll(store.connect(db), Engine.from_config(CONFIG), files)
    assert first > 0
    # a new process: fresh engine state, offsets come from the database
    assert poll(store.connect(db), Engine.from_config(CONFIG), files) == 0
    assert store.connect(db).execute("SELECT count(*) FROM alerts").fetchone()[0] == first


def test_tail_requires_a_file(capsys):
    try:
        main(["tail"])
    except SystemExit as exc:
        assert exc.code == 2
    assert "--sshd" in capsys.readouterr().err


def test_tail_updates_a_growing_web_alert_in_place(tmp_path):
    db, log = tmp_path / "t.db", tmp_path / "access.log"
    lines = (FIXTURES / "nginx_attacks.log").read_text().splitlines(keepends=True)
    log.write_text("".join(lines[:2]))  # two traversal requests
    conn, engine, files, notified = store.connect(db), Engine.from_config(CONFIG), {}, []
    files["nginx"] = log
    poll(conn, engine, files, notified.append)
    with log.open("a") as f:
        f.write("".join(lines[2:5]))  # SQLi, XSS, SQLi from the same IP seconds later
    poll(conn, engine, files, notified.append)
    (row,) = conn.execute("SELECT * FROM alerts").fetchall()
    assert (row["event_count"], row["severity"]) == (5, "high")
    assert json.loads(row["categories"]) == ["Path traversal / LFI", "SQL injection", "XSS"]
    # traversal 400 (blocked: low), then a 200 (mixed: medium), then SQLi got a 200 (high);
    # the 500 and second XSS change nothing worth a notification
    assert [a.severity for a in notified] == ["low", "medium", "high"]
