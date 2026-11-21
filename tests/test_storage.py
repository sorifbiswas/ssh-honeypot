import sqlite3

from honeypot.storage import Storage


def make(tmp_path):
    path = str(tmp_path / "t.db")
    return Storage(path), path


def count(path, table):
    with sqlite3.connect(path) as c:
        return c.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_logs_are_stored(tmp_path):
    db, path = make(tmp_path)
    db.log_connection("203.0.113.5", 4444, "SSH-2.0-test")
    db.log_auth("203.0.113.5", "root", "123456")
    db.log_command("203.0.113.5", "root", "ls")
    assert count(path, "connections") == 1
    assert count(path, "auth_attempts") == 1
    assert count(path, "commands") == 1


def test_enrichment_queue(tmp_path):
    db, path = make(tmp_path)
    db.log_auth("203.0.113.5", "root", "x")
    assert db.unenriched_ips() == ["203.0.113.5"]
    db.save_ip_info("203.0.113.5", "Testland", "Testville", "AS1", "TestOrg")
    assert db.unenriched_ips() == []
