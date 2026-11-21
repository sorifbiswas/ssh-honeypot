# Findings

This file is where results from a real deployment go. The honeypot needs to
be online for a while before there is anything to report, so the sections
below describe what to record and how to read it.

## How to collect the data
1. Deploy on an isolated VPS (`docker compose up -d --build`).
2. Let it run for at least 7 days.
3. Open the dashboard (`ssh -L 8501:localhost:8501 user@your-vps`, then
   http://localhost:8501) and take screenshots.
4. Export counts with `sqlite3 data/honeypot.db` (see queries below).

## Useful queries
```sql
-- most tried passwords
SELECT password, COUNT(*) c FROM auth_attempts GROUP BY password ORDER BY c DESC LIMIT 10;
-- most active IPs
SELECT ip, COUNT(*) c FROM auth_attempts GROUP BY ip ORDER BY c DESC LIMIT 10;
-- all commands run after login
SELECT ts, ip, command FROM commands ORDER BY ts;
-- time to first attempt after going online
SELECT MIN(ts) FROM auth_attempts;
```

## What to write up
- Headline numbers: attempts, unique IPs, usernames, passwords, commands
- Top credentials, and how many are default or vendor passwords
- Where attackers come from (countries, hosting providers)
- Timeline: how quickly the first attacker arrived, and any spikes
- Commands attackers ran, grouped into recon, malware download and persistence
- Defensive lessons: key-only SSH, fail2ban, no default accounts

> Dashboard screenshots with demo data can be generated with
> `python scripts/seed_demo_data.py`. Mark demo data clearly as fake if you
> publish it.
