# ssh-honeypot

A low-interaction SSH honeypot in Python. It pretends to be an Ubuntu server,
records every connection, username, password and command an attacker tries,
stores it in SQLite, and visualises it on a Streamlit dashboard.

**Nothing an attacker types is ever executed.** Responses come from a fixed
dictionary of canned outputs.

> **Ethical use:** run this only on infrastructure you own, inside Docker or a
> VM, ideally on an isolated VPS. Never on your main machine or home network.
> Captured data contains attacker IP addresses and passwords, so do not publish
> raw logs.

## Features
- SSH server built on `paramiko` that mimics OpenSSH on Ubuntu
- Logs connections, client banners, credentials and commands
- Optional fake shell (`HONEYPOT_FAKE_SHELL=1`) with canned responses
- IP enrichment (country, city, ASN) via ip-api.com
- Dashboard: attempts over time, top usernames/passwords/IPs, countries, commands
- Docker setup with dropped capabilities and a non-root user
- Unit tests and GitHub Actions CI

## Quick start (Docker)
```bash
docker compose up -d --build
```
| Service | What | Where |
|---|---|---|
| honeypot | fake SSH server | port `2222` |
| enricher | geo/ASN lookups every 10 min | background |
| dashboard | Streamlit UI | http://localhost:8501 (local only) |

Try it:
```bash
ssh -p 2222 root@localhost      # any password works in fake-shell mode
```

## Quick start (without Docker)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m honeypot.server            # terminal 1
streamlit run dashboard/app.py       # terminal 2
python -m honeypot.enrich            # optional, adds geo data
```

## Preview with demo data
```bash
python scripts/seed_demo_data.py     # fills the DB with fake data
streamlit run dashboard/app.py
```

## Configuration
| Variable | Default | Meaning |
|---|---|---|
| `HONEYPOT_PORT` | `2222` | listening port |
| `HONEYPOT_HOST` | `0.0.0.0` | bind address |
| `HONEYPOT_FAKE_SHELL` | `0` (`1` in compose) | `1` accepts any password and gives a fake shell; `0` rejects every login |
| `HONEYPOT_DB` | `data/honeypot.db` | SQLite path |
| `HONEYPOT_HOST_KEY` | `data/host_key` | SSH host key (auto-generated) |

Compose maps host port 2222 to the honeypot. To catch real-world scanners on
the standard port, move your own admin SSH to another port first, then change
the mapping to `"22:2222"`.

## Project layout
```
honeypot/server.py      SSH listener
honeypot/fake_shell.py  canned command responses
honeypot/storage.py     SQLite layer
honeypot/enrich.py      geoip / ASN lookups
dashboard/app.py        Streamlit dashboard
scripts/                demo data generator
tests/                  pytest suite
docs/findings.md        how to write up a deployment
```

## Development
```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Privacy note
`enrich.py` sends attacker IPs to ip-api.com over plain HTTP. Disable the
`enricher` service in `docker-compose.yml` if you do not want that.

## Roadmap
- [ ] Per-IP rate limiting and connection caps
- [ ] Tag known scanners (Shodan, Censys)
- [ ] Telegram/email alerts for new attackers
- [ ] Export reports as CSV/HTML

## License
MIT
