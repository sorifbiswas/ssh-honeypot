"""Enrich attacker IPs with geolocation/ASN info.

Uses the free ip-api.com endpoint (HTTP, ~45 requests/min limit).
Run separately from the listener:  python -m honeypot.enrich
"""
import ipaddress
import json
import time
import urllib.request

from .storage import Storage

API = "http://ip-api.com/json/{ip}?fields=status,country,city,as,org"


def lookup(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return ("Private", "", "", "")
    except ValueError:
        return None
    try:
        with urllib.request.urlopen(API.format(ip=ip), timeout=10) as resp:
            data = json.load(resp)
    except Exception:
        return None
    if data.get("status") != "success":
        return None
    return (data.get("country", ""), data.get("city", ""), data.get("as", ""), data.get("org", ""))


def main():
    db = Storage()
    ips = db.unenriched_ips()
    print(f"{len(ips)} IPs to enrich")
    for ip in ips:
        info = lookup(ip)
        if info:
            db.save_ip_info(ip, *info)
            print(ip, info)
        time.sleep(1.5)  # stay under the rate limit


if __name__ == "__main__":
    main()
