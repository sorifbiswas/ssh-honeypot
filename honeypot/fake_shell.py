"""Fake shell: canned responses only. Nothing the attacker types is ever executed."""

HOSTNAME = "srv-web01"

CANNED = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "pwd": "/root",
    "hostname": HOSTNAME,
    "uname": "Linux",
    "uname -a": f"Linux {HOSTNAME} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "ls": "backup.tar.gz  notes.txt",
    "ls -la": (
        "total 20\n"
        "drwx------ 2 root root 4096 Jan  9 10:12 .\n"
        "drwxr-xr-x 18 root root 4096 Jan  9 10:10 ..\n"
        "-rw-r--r-- 1 root root 2048 Jan  8 22:41 backup.tar.gz\n"
        "-rw-r--r-- 1 root root  120 Jan  8 22:43 notes.txt"
    ),
    "uptime": " 10:42:11 up 41 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
    ),
}


def respond(command: str):
    """Return (output, should_exit)."""
    cmd = command.strip()
    if not cmd:
        return "", False
    if cmd in ("exit", "logout", "quit"):
        return "logout", True
    if cmd in CANNED:
        return CANNED[cmd], False
    first = cmd.split()[0]
    if first in ("wget", "curl", "tftp", "ftp"):
        return f"{first}: connection timed out", False
    if first == "cd":
        return "", False
    return f"bash: {first}: command not found", False
