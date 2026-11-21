"""Low-interaction SSH honeypot.

Logs every connection, credential attempt and typed command. By default it
rejects all logins. Set HONEYPOT_FAKE_SHELL=1 to accept any password and drop
the attacker into a fake shell (canned output, nothing is ever executed).

Run:  python -m honeypot.server
"""
import logging
import os
import socket
import threading

import paramiko

from . import fake_shell
from .storage import Storage

HOST = os.environ.get("HONEYPOT_HOST", "0.0.0.0")
PORT = int(os.environ.get("HONEYPOT_PORT", "2222"))
FAKE_SHELL = os.environ.get("HONEYPOT_FAKE_SHELL", "0") == "1"
HOST_KEY_PATH = os.environ.get("HONEYPOT_HOST_KEY", "data/host_key")
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
SESSION_TIMEOUT = 120  # seconds

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("honeypot")


def load_host_key():
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    os.makedirs(os.path.dirname(HOST_KEY_PATH) or ".", exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    os.chmod(HOST_KEY_PATH, 0o600)
    return key


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, ip, db):
        self.ip = ip
        self.db = db
        self.username = None
        self.shell_event = threading.Event()
        self.exec_command = None

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.username = username
        self.db.log_auth(self.ip, username, password, success=FAKE_SHELL)
        log.info("auth %s user=%r pass=%r", self.ip, username, password)
        return paramiko.AUTH_SUCCESSFUL if FAKE_SHELL else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode("utf-8", "replace")
        self.shell_event.set()
        return True


def run_shell(chan, server):
    """Very small interactive loop. Input is only logged, never executed."""
    chan.send("Welcome to Ubuntu 22.04.3 LTS\r\n\r\n")
    prompt = f"root@{fake_shell.HOSTNAME}:~# "
    buf = ""
    chan.send(prompt)
    while True:
        data = chan.recv(1024)
        if not data:
            return
        for ch in data.decode("utf-8", "replace"):
            if ch in ("\r", "\n"):
                chan.send("\r\n")
                cmd = buf
                buf = ""
                if cmd.strip():
                    server.db.log_command(server.ip, server.username, cmd)
                    log.info("cmd  %s %r", server.ip, cmd)
                out, done = fake_shell.respond(cmd)
                if out:
                    chan.send(out.replace("\n", "\r\n") + "\r\n")
                if done:
                    return
                chan.send(prompt)
            elif ch in ("\x7f", "\x08"):
                if buf:
                    buf = buf[:-1]
                    chan.send("\b \b")
            elif ch == "\x03":  # Ctrl-C
                buf = ""
                chan.send("^C\r\n" + prompt)
            elif ch == "\x04":  # Ctrl-D
                return
            elif ch.isprintable():
                buf += ch
                chan.send(ch)


def handle_client(client, addr, host_key, db):
    ip, port = addr[0], addr[1]
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        server = HoneypotServer(ip, db)
        transport.start_server(server=server)
        db.log_connection(ip, port, transport.remote_version)
        log.info("conn %s:%s client=%s", ip, port, transport.remote_version)

        chan = transport.accept(20)
        if chan is None:
            return
        chan.settimeout(SESSION_TIMEOUT)
        if not server.shell_event.wait(10):
            return
        if server.exec_command is not None:
            cmd = server.exec_command
            db.log_command(ip, server.username, cmd)
            out, _ = fake_shell.respond(cmd)
            if out:
                chan.send(out + "\n")
            chan.send_exit_status(0)
        else:
            run_shell(chan, server)
        chan.close()
    except (paramiko.SSHException, EOFError, ConnectionError, socket.timeout, OSError) as exc:
        log.debug("session ended %s: %s", ip, exc)
    finally:
        if transport is not None:
            transport.close()
        client.close()


def main():
    db = Storage()
    host_key = load_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    log.info("honeypot listening on %s:%s (fake shell: %s)", HOST, PORT, FAKE_SHELL)
    while True:
        client, addr = sock.accept()
        threading.Thread(
            target=handle_client, args=(client, addr, host_key, db), daemon=True
        ).start()


if __name__ == "__main__":
    main()
