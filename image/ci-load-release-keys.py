#!/usr/bin/env python3
"""Run keys-load.sh --age on a CI runner, where nobody is at the terminal.

age reads the passphrase only from a terminal, so keys-load.sh runs on a pty and this script types
MASTERSOS_AGE_PASSPHRASE when age asks. Every check in keys-load.sh still applies.
usage: ci-load-release-keys.py <file.age>
"""
import os
import pty
import sys

PROMPT = b"Enter passphrase"


def main():
    secret = os.environ.pop("MASTERSOS_AGE_PASSPHRASE", "")
    if len(sys.argv) != 2 or not secret:
        sys.exit("ci-load-release-keys.py: needs <file.age> and MASTERSOS_AGE_PASSPHRASE")
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys-load.sh")
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(script, [script, "--age", sys.argv[1]])
    seen = b""
    sent = False
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:  # EIO: the child closed the pty
            break
        if not chunk:
            break
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        if not sent:
            seen += chunk
            if PROMPT in seen:
                os.write(fd, secret.encode() + b"\n")
                sent = True
    status = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    if not sent:
        sys.exit("ci-load-release-keys.py: age never asked for the passphrase")
    sys.exit(status)


if __name__ == "__main__":
    main()
