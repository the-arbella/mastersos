#!/usr/bin/env python3
"""A GitHub release served on 127.0.0.1, for the installer tests.

    fake-release.py <DIR> <PORT FILE>

Serves the files under DIR (<DIR>/<tag>/<asset>, like github.com/<repo>/releases/download), and
/releases?page=N like the GitHub API's release list: <DIR>/releases-N.json, or [] past the last page.
Writes the port it listens on to PORT FILE once it is ready.
"""
import functools
import http.server
import os
import sys
import urllib.parse


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/releases":
            page = urllib.parse.parse_qs(url.query).get("page", ["1"])[0]
            if not page.isdigit():
                self.send_error(400)
                return
            path = os.path.join(self.directory, f"releases-{int(page)}.json")
            body = open(path, "rb").read() if os.path.exists(path) else b"[]"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def log_message(self, *args):
        pass


def main():
    root, port_file = sys.argv[1], sys.argv[2]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=root))
    tmp = port_file + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(server.server_address[1]))
    os.replace(tmp, port_file)
    server.serve_forever()


if __name__ == "__main__":
    main()
