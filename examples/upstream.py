#!/usr/bin/env python3
"""A stand-in application: answers every request with a JSON echo of it."""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        payload = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body.decode("utf-8", "replace"),
            },
            indent=2,
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = respond

    def log_message(self, fmt, *args):
        sys.stderr.write("upstream: %s\n" % (fmt % args))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    print(f"upstream listening on 127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), Echo).serve_forever()
