#!/usr/bin/env python3
"""Mint an HS256 JWT accepted by the `api` token configuration in config.yaml.

Usage: python3 token.py [subject] [lifetime-seconds]
"""

import base64
import hashlib
import hmac
import json
import sys
import time

SECRET = b"openshield-demo-secret-change-me!"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


subject = sys.argv[1] if len(sys.argv) > 1 else "alice"
lifetime = int(sys.argv[2]) if len(sys.argv) > 2 else 3600
header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "demo"}).encode())
claims = b64(json.dumps({"sub": subject, "exp": int(time.time()) + lifetime}).encode())
signature = b64(hmac.new(SECRET, f"{header}.{claims}".encode(), hashlib.sha256).digest())
print(f"{header}.{claims}.{signature}")
