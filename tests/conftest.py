import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import dns.resolver
import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).parent / "fixtures"


class _NoNetwork(RuntimeError):
    pass


def _refuse(*_a, **_k):
    raise _NoNetwork("network access attempted in a test")


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch, request):
    """Fail any outbound lookup. Tests that need the local fake server opt out with @pytest.mark.localhttp.

    (socket.socket itself is left alone because asyncio needs a socketpair.)
    """
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _refuse)
    monkeypatch.setattr(socket, "getaddrinfo", _refuse)
    if "localhttp" not in request.keywords:
        monkeypatch.setattr(requests.Session, "request", _refuse)
        monkeypatch.setattr(socket, "create_connection", _refuse)


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Temp SQLite DB and cache dir; no throttling delays."""
    import storage
    from scanners import collect

    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "watchlist.db")
    collect.configure(tmp_path / "cache")
    monkeypatch.setattr(collect, "MIN_INTERVAL", {"crt.sh": 0.0, "rdap": 0.0})
    monkeypatch.setattr(collect, "_client", None)
    yield
    collect.configure(None)


class FakeServer:
    """Local HTTP server on 127.0.0.1. handler(path, n) -> (status, headers, body)."""

    def __init__(self, handler):
        self.handler = handler
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append(self.path)
                status, headers, body = outer.handler(self.path, len(outer.requests))
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def fake_server(monkeypatch):
    # The no-network guard blocks getaddrinfo; requests needs it for 127.0.0.1, so allow numeric hosts.
    real = socket.__dict__.get("_real_getaddrinfo") or __import__("_socket").getaddrinfo

    def numeric_only(host, *a, **k):
        if host in ("127.0.0.1", "localhost"):
            return real("127.0.0.1", *a, **k)
        raise _NoNetwork(f"lookup of {host} attempted in a test")
    monkeypatch.setattr(socket, "getaddrinfo", numeric_only)
    servers = []

    def make(handler):
        s = FakeServer(handler)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()
