"""One fresh network connection from a real client, with no HTTP proxy."""

import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

PAYLOAD = b"knocker-firewall-e2e"


def probe(request):
    """Send fresh traffic; only a timeout counts as a firewall drop."""
    host = request["host"]
    if request["kind"] == "access":
        # Independent fresh sockets share one Docker exec and wait concurrently.
        requests = [
            {"host": host, "kind": kind, "port": port}
            for kind, port in (("tcp", 9002), ("tcp", 9000), ("udp", 9001))
        ]
        with ThreadPoolExecutor(max_workers=3) as pool:
            return list(pool.map(probe, requests))
    if request["kind"] == "http":
        import http.client

        conn = http.client.HTTPConnection(host, 8000, timeout=20)
        try:
            body = json.dumps(request.get("body", {}))
            conn.request(
                request.get("method", "GET"),
                request["path"],
                body=body,
                headers={"Content-Type": "application/json", **request.get("headers", {})},
            )
            response = conn.getresponse()
            return {"status": response.status, "body": json.loads(response.read())}
        finally:
            conn.close()

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    kind = socket.SOCK_STREAM if request["kind"] == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as sock:
        sock.settimeout(0.8)
        try:
            sock.connect((host, request["port"]))
            if kind == socket.SOCK_DGRAM:
                sock.send(PAYLOAD)
            result = sock.recv(1024)
            return {"allowed": result == PAYLOAD, "received": result.decode()}
        except TimeoutError:
            return {"allowed": False, "error": "timeout"}


if __name__ == "__main__":
    print(json.dumps(probe(json.load(sys.stdin))))
