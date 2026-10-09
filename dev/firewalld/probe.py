"""One fresh network connection from a real client, with no HTTP proxy."""

import json
import socket
import sys

PAYLOAD = b"knocker-firewall-e2e"


def probe(request):
    host = request["host"]
    time_scale = request.get("time_scale", 1)
    if request["kind"] == "http":
        import http.client

        conn = http.client.HTTPConnection(host, 8000, timeout=20 * time_scale)
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
    # Resolve the interface scope into the IPv6 sockaddr's fourth field.
    # Passing a scoped string directly to socket.connect loses that scope.
    endpoint = socket.getaddrinfo(host, request["port"], family, kind)[0][4]
    with socket.socket(family, kind) as sock:
        sock.settimeout(0.8 * time_scale)
        try:
            sock.connect(endpoint)
            if kind == socket.SOCK_DGRAM:
                sock.send(PAYLOAD)
            result = sock.recv(1024)
            return {"allowed": result == PAYLOAD, "received": result.decode()}
        except TimeoutError:
            return {"allowed": False, "error": "timeout"}


if __name__ == "__main__":
    print(json.dumps(probe(json.load(sys.stdin))))
