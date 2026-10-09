"""Run the production application on distinct IPv4 and IPv6 listening sockets.

Separate sockets preserve the actual IPv4 peer rather than an IPv4-mapped IPv6
address from a dual-stack socket. Both listeners share one application/worker.
"""

import socket

import uvicorn


if __name__ == "__main__":
    sockets = []
    for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((address, 8000))
        sockets.append(listener)
    config = uvicorn.Config("src.main:create_app", factory=True, proxy_headers=False)
    uvicorn.Server(config).run(sockets=sockets)
