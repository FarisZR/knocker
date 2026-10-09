"""Addresses assigned to this test container by Docker's dual-stack bridge."""

import socket


def addresses():
    """Resolve the container hostname to its assigned IPv4 and IPv6 addresses."""
    return sorted(
        {
            (family, endpoint[0])
            for family, _, _, _, endpoint in socket.getaddrinfo(
                socket.gethostname(), 0, type=socket.SOCK_STREAM
            )
            if family in (socket.AF_INET, socket.AF_INET6)
        }
    )
