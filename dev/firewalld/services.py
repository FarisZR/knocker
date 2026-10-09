"""Real TCP/UDP echo services, plus an unmonitored TCP control service."""

import socket
import threading

PAYLOAD = b"knocker-firewall-e2e"


def serve(family, protocol, port):
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", port))
        if protocol == "tcp":
            sock.listen()
        while True:
            if protocol == "tcp":
                conn, _ = sock.accept()
                with conn:
                    conn.sendall(PAYLOAD)
            else:
                data, peer = sock.recvfrom(1024)
                sock.sendto(data, peer)


if __name__ == "__main__":
    threads = []
    for family in (socket.AF_INET, socket.AF_INET6):
        for protocol, port in (("tcp", 9000), ("udp", 9001), ("tcp", 9002)):
            thread = threading.Thread(target=serve, args=(family, protocol, port))
            thread.start()
            threads.append(thread)
    for thread in threads:
        thread.join()
