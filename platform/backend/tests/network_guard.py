"""Makes a test fail if it tries to reach a real service.

Refused: any connection to a non-loopback address, any loopback connection to a port the
agent's dependencies listen on (Ollama, Postgres, OpenSearch/Wazuh, Cortex, MISP, HTTP/S),
and socket.create_connection. Allowed: the loopback socket pair asyncio and TestClient use
internally.
"""

import socket

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
SERVICE_PORTS = {80, 443, 5432, 8443, 9000, 9001, 9200, 9443, 11434}
_REAL_CONNECT = socket.socket.connect


def install(monkeypatch):
    def guarded_connect(self, address):
        if isinstance(address, tuple) and len(address) >= 2:
            host, port = address[0], address[1]

            if host not in LOOPBACK or port in SERVICE_PORTS:
                raise AssertionError(
                    f"A test tried to open a real network connection to {host}:{port}."
                )

        return _REAL_CONNECT(self, address)

    def guarded_create_connection(address, *args, **kwargs):
        raise AssertionError(
            f"A test tried to open a real network connection to {address}."
        )

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)
