import socket

import pytest

from reva.cli import claim_port, main


def test_free_port_is_claimable():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    claim_port("127.0.0.1", port, "target")


def test_port_in_use_names_the_port_and_the_flag():
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        with pytest.raises(SystemExit) as exc:
            main(["watch", "target", "--port", str(port)])
    message = str(exc.value)
    assert f"port {port}" in message and "already in use" in message
    assert f"--port {port + 1}" in message
