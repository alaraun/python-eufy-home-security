"""Loopback tests for the vendored ikcp port (:mod:`.rtc._ikcp`).

KCP interoperability with the C ``kcp`` package (and so with the station's peer) is
checked out of tree; here two instances of the port exchange messages over an in-memory
pump, including a message large enough to fragment.
"""

from __future__ import annotations

from eufy_home_security.rtc import _ikcp


def _configured(conv: int) -> _ikcp.KCP:
    k = _ikcp.KCP(conv)
    k.set_performance_options(True, 2, 2, True)  # nodelay(1, 2 ms, resend 2, no congestion)
    k.set_window_size(512, 512)
    k.set_maximum_transmission(1200)
    return k


def _pump(
    a: _ikcp.KCP, b: _ikcp.KCP, a_to_b: list[bytes], b_to_a: list[bytes]
) -> tuple[list[bytes], list[bytes]]:
    ab: list[bytes] = []
    ba: list[bytes] = []
    a.include_outbound_handler(lambda _k, d: ab.append(bytes(d)))
    b.include_outbound_handler(lambda _k, d: ba.append(bytes(d)))
    for m in a_to_b:
        a.enqueue(m)
    for m in b_to_a:
        b.enqueue(m)
    got_a: list[bytes] = []
    got_b: list[bytes] = []
    for t in range(0, 6000, 5):
        a.update(t)
        b.update(t)
        while ab:
            b.receive(ab.pop(0))
        while ba:
            a.receive(ba.pop(0))
        while b.next_packet_available:
            got_b.append(bytes(b.get_received()))
        while a.next_packet_available:
            got_a.append(bytes(a.get_received()))
        if len(got_b) >= len(a_to_b) and len(got_a) >= len(b_to_a):
            break
    return got_a, got_b


def test_small_messages_both_ways() -> None:
    got_a, got_b = _pump(_configured(1), _configured(1), [b"ping", b"ping2"], [b"pong"])
    assert got_b == [b"ping", b"ping2"]
    assert got_a == [b"pong"]


def test_large_message_fragments_and_reassembles() -> None:
    big = bytes(range(256)) * 12  # 3072 bytes > mss (1176), so it fragments
    _got_a, got_b = _pump(_configured(1), _configured(1), [big], [])
    assert got_b == [big]


def test_order_preserved_under_many_messages() -> None:
    msgs = [f"msg-{i:03d}".encode() for i in range(50)]
    _got_a, got_b = _pump(_configured(1), _configured(1), msgs, [])
    assert got_b == msgs
