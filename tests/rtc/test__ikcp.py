"""Loopback tests for the vendored KCP port (:mod:`.rtc._ikcp`): two instances
exchange messages over an in-memory pump, with loss, fragmentation and window limits."""

from __future__ import annotations

import struct

import pytest

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


def test_a_pushed_segment_advertises_the_free_receive_window() -> None:
    k = _configured(7)
    out: list[bytes] = []
    k.include_outbound_handler(lambda _k, d: out.append(bytes(d)))
    k.enqueue(b"hello")
    k.update(0)
    _conv, cmd, _frg, wnd = struct.unpack_from("<IBBH", out[0])
    assert (cmd, wnd) == (_ikcp.IKCP_CMD_PUSH, 512)


def test_a_message_of_128_fragments_is_refused() -> None:
    k = _configured(1)
    k.enqueue(bytes(k.mss * 127))  # 127 fragments fit
    with pytest.raises(ValueError, match="128 fragments"):
        k.enqueue(bytes(k.mss * 127 + 1))


def test_a_lost_segment_is_resent() -> None:
    a, b = _configured(1), _configured(1)
    ab: list[bytes] = []
    ba: list[bytes] = []
    a.include_outbound_handler(lambda _k, d: ab.append(bytes(d)))
    b.include_outbound_handler(lambda _k, d: ba.append(bytes(d)))
    a.enqueue(b"one")
    a.update(0)
    assert ab
    ab.clear()  # the first transmission is lost
    got: list[bytes] = []
    for t in range(10, 2000, 10):
        a.update(t)
        b.update(t)
        while ab:
            b.receive(ab.pop(0))
        while ba:
            a.receive(ba.pop(0))
        while b.next_packet_available:
            got.append(bytes(b.get_received()))
        if got:
            break
    assert got == [b"one"]
    assert a.xmit >= 1


def test_receive_refuses_another_conv_and_a_short_segment() -> None:
    k = _configured(1)
    other = _configured(2)
    out: list[bytes] = []
    other.include_outbound_handler(lambda _k, d: out.append(bytes(d)))
    other.enqueue(b"x")
    other.update(0)
    assert k.receive(out[0]) == -1
    seg = bytearray(out[0])
    seg[0] = 1  # conv 1, but the declared length runs past the data
    assert k.receive(bytes(seg[:-1])) == -2
    seg[4] = 99  # unknown command
    assert k.receive(bytes(seg)) == -3


def test_a_full_receive_window_announces_its_reopening() -> None:
    k = _configured(1)
    k.rcv_wnd = 2
    for sn in range(2):
        k.receive(struct.pack("<IBBHIIII", 1, _ikcp.IKCP_CMD_PUSH, 0, 32, 0, sn, 0, 1) + b"m")
    assert len(k.rcv_queue) == 2
    k.probe = 0
    k.get_received()
    assert k.probe & _ikcp.IKCP_ASK_TELL
