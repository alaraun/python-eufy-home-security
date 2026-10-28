"""A pure-Python port of ikcp.c (skywind3000/kcp), MIT-licensed.

KCP is the reliable-ordered transport the eufy WebRTC data channel runs over libjuice.
The C ``kcp`` package ships no aarch64 Linux wheel, so the library carries this port;
KCP is wire-defined, so it interoperates byte-for-byte with the station's ikcp peer.

Only the subset the data channel needs is exposed, with the method names the ``kcp``
package uses: :class:`KCP` with ``include_outbound_handler``, ``enqueue``, ``flush``,
``receive``, ``next_packet_available``, ``get_received`` and ``update``.
"""

from __future__ import annotations

import struct
import time
from collections import deque
from collections.abc import Callable
from typing import Final

IKCP_RTO_NDL: Final = 30
IKCP_RTO_MIN: Final = 100
IKCP_RTO_DEF: Final = 200
IKCP_RTO_MAX: Final = 60000
IKCP_CMD_PUSH: Final = 81
IKCP_CMD_ACK: Final = 82
IKCP_CMD_WASK: Final = 83
IKCP_CMD_WINS: Final = 84
IKCP_ASK_SEND: Final = 1
IKCP_ASK_TELL: Final = 2
IKCP_WND_SND: Final = 32
IKCP_WND_RCV: Final = 128
IKCP_MTU_DEF: Final = 1400
IKCP_INTERVAL: Final = 100
IKCP_OVERHEAD: Final = 24
IKCP_DEADLINK: Final = 20
IKCP_THRESH_INIT: Final = 2
IKCP_THRESH_MIN: Final = 2
IKCP_PROBE_INIT: Final = 7000
IKCP_PROBE_LIMIT: Final = 120000
IKCP_FASTACK_LIMIT: Final = 5

_MASK: Final = 0xFFFFFFFF


def _u32(x: int) -> int:
    return x & _MASK


def _itimediff(later: int, earlier: int) -> int:
    """Signed difference of two u32 sequence/time values (wrap-aware)."""
    return ((later - earlier) & _MASK) - (((later - earlier) & 0x80000000) << 1)


def _now_ms() -> int:
    return int(time.monotonic() * 1000) & _MASK


class _Seg:
    """One KCP segment: its header fields, payload and retransmit bookkeeping."""

    __slots__ = (
        "cmd",
        "conv",
        "data",
        "fastack",
        "frg",
        "resendts",
        "rto",
        "sn",
        "ts",
        "una",
        "wnd",
        "xmit",
    )

    def __init__(self) -> None:
        self.conv = 0
        self.cmd = 0
        self.frg = 0
        self.wnd = 0
        self.ts = 0
        self.sn = 0
        self.una = 0
        self.data = b""
        self.resendts = 0
        self.rto = 0
        self.fastack = 0
        self.xmit = 0


def _encode_seg(seg: _Seg, data: bytes) -> bytes:
    return (
        struct.pack(
            "<IBBHIIII",
            _u32(seg.conv),
            seg.cmd & 0xFF,
            seg.frg & 0xFF,
            seg.wnd & 0xFFFF,
            _u32(seg.ts),
            _u32(seg.sn),
            _u32(seg.una),
            len(data),
        )
        + data
    )


class KCP:
    """A KCP control block (one direction pair of a reliable channel)."""

    def __init__(self, conv_id: int = 0) -> None:
        self.conv = _u32(conv_id)
        self.snd_una = 0
        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.ssthresh = IKCP_THRESH_INIT
        self.rx_rttval = 0
        self.rx_srtt = 0
        self.rx_rto = IKCP_RTO_DEF
        self.rx_minrto = IKCP_RTO_MIN
        self.snd_wnd = IKCP_WND_SND
        self.rcv_wnd = IKCP_WND_RCV
        self.rmt_wnd = IKCP_WND_RCV
        self.cwnd = 0
        self.probe = 0
        self.current = 0
        self.interval = IKCP_INTERVAL
        self.ts_flush = IKCP_INTERVAL
        self.xmit = 0
        self.nodelay = 0
        self.updated = 0
        self.ts_probe = 0
        self.probe_wait = 0
        self.dead_link = IKCP_DEADLINK
        self.incr = 0
        self.mtu = IKCP_MTU_DEF
        self.mss = self.mtu - IKCP_OVERHEAD
        self.stream = 0
        self.fastresend = 0
        self.fastlimit = IKCP_FASTACK_LIMIT
        self.nocwnd = 0
        self.state = 0
        self.snd_queue: deque[_Seg] = deque()
        self.rcv_queue: deque[_Seg] = deque()
        self.snd_buf: deque[_Seg] = deque()
        self.rcv_buf: list[_Seg] = []
        self.acklist: list[tuple[int, int]] = []
        self._output: Callable[[KCP, bytes], None] | None = None

    # ── configuration (names match the ``kcp`` package) ───────────────────────
    def include_outbound_handler(self, handler: Callable[[KCP, bytes], None]) -> None:
        """Register the callback that puts each outbound KCP segment on the wire."""
        self._output = handler

    def set_maximum_transmission(self, mtu: int) -> None:
        if mtu < 50 or mtu < IKCP_OVERHEAD:
            raise ValueError("KCP mtu too small")
        self.mtu = mtu
        self.mss = mtu - IKCP_OVERHEAD

    def set_window_size(self, send: int, receive: int) -> None:
        if send > 0:
            self.snd_wnd = send
        if receive > 0:
            self.rcv_wnd = max(receive, IKCP_WND_RCV)

    def set_performance_options(
        self, no_delay: bool, update_interval: int, resend_count: int, no_congestion_control: bool
    ) -> None:
        self.nodelay = 1 if no_delay else 0
        self.rx_minrto = IKCP_RTO_NDL if no_delay else IKCP_RTO_MIN
        self.interval = min(max(update_interval, 10), 5000)
        if resend_count >= 0:
            self.fastresend = resend_count
        self.nocwnd = 1 if no_congestion_control else 0

    # ── application send / receive ────────────────────────────────────────────
    def enqueue(self, buffer: bytes) -> None:
        """Queue an application message to send, fragmented to the mss."""
        if not buffer:
            return
        count = max(1, (len(buffer) + self.mss - 1) // self.mss)
        for i in range(count):
            size = min(self.mss, len(buffer))
            seg = _Seg()
            seg.data = buffer[:size]
            seg.frg = (count - i - 1) if self.stream == 0 else 0
            self.snd_queue.append(seg)
            buffer = buffer[size:]

    @property
    def next_packet_available(self) -> bool:
        return self._peeksize() >= 0

    def _peeksize(self) -> int:
        if not self.rcv_queue:
            return -1
        first = self.rcv_queue[0]
        if first.frg == 0:
            return len(first.data)
        if len(self.rcv_queue) < first.frg + 1:
            return -1
        length = 0
        for seg in self.rcv_queue:
            length += len(seg.data)
            if seg.frg == 0:
                break
        return length

    def get_received(self) -> bytearray:
        """Return the next complete application message, or empty if none is ready."""
        if self._peeksize() < 0:
            return bytearray()
        out = bytearray()
        for seg in list(self.rcv_queue):
            out += seg.data
            self.rcv_queue.popleft()
            if seg.frg == 0:
                break
        self._buf_to_queue()
        return out

    def _buf_to_queue(self) -> None:
        while self.rcv_buf:
            seg = self.rcv_buf[0]
            if seg.sn == self.rcv_nxt and len(self.rcv_queue) < self.rcv_wnd:
                self.rcv_buf.pop(0)
                self.rcv_queue.append(seg)
                self.rcv_nxt = _u32(self.rcv_nxt + 1)
            else:
                break

    # ── wire input ──────────────────────────────────────────────────────────────
    def receive(self, data: bytes) -> int:
        """Feed a datagram of one or more KCP segments; returns 0 on success."""
        prev_una = self.snd_una
        maxack = 0
        latest_ts = 0
        flag = False
        off = 0
        while len(data) - off >= IKCP_OVERHEAD:
            conv, cmd, _frg, wnd, ts, sn, una, length = struct.unpack_from("<IBBHIIII", data, off)
            off += IKCP_OVERHEAD
            if conv != self.conv:
                return -1
            if len(data) - off < length:
                return -2
            if cmd not in (IKCP_CMD_PUSH, IKCP_CMD_ACK, IKCP_CMD_WASK, IKCP_CMD_WINS):
                return -3
            self.rmt_wnd = wnd
            self._parse_una(una)
            self._shrink_buf()
            if cmd == IKCP_CMD_ACK:
                if _itimediff(self.current, ts) >= 0:
                    self._update_ack(_itimediff(self.current, ts))
                self._parse_ack(sn)
                self._shrink_buf()
                if not flag:
                    flag, maxack, latest_ts = True, sn, ts
                elif _itimediff(sn, maxack) > 0 and _itimediff(ts, latest_ts) > 0:
                    maxack, latest_ts = sn, ts
            elif cmd == IKCP_CMD_PUSH:
                if _itimediff(sn, self.rcv_nxt + self.rcv_wnd) < 0:
                    self.acklist.append((sn, ts))
                    if _itimediff(sn, self.rcv_nxt) >= 0:
                        seg = _Seg()
                        seg.conv, seg.cmd, seg.frg, seg.wnd = conv, cmd, _frg, wnd
                        seg.ts, seg.sn, seg.una = ts, sn, una
                        seg.data = data[off : off + length]
                        self._parse_data(seg)
            elif cmd == IKCP_CMD_WASK:
                self.probe |= IKCP_ASK_TELL
            off += length
        if flag:
            self._parse_fastack(maxack, latest_ts)
        if _itimediff(self.snd_una, prev_una) > 0 and self.cwnd < self.rmt_wnd:
            self._grow_cwnd()
        return 0

    def _grow_cwnd(self) -> None:
        mss = self.mss
        if self.cwnd < self.ssthresh:
            self.cwnd += 1
            self.incr += mss
        else:
            self.incr = max(self.incr, mss)
            self.incr += (mss * mss) // self.incr + (mss // 16)
            if (self.cwnd + 1) * mss <= self.incr:
                self.cwnd = (self.incr + mss - 1) // mss if mss > 0 else self.cwnd + 1
        if self.cwnd > self.rmt_wnd:
            self.cwnd = self.rmt_wnd
            self.incr = self.rmt_wnd * mss

    def _update_ack(self, rtt: int) -> None:
        if self.rx_srtt == 0:
            self.rx_srtt = rtt
            self.rx_rttval = rtt // 2
        else:
            delta = abs(rtt - self.rx_srtt)
            self.rx_rttval = (3 * self.rx_rttval + delta) // 4
            self.rx_srtt = max(1, (7 * self.rx_srtt + rtt) // 8)
        rto = self.rx_srtt + max(self.interval, 4 * self.rx_rttval)
        self.rx_rto = min(max(self.rx_minrto, rto), IKCP_RTO_MAX)

    def _shrink_buf(self) -> None:
        self.snd_una = self.snd_buf[0].sn if self.snd_buf else self.snd_nxt

    def _parse_ack(self, sn: int) -> None:
        if _itimediff(sn, self.snd_una) < 0 or _itimediff(sn, self.snd_nxt) >= 0:
            return
        for i, seg in enumerate(self.snd_buf):
            if sn == seg.sn:
                del self.snd_buf[i]
                break
            if _itimediff(sn, seg.sn) < 0:
                break

    def _parse_una(self, una: int) -> None:
        while self.snd_buf and _itimediff(una, self.snd_buf[0].sn) > 0:
            self.snd_buf.popleft()

    def _parse_fastack(self, sn: int, _ts: int) -> None:
        if _itimediff(sn, self.snd_una) < 0 or _itimediff(sn, self.snd_nxt) >= 0:
            return
        for seg in self.snd_buf:
            if _itimediff(sn, seg.sn) < 0:
                break
            if sn != seg.sn:
                seg.fastack += 1

    def _parse_data(self, newseg: _Seg) -> None:
        sn = newseg.sn
        if _itimediff(sn, self.rcv_nxt + self.rcv_wnd) >= 0 or _itimediff(sn, self.rcv_nxt) < 0:
            return
        pos = len(self.rcv_buf)
        repeat = False
        for i in range(len(self.rcv_buf) - 1, -1, -1):
            seg = self.rcv_buf[i]
            if seg.sn == sn:
                repeat = True
                break
            if _itimediff(sn, seg.sn) > 0:
                pos = i + 1
                break
            pos = i
        if not repeat:
            self.rcv_buf.insert(pos, newseg)
        self._buf_to_queue()

    # ── flush / update ──────────────────────────────────────────────────────────
    def flush(self, current: int | None = None) -> None:
        """Send pending acks, window probes and data segments (with retransmits)."""
        self.current = _u32(current) if current is not None else _now_ms()
        if not self.updated:
            self.updated = 1
            self.ts_flush = self.current
        output = self._output
        if output is None:
            return
        cur = self.current
        buffer = bytearray()
        seg = _Seg()
        seg.conv = self.conv
        seg.cmd = IKCP_CMD_ACK
        seg.wnd = self._wnd_unused()
        seg.una = self.rcv_nxt

        def emit(extra: int) -> None:
            if len(buffer) + extra > self.mtu:
                output(self, bytes(buffer))
                buffer.clear()

        for sn, ts in self.acklist:
            emit(IKCP_OVERHEAD)
            seg.sn, seg.ts = sn, ts
            buffer += _encode_seg(seg, b"")
        self.acklist.clear()

        self._probe_window(cur)
        if self.probe & IKCP_ASK_SEND:
            seg.cmd = IKCP_CMD_WASK
            emit(IKCP_OVERHEAD)
            buffer += _encode_seg(seg, b"")
        if self.probe & IKCP_ASK_TELL:
            seg.cmd = IKCP_CMD_WINS
            emit(IKCP_OVERHEAD)
            buffer += _encode_seg(seg, b"")
        self.probe = 0

        cwnd = min(self.snd_wnd, self.rmt_wnd)
        if self.nocwnd == 0:
            cwnd = min(self.cwnd, cwnd)
        self._move_queued(cwnd, seg.wnd, cur)

        resent = self.fastresend if self.fastresend > 0 else _MASK
        rtomin = (self.rx_rto >> 3) if self.nodelay == 0 else 0
        lost = False
        change = 0
        for segx in self.snd_buf:
            needsend = False
            if segx.xmit == 0:
                needsend = True
                segx.xmit += 1
                segx.rto = self.rx_rto
                segx.resendts = cur + segx.rto + rtomin
            elif _itimediff(cur, segx.resendts) >= 0:
                needsend = True
                segx.xmit += 1
                self.xmit += 1
                if self.nodelay == 0:
                    segx.rto += max(segx.rto, self.rx_rto)
                else:
                    segx.rto += (segx.rto if self.nodelay < 2 else self.rx_rto) // 2
                segx.resendts = cur + segx.rto
                lost = True
            elif segx.fastack >= resent and (segx.xmit <= self.fastlimit or self.fastlimit <= 0):
                needsend = True
                segx.xmit += 1
                segx.fastack = 0
                segx.resendts = cur + segx.rto
                change += 1
            if needsend:
                segx.ts = cur
                segx.wnd = seg.wnd
                segx.una = self.rcv_nxt
                emit(IKCP_OVERHEAD + len(segx.data))
                buffer += _encode_seg(segx, segx.data)
                if segx.xmit >= self.dead_link:
                    self.state = _MASK
        if buffer:
            output(self, bytes(buffer))
        if change:
            inflight = _u32(self.snd_nxt - self.snd_una)
            self.ssthresh = max(inflight // 2, IKCP_THRESH_MIN)
            self.cwnd = self.ssthresh + resent
            self.incr = self.cwnd * self.mss
        if lost:
            self.ssthresh = max(cwnd // 2, IKCP_THRESH_MIN)
            self.cwnd = 1
            self.incr = self.mss
        if self.cwnd < 1:
            self.cwnd = 1
            self.incr = self.mss

    def _move_queued(self, cwnd: int, wnd: int, cur: int) -> None:
        """Move queued segments into the send buffer while the window ``cwnd`` allows."""
        while _itimediff(self.snd_nxt, self.snd_una + cwnd) < 0 and self.snd_queue:
            newseg = self.snd_queue.popleft()
            newseg.conv = self.conv
            newseg.cmd = IKCP_CMD_PUSH
            newseg.wnd = wnd
            newseg.ts = cur
            newseg.sn = self.snd_nxt
            newseg.una = self.rcv_nxt
            newseg.resendts = cur
            newseg.rto = self.rx_rto
            newseg.fastack = 0
            newseg.xmit = 0
            self.snd_buf.append(newseg)
            self.snd_nxt = _u32(self.snd_nxt + 1)

    def _probe_window(self, cur: int) -> None:
        if self.rmt_wnd != 0:
            self.ts_probe = 0
            self.probe_wait = 0
            return
        if self.probe_wait == 0:
            self.probe_wait = IKCP_PROBE_INIT
            self.ts_probe = cur + self.probe_wait
        elif _itimediff(cur, self.ts_probe) >= 0:
            self.probe_wait = max(self.probe_wait, IKCP_PROBE_INIT)
            self.probe_wait += self.probe_wait // 2
            self.probe_wait = min(self.probe_wait, IKCP_PROBE_LIMIT)
            self.ts_probe = cur + self.probe_wait
            self.probe |= IKCP_ASK_SEND

    def _wnd_unused(self) -> int:
        return max(self.rcv_wnd - len(self.rcv_queue), 0)

    def update(self, ts_ms: int | None = None) -> None:
        """Advance KCP's clock and flush when the flush interval has elapsed."""
        self.current = _u32(ts_ms) if ts_ms is not None else _now_ms()
        if self.updated == 0:
            self.updated = 1
            self.ts_flush = self.current
        slap = _itimediff(self.current, self.ts_flush)
        if slap >= 10000 or slap < -10000:
            self.ts_flush = self.current
            slap = 0
        if slap >= 0:
            self.ts_flush = _u32(self.ts_flush + self.interval)
            if _itimediff(self.current, self.ts_flush) >= 0:
                self.ts_flush = _u32(self.current + self.interval)
            self.flush(self.current)
