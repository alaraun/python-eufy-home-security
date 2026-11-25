"""A smart lock behind the fake station (:class:`FakeLock`): it answers the lock and unlock
commands of every P2P form the library sends (1940 cm2, 1961 JSON, 1930 cm), as a lock is
declared to (docs/protocol/locks.md § Commands), and reports its new state.

Synthetic keys only: the lock's ECC and ECDH key pairs are generated per instance; give
:meth:`FakeLock.public_keys` to :attr:`~.cloud.FakeCloud.lock_public_keys`.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..lock_commands import anker, cm2, frames
from ..lock_commands.actions import LockAction, cbc_decrypt, serial_iv
from ..p2p.crypto import ecies_decrypt
from ..p2p.xzyh import FrameType

if TYPE_CHECKING:
    from .station import FakeStation

LOCK_COMMANDS: Final = frozenset({cm2.P2P_COMMAND, anker.COMMAND_1961, anker.COMMAND_1930})
"""The 1350 commands a :class:`FakeLock` answers."""
LOCKED: Final = 4
UNLOCKED: Final = 3
_SEQ_REPORT: Final = 1916


def tlv_entries(body: bytes) -> dict[int, bytes]:
    """A TLV body's values by tag."""
    entries: dict[int, bytes] = {}
    index = 0
    while index + 1 < len(body):
        tag, length = body[index], body[index + 1]
        entries[tag] = body[index + 2 : index + 2 + length]
        index += 2 + length
    return entries


def _private_hex(key: ec.EllipticCurvePrivateKey) -> str:
    return format(key.private_numbers().private_value, "064x")


@dataclass(slots=True, kw_only=True)
class FakeLock:
    """A lock on the fake station's channel ``channel``.

    ``user_id`` is the key user id a 1940 command names (the account's, or its member
    record's admin id); ``state_param`` the parameter the station reports its state in.
    ``result_code`` is the station's result to each command (-151: sequence refused);
    ``answer_code`` the lock's (0 accepted; 48/49 already unlocked/locked; another refused).
    An accepted command moves the lock to the asked state, or to ``move_to`` (a lock-state
    code: 5 stops between positions), and the lock reports it unless ``report`` is False:
    a 1940 lock in its status report, the others in a parameter dump. ``mismatch_first``
    sends an answer to another request before the real one; ``seq_report`` answers the
    next command with a sequence report of that number while the station refuses it (-151);
    a 1940 client resends, a 1961 one fails.
    ``answer`` False: the lock sends no answer after the station's result; ``result`` False:
    the station sends no result for a 1961 command (only its acknowledgement).
    ``seq_after_answer`` sends a sequence report of that number naming the on/off command
    right after a 1940 answer.
    ``status_code`` is the code of a 1940 lock's status report (0: a state).
    ``received`` records each command as decrypted: ``(command, action, seq_num)``;
    ``names`` its sender name (the account's nickname), ``user_ids`` the user id it names
    (1940 ``A2``, 1961 ``userId``; None when left out, and for 1930, which names none).
    """

    serial: str
    channel: int
    user_id: str = ""
    state_param: int = 1912
    state_code: int = UNLOCKED
    result_code: int = 0
    answer_code: int = 0
    move_to: int | None = None
    report: bool = True
    mismatch_first: bool = False
    seq_report: int | None = None
    answer: bool = True
    result: bool = True
    seq_after_answer: int | None = None
    status_code: int = 0
    ecc_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    ecdh_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    received: list[tuple[int, LockAction, int | None]] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    user_ids: list[str | None] = field(default_factory=list)

    def public_keys(self) -> dict[tuple[str, int], bytes]:
        """The lock's keys as the cloud's public-key query serves them (types 2 and 3)."""
        point = self.ecc_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        ecdh = self.ecdh_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return {(self.serial, 2): point[1:], (self.serial, 3): ecdh}

    # ── commands ─────────────────────────────────────────────────────────────

    def on_command(self, station: FakeStation, command: int, obj: Mapping[str, Any]) -> None:
        """Answer one 1350 lock command as the station and the lock do."""
        if command == cm2.P2P_COMMAND:
            self._on_1940(station, obj["payload"])
        elif command == anker.COMMAND_1961:
            self._on_1961(station, obj)
        else:
            self._on_1930(station, obj["payload"])

    def _result(self, station: FakeStation, command: int, code: int) -> None:
        station.send_json(FrameType.NOTIFY_PAYLOAD, {"cmd": command, "code": code})

    def _through(self, station: FakeStation, command: int, payload: dict[str, Any]) -> None:
        station.send_json(
            FrameType.NOTIFY_PAYLOAD,
            {
                "cmd": command,
                "mChannel": self.channel,
                "payload": {"dev_sn": self.serial} | payload,
            },
        )

    def _moved(self, action: LockAction) -> int:
        self.state_code = (
            self.move_to
            if self.move_to is not None
            else (LOCKED if action is LockAction.LOCK else UNLOCKED)
        )
        return self.state_code

    def _report_param(self, station: FakeStation) -> None:
        station.params.setdefault(self.channel, {})[self.state_param] = str(self.state_code)
        if self.report:
            station.send_param_dump()

    def _on_1940(self, station: FakeStation, payload: Mapping[str, Any]) -> None:
        time_field = payload["time"]
        if "version" in payload:
            user, salt = cm2.open_hkdf_time_field(str(time_field))
            key, time_text = cm2.hkdf_key(user, salt), str(time_field)
        else:
            key, time_text = cm2.time_key(self.user_id, int(time_field)), f"{int(time_field):08x}"
        frame = frames.parse_cm2_frame(bytes.fromhex(payload["lock_payload"]))
        body = tlv_entries(cbc_decrypt(frame.body, key, serial_iv(self.serial)))
        action = LockAction.LOCK if body[0xA3] == b"\x00" else LockAction.UNLOCK
        self.received.append((cm2.P2P_COMMAND, action, int(payload["seq_num"])))
        self.names.append(body[0xA4].decode())
        self.user_ids.append(body[0xA2].decode())
        if self.seq_report is not None:
            seq, self.seq_report = self.seq_report, None
            self._result(station, cm2.P2P_COMMAND, -151)
            report = {"seq_num": seq, "bus_type": cm2.FUNCTION_TYPE, "lock_cmd": cm2.COMMAND_ON_OFF}
            self._through(station, _SEQ_REPORT, report)
            return
        self._result(station, cm2.P2P_COMMAND, self.result_code)
        if self.result_code not in (0, -151) or not self.answer:
            return
        iv = serial_iv(self.serial)

        def sealed(command: int, plain: bytes) -> str:
            sealed_body = cm2.seal_body(plain, key, iv)
            return frames.cm2_frame(
                sealed_body,
                command=command,
                function_type=cm2.FUNCTION_TYPE,
                version=cm2.FRAME_VERSION,
                encrypted=True,
            ).hex()

        if self.mismatch_first and "version" not in payload:
            other = int(time_field) ^ 0x40
            other_key = cm2.time_key(self.user_id, other)
            stale = frames.cm2_frame(
                cm2.seal_body(bytes([0, 0]), other_key, iv),
                command=cm2.COMMAND_ON_OFF,
                function_type=cm2.FUNCTION_TYPE,
                version=cm2.FRAME_VERSION,
                encrypted=True,
            ).hex()
            self._through(station, cm2.P2P_COMMAND, {"lock_payload": stale, "time": f"{other:08x}"})
        answer = sealed(cm2.COMMAND_ON_OFF, bytes([self.answer_code, 0]))
        self._through(station, cm2.P2P_COMMAND, {"lock_payload": answer, "time": time_text})
        if self.seq_after_answer is not None:
            seq, self.seq_after_answer = self.seq_after_answer, None
            report = {"seq_num": seq, "bus_type": cm2.FUNCTION_TYPE, "lock_cmd": cm2.COMMAND_ON_OFF}
            self._through(station, _SEQ_REPORT, report)
        if self.answer_code != 0:
            return
        state = self._moved(action)
        station.params.setdefault(self.channel, {})[self.state_param] = str(state)
        if self.report:
            status = sealed(
                cm2.STATUS_COMMAND, bytes([self.status_code, 0xA1, 1, 90, 0xA2, 1, state])
            )
            self._through(station, cm2.P2P_COMMAND, {"lock_payload": status, "time": time_text})

    def _on_1961(self, station: FakeStation, obj: Mapping[str, Any]) -> None:
        payload = obj["payload"]
        if "key" in obj:
            text = ecies_decrypt(bytes.fromhex(obj["key"]), _private_hex(self.ecc_key))
            aes = bytes.fromhex(text.decode())
            plain = cbc_decrypt(base64.b64decode(payload), aes, serial_iv(self.serial))
            payload = json.loads(plain)
        action = LockAction(int(payload["slOperation"]))
        self.received.append((anker.COMMAND_1961, action, payload.get("seq_num")))
        self.names.append(str(payload["userName"]))
        self.user_ids.append(payload.get("userId"))
        if self.seq_report is not None:
            seq, self.seq_report = self.seq_report, None
            self._through(station, _SEQ_REPORT, {"seq_num": seq, "bus_type": 0, "lock_cmd": 0})
            self._result(station, anker.COMMAND_1961, -151)
            return
        if not self.result:
            return
        code = self.result_code if self.result_code != 0 else self.answer_code
        self._result(station, anker.COMMAND_1961, code)
        if code == 0:
            self._moved(action)
            self._report_param(station)

    def _on_1930(self, station: FakeStation, payload: Mapping[str, Any]) -> None:
        raw = bytes.fromhex(payload["lock_payload"])
        version, key_len = raw[4], raw[9]
        key_field, cipher = raw[10 : 10 + key_len], raw[10 + key_len : -1]
        if version == anker.VERSION_ECDH:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key_field)
            key = self.ecdh_key.exchange(ec.ECDH(), peer)[:16]
        else:
            key = ecies_decrypt(key_field, _private_hex(self.ecc_key))
        body = tlv_entries(cbc_decrypt(cipher, key, serial_iv(self.serial)))
        action = LockAction(body[0xA2][0])
        self.received.append((anker.COMMAND_1930, action, int(payload["seq_num"])))
        self.names.append(body[0xA4].decode())
        self.user_ids.append(None)
        self._result(station, anker.COMMAND_1930, self.result_code)
        if self.result_code not in (0, -151) or not self.answer:
            return
        plain = bytes([self.answer_code])
        head = bytes([anker.VERSION_PLAIN_ANSWER, frames.ANKER_DEVICE_TYPE, anker.CM_ON_OFF])
        frame = frames.START + (9 + len(plain)).to_bytes(2, "little") + head
        frame += bytes([frames.ANKER_SINGLE]) + plain
        frame += bytes([frames.xor8(frame)])
        self._through(station, anker.COMMAND_1930, {"lock_payload": frame.hex()})
        if self.answer_code == 0:
            self._moved(action)
            self._report_param(station)
