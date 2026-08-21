#!/usr/bin/env python3
"""Generate MAC-bound SendInfo payloads for webFac generations."""

import itertools
import socket
import struct

try:
    import fcntl
except ImportError:  # pragma: no cover - fcntl is unavailable on Windows
    fcntl = None


# Method 2 (early-2025 newrand generation). These constants and the unusual
# final short operand are retained for compatibility with that older VM.
EARLY2025_EXPONENT = 0x4F8 - 1
EARLY2025_MODULUS = 0x9E9

# Method 3 (F6201B/latest re_rand generation). The first four VM words derive
# the exponent and modulus used for all later words. These values are immediate
# operands in _1_do_check_client_$array in the analyzed F6201B httpd.
HEADER_EXPONENT = 0x1687
HEADER_MODULUS = 0x7561

# Restrict every payload byte to URL-safe lowercase letters. The chosen header
# words cancel the server-generated proof index and select exponent 1 with
# modulus HEADER_EXPONENT for the bridge/client MAC words.
PAYLOAD_ALPHABET = "lmaoztebcdfghijknpqrsuvwxy"
SELECTED_EXPONENT = 1
SELECTED_MODULUS = HEADER_EXPONENT
SENDINFO_WORD_COUNT = 22

# Method-3 "latest" 34-word profile (re_rand handshake, info=34). The fourth
# header word is a preimage of HEADER_EXPONENT under the header transform
# (pow(9893, 0x1687, 0x7561) == 0x1687), so the derived modulus stays 0x1687
# regardless of the server proof index. Two trailing marker groups follow the
# client-MAC groups.
RERAND34_HEADER_MODULUS_WORD = 9893
RERAND34_MARKER = bytes.fromhex("00ff72463411")
RERAND34_WORD_COUNT = 34
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927


def _alphabet_words():
    alphabet = PAYLOAD_ALPHABET.encode("ascii")
    for combination in itertools.product(alphabet, repeat=4):
        yield int.from_bytes(bytes(combination), "little")


def _build_encoding_map(exponent, modulus, value_map=lambda value: value):
    """Find deterministic four-letter preimages for every VM output value."""
    required = {value_map(pow(value, exponent, modulus)) for value in range(modulus)}
    encoded = {}
    for word in _alphabet_words():
        result = value_map(pow(word, exponent, modulus))
        if result not in encoded:
            encoded[result] = word
            if len(encoded) == len(required):
                return encoded
    raise RuntimeError("the restricted SendInfo alphabet cannot encode every required value")


_HEADER_ENCODING = _build_encoding_map(HEADER_EXPONENT, HEADER_MODULUS)
_MAC_ENCODING = _build_encoding_map(
    SELECTED_EXPONENT,
    SELECTED_MODULUS,
    lambda value: value & 0xFF,
)


def _build_early2025_reverse_table():
    table = [None] * 256
    for value in range(EARLY2025_MODULUS):
        decoded = pow(value, EARLY2025_EXPONENT, EARLY2025_MODULUS) & 0xFF
        if table[decoded] is None:
            table[decoded] = value
    if any(value is None for value in table):
        raise RuntimeError("the method-2 SendInfo transform cannot encode every MAC byte")
    return table


_EARLY2025_REVERSE_TABLE = _build_early2025_reverse_table()


def parse_mac(value):
    """Parse a colon- or hyphen-delimited six-byte MAC address."""
    compact = value.replace(":", "").replace("-", "").replace(".", "")
    try:
        mac = bytes.fromhex(compact)
    except ValueError as error:
        raise ValueError("invalid MAC address: %s" % value) from error
    if len(mac) != 6:
        raise ValueError("invalid MAC address: %s" % value)
    return mac


def format_mac(mac):
    return ":".join("%02x" % byte for byte in mac)


def mac_to_early2025_magic_bytes(client_mac):
    """Build the method-2 ``info=12`` payload for a client MAC."""
    if len(client_mac) != 6:
        raise ValueError("client MAC must contain exactly six bytes")

    values = [_EARLY2025_REVERSE_TABLE[byte] for byte in client_mac] + [0] * 6
    payload = bytearray()
    for value in values[:11]:
        payload.extend(struct.pack("<H", value))
        payload.extend(b"\x00\x00")
    payload.extend(struct.pack("<H", values[11]))
    return bytes(payload)


def create_payload_words(bridge_mac, client_mac):
    """Build the 22 VM words validated against bridge then client MACs.

    The first and third header words make the proof-index multipliers zero.
    The second and fourth select exponent 1 and modulus 0x1687. The VM then
    requires its first six decoded bytes to equal the bridge MAC and accepts
    when a later six-byte group equals the request-source client MAC.
    """
    if len(bridge_mac) != 6:
        raise ValueError("bridge MAC must contain exactly six bytes")
    if len(client_mac) != 6:
        raise ValueError("client MAC must contain exactly six bytes")

    words = [
        _HEADER_ENCODING[0],
        _HEADER_ENCODING[SELECTED_EXPONENT],
        _HEADER_ENCODING[0],
        _HEADER_ENCODING[SELECTED_MODULUS],
    ]
    words.extend(_MAC_ENCODING[byte] for byte in bridge_mac)
    # One client-MAC group is sufficient. The second captured group is retained
    # to match the known-working request and remains accepted by the VM loop.
    words.extend(_MAC_ENCODING[byte] for byte in client_mac + client_mac)
    if len(words) != SENDINFO_WORD_COUNT:
        raise AssertionError("invalid SendInfo word count")
    return words


def create_rerand34_payload_words(bridge_mac, client_mac):
    """Build the latest 34-word (info=34) SendInfo proof payload."""
    if len(bridge_mac) != 6 or len(client_mac) != 6:
        raise ValueError("MAC addresses must contain exactly six bytes")

    words = [0, 1, 0, RERAND34_HEADER_MODULUS_WORD]
    words.extend(bridge_mac)
    words.extend(client_mac + client_mac)
    words.extend(RERAND34_MARKER + RERAND34_MARKER)
    if len(words) != RERAND34_WORD_COUNT:
        raise AssertionError("invalid rerand34 SendInfo word count")
    return words


def mac_to_magic_bytes(bridge_mac, client_mac):
    """Serialize the method-3 words as 88 little-endian payload bytes."""
    return b"".join(struct.pack("<I", word) for word in create_payload_words(bridge_mac, client_mac))


def mac_to_rerand34_magic_bytes(bridge_mac, client_mac):
    """Serialize the latest rerand34 words as little-endian uint32 values."""
    return b"".join(
        struct.pack("<I", word)
        for word in create_rerand34_payload_words(bridge_mac, client_mac)
    )


def verify_magic_payload(payload, bridge_mac, client_mac, proof_index):
    """High-level equivalent of the recovered do_check_client VM program."""
    if len(payload) % 4:
        return False
    words = [struct.unpack_from("<I", payload, offset)[0] for offset in range(0, len(payload), 4)]
    if len(words) < 10:
        return False

    header = [pow(word, HEADER_EXPONENT, HEADER_MODULUS) for word in words[:4]]
    exponent = header[0] * proof_index + header[1]
    modulus = header[2] * proof_index + header[3]
    if modulus == 0:
        return False
    decoded = bytes(pow(word, exponent, modulus) & 0xFF for word in words[4:])
    if decoded[:6] != bridge_mac:
        return False
    return any(
        decoded[offset:offset + 6] == client_mac
        for offset in range(6, len(decoded), 6)
        if len(decoded[offset:offset + 6]) == 6
    )


def verify_rerand34_payload(payload, bridge_mac, client_mac, proof_index):
    """Verify the latest 34-word rerand34 profile at high level."""
    if len(payload) != RERAND34_WORD_COUNT * 4:
        return False
    words = [struct.unpack_from("<I", payload, offset)[0]
             for offset in range(0, len(payload), 4)]
    header = [pow(word, HEADER_EXPONENT, HEADER_MODULUS) for word in words[:4]]
    exponent = header[0] * proof_index + header[1]
    modulus = header[2] * proof_index + header[3]
    if (exponent, modulus) != (1, HEADER_EXPONENT):
        return False
    decoded = bytes(pow(word, exponent, modulus) & 0xFF for word in words[4:])
    return decoded == bridge_mac + client_mac + client_mac + RERAND34_MARKER + RERAND34_MARKER


def _require_fcntl():
    if fcntl is None:
        raise RuntimeError(
            "automatic interface MAC detection is unavailable on this platform; "
            "provide --mac with the client MAC observed by the ONU/ONT"
        )


def _interface_request(interface):
    encoded = interface.encode("utf-8")
    if len(encoded) > 15:
        raise ValueError("network interface name is too long: %s" % interface)
    return struct.pack("256s", encoded)


def interface_mac(interface):
    """Read the six-byte hardware address of a Linux network interface."""
    _require_fcntl()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        result = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR, _interface_request(interface))
    return result[18:24]


def _interface_ipv4(interface):
    _require_fcntl()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        result = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, _interface_request(interface))
    return socket.inet_ntoa(result[20:24])


def route_interface(target_ip, target_port):
    """Return the interface selected by the IPv4 route to the ONU/ONT."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((target_ip, target_port))
        source_ip = sock.getsockname()[0]

    for _, interface in socket.if_nameindex():
        try:
            if _interface_ipv4(interface) == source_ip:
                return interface
        except OSError:
            continue
    raise RuntimeError("cannot find the interface owning route source %s" % source_ip)


def client_mac(target_ip, target_port, mac=None, interface=None):
    """Select an explicit, interface, or route-derived client MAC."""
    if mac:
        return parse_mac(mac), "--mac"
    if interface:
        return interface_mac(interface), interface
    selected_interface = route_interface(target_ip, target_port)
    return interface_mac(selected_interface), selected_interface
