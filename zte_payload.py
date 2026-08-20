#!/usr/bin/env python3
"""Generate the MAC-bound SendInfo payload used by newer ZTE firmware."""

import socket
import struct

try:
    import fcntl
except ImportError:  # pragma: no cover - fcntl is unavailable on Windows
    fcntl = None


MODULUS = 0x9E9
EXPONENT = 0x4F8 - 1
SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927


def _power(value):
    """Return the byte produced by the firmware's verification VM."""
    return pow(value, EXPONENT, MODULUS) & 0xFF


def _build_reverse_table():
    table = [None] * 256
    for value in range(MODULUS):
        decoded = _power(value)
        if table[decoded] is None:
            table[decoded] = value
    if any(value is None for value in table):
        raise RuntimeError("the SendInfo transform cannot encode every MAC byte")
    return table


_REVERSE_TABLE = _build_reverse_table()


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


def mac_to_magic_bytes(mac):
    """Build the 46-byte info=12 payload for a runtime client MAC."""
    if len(mac) != 6:
        raise ValueError("client MAC must contain exactly six bytes")

    values = [_REVERSE_TABLE[byte] for byte in mac] + [0] * 6
    payload = bytearray()
    for value in values[:11]:
        payload.extend(struct.pack("<H", value))
        payload.extend(b"\x00\x00")
    payload.extend(struct.pack("<H", values[11]))
    return bytes(payload)


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
