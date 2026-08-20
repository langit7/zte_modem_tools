import struct
import unittest

from zte_payload import client_mac, mac_to_magic_bytes, parse_mac


def decode_payload(payload):
    decoded = []
    for offset in range(0, 48, 4):
        chunk = payload[offset:offset + 4].ljust(4, b"\x00")
        value = struct.unpack("<I", chunk)[0]
        decoded.append(pow(value, 1271, 2537) & 0xFF)
    return bytes(decoded)


class PayloadTests(unittest.TestCase):
    def test_every_mac_byte_can_be_encoded(self):
        for value in range(256):
            mac = bytes([value]) * 6
            payload = mac_to_magic_bytes(mac)
            self.assertEqual(46, len(payload))
            self.assertEqual(mac, decode_payload(payload)[:6])

    def test_different_macs_produce_different_payloads(self):
        first = mac_to_magic_bytes(bytes.fromhex("001122334455"))
        second = mac_to_magic_bytes(bytes.fromhex("deadbeef0001"))
        self.assertNotEqual(first, second)

    def test_explicit_mac_does_not_require_interface_detection(self):
        mac, source = client_mac("192.0.2.1", 80, mac="de:ad:be:ef:00:01")
        self.assertEqual(bytes.fromhex("deadbeef0001"), mac)
        self.assertEqual("--mac", source)

    def test_parse_mac_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            parse_mac("00:11:22:33:44")


if __name__ == "__main__":
    unittest.main()
