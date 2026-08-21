import unittest

from zte_payload import (
    client_mac,
    mac_to_early2025_magic_bytes,
    mac_to_magic_bytes,
    mac_to_rerand34_magic_bytes,
    parse_mac,
    verify_magic_payload,
    verify_rerand34_payload,
)


class PayloadTests(unittest.TestCase):
    def test_early_2025_payload_retains_info_12_wire_shape(self):
        payload = mac_to_early2025_magic_bytes(bytes.fromhex("000729553557"))
        self.assertEqual(46, len(payload))

    def test_every_mac_byte_can_be_encoded(self):
        bridge_mac = bytes.fromhex("0c014b40a9ca")
        for value in range(256):
            client = bytes([value]) * 6
            payload = mac_to_magic_bytes(bridge_mac, client)
            self.assertEqual(88, len(payload))
            self.assertTrue(verify_magic_payload(payload, bridge_mac, client, 40))

    def test_different_macs_produce_different_payloads(self):
        bridge_mac = bytes.fromhex("0c014b40a9ca")
        first = mac_to_magic_bytes(bridge_mac, bytes.fromhex("001122334455"))
        second = mac_to_magic_bytes(bridge_mac, bytes.fromhex("deadbeef0001"))
        self.assertNotEqual(first, second)

    def test_known_working_trace_payload_matches_exactly(self):
        payload = mac_to_magic_bytes(
            bytes.fromhex("0c014b40a9ca"),
            bytes.fromhex("000729553557"),
        )
        self.assertEqual(
            b"apjdapalapjdafpelleflleglocxllcyllmyllmv"
            b"lltnlluglllullfdllarllyflltnlluglllullfdllarllyf",
            payload,
        )

    def test_payload_cancels_server_proof_index(self):
        bridge_mac = bytes.fromhex("843c996404e5")
        client = bytes.fromhex("000729553557")
        payload = mac_to_magic_bytes(bridge_mac, client)
        for proof_index in (0, 11, 40, 0x1FFF):
            self.assertTrue(verify_magic_payload(payload, bridge_mac, client, proof_index))

    def test_rerand34_payload_has_marker_groups(self):
        bridge_mac = bytes.fromhex("843c996404e5")
        client = bytes.fromhex("000729553557")
        payload = mac_to_rerand34_magic_bytes(bridge_mac, client)
        self.assertEqual(34 * 4, len(payload))
        self.assertTrue(verify_rerand34_payload(payload, bridge_mac, client, 11))

    def test_explicit_mac_does_not_require_interface_detection(self):
        mac, source = client_mac("192.0.2.1", 80, mac="de:ad:be:ef:00:01")
        self.assertEqual(bytes.fromhex("deadbeef0001"), mac)
        self.assertEqual("--mac", source)

    def test_parse_mac_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            parse_mac("00:11:22:33:44")


if __name__ == "__main__":
    unittest.main()
