import re
import unittest
from unittest.mock import patch
from Crypto.Cipher import AES

from zte_factroymode import WebFac, WebFacTelnet, pad, unpad


class FakeResponse:
    def __init__(self, status_code, content=b""):
        self.status_code = status_code
        self.content = content
        self.text = content.decode("latin-1")


class FakeSession:
    def __init__(self, response):
        self.response = response

    def post(self, *args, **kwargs):
        return self.response


class FactoryCommandTests(unittest.TestCase):
    def test_request_factory_metadata_avoids_python_user_agent(self):
        webfac = WebFac("192.168.1.1", 8080, "user", "pass")
        self.assertNotIn("python", webfac.S.headers["User-Agent"].lower())
        self.assertEqual(
            "http://192.168.1.1/login.html",
            webfac.S.headers["Referer"],
        )

    def test_f6201b_re_rand_handshake_is_parsed_as_binary(self):
        response = FakeResponse(
            200,
            b"re_rand=11&123456&" + bytes.fromhex("001122334455"),
        )
        webfac = WebFac("192.168.1.1", 80, "user", "pass")
        webfac.S = FakeSession(response)

        with patch("zte_factroymode.Random") as random_source:
            random_source.return_value.randint.return_value = 7
            self.assertEqual(3, webfac.sendSq())

        self.assertEqual(11, webfac.re_rand)
        self.assertEqual(123456, webfac.proof_random)
        self.assertEqual(bytes.fromhex("001122334455"), webfac.bridge_mac)
        self.assertEqual(14, webfac.aes_index)
        self.assertEqual(3, webfac.protocol_method)

    def test_f6201b_protocol_requires_mac_bound_send_info(self):
        webfac = WebFac("192.168.1.1", 80, "user", "pass")
        webfac.protocol_method = 3
        with self.assertRaises(ValueError):
            webfac.sendInfoCommand()

    def test_zero_unpad_removes_all_response_padding(self):
        plaintext = b"FactoryModeAuth.gch?user=temp&pass=secret"
        self.assertEqual(plaintext, unpad(plaintext + b"\x00" * 560, 16))

    def test_zero_pad_does_not_add_a_block_to_aligned_input(self):
        self.assertEqual(b"A" * 16, pad(b"A" * 16, 16))
        self.assertEqual(b"A" + b"\x00" * 15, pad(b"A", 16))

    def test_auth_reply_uses_only_complete_ciphertext_blocks(self):
        key = bytes(range(24))
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(b"FactoryMode.gch", 16))
        webfac = WebFac("192.168.1.1", 80, "user", "pass")
        webfac.cipher = AES.new(key, AES.MODE_ECB)
        webfac.S = FakeSession(FakeResponse(200, ciphertext + b"partial"))
        self.assertEqual(b"FactoryMode.gch", webfac.checkLoginAuth())

    def test_auth_reply_rejects_truncation_inside_first_block(self):
        webfac = WebFac("192.168.1.1", 80, "user", "pass")
        webfac.cipher = AES.new(bytes(range(24)), AES.MODE_ECB)
        webfac.S = FakeSession(FakeResponse(200, b"too short"))
        self.assertFalse(webfac.checkLoginAuth())

    def test_close_accepts_empty_http_200_response(self):
        webfac = WebFacTelnet("192.168.1.1", 80, "user", "pass")
        webfac.cipher = AES.new(bytes(range(24)), AES.MODE_ECB)
        webfac.S = FakeSession(FakeResponse(200, b""))
        self.assertIs(webfac.factoryMode("close"), True)

    def test_legacy_commands_remain_unchanged(self):
        webfac = WebFacTelnet("192.168.1.1", 80, "user", "pass")
        self.assertEqual(b"SendInfo.gch?info=6|", webfac.sendInfoCommand())
        self.assertEqual(
            b"CheckLoginAuth.gch?version50&user=user&pass=pass",
            webfac.checkLoginAuthCommand(),
        )
        self.assertEqual(
            b"FactoryMode.gch?mode=2&user=notused",
            webfac.factoryModeCommand("open"),
        )

    def test_new_commands_use_mac_and_ordered_times(self):
        mac = bytes.fromhex("deadbeef0001")
        webfac = WebFacTelnet("192.168.1.1", 80, "user", "pass", True, mac, "rerand22")
        webfac.protocol_method = 3
        webfac.bridge_mac = bytes.fromhex("0c014b40a9ca")

        info = webfac.sendInfoCommand()
        self.assertTrue(info.startswith(b"SendInfo.gch?info=22|"))
        self.assertEqual(88, len(info) - len(b"SendInfo.gch?info=22|"))

        auth = webfac.checkLoginAuthCommand().decode()
        auth_match = re.fullmatch(
            r"CheckLoginAuth\.gch\?time(\d+)&version61&user=user&pass=pass",
            auth,
        )
        self.assertIsNotNone(auth_match)
        auth_time = int(auth_match.group(1))

        mode = webfac.factoryModeCommand("open").decode()
        mode_match = re.fullmatch(
            r"FactoryMode\.gch\?time(\d+)&mode=2&user=notused",
            mode,
        )
        self.assertIsNotNone(mode_match)
        mode_time = int(mode_match.group(1))
        self.assertGreaterEqual(mode_time, auth_time)
        self.assertLess(mode_time, 1000)

    def test_new_factory_mode_requires_authentication_time(self):
        webfac = WebFacTelnet(
            "192.168.1.1", 80, "user", "pass", True, bytes.fromhex("deadbeef0001")
        )
        with self.assertRaises(ValueError):
            webfac.factoryModeCommand("open")

    def test_method_2_send_info_requires_client_mac(self):
        webfac = WebFac("192.168.1.1", 80, "user", "pass")
        webfac.protocol_method = 2
        with self.assertRaises(ValueError):
            webfac.sendInfoCommand()

    def test_new_send_info_requires_handshake_bridge_mac(self):
        webfac = WebFac(
            "192.168.1.1", 80, "user", "pass", True, bytes.fromhex("deadbeef0001")
        )
        webfac.protocol_method = 3
        with self.assertRaises(ValueError):
            webfac.sendInfoCommand()

    def test_early_2025_newrand_selects_method_2(self):
        webfac = WebFac(
            "192.168.1.1",
            80,
            "user",
            "pass",
            selected_mac=bytes.fromhex("000729553557"),
            sendinfo_profile="rerand22",
        )
        webfac.S = FakeSession(FakeResponse(200, b"newrand=11"))
        with patch("zte_factroymode.Random") as random_source:
            random_source.return_value.randint.return_value = 7
            self.assertEqual(2, webfac.sendSq())

        self.assertEqual(2, webfac.protocol_method)
        command = webfac.sendInfoCommand()
        self.assertTrue(command.startswith(b"SendInfo.gch?info=12|"))
        self.assertEqual(46, len(command) - len(b"SendInfo.gch?info=12|"))

    def test_captured_aes_slice_matches_known_working_trace(self):
        key = bytes(value ^ 0xA5 for value in WebFac.AES_KEY_POOL_LATEST[40:64])
        self.assertEqual(
            bytes.fromhex("90888a447be9d250bfc0745bbde62b02e7ada1dd70415691"),
            key,
        )

    def test_known_working_trace_builds_exact_send_info_command(self):
        webfac = WebFac(
            "192.168.1.1",
            80,
            "user",
            "pass",
            selected_mac=bytes.fromhex("000729553557"),
            sendinfo_profile="rerand22",
        )
        webfac.S = FakeSession(
            FakeResponse(
                200,
                b"re_rand=40&6076665&" + bytes.fromhex("0c014b40a9ca"),
            )
        )
        with patch("zte_factroymode.Random") as random_source:
            random_source.return_value.randint.return_value = 0
            self.assertEqual(3, webfac.sendSq())

        self.assertEqual(3, webfac.protocol_method)
        self.assertEqual(40, webfac.aes_index)
        self.assertEqual(
            b"SendInfo.gch?info=22|"
            b"apjdapalapjdafpelleflleglocxllcyllmyllmv"
            b"lltnlluglllullfdllarllyflltnlluglllullfdllarllyf",
            webfac.sendInfoCommand(),
        )

    def test_early_2025_gist_trace_uses_version50_with_rerand(self):
        webfac = WebFac(
            "192.168.1.1",
            80,
            "admin",
            "996404E5",
            selected_mac=bytes.fromhex("000729553557"),
            sendinfo_profile="rerand22",
        )
        webfac.S = FakeSession(
            FakeResponse(
                200,
                b"re_rand=11&7922936&" + bytes.fromhex("843c996404e5"),
            )
        )
        with patch("zte_factroymode.Random") as random_source:
            random_source.return_value.randint.return_value = 0
            self.assertEqual(3, webfac.sendSq())

        self.assertEqual(
            b"CheckLoginAuth.gch?version50&user=admin&pass=996404E5",
            webfac.checkLoginAuthCommand(),
        )
        self.assertEqual(
            b"SendInfo.gch?info=22|"
            b"apjdapalapjdafpelllcllbkllwclladllmgmlbhlltn"
            b"lluglllullfdllarllyflltnlluglllullfdllarllyf",
            webfac.sendInfoCommand(),
        )
        telnet = WebFacTelnet("192.168.1.1", 80, "admin", "996404E5")
        self.assertEqual(b"FactoryMode.gch?mode=2&user=notused", telnet.factoryModeCommand("open"))

    def test_rerand34_latest_profile_uses_34_words(self):
        webfac = WebFac(
            "192.168.1.1", 80, "user", "pass",
            selected_mac=bytes.fromhex("000729553557"),
        )
        webfac.protocol_method = 3
        webfac.bridge_mac = bytes.fromhex("843c996404e5")
        command = webfac.sendInfoCommand()
        prefix = b"SendInfo.gch?info=34|"
        self.assertTrue(command.startswith(prefix))
        self.assertEqual(34 * 4, len(command) - len(prefix))


if __name__ == "__main__":
    unittest.main()
