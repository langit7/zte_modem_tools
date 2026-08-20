import re
import unittest

from zte_factroymode import WebFac, WebFacTelnet


class FactoryCommandTests(unittest.TestCase):
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
        webfac = WebFacTelnet("192.168.1.1", 80, "user", "pass", True, mac)

        info = webfac.sendInfoCommand()
        self.assertTrue(info.startswith(b"SendInfo.gch?info=12|"))
        self.assertEqual(46, len(info) - len(b"SendInfo.gch?info=12|"))

        auth = webfac.checkLoginAuthCommand().decode()
        auth_match = re.fullmatch(
            r"CheckLoginAuth\.gch\?time(\d+)&version61&user=user&pass=pass",
            auth,
        )
        self.assertIsNotNone(auth_match)
        auth_time = int(auth_match.group(1))

        mode = webfac.factoryModeCommand("open").decode()
        mode_match = re.fullmatch(
            r"FactoryMode\.gch\?time(\d+)&mode=2&user=fuckyou",
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

    def test_new_send_info_requires_client_mac(self):
        webfac = WebFac("192.168.1.1", 80, "user", "pass", True)
        with self.assertRaises(ValueError):
            webfac.sendInfoCommand()


if __name__ == "__main__":
    unittest.main()
