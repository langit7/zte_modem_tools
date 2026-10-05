import unittest

from zte_telnet import TelnetError, filter_telnet, parse_temp_credentials
from zte_telnet import _parse_region, _parse_telnetd_pid


class FilterTelnetTests(unittest.TestCase):
    def test_plain_output_passes_through(self):
        self.assertEqual("Login: ", filter_telnet(b"Login: "))

    def test_two_byte_iac_commands_are_dropped(self):
        # IAC + NOP(0xF1) is a 2-byte command
        self.assertEqual("ok", filter_telnet(b"\xff\xf1ok"))

    def test_escaped_ff_becomes_single_ff(self):
        self.assertEqual("\xff", filter_telnet(b"\xff\xff"))

    def test_will_dont_commands_are_three_bytes(self):
        self.assertEqual("sh", filter_telnet(b"sh\xff\xfb\x01\xff\xfe\x01"))

    def test_subnegotiation_is_skipped(self):
        data = b"a\xff\xfa\x18\x00\x54\x54\x59\xff\xf0b"
        self.assertEqual("ab", filter_telnet(data))

    def test_truncated_sequence_is_dropped(self):
        self.assertEqual("", filter_telnet(b"\xff"))


class ParseTelnetdPidTests(unittest.TestCase):
    def _table(self, pid):
        return (
            "Name      APPID pid    inst  parent\n"
            "telnetd   0x2a  %s     0     0x1\n"
            "cwmp      0x33  999    0     0x1\n"
        ) % pid

    def test_parses_pid_from_show_table(self):
        self.assertEqual(4321, _parse_telnetd_pid(self._table(4321)))

    def test_missing_telnetd_raises(self):
        with self.assertRaises(RuntimeError):
            _parse_telnetd_pid("Name APPID pid inst\ncwmp 0x33 999 0\n")

    def test_invalid_pid_raises(self):
        with self.assertRaises(ValueError):
            _parse_telnetd_pid(self._table("abc"))


class ParseRegionTests(unittest.TestCase):
    def test_parses_region_from_flag_type(self):
        self.assertEqual("198", _parse_region("current : 198"))

    def test_missing_region_is_none(self):
        self.assertIsNone(_parse_region("default : 0"))


class ParseTempCredentialsTests(unittest.TestCase):
    def test_parses_user_and_pass(self):
        url = b"FactoryModeAuth.gch?user=tl&pass=tp123"
        self.assertEqual(("tl", "tp123"), parse_temp_credentials(url.decode()))

    def test_missing_credentials_raise(self):
        with self.assertRaises(TelnetError):
            parse_temp_credentials("FactoryModeAuth.gch?user=only")


if __name__ == "__main__":
    unittest.main()
