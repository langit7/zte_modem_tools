import threading
import unittest

import zte_telnet
from zte_telnet import Telnet, TelnetError


class FakeTelnetd(threading.Thread):
    """Scripted telnetd: answers the interactive login prompts, then confirms
    every shell command with "# "; `sendcmd -pc show` returns a process table,
    `sendcmd -pc kill <pid>` and `reboot` drop the session."""

    def __init__(self, reprompt=False, region="198"):
        super().__init__(daemon=True)
        self.lines = []
        self.killed = threading.Event()
        self.reprompt = reprompt
        self.region = region
        self.server, self.port = socket_server()

    def run(self):
        conn, _ = self.server.accept()
        try:
            conn.sendall(b"Login:")
            data = b""
            state = 0  # 0=user, 1=password, 2=shell
            while True:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                data += chunk
                while b"\r\n" in data:
                    line, data = data.split(b"\r\n", 1)
                    text = line.decode("latin-1")
                    if self.reprompt:
                        conn.sendall(b"Username:")
                        continue
                    if state == 0:
                        self.lines.append("USER:" + text)
                        conn.sendall(b"Password:")
                        state = 1
                    elif state == 1:
                        self.lines.append("PASS:" + text)
                        conn.sendall(b"# ")
                        state = 2
                    else:
                        self.lines.append(text)
                        conn.sendall(text.encode("latin-1") + b"\r\n")
                        if text == "sendcmd -pc show":
                            conn.sendall(b"\r\ntelnetd   0x2a  777     0\r\n# ")
                        elif text == "cat /userconfig/flag_type":
                            response = "current : %s\r\n# " % self.region
                            conn.sendall(response.encode("latin-1"))
                        elif text == "upgradetest sfactoryconf 198":
                            self.region = "198"
                            conn.sendall(b"# ")
                        elif text.startswith("sendcmd -pc kill"):
                            self.killed.set()
                            conn.close()  # killing telnetd drops the session
                            return
                        elif text.startswith("reboot"):
                            conn.close()
                            return
                        else:
                            conn.sendall(b"# ")
        except OSError:
            pass
        finally:
            conn.close()
            self.server.close()


def socket_server():
    import socket

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    return server, server.getsockname()[1]


class TelnetFlowTests(unittest.TestCase):
    def setUp(self):
        # keep intentional failure timeouts short
        self._old_timeout = zte_telnet.READ_TIMEOUT
        zte_telnet.READ_TIMEOUT = 2.0
        self.fake = FakeTelnetd()
        self.fake.start()
        import time

        time.sleep(0.05)

    def tearDown(self):
        zte_telnet.READ_TIMEOUT = self._old_timeout
        self.fake.join(timeout=3)

    def _connect(self, user="tluser", passwd="tlpass", fake=None):
        fake = fake or self.fake
        session = Telnet.connect(user, passwd, "127.0.0.1",
                                 fake.port, attempts=2, interval=0.05)
        session.user, session.passwd = user, passwd
        return session

    def test_login_with_temp_credentials(self):
        session = self._connect()
        try:
            session.login()
        finally:
            session.close()
        self.assertIn("USER:tluser", self.fake.lines)
        self.assertIn("PASS:tlpass", self.fake.lines)

    def test_solidify_writes_permanent_settings_and_db_save(self):
        session = self._connect("root", "Zte521")
        try:
            session.login()
            session.solidify()
        finally:
            session.close()
        joined = "\n".join(self.fake.lines)
        self.assertIn("sendcmd 1 DB set TelnetCfg 0 Lan_Enable 1", joined)
        self.assertIn("sendcmd 1 DB set TelnetCfg 0 TS_UName root", joined)
        self.assertIn("sendcmd 1 DB set TelnetCfg 0 TS_UPwd Zte521", joined)
        self.assertIn("sendcmd 1 DB set TelnetCfg 0 TSLan_UName root", joined)
        self.assertIn("sendcmd 1 DB set TelnetCfg 0 TSLan_UPwd Zte521", joined)
        self.assertIn("sendcmd 1 DB set TelnetCfg 0 Max_Con_Num 99", joined)
        self.assertIn("sendcmd 1 DB set TelnetCfg 0 InitSecLvl 3", joined)
        self.assertIn("sendcmd 1 DB save", joined)
        self.assertNotIn("sendcmd 1 DB recsave", joined)

    def test_solidify_refuses_unsupported_region(self):
        unsupported = FakeTelnetd(region="77")
        unsupported.start()
        import time

        time.sleep(0.05)
        session = Telnet.connect("root", "Zte521", "127.0.0.1",
                                 unsupported.port, attempts=2, interval=0.05)
        try:
            session.login()
            with self.assertRaises(TelnetError):
                session.solidify()
        finally:
            session.close()
        unsupported.join(timeout=3)
        self.assertEqual(["USER:root", "PASS:Zte521",
                          "cat /userconfig/flag_type"], unsupported.lines)

    def test_solidify_can_enforce_region_198_before_saving(self):
        unsupported = FakeTelnetd(region="77")
        unsupported.start()
        import time

        time.sleep(0.05)
        session = Telnet.connect("root", "Zte521", "127.0.0.1",
                                 unsupported.port, attempts=2, interval=0.05)
        try:
            session.login()
            session.solidify(enforce_region=True)
        finally:
            session.close()
        unsupported.join(timeout=3)
        self.assertIn("upgradetest sfactoryconf 198", unsupported.lines)
        self.assertEqual(2, unsupported.lines.count("cat /userconfig/flag_type"))
        self.assertIn("sendcmd 1 DB save", unsupported.lines)

    def test_restart_telnetd_kills_parsed_pid(self):
        session = self._connect("root", "Zte521")
        try:
            session.login()
            session.restart_telnetd()
        finally:
            session.close()
        self.assertIn("sendcmd -pc show", self.fake.lines)
        self.assertIn("sendcmd -pc kill 777", self.fake.lines)
        self.assertTrue(self.fake.killed.is_set())

    def test_reboot_waits_for_device_close(self):
        session = self._connect("root", "Zte521")
        try:
            session.login()
            session.reboot()
        finally:
            session.close()
        self.assertIn("reboot", self.fake.lines)

    def test_rejected_login_raises(self):
        reprompt = FakeTelnetd(reprompt=True)
        reprompt.start()
        import time

        time.sleep(0.05)
        session = None
        try:
            session = self._connect("bad", "creds", fake=reprompt)
            with self.assertRaises(TelnetError):
                session.login()
        finally:
            if session:
                session.close()
            reprompt.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
