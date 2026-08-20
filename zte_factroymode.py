#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import argparse
from random import Random, SystemRandom
from Crypto.Cipher import AES

from zte_payload import client_mac as select_client_mac
from zte_payload import format_mac, mac_to_magic_bytes


def pad(data_to_pad, block_size):
    # zero-pad, pad one byte at least

    padding_len = block_size-len(data_to_pad) % block_size
    return data_to_pad+b'\x00'*padding_len


def unpad(padded_data, block_size):
    # zero-unpad, only work for null-terminated string

    return padded_data[:-block_size] + padded_data[-block_size:].rstrip(b'\x00')


class WebFac:
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

    # newrand
    AES_KEY_POOL_NEW = [
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

    def __init__(self, ip, port, user, pw, new_method=False, selected_mac=None) -> None:
        self.ip = ip
        self.port = port
        self.user = user
        self.pw = pw
        self.new_method = new_method
        self.client_mac = selected_mac
        self.auth_time = None
        self.S = requests.Session()

    def reset(self):
        # any wrong step request should reset the facTelnetStep
        resp = self.S.post(f"http://{self.ip}:{self.port}/webFac", data='SendSq.gch')
        if resp.status_code == 400:
            return True
        return False

    def requestFactoryMode(self):
        try:
            self.S.post(f"http://{self.ip}:{self.port}/webFac", data='RequestFactoryMode.gch')
        except requests.exceptions.ConnectionError:
            # this is normal
            pass
        except Exception as e:
            print(e)

    def sendSq(self):
        try:
            # rand takes from time seconds, range 0-59
            rand = Random().randint(0, 59)

            # the byte after last digital can not be null
            resp = self.S.post(f"http://{self.ip}:{self.port}/webFac", data=f'SendSq.gch?rand={rand}\r\n')
            if resp.status_code != 200:
                return False
            # print(repr(resp.text))

            if len(resp.content) == 0:
                index = rand
                key_pool = WebFacTelnet.AES_KEY_POOL
                version = 1
            # new protocol
            elif "newrand" in resp.text:
                newrand = int(resp.text[len("newrand="):])
                #           v62 = (0x1000193 * rand) & 0x3F;
                #   if ( (int)(0xFEFFFE6D * rand) >= 0 )
                #     v62 = -((0xFEFFFE6D * rand) & 0x3F);
                #   sub_2AF88((v62 ^ newrand) % 60, AES_KEY)
                index = ((0x1000193 * rand) & 0x3F ^ newrand) % 60
                key_pool = WebFacTelnet.AES_KEY_POOL_NEW
                version = 2
            else:
                print("protocol error")
                return False

            key = map(lambda x: (x ^ 0xA5) & 0xFF, key_pool[index:index+24])
            key = bytes(key)

            self.chiper = AES.new(key, AES.MODE_ECB)
            return version
        except requests.exceptions.ConnectionError:
            print("protocol error?")
        except Exception as e:
            print(e)
        return False

    def sendInfo(self):
        try:
            command = self.sendInfoCommand()
            resp = self.S.post(f"http://{self.ip}:{self.port}/webFacEntry",
                               data=self.chiper.encrypt(pad(command, 16)))
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
        if not self.new_method:
            return b'SendInfo.gch?info=6|'
        if self.client_mac is None:
            raise ValueError("the new method requires the client MAC observed by the ONU/ONT")
        return b'SendInfo.gch?info=12|' + mac_to_magic_bytes(self.client_mac)

    def checkLoginAuth(self):
        try:
            command = self.checkLoginAuthCommand()
            resp = self.S.post(
                f"http://{self.ip}:{self.port}/webFacEntry",
                data=self.chiper.encrypt(
                    # httpd will alloc 1 more byte to ensure null terminated, anyway we add one more null to ensure
                    pad(command, 16)
                ))
            # print(repr(resp.text))
            if resp.status_code == 200:
                # checkLoginAuth use wrong function strlen to calc response size, so we may need to pad ciphertext first
                # but ciphertext can still be truncated prematurely，resulting in undecryptable data
                ciphertext = resp.content
                # print(len(ciphertext))
                if len(ciphertext) % 16:
                    ciphertext = pad(ciphertext, 16)
                url = unpad(self.chiper.decrypt(ciphertext), 16)
                # resp should be "FactoryMode.gch"
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
    def __init__(self, ip, port, user, pw, new_method=False, selected_mac=None) -> None:
        super().__init__(ip, port, user, pw, new_method, selected_mac)

    def serialSlience(self, action):
        try:
            resp = self.S.post(
                f"http://{self.ip}:{self.port}/webFacEntry",
                data=self.chiper.encrypt(
                    pad(f'SerialSlience.gch?action={action}'.encode(), 16)
                ))
            # print(repr(resp.text))
            if resp.status_code == 200:
                return True
            elif resp.status_code == 400:
                print("protocol error")
        except Exception as e:
            print(e)
        return False


class WebFacTelnet(WebFac):
    def __init__(self, ip, port, user, pw, new_method=False, selected_mac=None) -> None:
        super().__init__(ip, port, user, pw, new_method, selected_mac)

    def factoryMode(self, action):
        try:
            command = self.factoryModeCommand(action)
            resp = self.S.post(
                f"http://{self.ip}:{self.port}/webFacEntry",
                data=self.chiper.encrypt(pad(command, 16)))
            # print(repr(resp.text))
            if resp.status_code == 200:
                # resp should be "FactoryModeAuth.gch?user=<telnetuser>&pass=<telnetpass>"
                url = unpad(self.chiper.decrypt(resp.content), 16)
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
            # mode 1:ops 2:dev 3:production 4:user
            return b'FactoryMode.gch?mode=2&user=notused'
        if self.auth_time is None:
            raise ValueError("new factory mode requires a completed authentication step")
        mode_time = SystemRandom().randint(self.auth_time, 999)
        return f'FactoryMode.gch?time{mode_time}&mode=2&user=fuckyou'.encode()


def dealFacAuth(Class: WebFac, ip, port, users, pws, new_method=False, selected_mac=None):
    for user in users:
        for pw in pws:
            print(f"trying  user:\"{user}\" pass:\"{pw}\" ")
            webfac: WebFac = Class(ip, port, user, pw, new_method, selected_mac)
            print("reset facTelnetSteps:")
            if webfac.reset():
                print("reset OK!\n")

            print("facStep 1:")
            webfac.requestFactoryMode()
            print("OK!\n")

            print("facStep 2:")
            version = webfac.sendSq()
            print("OK!\n")

            if version == 1:
                print("facStep 3:")
                print("OK!\n")
                if webfac.checkLoginAuth():
                    print("facStep 4:")
                    print("OK!\n")
                    return webfac
            elif version == 2:
                print("facStep 3:")
                if not webfac.sendInfo():
                    print("sendInfo error")
                    return
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


def dealSerial(ip, port, users, pws, action, new_method=False, selected_mac=None):
    serial = dealFacAuth(WebFacSerial, ip, port, users, pws, new_method, selected_mac)
    if not serial:
        return

    print("facStep 5:")
    if serial.serialSlience(action):
        print("OK!\n")
    print('done')
    return


def dealTelnet(ip, port, users, pws, action, new_method=False, selected_mac=None):
    telnet = dealFacAuth(WebFacTelnet, ip, port, users, pws, new_method, selected_mac)
    if not telnet:
        print('No Luck!')
        return

    print("facStep 5:")
    url = telnet.factoryMode(action)
    if url:
        print("OK!\n")
        print(repr(url))
        print('done')
        return


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
                        help='use the newer time-qualified version61 method')
    mac_group = parser.add_mutually_exclusive_group()
    mac_group.add_argument('--iface', help='network interface whose MAC is observed by the ONU/ONT')
    mac_group.add_argument('--mac', '-m', help='exact client MAC observed by the ONU/ONT')
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
    if args.new_method:
        try:
            selected_mac, source = select_client_mac(args.ip, args.port, args.mac, args.iface)
        except (OSError, RuntimeError, ValueError) as error:
            raise SystemExit("cannot select the ONU/ONT-visible client MAC: %s" % error)
        print("new method client MAC: %s (%s)" % (format_mac(selected_mac), source))

    # print(args)
    if args.cmd == 'serial':
        dealSerial(args.ip, args.port, args.user, args.pw, args.action,
                   args.new_method, selected_mac)
    elif args.cmd == 'telnet':
        dealTelnet(args.ip, args.port, args.user, args.pw, args.action,
                   args.new_method, selected_mac)


if __name__ == '__main__':
    main()
