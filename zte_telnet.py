#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Interactive telnet shell client for ZTE ONU devices.

Port of zteOnu (Go) app/telnet/telnet.go: login with temp credentials,
write permanent telnet settings to the device DB, reboot the device or
restart telnetd in place through the program manager.
"""

import re
import socket
import time

# The factory telnet listener on some firmwares only comes up minutes
# after the webFac flow returns, so keep dialing for a while instead of
# failing on the first refused/filtered attempt.
CONNECT_TIMEOUT = 3.0
DIAL_ATTEMPTS = 5
DIAL_INTERVAL = 1.0
READ_TIMEOUT = 10.0

# The device only starts the actual shutdown a while after the reboot
# command returns, so the connection must be held open until the device
# closes it; closing the session ourselves can abort the reboot.
REBOOT_CLOSE_TIMEOUT = 12.0

# The device drops the current session when telnetd is killed through the
# program manager, so the connection must be held open until the close
# announces that the kill took effect and pc has taken over respawning.
RESTART_CLOSE_TIMEOUT = 12.0

# ctrl terminates every command line sent to the device shell.
CTRL = "\r\n"

# shellPrompts are matched against device output to detect that a command has
# finished and the shell is ready for the next one.
SHELL_PROMPTS = ("#", "$")


def filter_telnet(data):
    """Drop telnet in-band control bytes (RFC 854) from raw device output.

    Handles the cases these devices actually emit: 2-byte IAC commands,
    escaped 0xFF data, 3-byte WILL/WONT/DO/DONT commands and IAC SB ...
    IAC SE subnegotiations.
    """
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b != 0xFF:  # telnetIAC
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break  # truncated sequence
        nxt = data[i + 1]
        if nxt == 0xFF:  # escaped IAC
            out.append(0xFF)
            i += 2
        elif nxt == 0xFA:  # IAC SB ... IAC SE
            j = i + 2
            while j + 1 < n and not (data[j] == 0xFF and data[j + 1] == 0xF0):
                j += 1
            i = j + 2  # past IAC SE, or past the end
        elif 0xFB <= nxt <= 0xFE:  # WILL/WONT/DO/DONT
            i += 3
        else:
            i += 2
    return out.decode("latin-1")


def _match_any(s, patterns):
    return any(p in s for p in patterns)


def _truncate(s, n=128):
    return s if len(s) <= n else s[:n] + "..."


def _parse_telnetd_pid(out):
    """Extract the current telnetd pid from a `sendcmd -pc show` table,
    which has the columns "Name APPID pid inst ..."."""
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "telnetd":
            try:
                return int(fields[2])
            except ValueError:
                raise ValueError("invalid telnetd pid %r" % fields[2])
    raise RuntimeError("telnetd not found in `sendcmd -pc show` output")


class TelnetError(Exception):
    pass


class Telnet:
    """An interactive shell connection to the ONU."""

    def __init__(self, sock, user, passwd):
        self.sock = sock
        self.user = user
        self.passwd = passwd
        self._buffer = b""

    @classmethod
    def connect(cls, user, passwd, ip, port=23, attempts=DIAL_ATTEMPTS,
                interval=DIAL_INTERVAL):
        """Dial the telnet service, retrying until the budget is exhausted.

        A custom retry budget is used to verify a telnetd that has just been
        restarted in place: the pc supervisor can take a while to respawn the
        daemon, longer than the default budget covers.
        """
        last_error = None
        for _ in range(attempts):
            try:
                sock = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
                return cls(sock, user, passwd)
            except OSError as error:
                last_error = error
                time.sleep(interval)
        raise TelnetError(
            "telnet service did not come up within %.0fs: %s"
            % (attempts * interval, last_error)
        )

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def _send_cmd(self, *commands):
        data = (CTRL.join(commands) + CTRL).encode("latin-1")
        self.sock.sendall(data)

    def _read_some(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return b""
        self.sock.settimeout(remaining)
        try:
            return self.sock.recv(1024)
        except socket.timeout:
            return b""

    def wait_for(self, timeout, *patterns):
        """Read device output until one of the patterns appears or the timeout
        elapses. Only output received during this call is considered, and
        telnet control sequences are stripped before matching."""
        deadline = time.monotonic() + timeout
        raw = bytearray()
        while True:
            out = filter_telnet(bytes(raw))
            if _match_any(out, patterns):
                return out
            if time.monotonic() >= deadline:
                raise TelnetError(
                    "timeout waiting for %s, device output: %r"
                    % (" or ".join(patterns), _truncate(out))
                )
            chunk = self._read_some(deadline)
            raw.extend(chunk)
            if not chunk and time.monotonic() >= deadline:
                raise TelnetError(
                    "timeout waiting for %s, device output: %r"
                    % (" or ".join(patterns), _truncate(out))
                )

    def wait_for_close(self, timeout):
        """Read until the peer closes the connection (EOF or a reset, both
        mean the device is going down) or the timeout elapses."""
        deadline = time.monotonic() + timeout
        while True:
            chunk = self._read_some(deadline)
            if chunk:
                continue  # device is still sending; keep waiting for the close
            if time.monotonic() < deadline:
                return  # EOF/reset before the timeout: the close happened
            raise TelnetError(
                "device did not close the connection within %.0fs; "
                "the reboot may not have started" % timeout
            )

    def login(self):
        """Perform the interactive telnet login with the credentials the
        client was created with. A clean return proves the credentials are
        currently accepted."""
        # "ogin:"/"sername:" cover both the "Login:" and "Username:" spellings
        try:
            self.wait_for(READ_TIMEOUT, "ogin:", "sername:")
        except TelnetError as error:
            raise TelnetError("no login prompt: %s" % error)
        self._send_cmd(self.user)
        try:
            self.wait_for(READ_TIMEOUT, "assword:")
        except TelnetError as error:
            raise TelnetError("no password prompt: %s" % error)
        self._send_cmd(self.passwd)
        # A rejected login either re-prompts for the username or prints an
        # error and drops the connection, so waiting for the shell prompt is
        # also the login check.
        try:
            self.wait_for(READ_TIMEOUT, *SHELL_PROMPTS)
        except TelnetError as error:
            raise TelnetError("login failed: %s" % error)

    def run_output(self, cmd, timeout=READ_TIMEOUT):
        """Send a shell command and return its device output, with the echoed
        command and telnet control bytes stripped. Only output received after
        the command is returned; waiting for the echoed command text first
        makes the match robust against a leftover prompt from the previous
        command."""
        # drain any output left over from a previous command so a stale
        # prompt cannot satisfy the match before the echo arrives
        self.sock.settimeout(0.25)
        try:
            while self.sock.recv(1024):
                pass
        except OSError:
            pass

        self._send_cmd(cmd)
        deadline = time.monotonic() + timeout
        raw = bytearray()
        while True:
            out = filter_telnet(bytes(raw))
            if cmd in out and _match_any(out, SHELL_PROMPTS):
                break
            if time.monotonic() >= deadline:
                raise TelnetError(
                    "timeout waiting for the result of %r: %r"
                    % (cmd, _truncate(out))
                )
            chunk = self._read_some(deadline)
            raw.extend(chunk)

        out = filter_telnet(bytes(raw))
        out = out[out.index(cmd) + len(cmd):].lstrip("\r\n")
        return out

    def solidify(self, username="root", password="Zte521"):
        """Write the permanent telnet settings to the device DB and save them.

        The connection must already be logged in (see login); each command is
        confirmed by the shell prompt, and the prompt after "DB save" means
        the flash write has finished, which is what makes the later reboot
        safe."""
        prefix = "sendcmd 1 DB set TelnetCfg 0 "
        commands = [
            prefix + "TS_Enable 1",
            prefix + "Lan_Enable 1",
            prefix + "TS_UName " + username,
            prefix + "TS_UPwd " + password,
            prefix + "TSLan_UName " + username,
            prefix + "TSLan_UPwd " + password,
            prefix + "Max_Con_Num 99",
            prefix + "ExitTime 999999",
            prefix + "CloseServerTime 9999999",
            prefix + "Lan_EnableAfterOlt 1",
            prefix + "InitSecLvl 3",
            # save DB; DB recsave is not available on every F6600P firmware.
            "sendcmd 1 DB save",
        ]
        for cmd in commands:
            try:
                output = self.run_output(cmd)
            except TelnetError as error:
                raise TelnetError("command %r failed: %s" % (cmd, error))
            lowered = output.lower()
            error_words = ("access denied", "error", "failed", "invalid", "not found")
            if any(word in lowered for word in error_words):
                raise TelnetError("command %r returned an error: %s" % (cmd, output.strip()))

    def reboot(self):
        """Send the reboot command and block until the device closes the
        connection, which is how the shutdown announces itself. Closing the
        session ourselves right after the command can abort the reboot before
        it starts."""
        self._send_cmd("reboot")
        self.wait_for_close(REBOOT_CLOSE_TIMEOUT)

    def restart_telnetd(self):
        """Restart the telnetd service in place through the device's program
        manager (`sendcmd -pc`): the running telnetd is killed and pc respawns
        it, which applies the currently saved DB settings without a reboot.
        Killing telnetd drops the current session, so like reboot the
        connection is held open until the device closes it."""
        try:
            out = self.run_output("sendcmd -pc show", READ_TIMEOUT)
        except TelnetError as error:
            raise TelnetError("could not read managed programs: %s" % error)
        try:
            pid = _parse_telnetd_pid(out)
        except (RuntimeError, ValueError) as error:
            raise TelnetError(
                "%s; this firmware requires a reboot to apply permanent Telnet settings "
                "(rerun with --telnet-restart)" % error
            )
        self._send_cmd("sendcmd -pc kill %d" % pid)
        self.wait_for_close(RESTART_CLOSE_TIMEOUT)


def parse_temp_credentials(url):
    """Extract user/pass from a "FactoryModeAuth.gch?user=X&pass=Y" response."""
    match = re.search(r"[?&]user=([^&]*)&pass=([^&]*)", url)
    if not match:
        raise TelnetError(
            "factory mode response carries no credentials: %r" % url
        )
    return match.group(1), match.group(2)
