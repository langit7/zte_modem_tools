# ZXHN G7615TV2-XE: Wuhan Telecom temporary Telnet and bridge-mode clock

## Scope and result

This is a single-device field report, not a general firmware compatibility
claim. The troubleshooting and documentation were assisted by Codex.

| Item | Tested environment |
| --- | --- |
| ISP | China Telecom, Wuhan, Hubei, China |
| Device | ZTE ZXHN G7615TV2-XE |
| Hardware | V2.0 |
| Firmware | V3.1.0P1T1 |
| Region | 211, unchanged |
| Internet setup | Bridged modem; PPPoE on an OpenWrt-based router |
| Tool revision | `010dab9f14d6d71d9df458f233c25926b5e3d87d` |
| Verified | Temporary Telnet login, Linux shell commands, UTC clock adjustment |
| Not achieved | Native persistent Telnet or a persistent modem clock |

The original problem was a modem clock near 1970, making its logs difficult
to correlate with router logs. The operator-management path and native SNTP
were checked first, but synchronization did not succeed. Temporary Telnet
allowed the clock to be corrected without flashing or a factory reset.
TR-069 is remote management, not the NTP/SNTP time protocol itself.

Bridge mode, VLANs, provisioning/registration data and the operator-management
connection were preserved. No region change or TR-069 removal was used.
An ordinary modem reboot was used for validation; it is not a factory reset.

## What made temporary Telnet work

- An existing, authorized modem superadmin account, not a password search.
- The reachable LAN management endpoint, HTTP port `8080` in this case.
- The current wired client MAC actually visible to the modem, not MAC spoofing.
- The `re_rand` handshake with `rerand34` / `SendInfo.gch?info=34`.
- The browser-style User-Agent and modem `login.html` Referer already set by
  this revision, plus the complete authentication sequence.
- Verification by real Telnet login and `uname -s`, not just HTTP 200,
  authentication success, or receipt of temporary credentials.

Earlier attempts using incompatible clients/payloads did not establish a
usable shell. One successful attempt followed a normal reboot and a clean
handshake state; subsequent reopening worked without rebooting. This does
**not** isolate a single cause or prove that rebooting is always necessary.

Older tools can assume `newrand` or a different SendInfo format. The
[upstream new-handshake discussion](https://github.com/douniwan5788/zte_modem_tools/issues/20)
provides background, not proof of all restrictions in this particular firmware.

## Reproduction outline

Use only your own authorized equipment. Temporary Telnet and management HTTP
are plaintext privileged interfaces: keep them on a trusted management LAN,
never expose them to the Internet, and never post credentials or raw logs.

1. Install the repository dependencies using the README's isolated environment.
2. Connect a wired client to a management-capable modem LAN port. Preserve the
   working PPPoE uplink; use a maintenance window if no spare port is available.
3. Confirm that the route to the modem uses that wired client and its current
   MAC. The original test explicitly bound management HTTP to the wired IPv4
   using a local transport wrapper; the reference below uses OS routing.
4. Use the authenticated temporary-only flow below from the repository root.

Example addresses, **not values to copy without checking**: modem
`192.168.1.1`, wired client `192.168.1.3/24`, router management alias
`192.168.1.2/24`. They must not conflict with existing hosts or the LAN subnet.
Do not add a default gateway or DNS to the management-only interface.

Linux route/interface checks:

```bash
ip -br addr
ip route get 192.168.1.1
ip link
```

macOS route/interface checks:

```bash
networksetup -listallhardwareports
route -n get 192.168.1.1
# Replace enX with the wired Device reported above.
ifconfig enX
```

The following is a reference composition of the tested library calls, not a
claim that this exact standalone snippet was separately tested on every OS.
It performs no permanent-setting writes, region change or reboot. Library
diagnostics are captured rather than printed; credentials are entered using
the controlling terminal, not command-line password arguments.

```bash
python3 - <<'PY'
import contextlib, getpass, io, sys
from zte_factroymode import WebFacTelnet
from zte_telnet import Telnet, parse_temp_credentials

sys.stdin = open('/dev/tty')
host = input('Modem IPv4 [192.168.1.1]: ').strip() or '192.168.1.1'
mac = bytes.fromhex(input('Current wired MAC: ').replace(':', '').replace('-', ''))
if len(mac) != 6:
    raise SystemExit('Invalid MAC')
user = input('Existing superadmin username [telecomadmin]: ').strip() or 'telecomadmin'
password = getpass.getpass('Existing modem superadmin password: ')
if not password:
    raise SystemExit('Empty password refused')
client = WebFacTelnet(host, 8080, user, password,
                      selected_mac=mac, sendinfo_profile='rerand34', verbose=False)
session = None
try:
    # reset() resets the authentication exchange, NOT the device configuration.
    with contextlib.redirect_stdout(io.StringIO()):
        for op in (client.reset, client.requestFactoryMode, client.sendSq,
                   client.sendInfo, client.checkLoginAuth):
            if not op():
                raise RuntimeError('Authentication step failed')
        reply = client.factoryMode('open')  # Temporary mode only.
    if not reply:
        raise RuntimeError('No temporary credentials returned')
    temporary_user, temporary_password = parse_temp_credentials(reply.decode())
    session = Telnet.connect(temporary_user, temporary_password, host, attempts=2)
    session.login()
    if 'Linux' not in session.run_output('uname -s').splitlines():
        raise RuntimeError('Shell verification failed')
    print('Verified: actual Telnet login and Linux shell')
    print('Temporary username (keep private):', temporary_user)
    print('Temporary password (keep private):', temporary_password)
    print(session.run_output('date +%s'))
finally:
    if session is not None:
        session.close()
    client.S.close()
    client.pw = None
PY
```

If the flow fails, check the route, visible MAC, known credentials and firmware
before retrying. Do not automatically reboot, factory-reset or change region.
Temporary credentials can rotate or expire; do not treat them as a permanent
account or run another session while a maintenance worker is using the modem.

## Clock observations and correction

The modem reported `SNTP Enable=1` but `isSynchronized=0`. Generated `msntp`
parameters selected the operator-management interface; no ordinary Internet
default route was available. A local-router NTP trial did not produce an
observed successful local synchronization and its trial settings were reverted.
This is **not** evidence that all bridged modems cannot synchronize time.

Read-only checks inside the modem's authenticated shell:

```sh
date '+%Y-%m-%d %H:%M:%S %Z %z'
date +%s
sendcmd 1 DB p SNTP
ip route
cat /var/tmp/IGD.SNTP.PARMS
```

After confirming the client clock is synchronized, set the modem to the
accurate **current UTC time** using the supported `date` syntax. The following
is a placeholder, not a literal value to execute:

```sh
date -u -s 'YYYY-MM-DD HH:MM:SS'
date +%s
```

Compare Unix seconds with a trusted clock; they should differ by only a few
seconds. Convert UTC log display to China Standard Time by adding eight hours,
not by deliberately setting the Unix clock eight hours ahead.
Existing incorrectly timestamped logs are not rewritten.

## Reboot and persistence limits

A normal modem reboot invalidated the usable temporary entry and returned the
clock to the 1970 baseline. Old temporary credentials are not guaranteed to
remain valid. Native persistence was **not** achieved: attempted writes to
the available `TelnetCfg` fields did not produce the desired read-back values.
The reason was not established; do not assume a TR-069 rewrite or copy old
firmware's persistence commands blindly.

This device's region is `211`. The tool's permanent-Telnet path requires
region `198`; its region-change option was deliberately **not** used. A normal
configuration backup is not a full flash/calibration/provisioning backup.

As a separate local workaround, an OpenWrt/procd worker was used to reopen the
authenticated temporary entry and correct time every 60 seconds. It first
checks the router's local NTP response for synchronization, valid stratum,
matching origin timestamp and agreement with the router clock; it only sets
the modem clock when drift exceeds three seconds and then reads it back.
Separate LuCI switches control time correction and temporary-entry recovery.
The worker is not part of this PR and does not make Telnet natively persistent.

Modem reboot recovery and clock correction were observed; router startup
enablement was checked, but an actual router-reboot test was not performed.
Logs between modem boot and successful correction can still show 1970.
This workaround does not fix packet loss or establish the cause of WAN drops.

Future persistence research should first identify the actual writable fields,
startup/configuration sources and recovery procedure for this exact firmware.
Require read-back, fresh authenticated login and post-reboot shell verification
before claiming success. No unverified startup-partition writes, universal weak
passwords or WAN Telnet exposure are recommended here.

## 中文摘要

湖北武汉电信 ZXHN G7615TV2-XE（硬件 V2.0，固件 V3.1.0P1T1，地区 211）
实测可通过已有超级管理员凭据、正确有线 MAC、re_rand / info=34 与完整认证流程
开启临时 Telnet。以实际登录并执行 uname -s 为准，不以 HTTP 200 为准。
桥接状态下原生 SNTP 未同步，使用 Telnet 写入准确 UTC 时间后可对齐后续日志。
普通重启后临时入口和正确时钟未保留；软路由定时恢复只是替代方案，不是原生固化。
全程未刷机、未恢复出厂、未改地区、桥接或注册信息；未删除 TR-069。
