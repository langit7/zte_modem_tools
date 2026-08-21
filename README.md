# ENV

```
python3 -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
```

# zte_factroymode.py

open telnet(use embed user/pass to 192.168.1.1 80):

`python3 zte_factroymode.py telnet`

or custom args

`python3 zte_factroymode.py --user CUAdmin --pass CUAdmin --ip 192.168.1.1 --port 80 telnet open`

The client recognizes three webFac generations. F6201B uses method 3, the
`re_rand` handshake. Latest firmware uses the 34-word `info=34` proof by
default; the earlier 22-word `info=22` proof remains selectable:

| Method | Generation | SendSq reply | SendInfo behavior |
|---|---|---|---|
| 1 | Before 2024 | empty body | legacy/direct-auth flow; `info=6` command retained for compatibility |
| 2 | Early 2025 | `newrand=N` | 46-byte, client-MAC-bound `info=12` proof |
| 3 | After mid-2025; F6201B | `re_rand=N1&N2&` plus six raw bridge-MAC bytes | latest: 136-byte `info=34`; compatibility: 88-byte `info=22` |

Detection comes from the SendSq response; `--new` controls only the historical
version61/time-compatible authentication form. For method 3, the client parses
the binary `re_rand` response and automatically uses the MAC-bound SendInfo
flow. On Linux the client MAC is detected from the route to the ONU/ONT:

Method 3 can use the gist's `version50` workflow with `--sendinfo-profile
rerand22`. The default `rerand34` profile is required by the known-working latest
tool. The handshake generation and authentication version are separate choices.

`python3 zte_factroymode.py --ip 192.168.1.1 --port 80 telnet open`

Select an interface explicitly, or provide the exact client MAC observed by the ONU/ONT:

`python3 zte_factroymode.py --iface eth0 telnet open`

`python3 zte_factroymode.py --mac <mac-seen-by-ont> telnet open`

The default flow computes a 136-byte `info=34` payload from both the bridge MAC returned by `SendSq` and the selected
client MAC; it does not use a hardcoded sample MAC. Its words are `[0,1,0,9893]`, bridge MAC, client MAC twice, and
the `rerand34` marker twice. Use `--sendinfo-profile rerand22` for the 88-byte early profile. The `--mac` option changes only the encoded
payload and does not spoof the interface MAC. With a bridge, repeater, VM, Wi-Fi link or routed connection, make
sure the supplied value is the layer-2 client MAC actually seen by the ONU/ONT. `--new` remains available for the
version61/time-compatible request form, but the inspected F6201B dispatcher does not independently validate the time
field; `version50` and `version61` only pass the same numeric version threshold there.

The F6201B `RequestFactoryMode.gch` check requires a Referer containing the
management-interface IP immediately followed by `/login.html` and a User-Agent
without the substring `python`. The client supplies both automatically and
deliberately omits the HTTP port from the Referer. The firmware's failure flag
is process-global and sticky, so a previous attempt made without valid headers
may require reinitializing `httpd` (normally by restarting the device) before a
corrected attempt can configure Telnet.

The detailed binary-to-client conformance matrix and remaining uncertainties
are documented in `../RE/zte_factroymode_client_audit.md`.

```shell
$ python3 ./zte_factroymode.py -h
usage: zte_factroymode [-h] [--user USER [USER ...]] [--pass PASS [PASS ...]] [--ip IP] [--port PORT] [--new] [--iface IFACE | --mac MAC] [--telnet | --telnet-restart] [--tp TP] {telnet,serial} ...

options:
  -h, --help            show this help message and exit
  --user USER [USER ...], -u USER [USER ...]
                        factorymode auth username (default: ['factorymode', 'CMCCAdmin', 'CUAdmin', 'telecomadmin', 'cqadmin', 'user', 'admin', 'cuadmin', 'lnadmin', 'useradmin'])
  --pass PASS [PASS ...], -p PASS [PASS ...]
                        factorymode auth password (default: ['nE%jA@5b', 'aDm8H%MdA', 'CUAdmin', 'nE7jA%5m', 'cqunicom', '1620@CTCC', '1620@CUcc', 'admintelecom', 'cuadmin', 'lnadmin'])
  --ip IP               route ip (default: 192.168.1.1)
  --port PORT           router http port (default: 80)
  --new                  use version61/time-compatible authentication; webFac method is auto-detected (default: False)
  --iface IFACE         network interface whose MAC is observed by the ONU/ONT (default: None)
  --mac MAC, -m MAC     exact client MAC observed by the ONU/ONT (default: None)
  --telnet              persist root/Zte521 and restart managed telnetd in place (default: False)
  --telnet-restart      persist root/Zte521 and reboot the device (default: False)
  --tp TP               router telnet port (default: 23)

subcommands:
  valid subcommands

  {telnet,serial}       supported commands
    telnet              control telnet services on/off
    serial              control /proc/serial on/off

https://github.com/douniwan5788/zte_modem_tools
```

# zte_hardcode_dump.py

decrypt /etc/hardcodefile

`./zte_hardcode_dump.py test/hardcode test/hardcodefile/*`

```shell
$ python3 ./zte_hardcode_dump.py -h
usage: zte_hardcode_dump [-h] hardcode hardcodefile [hardcodefile ...]

positional arguments:
  hardcode      the /etc/hardcode file which contains root key
  hardcodefile  config files under /etc/hardcodefile

options:
  -h, --help    show this help message and exit

https://github.com/douniwan5788/zte_modem_tools
```
