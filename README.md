# ZTE Modem Tools

Python tools for enabling factory-mode features on supported ZTE ONU/ONT
firmware and decrypting ZTE `hardcodefile` configuration files.

The factory-mode client supports legacy firmware, early-2025 firmware, and the
newer `re_rand` handshake used by the F6201B. The protocol generation is
detected automatically.

> Use these tools only on devices you own or are authorized to manage. Opening
> Telnet exposes a privileged management service to the local network.

## Installation

Python 3 and Linux are recommended. Linux is required for automatic
route/interface MAC detection.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Open Telnet

The default command connects to `192.168.1.1` over HTTP port `80`, tries the
built-in factory-mode credentials, opens temporary Telnet on port `23`, and
verifies that the returned credentials work:

```bash
python3 zte_factroymode.py telnet open
```

`open` is optional, so this is equivalent:

```bash
python3 zte_factroymode.py telnet
```

The temporary username and password are printed after a successful login.

### Make Telnet permanent

Save permanent credentials (`root` / `Zte521`) and restart `telnetd` without
rebooting the device:

```bash
python3 zte_factroymode.py --telnet telnet open
```

Save the same credentials and reboot the device to apply them:

```bash
python3 zte_factroymode.py --telnet-restart telnet open
```

Permanent settings are written only after the tool successfully logs in with
the temporary credentials.

### Close Telnet

```bash
python3 zte_factroymode.py telnet close
```

## Connection options

Place global options before the `telnet` or `serial` subcommand.

### Different management address or ports

```bash
python3 zte_factroymode.py \
  --ip 192.168.1.1 \
  --port 8080 \
  --tp 23 \
  telnet open
```

- `--port` is the HTTP management port.
- `--tp` is the Telnet port.

### Custom factory-mode credentials

```bash
python3 zte_factroymode.py \
  --user CUAdmin \
  --pass CUAdmin \
  --ip 192.168.1.1 \
  telnet open
```

You can provide multiple usernames or passwords. The tool tries each
combination:

```bash
python3 zte_factroymode.py \
  --user admin CUAdmin \
  --pass password CUAdmin \
  --ip 192.168.1.1 \
  telnet open
```

The fixed-value `--ip` option also marks the end of the multi-value password
list, preventing `telnet open` from being interpreted as more passwords.

### Select the client MAC

Newer firmware binds the factory-mode proof to the client MAC address visible
to the ONU/ONT. The tool normally detects it from the route automatically.

Select a Linux interface explicitly:

```bash
python3 zte_factroymode.py --iface eth0 telnet open
```

Or provide the exact MAC address seen by the ONU/ONT:

```bash
python3 zte_factroymode.py --mac 00:11:22:33:44:55 telnet open
```

`--mac` changes the proof payload only; it does not change or spoof the
interface MAC. With a bridge, repeater, VM, Wi-Fi link, or routed connection,
make sure this is the layer-2 address the ONU/ONT actually sees.

## F6201B and firmware compatibility

The default `rerand34` profile is intended for current F6201B firmware:

```bash
python3 zte_factroymode.py telnet open
```

If an earlier method-3 firmware expects the 22-word proof, select the
compatibility profile:

```bash
python3 zte_factroymode.py --sendinfo-profile rerand22 telnet open
```

Use `--new` only when the device requires the historical
`version61`/time-qualified authentication form:

```bash
python3 zte_factroymode.py --new telnet open
```

`--new` does not select the handshake generation; handshake detection remains
automatic.

| Method | Typical firmware | `SendSq` response | Proof |
| --- | --- | --- | --- |
| 1 | Before 2024 | Empty body | Legacy `info=6` flow |
| 2 | Early 2025 | `newrand=N` | Client-MAC-bound `info=12` |
| 3 | Mid-2025 and later; F6201B | `re_rand=N1&N2&` plus six bridge-MAC bytes | Default `info=34`, optional `info=22` |

## Serial control

Enable or disable `/proc/serial` through the same factory-mode authentication
flow:

```bash
python3 zte_factroymode.py serial open
python3 zte_factroymode.py serial close
```

## Troubleshooting

### Show request and response details

Add `-v` or `--verbose` before the subcommand to print each HTTP request,
plaintext factory command, encrypted wire payload, response status/body, and
decrypted response:

```bash
python3 zte_factroymode.py -v telnet open
```

Debug output is written to standard error and can contain usernames,
passwords, and temporary Telnet credentials. Avoid sharing it without first
removing secrets.

### Authentication succeeds but Telnet does not open

For F6201B firmware, the request must contain a suitable `Referer` and a
User-Agent that does not contain `python`. The client supplies both headers
automatically.

The firmware also keeps a process-wide failure flag. If an earlier attempt used
invalid headers, restart the ONU/ONT before retrying so its HTTP service is
reinitialized.

### The MAC-bound proof is rejected

Specify `--iface` or `--mac`. This is commonly necessary when the computer is
connected through a bridge, repeater, VM, or another device that changes the
source MAC visible to the ONU/ONT.

### Show every option

```bash
python3 zte_factroymode.py --help
python3 zte_factroymode.py telnet --help
```

## Decrypt hardcode configuration files

`zte_hardcode_dump.py` decrypts files copied from `/etc/hardcodefile` using the
key material in `/etc/hardcode`:

```bash
python3 zte_hardcode_dump.py /path/to/hardcode /path/to/hardcodefile/*
```

Each decrypted result is written beside its input file with a `.txt` suffix.
For example, `webpri` produces `webpri.txt`.

Run the included sample:

```bash
python3 zte_hardcode_dump.py test/hardcode test/hardcodefile/*
```

## Tests

The test suite uses Python's standard-library test runner:

```bash
python3 -m unittest discover -s test -v
```

## License and upstream project

This project is distributed under the [MIT License](LICENSE) and is based on
[douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools).
