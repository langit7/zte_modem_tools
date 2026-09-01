# ZTE Modem Tools

Tools for supported ZTE ONU/ONT devices:

- Open or close factory-mode Telnet.
- Enable `/proc/serial`.
- Decrypt ZTE `hardcodefile` configuration files.

> Use this only on devices you own or are authorized to manage. Telnet exposes
> a privileged service on your local network.

## Quick start

Install Python 3, open a terminal in this repository, then create an isolated
environment and install the dependencies.

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Windows Command Prompt:

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

## Telnet

### Open temporary Telnet

This uses the default modem address (`192.168.1.1`) and ports (HTTP `80`,
Telnet `23`). A successful run prints temporary Telnet credentials.

```bash
python3 zte_factroymode.py telnet
```

On Windows, use `python` instead of `python3`:

```powershell
python .\zte_factroymode.py telnet
```

### Make Telnet persistent

Permanent Telnet uses the configured Telnet credentials. It is allowed only
when every `WLANBase.CountryCode` value is `198`.

```bash
# Restart telnetd without rebooting.
python3 zte_factroymode.py --telnet telnet

# Reboot the modem to apply the saved settings.
python3 zte_factroymode.py --telnet-restart telnet
```

Use `--telnet-restart` if in-place restart fails. Some firmware accepts the
login after reboot but still denies shell commands; that firmware does not
persist developer-shell privilege.

### Close Telnet

```bash
python3 zte_factroymode.py telnet close
```

## Common options

Put options before `telnet` or `serial`.

```bash
# Different modem address or ports.
python3 zte_factroymode.py --ip 192.168.1.1 --port 8080 --tp 23 telnet

# Try a specific factory-mode login.
python3 zte_factroymode.py --user modem-admin --pass '<factory-password>' telnet

# Provide the MAC address visible to the modem (especially on Windows).
python3 zte_factroymode.py --mac 00:11:22:33:44:55 telnet
```

Newer firmware may bind authentication to the client MAC. On Linux, the tool
normally detects it automatically; use `--iface eth0` to choose an interface.
On Windows, provide `--mac`. The MAC must be the layer-2 address the modem
actually sees; it is not spoofed or changed by this tool.

For older method-3 firmware, try the compatibility profile:

```bash
python3 zte_factroymode.py --sendinfo-profile rerand22 telnet
```

Use `--new` only for firmware that requires its historical time-qualified
authentication form. Protocol generation is detected automatically.

## Serial control

```bash
python3 zte_factroymode.py serial open
python3 zte_factroymode.py serial close
```

## Troubleshooting

- Add `-v` before the subcommand for diagnostics, for example
  `python3 zte_factroymode.py -v telnet`. Do not share its output without
  removing credentials.
- If authentication works but Telnet does not open, retry with `--mac` or
  `--iface`. This is common through bridges, repeaters, VMs, or Wi-Fi links.
- If a failed F6201B attempt used invalid headers, reboot the modem before
  retrying; its HTTP service can retain the failed state.
- Run `python3 zte_factroymode.py --help` for every option.

## Decrypt hardcode files

Copy `/etc/hardcode` and `/etc/hardcodefile` from the modem, then run:

```bash
python3 zte_hardcode_dump.py /path/to/hardcode /path/to/hardcodefile/*
```

The input can be a file, folder, or wildcard. Decrypted files are written next
to their inputs with a `.txt` suffix. Try the included sample with:

```bash
python3 zte_hardcode_dump.py test/hardcode test/hardcodefile
```

## Tests

```bash
python3 -m unittest discover -s test -v
```

## License

Distributed under the [MIT License](LICENSE). Based on
[douniwan5788/zte_modem_tools](https://github.com/douniwan5788/zte_modem_tools).
