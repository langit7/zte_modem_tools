#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import glob
from pathlib import Path
from typing import BinaryIO, List

from struct import pack, unpack
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


# for (i=0
#      i != 64
#      + +i)
# {
#     if ((unsigned int)(i - 5) <= 15)
#     {
#         v13 = &place_holder[index_pre10++]
#         * (v13 - 640) = hardcode_key[i] + 3
#         // prefix_key
#     }
#     v19 = i - 7
#     v20 = (unsigned int)(i - 7) > 31
#     if ((unsigned int)(i - 7) <= 31)
#     {
#         v13 = &place_holder[v16++]
#         v19 = hardcode_key[i]
#     }
#     if (!v20)
#     * (v13 - 576) = v19 + 1
# }


def ascii_offset(s, offset):
    l = []
    for b in s:
        l.append(b + offset)
    return bytes(l)


def derive_key_iv(hardcoded, ciphertext):
    """Return the AES key and IV for legacy and newer ZTE hardcode formats.

    Newer F6600P firmware moved the source ranges and changed the offsets;
    the old derivation otherwise produces plausible-looking random bytes.
    """
    candidates = [
        ("legacy", ascii_offset(hardcoded[5:21], 3) + hardcoded[64:],
         ascii_offset(hardcoded[7:39], 1)),
        ("f6600p", ascii_offset(hardcoded[47:63], 2) + hardcoded[64:],
         ascii_offset(hardcoded[2:34], 3)),
    ]
    best = None
    for name, key_phrase, iv_phrase in candidates:
        key = SHA256.new(key_phrase).digest()
        iv = SHA256.new(iv_phrase).digest()[:16]
        probe = AES.new(key, mode=AES.MODE_CBC, iv=iv).decrypt(ciphertext[:16])
        score = sum(b in range(32, 127) or b in (9, 10, 13) for b in probe)
        item = (score, name, key, iv)
        if best is None or item[0] > best[0]:
            best = item
    return best[2], best[3], best[1]


def _expand_input_files(arguments):
    """Expand files, directories, and wildcards consistently on all shells.

    POSIX shells expand wildcards before invoking Python, while Windows CMD
    and PowerShell generally pass them through. Doing the expansion here
    makes the command line behave the same everywhere.
    """
    paths = []
    for argument in arguments:
        path = Path(argument)
        if path.is_dir():
            matches = sorted(item for item in path.iterdir() if item.is_file())
        elif path.exists():
            matches = [path]
        else:
            matches = [Path(item) for item in sorted(glob.glob(argument))]
        paths.extend(matches)

    if not paths:
        raise SystemExit("no hardcode configuration files matched the supplied paths")

    unique = []
    seen = set()
    for path in paths:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def dump(hardcoded, hardcodefiles: List[Path]):
    for f in hardcodefiles:
        print(f"\ndecrypting {f}")
        with f.open("rb") as source:
            header = source.read(4*15)
            if len(header) != 4 * 15:
                print(f"{f} is truncated, skip")
                continue
        magic1, magic2, *_ = unpack(">" + 'I'*15, header)
        if magic1 != 0x01020304 or magic2 != 0x00000003:
            print(f"{f} is not a hardcode config file, skip")
            continue
        with f.open("rb") as source:
            source.seek(4 * 15)
            first_record = source.read(4 * 3)
            if len(first_record) != 4 * 3:
                print(f"{f} has no records, skip")
                continue
            plaintext_length, ciphertext_length, has_next = unpack(">III", first_record)
            ciphertext = source.read(ciphertext_length)
            aes_key, aes_iv, variant = derive_key_iv(hardcoded, ciphertext)
            print(f"using {variant} key derivation")
            aes_chiper = AES.new(aes_key, mode=AES.MODE_CBC, iv=aes_iv)
            output_path = Path(str(f) + ".txt")
            with output_path.open("wb") as t:
                t.write(aes_chiper.decrypt(ciphertext)[:plaintext_length])
                while has_next:
                    record = source.read(4 * 3)
                    if len(record) != 4 * 3:
                        raise ValueError(f"truncated record in {f}")
                    plaintext_length, ciphertext_length, has_next = unpack(">III", record)
                    t.write(aes_chiper.decrypt(source.read(ciphertext_length))[:plaintext_length])


def parseArgs():
    parser = argparse.ArgumentParser(prog='zte_hardcode_dump', epilog='https://github.com/douniwan5788/zte_modem_tools',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('hardcode', help='the /etc/hardcode file which contains root key',
                        type=argparse.FileType('rb'))
    parser.add_argument('hardcodefile', nargs="+",
                        help='config files, directories, or wildcard patterns under /etc/hardcodefile')
    return parser.parse_args()


def main():
    args = parseArgs()
    # print(args)

    dump(args.hardcode.readline().strip(), _expand_input_files(args.hardcodefile))
    print('done')


if __name__ == '__main__':
    main()
