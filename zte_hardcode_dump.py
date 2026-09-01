#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
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


def dump(hardcoded, hardcodefiles: List[BinaryIO]):
    for f in hardcodefiles:
        print(f"\ndecrypting {f.name}")
        header = f.read(4*15)
        magic1, magic2, *_ = unpack(">" + 'I'*15, header)
        if magic1 != 0x01020304 or magic2 != 0x00000003:
            print(f"{f.name} is not a hardcode config file, skip")
            continue
        first_record = f.read(4 * 3)
        plaintext_length, ciphertext_length, has_next = unpack(">III", first_record)
        ciphertext = f.read(ciphertext_length)
        aes_key, aes_iv, variant = derive_key_iv(hardcoded, ciphertext)
        print(f"using {variant} key derivation")
        aes_chiper = AES.new(aes_key, mode=AES.MODE_CBC, iv=aes_iv)
        with open(f'{f.name}.txt', "wb") as t:
            t.write(aes_chiper.decrypt(ciphertext)[:plaintext_length])
            while has_next:
                plaintext_length, ciphertext_length, has_next = unpack(">III", f.read(4*3))
                t.write(aes_chiper.decrypt(f.read(ciphertext_length))[:plaintext_length])


def parseArgs():
    parser = argparse.ArgumentParser(prog='zte_hardcode_dump', epilog='https://github.com/douniwan5788/zte_modem_tools',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('hardcode', help='the /etc/hardcode file which contains root key',
                        type=argparse.FileType('rb'))
    parser.add_argument('hardcodefile', nargs="+", help='config files under /etc/hardcodefile',
                        type=argparse.FileType('rb'))
    return parser.parse_args()


def main():
    args = parseArgs()
    # print(args)

    dump(args.hardcode.readline().strip(), args.hardcodefile)
    print('done')


if __name__ == '__main__':
    main()
