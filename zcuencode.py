#!/usr/bin/env python3
"""zcuencode — enkode file XML konfigurasi menjadi config.bin router ZTE.

Repo ini sebelumnya tidak mempunyai encoder sama sekali (tab Encoder di
aplikasi GUI pun masih bertuliskan "COMING SOON"). Skrip ini membungkus
pustaka zcu untuk tipe payload:

  tipe 0  zlib saja (tanpa enkripsi)
  tipe 2  AES-128-ECB dengan --key
  tipe 3  AES-256-CBC, IV == kunci
  tipe 4  AES-256-CBC, IV != kunci

Untuk tipe 3/4, kunci/IV dapat diberikan langsung lewat --key/--iv, atau
diturunkan dari signature model router lewat keygen (--signature, dibantu
--serial/--mac/--longpass bila keygen model itu membutuhkannya).

Tipe 6 (varian F670L) tidak didukung untuk enkode: format tulisnya spesifik
perangkat dan belum terverifikasi, jadi tidak ditebak.

Contoh:
  python3 zcuencode.py config.xml config.bin
  python3 zcuencode.py config.xml config.bin --type 2 --key '402c38de39bed665' \
      --signature 'ZXHN H267A' --with-header
  python3 zcuencode.py config.xml config.bin --type 4 --signature 'ZXHN H268Q' --with-header
"""

import argparse
import struct
import sys
from io import BytesIO
from types import SimpleNamespace

from zcu import compression, zte
from zcu.known_keys import run_keygen
from zcu.xcryptors import CBCXcryptor, Xcryptor


def payload_type_of(payload_bytes):
    return struct.unpack('>I', payload_bytes[4:8])[0]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Enkode file XML konfigurasi menjadi config.bin router ZTE (IndiHome).')
    parser.add_argument('infile', help='file XML masukan')
    parser.add_argument('outfile', help='file config.bin keluaran')
    parser.add_argument('--type', type=int, default=0, choices=(0, 2, 3, 4),
                        help='tipe payload (bawaan: 0)')
    parser.add_argument('--key', help='kunci enkripsi (tipe 2: ECB; tipe 3/4: string kunci CBC)')
    parser.add_argument('--iv', help='string IV untuk tipe 4 (bawaan: sama dengan --key, menghasilkan tipe 3)')
    parser.add_argument('--signature', default='',
                        help='string signature model, mis. "ZXHN H267A" (juga dipakai keygen tipe 3/4)')
    parser.add_argument('--serial', help='nomor seri router (untuk keygen)')
    parser.add_argument('--mac', help='alamat MAC router (untuk keygen tagparams)')
    parser.add_argument('--longpass', help='long password (untuk keygen tagparams)')
    parser.add_argument('--with-header', action='store_true',
                        help='sertakan header ZTE 128 byte di depan signature+payload')
    parser.add_argument('--version', type=int, default=0,
                        help='field versi pada header ZTE (bawaan: 0)')
    parser.add_argument('--chunk-size', type=int, default=65536,
                        help='ukuran chunk kompresi (bawaan: 65536)')
    args = parser.parse_args(argv)

    with open(args.infile, 'rb') as f:
        xml_data = f.read()

    payload = compression.compress(BytesIO(xml_data), args.chunk_size)

    if args.type == 2:
        if not args.key:
            print('Kesalahan: tipe 2 membutuhkan --key', file=sys.stderr)
            return 2
        payload = Xcryptor(args.key, args.chunk_size).encrypt(payload)

    elif args.type in (3, 4):
        key, iv = args.key, args.iv
        if key is None:
            if not args.signature:
                print('Kesalahan: tipe 3/4 membutuhkan --key atau --signature untuk keygen',
                      file=sys.stderr)
                return 2
            params = SimpleNamespace(
                signature=args.signature,
                serial=args.serial or '',
                mac=args.mac or '',
                longPass=args.longpass or '',
            )
            generated = run_keygen(params)
            if generated is None:
                print('Kesalahan: tidak ada keygen yang cocok untuk signature %r'
                      % args.signature, file=sys.stderr)
                return 2
            key, iv = generated[0], generated[1]
            print('kunci dari keygen: %s' % generated[2])
        if iv is None:
            iv = key
        expected = 3 if key == iv else 4
        if expected != args.type:
            print('Kesalahan: --type %d tidak konsisten dengan kunci/IV '
                  '(key == iv menghasilkan tipe 3, key != iv menghasilkan tipe 4)'
                  % args.type, file=sys.stderr)
            return 2
        xcryptor = CBCXcryptor()
        xcryptor.set_key(key, iv)
        payload = xcryptor.encrypt(payload)

    payload_bytes = payload.getvalue() if hasattr(payload, 'getvalue') else payload.read()
    actual_type = payload_type_of(payload_bytes)
    if actual_type != args.type:
        print('Kesalahan: tipe payload hasil enkode adalah %d, bukan %d'
              % (actual_type, args.type), file=sys.stderr)
        return 1

    full = zte.add_header(BytesIO(payload_bytes), args.signature.encode(),
                          args.version, include_header=args.with_header)
    out_bytes = full.read()
    with open(args.outfile, 'wb') as f:
        f.write(out_bytes)

    print('Berhasil dienkode: %s -> %s' % (args.infile, args.outfile))
    print('tipe payload: %d, signature: %r, header ZTE: %s, ukuran: %d byte'
          % (args.type, args.signature,
             'ya' if args.with_header else 'tidak', len(out_bytes)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
