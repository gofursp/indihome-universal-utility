#!/usr/bin/env python3
"""zcudecode — dekode file config.bin router ZTE (IndiHome) menjadi XML.

Repo ini sebelumnya tidak mempunyai CLI sama sekali: aplikasi GUI hanya
menanam skrip dekoder yang menangani payload tipe 6 (ZTE F670L). Skrip ini
adalah dekoder umum untuk pustaka zcu:

  tipe 0  zlib saja (tanpa enkripsi)
  tipe 2  AES-128-ECB — kunci dicari dari signature (known_keys) lalu semua
          kunci yang diketahui dicoba satu per satu
  tipe 3  AES-256-CBC, IV == kunci — kunci/IV dari keygen (signature, serial,
          tagparams) berdasarkan signature/serial/MAC/longPass
  tipe 4  AES-256-CBC, IV != kunci — sama seperti tipe 3
  tipe 6  varian CBC ZTE F670L — kunci diturunkan dari serial + MAC router

Struktur kontainer (header ZTE 128 byte dan blok signature bersifat
opsional) dideteksi otomatis; file F670L yang payload-nya mulai di offset
145 juga dicoba secara otomatis.

Contoh:
  python3 zcudecode.py config.bin config.xml
  python3 zcudecode.py config.bin config.xml --serial ZTEG12345678 --mac AA:BB:CC:DD:EE:FF
  python3 zcudecode.py config.bin config.xml --extract
  python3 zcudecode.py config.bin --info
"""

import argparse
import re
import struct
import sys
from io import BytesIO
from types import SimpleNamespace

from zcu import constants, known_keys, zte
from zcu.compression import decompress
from zcu.xcryptors import CBCXcryptor, Xcryptor

DEFAULT_IV_PREFIX = "ZTE%FN$GponNJ025"
CANDIDATE_OFFSETS = (0, 145)
PAYLOAD_HEADER_LEN = 60


def parse_container(buf, offset):
    """Coba parse kontainer pada offset tertentu.

    Mengembalikan (stream, signature_bytes, payload_type, payload_pos) atau
    None bila pada offset itu tidak ditemukan header payload yang valid.
    Stream dikembalikan pada posisi payload_pos (awal header payload).
    """
    stream = BytesIO(buf)
    stream.seek(offset)
    start = stream.tell()

    magic = stream.read(16)
    stream.seek(start)
    if len(magic) == 16 and struct.unpack('>4I', magic) == constants.ZTE_MAGIC:
        try:
            zte.read_header(stream)
        except (AssertionError, struct.error):
            # header ada tetapi tidak konsisten (mis. endian/ukuran berbeda);
            # lewati 128 byte dan tetap coba parse sisanya
            stream.seek(start + 128)

    try:
        signature = zte.read_signature(stream)
    except struct.error:
        return None

    payload_pos = stream.tell()
    payload_type = zte.read_payload_type(stream, raise_on_error=False)
    if payload_type is None:
        return None
    stream.seek(payload_pos)
    return stream, signature, payload_type, payload_pos


def _decompress_stream(stream):
    """Stream harus berada tepat setelah header payload 60 byte."""
    data, _crc = decompress(stream)
    return data.read()


def try_plain(stream, payload_pos):
    """Tipe 0: payload adalah data zlib berheader, langsung didekompresi."""
    try:
        stream.seek(payload_pos)
        if zte.read_payload_type(stream, raise_on_error=False) is None:
            return None
        return _decompress_stream(stream)
    except Exception:
        return None


def try_decrypt(xcryptor, stream, payload_pos):
    """Dekripsi payload terenkripsi lalu validasi + dekompresi isinya.

    Hasil dekripsi yang benar selalu diawali header payload 60 byte milik
    blok kompresi di dalamnya; itulah cara menebak kunci yang benar.
    """
    try:
        stream.seek(payload_pos + PAYLOAD_HEADER_LEN)
        decrypted = xcryptor.decrypt(stream)
        if zte.read_payload_type(decrypted, raise_on_error=False) is None:
            return None
        return _decompress_stream(decrypted)
    except Exception:
        return None


def derive_f670l_key(serial, mac):
    """Turunkan kunci CBC tipe 6 (ZTE F670L) dari serial dan MAC router.

    Sama seperti skrip yang tertanam di aplikasi GUI: serial 12 karakter
    memakai serial[4:], serial 19 karakter memakai serial[11:]; MAC dipakai
    sebagai string hex dengan urutan byte dibalik.
    """
    if len(serial) == 12:
        key_part = serial[4:]
    elif len(serial) == 19:
        key_part = serial[11:]
    else:
        return None
    mac_clean = mac.replace(':', '').replace('-', '').strip()
    try:
        mac_bytes = bytes.fromhex(mac_clean)
    except ValueError:
        return None
    if len(mac_bytes) != 6:
        return None
    return key_part + mac_bytes[::-1].hex()


def decode_payload(parsed, args, sig_str):
    """Kembalikan (data_xml_bytes, deskripsi_metode) atau (None, pesan_gagal)."""
    stream, _signature, payload_type, payload_pos = parsed

    if payload_type == 0:
        out = try_plain(stream, payload_pos)
        if out is not None:
            return out, 'zlib saja (tanpa enkripsi)'
        return None, 'payload tipe 0 gagal didekompresi'

    if payload_type == 2:
        keys = []
        if args.key:
            keys.append(args.key)
        matched = known_keys.find_key(sig_str) if sig_str else None
        if matched and matched not in keys:
            keys.append(matched)
        for key in known_keys.get_all_keys():
            if key not in keys:
                keys.append(key)
        for key in keys:
            out = try_decrypt(Xcryptor(key), stream, payload_pos)
            if out is not None:
                return out, 'AES-128-ECB (kunci: %r)' % key
        return None, 'tidak ada kunci ECB yang cocok (%d kunci dicoba)' % len(keys)

    if payload_type in (3, 4):
        params = SimpleNamespace(
            signature=sig_str,
            serial=args.serial or '',
            mac=args.mac or '',
            longPass=args.longpass or '',
        )
        candidates = []
        if args.key:
            candidates.append((args.key, args.iv or args.key, '--key manual'))
        for key, iv, desc in known_keys.run_all_keygens(params):
            candidates.append((key, iv, desc))
        seen = set()
        for key, iv, desc in candidates:
            if (key, iv) in seen:
                continue
            seen.add((key, iv))
            xcryptor = CBCXcryptor()
            xcryptor.set_key(key, iv)
            out = try_decrypt(xcryptor, stream, payload_pos)
            if out is not None:
                return out, 'AES-256-CBC (%s)' % desc
        return None, 'tidak ada kandidat kunci/IV CBC yang cocok (%d dicoba)' % len(seen)

    if payload_type == 6:
        if not args.serial or not args.mac:
            return None, ('payload tipe 6 (F670L) membutuhkan --serial dan --mac '
                          'milik router')
        key = derive_f670l_key(args.serial, args.mac)
        if key is None:
            return None, ('serial harus 12 atau 19 karakter dan MAC harus 6 byte '
                          '(format AA:BB:CC:DD:EE:FF)')
        xcryptor = CBCXcryptor()
        xcryptor.set_key(key, args.iv_prefix)
        out = try_decrypt(xcryptor, stream, payload_pos)
        if out is not None:
            return out, 'AES-256-CBC varian F670L (serial+MAC, awalan IV %r)' % args.iv_prefix
        return None, 'kunci turunan serial+MAC tidak cocok (periksa serial, MAC, dan --iv-prefix)'

    return None, 'tipe payload %d tidak dikenal' % payload_type


_INTERESTING = ('user', 'pass', 'pwd', 'ppp', 'acs', 'serial', 'mac', 'admin',
                'login', 'ssid', 'wpa', 'key', 'auth', 'tr069', 'internet',
                'telepon', 'phone', 'voip', 'sip')
_TOKEN_RE = re.compile(r'<Tbl\s+name="([^"]+)"|name="([^"]+)"\s+val="([^"]*)"')


def extract_info(xml_text):
    """Heuristik 'Extract Info': kumpulkan pasangan name/val yang tampak
    seperti kredensial dari XML hasil dekode, dikelompokkan per <Tbl>.

    Ini heuristik penamaan, bukan parser skema DM resmi ZTE.
    """
    results = []
    current_tbl = ''
    for match in _TOKEN_RE.finditer(xml_text):
        if match.group(1) is not None:
            current_tbl = match.group(1)
            continue
        name, val = match.group(2), match.group(3)
        if val and any(word in name.lower() for word in _INTERESTING):
            results.append((current_tbl, name, val))
    return results


def print_extracted(xml_bytes):
    text = xml_bytes.decode('utf-8', 'replace')
    results = extract_info(text)
    print()
    print('=== Info terekstrak (heuristik) ===')
    if not results:
        print('(tidak ditemukan pasangan name/val yang tampak seperti kredensial)')
        return
    current_tbl = None
    for tbl, name, val in results:
        if tbl != current_tbl:
            current_tbl = tbl
            print('[%s]' % (tbl or '(tanpa tabel)'))
        print('  %s = %s' % (name, val))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Dekode file config.bin router ZTE (IndiHome) menjadi XML.')
    parser.add_argument('infile', help='file config.bin masukan')
    parser.add_argument('outfile', nargs='?',
                        help='file XML keluaran (wajib kecuali --info/--extract-only)')
    parser.add_argument('--serial', help='nomor seri router (tipe 3/4 keygen serial, wajib untuk tipe 6)')
    parser.add_argument('--mac', help='alamat MAC router, mis. AA:BB:CC:DD:EE:FF (wajib untuk tipe 6)')
    parser.add_argument('--signature', help='timpa signature dari file (untuk pencarian kunci/keygen)')
    parser.add_argument('--longpass', help='long password untuk keygen tagparams (model H288A)')
    parser.add_argument('--key', help='kunci manual (tipe 2: kunci ECB; tipe 3/4/6: string kunci CBC)')
    parser.add_argument('--iv', help='string IV manual untuk tipe 3/4 (bawaan: sama dengan --key)')
    parser.add_argument('--iv-prefix', default=DEFAULT_IV_PREFIX,
                        help='awalan IV tipe 6 (bawaan: %(default)r)')
    parser.add_argument('--offset', type=int,
                        help='offset paksa posisi payload (bawaan: coba 0 lalu 145)')
    parser.add_argument('--extract', action='store_true',
                        help='setelah dekode, cetak info kredensial dari XML')
    parser.add_argument('--extract-only', action='store_true',
                        help='hanya cetak info terekstrak, tanpa menulis file keluaran')
    parser.add_argument('--info', action='store_true',
                        help='hanya tampilkan info kontainer (offset, signature, tipe payload)')
    args = parser.parse_args(argv)

    with open(args.infile, 'rb') as f:
        buf = f.read()

    offsets = [args.offset] if args.offset is not None else list(CANDIDATE_OFFSETS)
    last_error = 'payload tidak ditemukan'
    for offset in offsets:
        parsed = parse_container(buf, offset)
        if parsed is None:
            last_error = 'tidak ada header payload valid di offset %d' % offset
            continue
        _stream, signature, payload_type, _pos = parsed
        sig_str = args.signature if args.signature is not None \
            else signature.decode('utf-8', 'replace')

        if args.info:
            print('offset     : %d' % offset)
            print('signature  : %r' % sig_str)
            print('tipe payload: %d' % payload_type)
            return 0

        data, method = decode_payload(parsed, args, sig_str)
        if data is None:
            last_error = method
            continue

        print('Berhasil didekode dari offset %d' % offset)
        print('signature  : %r' % sig_str)
        print('tipe payload: %d — %s' % (payload_type, method))
        if args.extract_only:
            print_extracted(data)
            return 0
        if not args.outfile:
            print('Kesalahan: argumen outfile wajib diisi', file=sys.stderr)
            return 2
        with open(args.outfile, 'wb') as f:
            f.write(data)
        print('keluaran   : %s (%d byte)' % (args.outfile, len(data)))
        if args.extract:
            print_extracted(data)
        return 0

    print('Gagal: %s' % last_error, file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
