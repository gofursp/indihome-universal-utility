"""Tes untuk pustaka zcu serta CLI zcudecode/zcuencode.

Jalankan dari root repo:  python3 -m unittest discover -s tests -v
Semua data bersifat sintetis; tidak ada file config router asli yang dipakai.
"""

import struct
import subprocess
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from zcu import compression, known_keys, zte  # noqa: E402
from zcu.xcryptors import CBCXcryptor, Xcryptor  # noqa: E402
import zcudecode  # noqa: E402

SAMPLE_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<DB><Tbl name="InternetGatewayDevice">'
    b'<DM name="SerialNumber" val="ZTEG12345678"/>'
    b'<DM name="Username" val="admin"/>'
    b'<DM name="Password" val="Telkomdso123"/>'
    b'<DM name="PPPoEUsername" val="1234567890@telkom.net"/>'
    b'<DM name="PPPoEPassword" val="rahasia"/>'
    b'</Tbl></DB>\n'
)


def decompress_payload(payload_stream):
    """payload_stream berada di awal header payload; kembalikan isi XML."""
    ptype = zte.read_payload_type(payload_stream)
    data, _crc = compression.decompress(payload_stream)
    return ptype, data.read()


class TestKnownKeys(unittest.TestCase):
    def test_find_key_by_signature_prefix(self):
        self.assertEqual(known_keys.find_key('ZXHN H118N V2'), 'MIK@0STzKpB%qJZf')
        self.assertEqual(known_keys.find_key('zxhn h267a'), '402c38de39bed665')
        self.assertIsNone(known_keys.find_key('model tidak dikenal'))

    def test_mac_to_str(self):
        self.assertEqual(known_keys.mac_to_str(bytes.fromhex('aabbccddeeff')),
                         'aa:bb:cc:dd:ee:ff')
        self.assertEqual(known_keys.mac_to_str('AA:BB:CC:DD:EE:FF'),
                         'aa:bb:cc:dd:ee:ff')
        self.assertEqual(known_keys.mac_to_str(''), '')


class TestCompression(unittest.TestCase):
    def roundtrip(self, data, chunk_size):
        payload = compression.compress(BytesIO(data), chunk_size)
        ptype, out = decompress_payload(payload)
        self.assertEqual(ptype, 0)
        self.assertEqual(out, data)

    def test_small(self):
        self.roundtrip(b'halo zte' * 10, 65536)

    def test_exact_multiple_of_chunk_size(self):
        # regresi: dulu tidak ada chunk yang ditandai terakhir untuk ukuran ini
        self.roundtrip(b'A' * 131072, 65536)

    def test_small_chunk_size(self):
        self.roundtrip(bytes(range(256)) * 40, 1024)

    def test_empty(self):
        payload = compression.compress(BytesIO(b''), 1024)
        _ptype, out = decompress_payload(payload)
        self.assertEqual(out, b'')


class TestZteContainer(unittest.TestCase):
    def test_header_signature_roundtrip_real_file(self):
        payload = compression.compress(BytesIO(SAMPLE_XML), 65536)
        full = zte.add_header(payload, b'ZXHN H267A', 1, include_header=True)
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(full.read())
            path = f.name
        with open(path, 'rb') as f:
            self.assertEqual(zte.read_header(f), 128)
            self.assertEqual(zte.read_signature(f), b'ZXHN H267A')
            _ptype, out = decompress_payload(f)
            self.assertEqual(out, SAMPLE_XML)

    def test_read_header_bytesio(self):
        # regresi: dulu stat(infile.name) membuat BytesIO crash
        payload = compression.compress(BytesIO(SAMPLE_XML), 65536)
        full = zte.add_header(payload, b'', 0, include_header=True)
        stream = BytesIO(full.read())
        self.assertEqual(zte.read_header(stream), 128)

    def test_read_signature_without_signature_keeps_position(self):
        # regresi: dulu seek(0) mutlak merusak posisi setelah header
        payload = compression.compress(BytesIO(SAMPLE_XML), 65536)
        full = zte.add_header(payload, b'', 0, include_header=True)
        stream = BytesIO(full.read())
        self.assertEqual(zte.read_header(stream), 128)
        self.assertEqual(zte.read_signature(stream), b'')
        self.assertEqual(stream.tell(), 128)


class TestCryptorRoundtrips(unittest.TestCase):
    def test_type2_ecb(self):
        payload = compression.compress(BytesIO(SAMPLE_XML), 65536)
        encrypted = Xcryptor('402c38de39bed665').encrypt(payload)
        raw = encrypted.getvalue()
        self.assertEqual(struct.unpack('>I', raw[4:8])[0], 2)
        stream = BytesIO(raw)
        self.assertEqual(zte.read_payload_type(stream), 2)
        decrypted = Xcryptor('402c38de39bed665').decrypt(stream)
        _ptype, out = decompress_payload(decrypted)
        self.assertEqual(out, SAMPLE_XML)

    def test_type3_cbc_iv_sama_dengan_key(self):
        payload = compression.compress(BytesIO(SAMPLE_XML), 65536)
        xc = CBCXcryptor()
        xc.set_key('kunci-rahasia')
        encrypted = xc.encrypt(payload)
        raw = encrypted.getvalue()
        self.assertEqual(struct.unpack('>I', raw[4:8])[0], 3)
        stream = BytesIO(raw)
        self.assertEqual(zte.read_payload_type(stream), 3)
        xc2 = CBCXcryptor()
        xc2.set_key('kunci-rahasia')
        _ptype, out = decompress_payload(xc2.decrypt(stream))
        self.assertEqual(out, SAMPLE_XML)

    def test_type4_cbc_iv_berbeda(self):
        payload = compression.compress(BytesIO(SAMPLE_XML), 65536)
        xc = CBCXcryptor()
        xc.set_key('kunci-rahasia', 'iv-berbeda')
        encrypted = xc.encrypt(payload)
        raw = encrypted.getvalue()
        self.assertEqual(struct.unpack('>I', raw[4:8])[0], 4)
        stream = BytesIO(raw)
        self.assertEqual(zte.read_payload_type(stream), 4)
        xc2 = CBCXcryptor()
        xc2.set_key('kunci-rahasia', 'iv-berbeda')
        _ptype, out = decompress_payload(xc2.decrypt(stream))
        self.assertEqual(out, SAMPLE_XML)


class TestCliRoundtrips(unittest.TestCase):
    def run_cli(self, *argv):
        return subprocess.run(
            [sys.executable, *argv], cwd=REPO_ROOT,
            capture_output=True, text=True, timeout=60)

    def test_encode_decode_type2_with_header(self):
        with tempfile.TemporaryDirectory() as d:
            xml_in = Path(d) / 'config.xml'
            bin_file = Path(d) / 'config.bin'
            xml_out = Path(d) / 'out.xml'
            xml_in.write_bytes(SAMPLE_XML)
            enc = self.run_cli('zcuencode.py', str(xml_in), str(bin_file),
                               '--type', '2', '--key', '402c38de39bed665',
                               '--signature', 'ZXHN H267A', '--with-header')
            self.assertEqual(enc.returncode, 0, enc.stderr)
            dec = self.run_cli('zcudecode.py', str(bin_file), str(xml_out))
            self.assertEqual(dec.returncode, 0, dec.stderr)
            self.assertEqual(xml_out.read_bytes(), SAMPLE_XML)

    def test_encode_decode_type4_via_keygen_signature(self):
        with tempfile.TemporaryDirectory() as d:
            xml_in = Path(d) / 'config.xml'
            bin_file = Path(d) / 'config.bin'
            xml_out = Path(d) / 'out.xml'
            xml_in.write_bytes(SAMPLE_XML)
            enc = self.run_cli('zcuencode.py', str(xml_in), str(bin_file),
                               '--type', '4', '--signature', 'ZXHN H268Q',
                               '--with-header')
            self.assertEqual(enc.returncode, 0, enc.stderr)
            dec = self.run_cli('zcudecode.py', str(bin_file), str(xml_out))
            self.assertEqual(dec.returncode, 0, dec.stderr)
            self.assertEqual(xml_out.read_bytes(), SAMPLE_XML)

    def test_decode_type6_f670l_at_offset_145(self):
        serial, mac = 'ZTEG12345678', 'AA:BB:CC:DD:EE:FF'
        key = zcudecode.derive_f670l_key(serial, mac)
        self.assertEqual(key, '12345678' + 'ffeeddccbbaa')
        payload = compression.compress(BytesIO(SAMPLE_XML), 65536)
        xc = CBCXcryptor()
        xc.set_key(key, zcudecode.DEFAULT_IV_PREFIX)
        encrypted = bytearray(xc.encrypt(payload).getvalue())
        # paksa field tipe payload menjadi 6 seperti file F670L asli
        struct.pack_into('>I', encrypted, 4, 6)
        full = zte.add_header(BytesIO(bytes(encrypted)), b'ZXHN F670L', 0,
                              include_header=True)
        blob = b'\x00' * 145 + full.read()
        with tempfile.TemporaryDirectory() as d:
            bin_file = Path(d) / 'config.bin'
            xml_out = Path(d) / 'out.xml'
            bin_file.write_bytes(blob)
            dec = self.run_cli('zcudecode.py', str(bin_file), str(xml_out),
                               '--serial', serial, '--mac', mac)
            self.assertEqual(dec.returncode, 0, dec.stderr)
            self.assertEqual(xml_out.read_bytes(), SAMPLE_XML)

    def test_extract_info(self):
        results = zcudecode.extract_info(SAMPLE_XML.decode())
        pairs = {(name, val) for _tbl, name, val in results}
        self.assertIn(('Username', 'admin'), pairs)
        self.assertIn(('PPPoEPassword', 'rahasia'), pairs)


if __name__ == '__main__':
    unittest.main()
