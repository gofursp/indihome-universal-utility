# Indihome Universal Utility

> **Peringatan:** :red_circle: Alat ini dibuat khusus untuk keperluan pendidikan dan penelitian. Penulis tidak bertanggung jawab atas segala bentuk penyalahgunaan atau kerusakan yang mungkin timbul dari penggunaan skrip ini. Harap gunakan dengan bijak dan hanya di lingkungan di mana Anda memiliki izin eksplisit.

Indihome Universal Utility adalah Tool sederhana untuk mengekstrak data konfigurasi pada modem/router indihome seperti mac address, serial number, admin login, user dan password pppoe, acs dll

#
Fitur yang terdapat pada Aplikasi Indihome Universal Utility.exe
- Auto Download Config
- Decoder Utility
- Encoder Utility
- Support windows x64 only

#
<b>Tutorial Penggunaan:</b>
1. Download dan instal python3 (minimum python 3.5):
https://www.python.org/downloads/
2. Instal Pycryptodome dan Pycryptodomex: 

   ```python -m pip install pycryptodome``` 
dan
```python -m pip install pycryptodomex```

    Dokumentasi lengkap Pycryptodome:
https://pypi.org/project/pycryptodome/

4. Download "Indihome Universal Utility" via [https://github.com/MichaelJorky/indihome-universal-utility/releases](https://github.com/MichaelJorky/indihome-universal-utility/releases) lalu download zip kemudian silahkan ekstrak dengan WinRAR, maka akan ada folder baru dengan nama "indihome-universal-utility-x.x.x.x" kemudian silahkan buka foldernya dan jalankan aplikasi Indihome Universal Utility.exe

5. Perhatikan status koneksi dibagian bawah kiri apakah offline atau online dan pastikan type modem/routernya terdeteksi.

6. Pada input data silahkan isi username: user dan password: user/user1234 atau tinggal disesuaikan jika sebelumnya pernah diganti lalu klik "start" (tidak perlu mengisikan mac address dan serial number), lalu klik "stop" untuk membersikan koneksi API.

7. Pindah pada bagian tab "Decoder Utility" lalu klik "Start" jika berhasil maka akan didapatkan login username dan password super admin dan serta username beserta password pppoe-nya.

#

## Perbaikan & Peningkatan (branch `peningkatan-v2`)

Repo ini awalnya hanya berisi pustaka `zcu/` tanpa program utama sama sekali — decoder yang dipakai aplikasi .exe tertanam di dalam binary dan hanya menangani payload tipe 6 (ZTE F670L). Di branch ini ditambahkan CLI mandiri dan sejumlah perbaikan bug:

### Yang diperbaiki di pustaka `zcu/`
- `xcryptors.py`: impor AES sekarang mencoba `Cryptodome` lalu jatuh ke `Crypto`, jadi cukup salah satu dari pycryptodome/pycryptodomex yang terpasang (sebelumnya wajib `Cryptodome` saja dan langsung gagal impor di banyak sistem). Impor `PAYLOAD_MAGIC` juga bekerja baik sebagai paket maupun modul lepas.
- `xcryptors.py` `decrypt()`: ciphertext sekarang dibaca utuh dari buffer. Cara lama bisa memotong ciphertext sehingga dekripsi CBC gagal.
- `zte.py` `read_header`: tidak lagi crash pada stream tanpa nama file (mis. `BytesIO`), dan posisi stream dipulihkan ke titik awal baca, bukan ke offset 0.
- `zte.py` `read_signature`: bila magic tidak cocok, posisi stream mundur tepat 12 byte (sebelumnya lompat ke offset 0 dan merusak pembacaan berikutnya).
- `compression.py`: bug laten — input yang ukurannya kelipatan persis `chunk_size` tidak pernah menandai blok terakhir, sehingga `decompress()` membaca melewati akhir data. Sekarang memakai lookahead satu blok. Input kosong juga valid: menghasilkan satu blok zlib terakhir agar selalu bisa didekompresi kembali.
- `fiberhome.py` dan `huawei.py`: sebelumnya file kosong 0 baris yang seolah-olah modul jadi. Sekarang berisi docstring jujur bahwa format FiberHome/Huawei **belum diimplementasikan**; satu-satunya format yang didukung adalah ZTE.

### CLI baru (Python 3.10+)

Instal dependensi cukup dengan:

```
pip install -r requirements.txt
```

**`zcudecode.py`** — dekode `config.bin` menjadi XML untuk payload tipe 0 (zlib), 2 (AES-128-ECB), 3/4 (AES-256-CBC), dan 6 (ZTE F670L, kunci diturunkan dari serial + MAC). Header 128 byte dan blok signature dideteksi otomatis; file F670L yang perlu dibaca dari offset 145 juga dicoba otomatis.

```
python zcudecode.py config.bin config.xml
python zcudecode.py config.bin config.xml --serial ZTEG12345678 --mac AA:BB:CC:DD:EE:FF
python zcudecode.py config.bin --info            # tampilkan offset, signature, tipe payload saja
python zcudecode.py config.bin config.xml --extract   # sekalian ekstrak kredensial dari XML
```

**`zcuencode.py`** — enkode XML kembali menjadi `config.bin` untuk tipe 0/2/3/4 (tipe 6 tidak didukung untuk enkode karena format tulis per-perangkatnya belum terverifikasi).

```
python zcuencode.py config.xml config.bin --type 2 --key 402c38de39bed665 --signature "ZXHN H267A" --with-header
python zcuencode.py config.xml config.bin --type 4 --signature "ZXHN H268Q"
```

### Tes

```
python -m unittest discover -s tests
```

16 tes (round-trip kompresi termasuk kasus kelipatan persis dan input kosong, round-trip enkripsi tipe 2/3/4, round-trip CLI tipe 2/4/6, dan parsing kontainer) — semuanya lulus.

### Soal "sertifikat kadaluarsa"

Hasil pemeriksaan terhadap `Indihome.Universal.Utility.exe` rilis v1.0.0.4-beta:

- **EXE tersebut tidak memiliki tanda tangan digital Authenticode sama sekali** (tabel sertifikat PE kosong). Jadi tidak ada sertifikat penandatanganan kode yang kadaluarsa di dalamnya — peringatan Windows "unknown publisher"/SmartScreen muncul karena file memang tidak ditandatangani. Perbaikannya bukan "memperbarui sertifikat", melainkan menandatangani hasil build dengan `signtool` dan sertifikat code-signing (untuk pemakaian pribadi boleh sertifikat self-signed). Kode sumber GUI (Delphi) tidak dipublikasikan di repo ini, jadi GUI tidak bisa di-build ulang dari sini.
- **Tidak ada blob sertifikat** (PEM/DER) yang tertanam di binary. Peringatan sertifikat yang biasa terlihat saat membuka web UI router berasal dari sertifikat self-signed bawaan router ZTE itu sendiri — memang begitu desainnya dan tidak ada yang bisa diperbarui dari sisi aplikasi.
- Satu-satunya endpoint publik yang dipanggil aplikasi, `https://myip.indihome.co.id/`, saat diuji (2026-11-08) merespons normal lewat HTTP, tetapi jalur HTTPS-nya tidak stabil dari jaringan pengujian sehingga tanggal berlaku sertifikatnya **belum bisa diverifikasi** — tidak ada dasar untuk menyatakan sertifikatnya kadaluarsa.

### GUI

`zcu_gui.py` adalah antarmuka grafis (Tkinter, bawaan Python — tanpa dependensi tambahan) yang membungkus kedua CLI di atas: pilih file, isi serial/MAC bila perlu, klik **Dekode** (hasil ekstrak kredensial tampil di panel log) atau **Enkode**.

```
python zcu_gui.py
```

Di Windows, klik ganda `Jalankan-GUI.bat` juga bisa. GUI ini sudah diuji end-to-end (enkode contoh lewat CLI, lalu dekode + ekstrak lewat tombol GUI). Untuk menjadikannya satu file .exe mandiri di Windows:

```
pip install pyinstaller
pyinstaller --onefile --windowed --name IndihomeUniversalUtility zcu_gui.py
```

Catatan: hasil PyInstaller tetap memerlukan `zcudecode.py`, `zcuencode.py`, dan paket `zcu/` berada satu folder dengan .exe-nya, karena GUI memanggil CLI tersebut sebagai proses terpisah.
