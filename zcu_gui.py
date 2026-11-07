#!/usr/bin/env python3
"""GUI sederhana Indihome Universal Utility (Tkinter, tanpa dependensi tambahan).

Membungkus zcudecode.py dan zcuencode.py:
- Dekode config.bin -> config.xml untuk payload tipe 0/2/3/4/6,
  dengan opsi ekstrak kredensial dari XML hasil dekode.
- Enkode config.xml -> config.bin untuk payload tipe 0/2/3/4.

Jalankan:  python zcu_gui.py   (atau klik ganda Jalankan-GUI.bat di Windows)
"""
import queue
import subprocess
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

BASE = Path(__file__).resolve().parent


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Indihome Universal Utility — Dekode/Enkode Config ZTE")
        self.minsize(680, 560)

        main = ttk.Frame(self, padding=10)
        main.pack(fill="both", expand=True)
        main.columnconfigure(1, weight=1)

        # ---------- Dekode ----------
        dec = ttk.LabelFrame(main, text="Dekode: config.bin -> config.xml", padding=8)
        dec.grid(row=0, column=0, columnspan=3, sticky="ew")
        dec.columnconfigure(1, weight=1)

        self.dec_in = tk.StringVar()
        self.dec_out = tk.StringVar()
        self.dec_serial = tk.StringVar()
        self.dec_mac = tk.StringVar()
        self.dec_key = tk.StringVar()
        self.dec_extract = tk.BooleanVar(value=True)

        self._file_row(dec, 0, "File config.bin", self.dec_in,
                       [("Config ZTE", "*.bin"), ("Semua file", "*.*")], save=False)
        self._file_row(dec, 1, "File XML hasil", self.dec_out,
                       [("XML", "*.xml"), ("Semua file", "*.*")], save=True)
        self._entry_row(dec, 2, "Serial router (tipe 6)", self.dec_serial)
        self._entry_row(dec, 3, "MAC router (tipe 6)", self.dec_mac)
        self._entry_row(dec, 4, "Kunci manual (opsional)", self.dec_key)
        ttk.Checkbutton(dec, text="Ekstrak kredensial dari hasil dekode",
                        variable=self.dec_extract).grid(
                            row=5, column=1, sticky="w", pady=2)
        ttk.Button(dec, text="Dekode", command=self.run_decode).grid(
            row=6, column=1, sticky="w", pady=4)

        # ---------- Enkode ----------
        enc = ttk.LabelFrame(main, text="Enkode: config.xml -> config.bin", padding=8)
        enc.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        enc.columnconfigure(1, weight=1)

        self.enc_in = tk.StringVar()
        self.enc_out = tk.StringVar()
        self.enc_type = tk.StringVar(value="0")
        self.enc_signature = tk.StringVar()
        self.enc_key = tk.StringVar()
        self.enc_iv = tk.StringVar()
        self.enc_header = tk.BooleanVar(value=False)

        self._file_row(enc, 0, "File config.xml", self.enc_in,
                       [("XML", "*.xml"), ("Semua file", "*.*")], save=False)
        self._file_row(enc, 1, "File config.bin hasil", self.enc_out,
                       [("Config ZTE", "*.bin"), ("Semua file", "*.*")], save=True)
        ttk.Label(enc, text="Tipe payload").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Combobox(enc, textvariable=self.enc_type, state="readonly", width=8,
                     values=["0", "2", "3", "4"]).grid(row=2, column=1, sticky="w")
        self._entry_row(enc, 3, "Signature (keygen)", self.enc_signature)
        self._entry_row(enc, 4, "Kunci (tipe 2/3/4)", self.enc_key)
        self._entry_row(enc, 5, "IV (tipe 4)", self.enc_iv)
        ttk.Checkbutton(enc, text="Sertakan header 128 byte + signature",
                        variable=self.enc_header).grid(
                            row=6, column=1, sticky="w", pady=2)
        ttk.Button(enc, text="Enkode", command=self.run_encode).grid(
            row=7, column=1, sticky="w", pady=4)

        # ---------- Log ----------
        ttk.Label(main, text="Log / hasil ekstrak:").grid(
            row=2, column=0, columnspan=3, sticky="w", pady=(10, 2))
        self.log = scrolledtext.ScrolledText(main, height=12, wrap="word")
        self.log.grid(row=3, column=0, columnspan=3, sticky="nsew")
        main.rowconfigure(3, weight=1)

        self.status = tk.StringVar(value="Siap.")
        ttk.Label(main, textvariable=self.status).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # hasil kerja thread latar dikirim lewat antrean ini dan diterapkan
        # oleh thread utama (memanggil Tk dari thread lain tidak aman)
        self.results = queue.Queue()
        self.after(100, self._poll_results)

    def _poll_results(self):
        try:
            while True:
                out, ok, done_msg = self.results.get_nowait()
                self.write_log(out if out.endswith("\n") else out + "\n")
                self.status.set(done_msg if ok else "Gagal — lihat log.")
                if ok:
                    messagebox.showinfo("Selesai", done_msg)
        except queue.Empty:
            pass
        self.after(100, self._poll_results)

    # ---------- pembantu tampilan ----------
    def _file_row(self, parent, row, label, var, types, save):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(parent, textvariable=var).grid(
            row=row, column=1, sticky="ew", padx=4)

        def pick():
            if save:
                path = filedialog.asksaveasfilename(filetypes=types)
            else:
                path = filedialog.askopenfilename(filetypes=types)
            if path:
                var.set(path)

        ttk.Button(parent, text="Telusuri...", command=pick).grid(
            row=row, column=2, sticky="e")

    def _entry_row(self, parent, row, label, var):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=2)
        ttk.Entry(parent, textvariable=var).grid(
            row=row, column=1, columnspan=2, sticky="ew", padx=4)

    def write_log(self, text):
        self.log.insert("end", text)
        self.log.see("end")

    # ---------- eksekusi CLI ----------
    def run_cli(self, argv, done_msg):
        self.status.set("Memproses...")

        def work():
            try:
                proc = subprocess.run(
                    [sys.executable, *argv], cwd=str(BASE),
                    capture_output=True, text=True, timeout=300)
                out = (proc.stdout or "") + (proc.stderr or "")
                ok = proc.returncode == 0
            except Exception as e:  # mis. file tidak ditemukan
                out, ok = f"Gagal menjalankan proses: {e}\n", False
            self.results.put((out, ok, done_msg))

        threading.Thread(target=work, daemon=True).start()

    def run_decode(self):
        src, dst = self.dec_in.get().strip(), self.dec_out.get().strip()
        if not src or not dst:
            messagebox.showwarning("Belum lengkap",
                                   "Pilih file config.bin dan file XML hasil dulu.")
            return
        argv = [str(BASE / "zcudecode.py"), src, dst]
        if self.dec_serial.get().strip():
            argv += ["--serial", self.dec_serial.get().strip()]
        if self.dec_mac.get().strip():
            argv += ["--mac", self.dec_mac.get().strip()]
        if self.dec_key.get().strip():
            argv += ["--key", self.dec_key.get().strip()]
        if self.dec_extract.get():
            argv += ["--extract"]
        self.write_log(f"\n> {' '.join(argv[1:])}\n")
        self.run_cli(argv, f"Dekode selesai: {dst}")

    def run_encode(self):
        src, dst = self.enc_in.get().strip(), self.enc_out.get().strip()
        if not src or not dst:
            messagebox.showwarning("Belum lengkap",
                                   "Pilih file config.xml dan file config.bin hasil dulu.")
            return
        argv = [str(BASE / "zcuencode.py"), src, dst,
                "--type", self.enc_type.get()]
        if self.enc_signature.get().strip():
            argv += ["--signature", self.enc_signature.get().strip()]
        if self.enc_key.get().strip():
            argv += ["--key", self.enc_key.get().strip()]
        if self.enc_iv.get().strip():
            argv += ["--iv", self.enc_iv.get().strip()]
        if self.enc_header.get():
            argv += ["--with-header"]
        self.write_log(f"\n> {' '.join(argv[1:])}\n")
        self.run_cli(argv, f"Enkode selesai: {dst}")


if __name__ == "__main__":
    App().mainloop()
