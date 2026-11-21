#!/usr/bin/env python3
"""
Physical Layout Generator for Crypto-Security Enclave SoC.
Generates binary GDSII layout viewable in KLayout without external dependencies.
Features physical anti-tamper shield mesh and multi-macro floorplan.
"""

import struct
import os
import time

class GDSWriter:
    def __init__(self, filename, libname="CRYPTO_SOC_LIB"):
        self.f = open(filename, "wb")
        self.libname = libname
        self._write_header()

    def _write_record(self, rec_type, data_type, data=b""):
        rec_len = len(data) + 4
        self.f.write(struct.pack(">HH", rec_len, (rec_type << 8) | data_type))
        if data:
            self.f.write(data)

    def _write_header(self):
        self._write_record(0x00, 0x02, struct.pack(">H", 600))
        t = time.localtime()
        time_data = struct.pack(">12H", t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
                                       t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        self._write_record(0x01, 0x02, time_data)
        libname_bytes = self.libname.encode("ascii")
        if len(libname_bytes) % 2 != 0:
            libname_bytes += b"\0"
        self._write_record(0x02, 0x06, libname_bytes)
        self._write_record(0x03, 0x05, struct.pack(">dd", 0.001, 1e-9))

    def bgn_str(self, strname):
        t = time.localtime()
        time_data = struct.pack(">12H", t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
                                       t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        self._write_record(0x05, 0x02, time_data)
        str_bytes = strname.encode("ascii")
        if len(str_bytes) % 2 != 0:
            str_bytes += b"\0"
        self._write_record(0x06, 0x06, str_bytes)

    def end_str(self):
        self._write_record(0x07, 0x00)

    def add_box(self, layer, datatype, x1, y1, x2, y2):
        self._write_record(0x08, 0x00)
        self._write_record(0x0D, 0x02, struct.pack(">H", layer))
        self._write_record(0x0E, 0x02, struct.pack(">H", datatype))
        pts = [
            (int(x1 * 1000), int(y1 * 1000)),
            (int(x2 * 1000), int(y1 * 1000)),
            (int(x2 * 1000), int(y2 * 1000)),
            (int(x1 * 1000), int(y2 * 1000)),
            (int(x1 * 1000), int(y1 * 1000))
        ]
        xy_data = b"".join(struct.pack(">ii", p[0], p[1]) for p in pts)
        self._write_record(0x10, 0x03, xy_data)
        self._write_record(0x11, 0x00)

    def close(self):
        self._write_record(0x04, 0x00)
        self.f.close()


def generate_crypto_soc_layout():
    out_dir = "layout/gds"
    os.makedirs(out_dir, exist_ok=True)
    gds_path = os.path.join(out_dir, "crypto_soc_top.gds")

    gds = GDSWriter(gds_path, libname="CRYPTO_SOC_TOP")
    gds.bgn_str("crypto_soc_top")

    # Layer Conventions:
    # Layer 100: PR Boundary (1400um x 1400um)
    # Layer 108: I/O Pads (70um x 80um)
    # Layer 21: Metal 1 (Standard Cells)
    # Layer 31: Metal 2 (Power Stripes Vertical)
    # Layer 41: Metal 3 (Power Stripes Horizontal)
    # Layer 51: Metal 4 (Power Ring & Clock Trunk)
    # Layer 61: Metal 5 (Active Anti-Tamper Shield Mesh)

    # 1. Die Boundary
    gds.add_box(100, 0, 0, 0, 1400, 1400)

    # 2. I/O Pad Ring (64 wirebond pads)
    pad_w = 60
    pad_h = 80
    for i in range(16):
        x = 110 + i * 75
        gds.add_box(108, 0, x, 10, x + pad_w, 10 + pad_h)       # Bottom
        gds.add_box(108, 0, x, 1310, x + pad_w, 1310 + pad_h)  # Top
    for i in range(16):
        y = 110 + i * 75
        gds.add_box(108, 0, 10, y, 10 + pad_h, y + pad_w)       # Left
        gds.add_box(108, 0, 1310, y, 1310 + pad_h, y + pad_w)  # Right

    # 3. Dual Power Ring (Metal 4 / Metal 3)
    gds.add_box(51, 0, 120, 120, 1280, 138)
    gds.add_box(51, 0, 120, 1262, 1280, 1280)
    gds.add_box(51, 0, 120, 120, 138, 1280)
    gds.add_box(51, 0, 1262, 120, 1280, 1280)

    # 4. Functional IP Macros Floorplan:
    # Macro A: Secure RV32I Processor Core + PMP (350um x 380um)
    gds.add_box(100, 1, 160, 160, 510, 540)
    gds.add_box(21, 0, 170, 170, 320, 340) # ALU & Control
    gds.add_box(21, 0, 330, 170, 500, 340) # Register File
    gds.add_box(21, 0, 170, 350, 500, 530) # PMP Boundary Protection

    # Macro B: AES-128/256 Cryptographic Engine (400um x 400um)
    gds.add_box(100, 2, 540, 160, 980, 580)
    gds.add_box(21, 0, 550, 170, 750, 360) # 16x S-Box Array
    gds.add_box(21, 0, 760, 170, 970, 360) # MixColumns & ShiftRows
    gds.add_box(21, 0, 550, 370, 970, 570) # Key Expansion & State FSM

    # Macro C: SHA-256 Hash Accelerator (380um x 350um)
    gds.add_box(100, 3, 160, 570, 540, 920)
    gds.add_box(21, 0, 170, 580, 340, 740) # Message Scheduler W[0..15]
    gds.add_box(21, 0, 350, 580, 530, 740) # 64-Round Compressor
    gds.add_box(21, 0, 170, 750, 530, 910) # Constants ROM & Hash Regs

    # Macro D: True Random Number Generator (TRNG) & Tamper Sensor
    gds.add_box(100, 4, 570, 610, 850, 880)
    gds.add_box(21, 0, 580, 620, 700, 740) # Ring Oscillators (4 chains)
    gds.add_box(21, 0, 710, 620, 840, 740) # Von Neumann Extractor
    gds.add_box(21, 0, 580, 750, 840, 870) # Anti-Tamper Detection Logic

    # Macro E: On-Chip Memories (Boot ROM & Zeroizable SRAM)
    gds.add_box(100, 5, 880, 610, 1240, 950)
    gds.add_box(21, 0, 890, 620, 1230, 770) # 8KB Secure Boot ROM
    gds.add_box(21, 0, 890, 780, 1230, 940) # 16KB Secure Zeroizable SRAM

    # Macro F: System Crossbar & UART / Timer
    gds.add_box(100, 6, 160, 950, 600, 1240)
    gds.add_box(21, 0, 170, 960, 370, 1230) # Crossbar Interconnect
    gds.add_box(21, 0, 380, 960, 590, 1230) # UART & Security Timer

    # 5. Core Standard Cell Rows
    for row in range(52):
        y = 160 + row * 20
        gds.add_box(21, 1, 160, y, 1240, y + 8)

    # 6. Power Grid (Metal 3 & Metal 2 stripes)
    for sx in range(14):
        x = 180 + sx * 75
        gds.add_box(31, 0, x, 150, x + 6, 1250)
    for sy in range(14):
        y = 180 + sy * 75
        gds.add_box(41, 0, 150, y, 1250, y + 6)

    # 7. Active Anti-Tamper Shield Mesh (Metal 5 Serpentine Grid over Core)
    for m in range(25):
        xm = 170 + m * 42
        gds.add_box(61, 0, xm, 160, xm + 3, 1240) # Vertical shield wires
    for n in range(25):
        ym = 170 + n * 42
        gds.add_box(61, 0, 160, ym, 1240, ym + 3) # Horizontal shield wires

    # 8. Clock Distribution H-Tree (Metal 4)
    gds.add_box(51, 1, 690, 160, 710, 1240)
    gds.add_box(51, 1, 160, 690, 1240, 710)

    gds.end_str()
    gds.close()

    print(f"[OK] Generated GDSII: {gds_path} ({os.path.getsize(gds_path)} bytes)")

if __name__ == "__main__":
    generate_crypto_soc_layout()
