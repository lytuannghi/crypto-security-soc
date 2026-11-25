#!/usr/bin/env python3
"""
Generate boot_rom.hex for Crypto-Security Enclave SoC.
Exercises UART baud=2 ("SEC"), Secure SRAM, Physical TRNG, Full NIST FIPS-197
AES-128 KAT encryption, Full FIPS 180-4 SHA-256("abc") compression, and Anti-Tamper.
"""

import os


def encode_lui(rd, imm20):
    return ((imm20 & 0xFFFFF) << 12) | (rd << 7) | 0x37


def encode_addi(rd, rs1, imm12):
    return ((imm12 & 0xFFF) << 20) | (rs1 << 15) | (0x0 << 12) | (rd << 7) | 0x13


def encode_andi(rd, rs1, imm12):
    return ((imm12 & 0xFFF) << 20) | (rs1 << 15) | (0x7 << 12) | (rd << 7) | 0x13


def encode_sw(rs2, rs1, imm12):
    return (((imm12 >> 5) & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | (0x2 << 12) | ((imm12 & 0x1F) << 7) | 0x23


def encode_lw(rd, rs1, imm12):
    return ((imm12 & 0xFFF) << 20) | (rs1 << 15) | (0x2 << 12) | (rd << 7) | 0x03


def encode_b(funct3, rs1, rs2, offset_bytes):
    imm = offset_bytes & 0x1FFF
    return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3F) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (((imm >> 1) & 0xF) << 8) | (((imm >> 11) & 1) << 7) | 0x63


def encode_jal(rd, imm21):
    return (((imm21 >> 20) & 1) << 31) | (((imm21 >> 1) & 0x3FF) << 21) | (((imm21 >> 11) & 1) << 20) | (((imm21 >> 12) & 0xFF) << 12) | (rd << 7) | 0x6F


def emit_li(instrs, rd, val32):
    val32 &= 0xFFFFFFFF
    lo = val32 & 0xFFF
    hi = (val32 >> 12) & 0xFFFFF
    if lo >= 0x800:
        hi = (hi + 1) & 0xFFFFF
        lo = lo - 0x1000
    instrs.append(encode_lui(rd, hi))
    if lo != 0:
        instrs.append(encode_addi(rd, rd, lo))


def emit_uart_putc(instrs, uart_reg, ch):
    poll = len(instrs)
    instrs.append(encode_lw(7, uart_reg, 4))
    instrs.append(encode_andi(7, 7, 1))
    instrs.append(encode_b(0x1, 7, 0, (poll - len(instrs)) * 4))
    instrs.append(encode_addi(6, 0, ord(ch)))
    instrs.append(encode_sw(6, uart_reg, 0))


instructions = []
instructions.append(encode_lui(2, 0x10004))
instructions.append(encode_addi(2, 2, -16))

# UART (0x60000000): baud_div=2 (30 ns/bit), send "SEC"
instructions.append(encode_lui(5, 0x60000))
instructions.append(encode_addi(6, 0, 2))
instructions.append(encode_sw(6, 5, 8))
for ch in "SEC":
    emit_uart_putc(instructions, 5, ch)

# Secure SRAM Integrity (0x10000000)
instructions.append(encode_lui(5, 0x10000))
instructions.append(encode_addi(6, 0, 0x77))
instructions.append(encode_sw(6, 5, 8))    # sram.mem[2] = 0x77

# Physical TRNG Read (0x40000000)
instructions.append(encode_lui(5, 0x40000))
instructions.append(encode_lw(8, 5, 0))

# Full NIST FIPS-197 AES-128 KAT (0x20000000)
# PT  = 00112233 44556677 8899aabb ccddeeff (byte0=0x00 at [7:0] -> words 33221100, 77665544, bbaa9988, ffeeddcc)
# KEY = 00010203 04050607 08090a0b 0c0d0e0f (-> words 03020100, 07060504, 0b0a0908, 0f0e0d0c)
instructions.append(encode_lui(5, 0x20000))
for i, w in enumerate((0x33221100, 0x77665544, 0xBBAA9988, 0xFFEEDDCC)):
    emit_li(instructions, 6, w)
    instructions.append(encode_sw(6, 5, 0x10 + i * 4))
for i, w in enumerate((0x03020100, 0x07060504, 0x0B0A0908, 0x0F0E0D0C)):
    emit_li(instructions, 6, w)
    instructions.append(encode_sw(6, 5, 0x20 + i * 4))
instructions.append(encode_addi(6, 0, 0x01))        # start=1, AES-128 (key_256_sel=0)
instructions.append(encode_sw(6, 5, 0x00))

# Full NIST FIPS 180-4 SHA-256("abc") (0x30000000)
# msg[0] = 0x61626380 ("abc" + 0x80), msg[1..14]=0, msg[15] = 0x00000018 (24 bits)
instructions.append(encode_lui(5, 0x30000))
emit_li(instructions, 6, 0x61626380)
instructions.append(encode_sw(6, 5, 0x10))
instructions.append(encode_addi(6, 0, 0x18))
instructions.append(encode_sw(6, 5, 0x4C))
instructions.append(encode_addi(6, 0, 0x01))        # init_hash=1
instructions.append(encode_sw(6, 5, 0x00))

# Anti-Tamper Status Read (0x50000000)
instructions.append(encode_lui(5, 0x50000))
instructions.append(encode_lw(9, 5, 0))

instructions.append(encode_jal(0, 0))

hex_lines = [f"{instr:08x}" for instr in instructions]
while len(hex_lines) < 2048:
    hex_lines.append("00000013")

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
out_hex = os.path.join(repo_root, "boot_rom.hex")
with open(out_hex, "w", encoding="utf-8") as f:
    f.write("\n".join(hex_lines) + "\n")

print(f"Generated {out_hex} with {len(instructions)} active instructions.")
