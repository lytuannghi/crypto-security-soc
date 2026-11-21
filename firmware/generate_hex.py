#!/usr/bin/env python3
"""
Generate boot_rom.hex for Crypto-Security Enclave SoC.
Assembles raw RV32I instructions executing cryptographic self-tests.
"""

def encode_lui(rd, imm20):
    return ((imm20 & 0xFFFFF) << 12) | (rd << 7) | 0x37

def encode_addi(rd, rs1, imm12):
    return ((imm12 & 0xFFF) << 20) | (rs1 << 15) | (0x0 << 12) | (rd << 7) | 0x13

def encode_sw(rs2, rs1, imm12):
    imm_11_5 = (imm12 >> 5) & 0x7F
    imm_4_0 = imm12 & 0x1F
    return (imm_11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (0x2 << 12) | (imm_4_0 << 7) | 0x23

def encode_lw(rd, rs1, imm12):
    return ((imm12 & 0xFFF) << 20) | (rs1 << 15) | (0x2 << 12) | (rd << 7) | 0x03

def encode_jal(rd, imm21):
    imm20 = (imm21 >> 20) & 0x1
    imm10_1 = (imm21 >> 1) & 0x3FF
    imm11 = (imm21 >> 11) & 0x1
    imm19_12 = (imm21 >> 12) & 0xFF
    return (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12) | (rd << 7) | 0x6F

# Registers: x0=0, x1=ra, x2=sp, x5=t0, x6=t1, x7=t2, x8=s0, x9=s1
instructions = [
    # 0x00: lui sp, 0x10004 -> sp = 0x10004000
    encode_lui(2, 0x10004),
    # 0x04: addi sp, sp, -16 -> sp = 0x10003FF0
    encode_addi(2, 2, -16),

    # --- Test 1: UART Initial Output ---
    # lui t0, 0x60000 -> t0 = 0x60000000 (UART)
    encode_lui(5, 0x60000),
    # addi t1, x0, 0x53 ('S')
    encode_addi(6, 0, 0x53),
    encode_sw(6, 5, 0),
    # addi t1, x0, 0x45 ('E')
    encode_addi(6, 0, 0x45),
    encode_sw(6, 5, 0),
    # addi t1, x0, 0x43 ('C')
    encode_addi(6, 0, 0x43),
    encode_sw(6, 5, 0),

    # --- Test 2: Secure SRAM Integrity ---
    # lui t0, 0x10000 -> t0 = 0x10000000 (SRAM)
    encode_lui(5, 0x10000),
    # addi t1, x0, 0x77
    encode_addi(6, 0, 0x77),
    encode_sw(6, 5, 8), # sram[2] = 0x77
    encode_lw(7, 5, 8), # t2 = sram[2]

    # --- Test 3: TRNG Entropy Read ---
    # lui t0, 0x40000 -> t0 = 0x40000000 (TRNG)
    encode_lui(5, 0x40000),
    encode_lw(8, 5, 0), # s0 = TRNG_DATA

    # --- Test 4: AES-256 Engine Configuration ---
    # lui t0, 0x20000 -> t0 = 0x20000000 (AES)
    encode_lui(5, 0x20000),
    # Plaintext word 0: 0x3243f6a8 -> (0x3243F << 12) + 0x6A8
    encode_lui(6, 0x3243F),
    encode_addi(6, 6, 0x6A8),
    encode_sw(6, 5, 0x10), # AES_DIN(0)
    # Cipher Key word 0: 0x01010101
    encode_lui(6, 0x01010),
    encode_addi(6, 6, 0x101),
    encode_sw(6, 5, 0x20), # AES_KEY(0)
    # Start AES-256: write 0x05 to AES_CTRL (0x20000000)
    encode_addi(6, 0, 0x05),
    encode_sw(6, 5, 0x00),

    # --- Test 5: SHA-256 Accelerator Configuration ---
    # lui t0, 0x30000 -> t0 = 0x30000000 (SHA)
    encode_lui(5, 0x30000),
    # Message word 0: 0x61626380 ("abc" + padding)
    encode_lui(6, 0x61626),
    encode_addi(6, 6, 0x380),
    encode_sw(6, 5, 0x10), # SHA_MSG(0)
    # Start SHA-256: write 0x01 to SHA_CTRL (0x30000000)
    encode_addi(6, 0, 0x01),
    encode_sw(6, 5, 0x00),

    # --- Test 6: Anti-Tamper Status Read ---
    # lui t0, 0x50000 -> t0 = 0x50000000 (Tamper)
    encode_lui(5, 0x50000),
    encode_lw(9, 5, 0), # s1 = TAMPER_STATUS

    # Infinite Loop
    encode_jal(0, 0)
]

hex_lines = [f"{instr:08x}" for instr in instructions]
while len(hex_lines) < 2048:
    hex_lines.append("00000013")

with open("boot_rom.hex", "w") as f:
    f.write("\n".join(hex_lines) + "\n")

print(f"Generated boot_rom.hex with {len(instructions)} active instructions.")
