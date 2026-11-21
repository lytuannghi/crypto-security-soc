#!/usr/bin/env python3
"""
Automated Simulation Script for Crypto-Security Enclave SoC.
Compiles RTL and Testbench using Icarus Verilog and executes with vvp.
"""

import subprocess
import sys
import os

def run():
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(repo_dir)

    rtl_files = [
        "rtl/cpu/riscv_alu.v",
        "rtl/cpu/riscv_regfile.v",
        "rtl/cpu/riscv_pmp.v",
        "rtl/cpu/secure_riscv_core.v",
        "rtl/crypto/aes_sbox.v",
        "rtl/crypto/aes_core.v",
        "rtl/crypto/sha256_k_constants.v",
        "rtl/crypto/sha256_core.v",
        "rtl/crypto/trng_ring_osc.v",
        "rtl/tamper/tamper_sensor.v",
        "rtl/bus/crypto_crossbar.v",
        "rtl/mem/secure_boot_rom.v",
        "rtl/mem/secure_sram.v",
        "rtl/peripherals/uart_controller.v",
        "rtl/peripherals/crypto_timer.v",
        "rtl/padframe/secure_padring.v",
        "rtl/crypto_soc_top.v",
        "tb/tb_crypto_soc.v"
    ]

    include_dirs = [
        "-Irtl/cpu",
        "-Irtl/bus",
        "-Irtl/crypto",
        "-Irtl/tamper",
        "-Irtl/mem",
        "-Irtl/peripherals",
        "-Irtl/padframe",
        "-Irtl"
    ]

    sim_bin = "sim/crypto_soc_sim.vvp"
    os.makedirs("sim", exist_ok=True)

    cmd_compile = ["iverilog", "-g2005-sv"] + include_dirs + ["-o", sim_bin] + rtl_files
    print("[RUN] Compiling Verilog RTL with iverilog...")
    res = subprocess.run(cmd_compile, capture_output=True, text=True)
    if res.returncode != 0:
        print("[ERROR] Compilation failed:")
        print(res.stderr)
        sys.exit(1)
    print("[OK] Compilation successful.")

    print("[RUN] Running simulation with vvp...")
    res_run = subprocess.run(["vvp", sim_bin], capture_output=True, text=True)
    print(res_run.stdout)
    if res_run.stderr:
        print(res_run.stderr)

    if "[STATUS] CRYPTO-SECURITY SOC VERIFICATION: 100% PASSED" in res_run.stdout:
        print("[SUCCESS] All cryptographic & security assertions verified!")
    else:
        print("[WARNING] Simulation did not return 100% PASS.")

if __name__ == "__main__":
    run()
