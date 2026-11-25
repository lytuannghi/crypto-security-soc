#!/usr/bin/env python3
"""
Portable Simulation Runner for Crypto-Security Enclave SoC.
Compiles RTL and Testbench using Icarus Verilog (-Wall) and executes with vvp.
"""

import os
import shutil
import subprocess
import sys


def resolve_tool(name, repo_dir):
    found = shutil.which(name)
    if found:
        return found
    sibling = os.path.join(os.path.dirname(repo_dir), "iverilog", "bin", name + ".exe")
    return sibling if os.path.exists(sibling) else name


def run():
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(repo_dir)
    os.makedirs("sim", exist_ok=True)

    iverilog_exe = resolve_tool("iverilog", repo_dir)
    vvp_exe = resolve_tool("vvp", repo_dir)

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
        "tb/tb_crypto_soc.v",
    ]

    include_dirs = [
        "-Irtl/cpu", "-Irtl/bus", "-Irtl/crypto", "-Irtl/tamper",
        "-Irtl/mem", "-Irtl/peripherals", "-Irtl/padframe", "-Irtl",
    ]

    sim_bin = "sim/crypto_soc_sim.vvp"
    cmd_compile = [iverilog_exe, "-Wall", "-g2005"] + include_dirs + ["-o", sim_bin] + rtl_files
    print("[RUN] Compiling Verilog RTL with iverilog (-Wall)...")
    res = subprocess.run(cmd_compile, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0 or res.stderr.strip():
        print("[ERROR] Compilation failed or emitted -Wall warnings:")
        print(res.stderr)
        sys.exit(1)
    print("[OK] Compilation Clean (0 warnings).")

    print("[RUN] Running simulation with vvp...")
    res_run = subprocess.run([vvp_exe, sim_bin], capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(res_run.stdout)
    if res_run.stderr:
        print(res_run.stderr)

    if res_run.returncode == 0 and "[STATUS] CRYPTO-SECURITY SOC VERIFICATION: 100% PASSED" in res_run.stdout and "[FAIL]" not in res_run.stdout:
        print("[SUCCESS] All cryptographic & security assertions verified!")
    else:
        print("[ERROR] Simulation did not return 100% PASS.")
        sys.exit(1)


if __name__ == "__main__":
    run()
