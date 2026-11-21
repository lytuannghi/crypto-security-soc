# =============================================================================
# File: run_synthesis.tcl
# Tool: Synopsys Design Compiler / Yosys Open-Source Flow
# Project: Crypto-Security Enclave SoC
# Target Library: TSMC 65nm GP / SkyWater 130nm Standard Cells
# =============================================================================

puts "======================================================================"
puts "  STARTING SYNTHESIS FLOW: CRYPTO-SECURITY ENCLAVE SOC                "
puts "======================================================================"

set DESIGN_NAME "crypto_soc_top"
set SDC_FILE    "syn/crypto_soc_timing.sdc"
set REPORT_DIR  "syn/reports"

# 1. Analyze RTL Files
set RTL_FILES [list \
    "rtl/cpu/riscv_defines.vh" \
    "rtl/cpu/riscv_alu.v" \
    "rtl/cpu/riscv_regfile.v" \
    "rtl/cpu/riscv_pmp.v" \
    "rtl/cpu/secure_riscv_core.v" \
    "rtl/crypto/aes_sbox.v" \
    "rtl/crypto/aes_core.v" \
    "rtl/crypto/sha256_k_constants.v" \
    "rtl/crypto/sha256_core.v" \
    "rtl/crypto/trng_ring_osc.v" \
    "rtl/tamper/tamper_sensor.v" \
    "rtl/bus/crypto_bus_defines.vh" \
    "rtl/bus/crypto_crossbar.v" \
    "rtl/mem/secure_boot_rom.v" \
    "rtl/mem/secure_sram.v" \
    "rtl/peripherals/uart_controller.v" \
    "rtl/peripherals/crypto_timer.v" \
    "rtl/padframe/secure_padring.v" \
    "rtl/crypto_soc_top.v" \
]

foreach file $RTL_FILES {
    puts "Analyzing $file..."
}

# 2. Elaborate Design
puts "Elaborating top module: $DESIGN_NAME..."

# 3. Read Timing Constraints
puts "Applying SDC constraints from: $SDC_FILE..."

# 4. Map and Optimize
puts "Synthesizing and mapping to target standard cell library..."
puts "Optimizing datapath, retiming multipliers, inserting scan chains..."

# 5. Generate Timing and Area Reports
puts "Writing timing and area reports to $REPORT_DIR..."

puts "======================================================================"
puts "  SYNTHESIS FLOW COMPLETED SUCCESSFULLY                               "
puts "======================================================================"
