// =============================================================================
// File: crypto_soc_top.v
// Module: crypto_soc_top
// Project: Crypto-Security Enclave SoC (Full-Flow ASIC Tape-Out)
// Description: Complete Cryptographic SoC Top-Level integrating Secure RV32I
//              Core with Physical Memory Protection (PMP), AES-256 Engine,
//              SHA-256 Accelerator, True Random Number Generator (TRNG),
//              Active Tamper Sensor, 8KB ROM, 16KB SRAM, and I/O Pad Ring.
// =============================================================================

`timescale 1ns / 1ps
`include "crypto_bus_defines.vh"

module crypto_soc_top (
    // Physical Chip I/O Pins
    input  wire        pad_clk,
    input  wire        pad_rst_n,

    // Serial Communication
    output wire        pad_uart_tx,
    input  wire        pad_uart_rx,

    // Tamper & Security Pins
    input  wire        pad_tamper_mesh,
    input  wire        pad_glitch_detect,
    output wire        pad_sec_alarm,
    output wire        pad_trng_pulse
);

    // Internal Signals
    wire clk;
    wire rst_n;
    wire core_uart_tx;
    wire core_uart_rx;
    wire core_tamper_mesh;
    wire core_glitch_detect;
    wire core_sec_alarm;
    wire core_trng_pulse;

    // Pad Ring Instance
    secure_padring u_padring (
        .pad_clk           (pad_clk),
        .pad_rst_n         (pad_rst_n),
        .pad_uart_tx       (pad_uart_tx),
        .pad_uart_rx       (pad_uart_rx),
        .pad_tamper_mesh   (pad_tamper_mesh),
        .pad_glitch_detect (pad_glitch_detect),
        .pad_sec_alarm     (pad_sec_alarm),
        .pad_trng_pulse    (pad_trng_pulse),

        .core_clk          (clk),
        .core_rst_n        (rst_n),
        .core_uart_tx      (core_uart_tx),
        .core_uart_rx      (core_uart_rx),
        .core_tamper_mesh  (core_tamper_mesh),
        .core_glitch_detect(core_glitch_detect),
        .core_sec_alarm    (core_sec_alarm),
        .core_trng_pulse   (core_trng_pulse)
    );

    // CPU Bus Signals
    wire [31:0] cpu_pc;
    wire [31:0] instr_addr;
    wire [31:0] instr_data;

    wire        cpu_data_req;
    wire        cpu_data_wr;
    wire [31:0] cpu_data_addr;
    wire [31:0] cpu_data_wdata;
    wire [3:0]  cpu_data_wstrb;
    wire [31:0] cpu_data_rdata;
    wire        cpu_data_ready;
    wire        pmp_trap;

    // Secure RV32I Core with PMP
    secure_riscv_core u_cpu (
        .clk               (clk),
        .rst_n             (rst_n),
        .instr_addr        (instr_addr),
        .instr_data        (instr_data),
        .data_req          (cpu_data_req),
        .data_wr           (cpu_data_wr),
        .data_addr         (cpu_data_addr),
        .data_wdata        (cpu_data_wdata),
        .data_wstrb        (cpu_data_wstrb),
        .data_rdata        (cpu_data_rdata),
        .data_ready        (cpu_data_ready),
        .curr_pc           (cpu_pc),
        .pmp_violation_trap(pmp_trap)
    );

    // Crossbar Slave Interconnect Signals
    wire        rom_req;
    wire [31:0] rom_addr;
    wire [31:0] rom_rdata;
    wire        rom_ready;

    wire        sram_req;
    wire        sram_wr;
    wire [31:0] sram_addr;
    wire [31:0] sram_wdata;
    wire [3:0]  sram_wstrb;
    wire [31:0] sram_rdata;
    wire        sram_ready;

    wire        aes_req;
    wire        aes_wr;
    wire [31:0] aes_addr;
    wire [31:0] aes_wdata;
    wire [31:0] aes_rdata;
    wire        aes_ready;

    wire        sha_req;
    wire        sha_wr;
    wire [31:0] sha_addr;
    wire [31:0] sha_wdata;
    wire [31:0] sha_rdata;
    wire        sha_ready;

    wire        trng_req;
    wire        trng_wr;
    wire [31:0] trng_addr;
    wire [31:0] trng_wdata;
    wire [31:0] trng_rdata;
    wire        trng_ready;

    wire        tamper_req;
    wire        tamper_wr;
    wire [31:0] tamper_addr;
    wire [31:0] tamper_wdata;
    wire [31:0] tamper_rdata;
    wire        tamper_ready;

    wire        uart_req;
    wire        uart_wr;
    wire [31:0] uart_addr;
    wire [31:0] uart_wdata;
    wire [31:0] uart_rdata;
    wire        uart_ready;

    wire        timer_req;
    wire        timer_wr;
    wire [31:0] timer_addr;
    wire [31:0] timer_wdata;
    wire [31:0] timer_rdata;
    wire        timer_ready;

    // Crossbar Interconnect
    crypto_crossbar u_bus (
        .clk         (clk),
        .rst_n       (rst_n),
        .cpu_req     (cpu_data_req),
        .cpu_wr      (cpu_data_wr),
        .cpu_addr    (cpu_data_addr),
        .cpu_wdata   (cpu_data_wdata),
        .cpu_wstrb   (cpu_data_wstrb),
        .cpu_rdata   (cpu_data_rdata),
        .cpu_ready   (cpu_data_ready),

        .rom_req     (rom_req),
        .rom_addr    (rom_addr),
        .rom_rdata   (rom_rdata),
        .rom_ready   (rom_ready),

        .sram_req    (sram_req),
        .sram_wr     (sram_wr),
        .sram_addr   (sram_addr),
        .sram_wdata  (sram_wdata),
        .sram_wstrb  (sram_wstrb),
        .sram_rdata  (sram_rdata),
        .sram_ready  (sram_ready),

        .aes_req     (aes_req),
        .aes_wr      (aes_wr),
        .aes_addr    (aes_addr),
        .aes_wdata   (aes_wdata),
        .aes_rdata   (aes_rdata),
        .aes_ready   (aes_ready),

        .sha_req     (sha_req),
        .sha_wr      (sha_wr),
        .sha_addr    (sha_addr),
        .sha_wdata   (sha_wdata),
        .sha_rdata   (sha_rdata),
        .sha_ready   (sha_ready),

        .trng_req    (trng_req),
        .trng_wr     (trng_wr),
        .trng_addr   (trng_addr),
        .trng_wdata  (trng_wdata),
        .trng_rdata  (trng_rdata),
        .trng_ready  (trng_ready),

        .tamper_req  (tamper_req),
        .tamper_wr   (tamper_wr),
        .tamper_addr (tamper_addr),
        .tamper_wdata(tamper_wdata),
        .tamper_rdata(tamper_rdata),
        .tamper_ready(tamper_ready),

        .uart_req    (uart_req),
        .uart_wr     (uart_wr),
        .uart_addr   (uart_addr),
        .uart_wdata  (uart_wdata),
        .uart_rdata  (uart_rdata),
        .uart_ready  (uart_ready),

        .timer_req   (timer_req),
        .timer_wr    (timer_wr),
        .timer_addr  (timer_addr),
        .timer_wdata (timer_wdata),
        .timer_rdata (timer_rdata),
        .timer_ready (timer_ready)
    );

    // 8KB Secure Boot ROM
    secure_boot_rom u_rom (
        .clk        (clk),
        .rst_n      (rst_n),
        .instr_addr (instr_addr),
        .instr_data (instr_data),
        .data_req   (rom_req),
        .data_addr  (rom_addr),
        .data_rdata (rom_rdata),
        .data_ready (rom_ready)
    );

    // 16KB Secure SRAM
    wire zeroize_pulse;
    secure_sram u_sram (
        .clk          (clk),
        .rst_n        (rst_n),
        .req          (sram_req),
        .wr           (sram_wr),
        .addr         (sram_addr),
        .wdata        (sram_wdata),
        .wstrb        (sram_wstrb),
        .rdata        (sram_rdata),
        .ready        (sram_ready),
        .zeroize_pulse(zeroize_pulse)
    );

    // AES-128/256 Cryptographic Engine
    wire aes_done_irq;
    aes_core u_aes (
        .clk     (clk),
        .rst_n   (rst_n),
        .req     (aes_req),
        .wr      (aes_wr),
        .addr    (aes_addr),
        .wdata   (aes_wdata),
        .rdata   (aes_rdata),
        .ready   (aes_ready),
        .done_irq(aes_done_irq)
    );

    // SHA-256 Hash Accelerator
    wire sha_done_irq;
    sha256_core u_sha (
        .clk     (clk),
        .rst_n   (rst_n),
        .req     (sha_req),
        .wr      (sha_wr),
        .addr    (sha_addr),
        .wdata   (sha_wdata),
        .rdata   (sha_rdata),
        .ready   (sha_ready),
        .done_irq(sha_done_irq)
    );

    // True Random Number Generator (TRNG)
    trng_ring_osc u_trng (
        .clk          (clk),
        .rst_n        (rst_n),
        .req          (trng_req),
        .wr           (trng_wr),
        .addr         (trng_addr),
        .wdata        (trng_wdata),
        .rdata        (trng_rdata),
        .ready        (trng_ready),
        .entropy_pulse(core_trng_pulse)
    );

    // Anti-Tamper Detection Module
    wire tamper_alarm_irq;
    tamper_sensor u_tamper (
        .clk              (clk),
        .rst_n            (rst_n),
        .req              (tamper_req),
        .wr               (tamper_wr),
        .addr             (tamper_addr),
        .wdata            (tamper_wdata),
        .rdata            (tamper_rdata),
        .ready            (tamper_ready),
        .tamper_mesh_pin  (core_tamper_mesh),
        .glitch_detect_pin(core_glitch_detect),
        .zeroize_pulse    (zeroize_pulse),
        .tamper_alarm_irq (tamper_alarm_irq)
    );

    assign core_sec_alarm = tamper_alarm_irq | pmp_trap;

    // Full-Duplex UART
    wire uart_tx_irq;
    uart_controller u_uart (
        .clk     (clk),
        .rst_n   (rst_n),
        .req     (uart_req),
        .wr      (uart_wr),
        .addr    (uart_addr),
        .wdata   (uart_wdata),
        .rdata   (uart_rdata),
        .ready   (uart_ready),
        .uart_tx (core_uart_tx),
        .uart_rx (core_uart_rx),
        .tx_irq  (uart_tx_irq)
    );

    // 32-bit Security Watchdog Timer
    wire timer_irq;
    crypto_timer u_timer (
        .clk      (clk),
        .rst_n    (rst_n),
        .req      (timer_req),
        .wr       (timer_wr),
        .addr     (timer_addr),
        .wdata    (timer_wdata),
        .rdata    (timer_rdata),
        .ready    (timer_ready),
        .timer_irq(timer_irq)
    );

endmodule
