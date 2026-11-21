// =============================================================================
// File: secure_padring.v
// Module: secure_padring
// Project: Crypto-Security Enclave SoC
// Description: Physical I/O Pad Ring with ESD protection clamps, level
//              shifters, and dedicated tamper sensor shielding pins.
// =============================================================================

`timescale 1ns / 1ps

module secure_padring (
    // External Physical Pins
    input  wire        pad_clk,
    input  wire        pad_rst_n,

    // UART
    output wire        pad_uart_tx,
    input  wire        pad_uart_rx,

    // Physical Tamper Sensors
    input  wire        pad_tamper_mesh,
    input  wire        pad_glitch_detect,

    // Status Alarm Pins
    output wire        pad_sec_alarm,
    output wire        pad_trng_pulse,

    // Internal Core Signals
    output wire        core_clk,
    output wire        core_rst_n,
    input  wire        core_uart_tx,
    output wire        core_uart_rx,
    output wire        core_tamper_mesh,
    output wire        core_glitch_detect,
    input  wire        core_sec_alarm,
    input  wire        core_trng_pulse
);

    assign core_clk           = pad_clk;
    assign core_rst_n         = pad_rst_n;
    assign pad_uart_tx        = core_uart_tx;
    assign core_uart_rx       = pad_uart_rx;
    assign core_tamper_mesh   = pad_tamper_mesh;
    assign core_glitch_detect = pad_glitch_detect;
    assign pad_sec_alarm      = core_sec_alarm;
    assign pad_trng_pulse     = core_trng_pulse;

endmodule
