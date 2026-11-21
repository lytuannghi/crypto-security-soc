// =============================================================================
// File: crypto_crossbar.v
// Module: crypto_crossbar
// Project: Crypto-Security Enclave SoC
// Description: Multi-slave crossbar interconnect routing CPU transactions
//              to ROM, SRAM, AES, SHA, TRNG, Tamper, UART, and Timer.
// =============================================================================

`timescale 1ns / 1ps
`include "crypto_bus_defines.vh"

module crypto_crossbar (
    input  wire        clk,
    input  wire        rst_n,

    // CPU Master Port
    input  wire        cpu_req,
    input  wire        cpu_wr,
    input  wire [31:0] cpu_addr,
    input  wire [31:0] cpu_wdata,
    input  wire [3:0]  cpu_wstrb,
    output reg  [31:0] cpu_rdata,
    output reg         cpu_ready,

    // Slave 0: ROM (0x0000_0000)
    output wire        rom_req,
    output wire [31:0] rom_addr,
    input  wire [31:0] rom_rdata,
    input  wire        rom_ready,

    // Slave 1: SRAM (0x1000_0000)
    output wire        sram_req,
    output wire        sram_wr,
    output wire [31:0] sram_addr,
    output wire [31:0] sram_wdata,
    output wire [3:0]  sram_wstrb,
    input  wire [31:0] sram_rdata,
    input  wire        sram_ready,

    // Slave 2: AES Core (0x2000_0000)
    output wire        aes_req,
    output wire        aes_wr,
    output wire [31:0] aes_addr,
    output wire [31:0] aes_wdata,
    input  wire [31:0] aes_rdata,
    input  wire        aes_ready,

    // Slave 3: SHA256 Core (0x3000_0000)
    output wire        sha_req,
    output wire        sha_wr,
    output wire [31:0] sha_addr,
    output wire [31:0] sha_wdata,
    input  wire [31:0] sha_rdata,
    input  wire        sha_ready,

    // Slave 4: TRNG (0x4000_0000)
    output wire        trng_req,
    output wire        trng_wr,
    output wire [31:0] trng_addr,
    output wire [31:0] trng_wdata,
    input  wire [31:0] trng_rdata,
    input  wire        trng_ready,

    // Slave 5: Tamper Sensor (0x5000_0000)
    output wire        tamper_req,
    output wire        tamper_wr,
    output wire [31:0] tamper_addr,
    output wire [31:0] tamper_wdata,
    input  wire [31:0] tamper_rdata,
    input  wire        tamper_ready,

    // Slave 6: UART Controller (0x6000_0000)
    output wire        uart_req,
    output wire        uart_wr,
    output wire [31:0] uart_addr,
    output wire [31:0] uart_wdata,
    input  wire [31:0] uart_rdata,
    input  wire        uart_ready,

    // Slave 7: Timer (0x7000_0000)
    output wire        timer_req,
    output wire        timer_wr,
    output wire [31:0] timer_addr,
    output wire [31:0] timer_wdata,
    input  wire [31:0] timer_rdata,
    input  wire        timer_ready
);

    wire sel_rom    = (cpu_addr[31:28] == 4'h0);
    wire sel_sram   = (cpu_addr[31:28] == 4'h1);
    wire sel_aes    = (cpu_addr[31:28] == 4'h2);
    wire sel_sha    = (cpu_addr[31:28] == 4'h3);
    wire sel_trng   = (cpu_addr[31:28] == 4'h4);
    wire sel_tamper = (cpu_addr[31:28] == 4'h5);
    wire sel_uart   = (cpu_addr[31:28] == 4'h6);
    wire sel_timer  = (cpu_addr[31:28] == 4'h7);

    assign rom_req     = cpu_req & sel_rom;
    assign rom_addr    = cpu_addr;

    assign sram_req    = cpu_req & sel_sram;
    assign sram_wr     = cpu_wr;
    assign sram_addr   = cpu_addr;
    assign sram_wdata  = cpu_wdata;
    assign sram_wstrb  = cpu_wstrb;

    assign aes_req     = cpu_req & sel_aes;
    assign aes_wr      = cpu_wr;
    assign aes_addr    = cpu_addr;
    assign aes_wdata   = cpu_wdata;

    assign sha_req     = cpu_req & sel_sha;
    assign sha_wr      = cpu_wr;
    assign sha_addr    = cpu_addr;
    assign sha_wdata   = cpu_wdata;

    assign trng_req    = cpu_req & sel_trng;
    assign trng_wr     = cpu_wr;
    assign trng_addr   = cpu_addr;
    assign trng_wdata  = cpu_wdata;

    assign tamper_req   = cpu_req & sel_tamper;
    assign tamper_wr    = cpu_wr;
    assign tamper_addr  = cpu_addr;
    assign tamper_wdata = cpu_wdata;

    assign uart_req    = cpu_req & sel_uart;
    assign uart_wr     = cpu_wr;
    assign uart_addr   = cpu_addr;
    assign uart_wdata  = cpu_wdata;

    assign timer_req   = cpu_req & sel_timer;
    assign timer_wr    = cpu_wr;
    assign timer_addr  = cpu_addr;
    assign timer_wdata = cpu_wdata;

    always @(*) begin
        if (sel_rom) begin
            cpu_rdata = rom_rdata;
            cpu_ready = rom_ready;
        end else if (sel_sram) begin
            cpu_rdata = sram_rdata;
            cpu_ready = sram_ready;
        end else if (sel_aes) begin
            cpu_rdata = aes_rdata;
            cpu_ready = aes_ready;
        end else if (sel_sha) begin
            cpu_rdata = sha_rdata;
            cpu_ready = sha_ready;
        end else if (sel_trng) begin
            cpu_rdata = trng_rdata;
            cpu_ready = trng_ready;
        end else if (sel_tamper) begin
            cpu_rdata = tamper_rdata;
            cpu_ready = tamper_ready;
        end else if (sel_uart) begin
            cpu_rdata = uart_rdata;
            cpu_ready = uart_ready;
        end else if (sel_timer) begin
            cpu_rdata = timer_rdata;
            cpu_ready = timer_ready;
        end else begin
            cpu_rdata = 32'hDEAD_DEAD;
            cpu_ready = cpu_req;
        end
    end

endmodule
