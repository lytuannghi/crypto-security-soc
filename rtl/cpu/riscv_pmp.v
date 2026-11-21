// =============================================================================
// File: riscv_pmp.v
// Module: riscv_pmp
// Project: Crypto-Security Enclave SoC
// Description: Physical Memory Protection (PMP) unit supporting 4 configurable
//              memory regions with R/W/X permission checking and Lock bit.
// =============================================================================

`timescale 1ns / 1ps

module riscv_pmp (
    input  wire        clk,
    input  wire        rst_n,

    // CPU Access Probe
    input  wire [31:0] fetch_addr,
    input  wire        fetch_req,
    output reg         fetch_fault,

    input  wire [31:0] data_addr,
    input  wire        data_req,
    input  wire        data_wr,
    output reg         data_fault,

    // CSR Configuration Interface
    input  wire        pmp_wr_en,
    input  wire [3:0]  pmp_reg_sel, // 0..3: addr0..3, 4: cfg0
    input  wire [31:0] pmp_wdata,
    output reg  [31:0] pmp_rdata
);

    // 4 PMP Address Registers
    reg [31:0] pmpaddr [0:3];
    // PMP Config: [7] Lock, [6:5] Reserved, [4:3] Address Match (00: OFF, 01: TOR), [2] X, [1] W, [0] R
    reg [7:0]  pmpcfg [0:3];

    // CSR Read/Write
    integer i;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pmpaddr[0] <= 32'h0000_2000; // ROM default bound
            pmpaddr[1] <= 32'h1000_4000; // SRAM default bound
            pmpaddr[2] <= 32'h2000_1000; // Crypto Registers bound
            pmpaddr[3] <= 32'hFFFF_FFFF; // Open upper bound
            pmpcfg[0]  <= 8'h0D; // TOR, X=1, W=0, R=1 (ROM read/exec)
            pmpcfg[1]  <= 8'h0B; // TOR, X=0, W=1, R=1 (SRAM data)
            pmpcfg[2]  <= 8'h0B; // TOR, X=0, W=1, R=1 (Crypto engine)
            pmpcfg[3]  <= 8'h00; // Disabled
        end else if (pmp_wr_en) begin
            if (pmp_reg_sel < 4) begin
                if (!pmpcfg[pmp_reg_sel][7]) begin // Not locked
                    pmpaddr[pmp_reg_sel] <= pmp_wdata;
                end
            end else if (pmp_reg_sel == 4) begin
                if (!pmpcfg[0][7]) pmpcfg[0] <= pmp_wdata[7:0];
                if (!pmpcfg[1][7]) pmpcfg[1] <= pmp_wdata[15:8];
                if (!pmpcfg[2][7]) pmpcfg[2] <= pmp_wdata[23:16];
                if (!pmpcfg[3][7]) pmpcfg[3] <= pmp_wdata[31:24];
            end
        end
    end

    // Instruction Fetch Permission Checking
    always @(*) begin
        fetch_fault = 1'b0;
        if (fetch_req) begin
            if (fetch_addr < pmpaddr[0]) begin
                fetch_fault = !pmpcfg[0][2]; // Check X bit
            end else if (fetch_addr < pmpaddr[1]) begin
                fetch_fault = !pmpcfg[1][2];
            end else begin
                fetch_fault = 1'b1; // Deny execution outside authorized memory
            end
        end
    end

    // Data Read/Write Permission Checking
    always @(*) begin
        data_fault = 1'b0;
        if (data_req) begin
            if (data_addr < pmpaddr[0]) begin
                // ROM region
                if (data_wr) data_fault = 1'b1; // Write to ROM is illegal
                else if (!pmpcfg[0][0]) data_fault = 1'b1; // Check R bit
            end else if (data_addr < pmpaddr[1]) begin
                // SRAM region
                if (data_wr && !pmpcfg[1][1]) data_fault = 1'b1; // Check W bit
                else if (!data_wr && !pmpcfg[1][0]) data_fault = 1'b1; // Check R bit
            end else if (data_addr >= 32'h2000_0000 && data_addr < pmpaddr[2]) begin
                // Crypto Registers
                if (data_wr && !pmpcfg[2][1]) data_fault = 1'b1;
                else if (!data_wr && !pmpcfg[2][0]) data_fault = 1'b1;
            end
        end
    end

endmodule
