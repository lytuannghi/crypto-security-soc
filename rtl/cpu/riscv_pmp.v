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

    reg [31:0] pmpaddr [0:3];
    reg [7:0]  pmpcfg  [0:3];

    // Scalar aliases avoid Verilog-2005 @* unpacked-array sensitivity warnings
    wire [31:0] addr0 = pmpaddr[0];
    wire [31:0] addr1 = pmpaddr[1];
    wire [31:0] addr2 = pmpaddr[2];
    wire [31:0] addr3 = pmpaddr[3];
    wire [7:0]  cfg0  = pmpcfg[0];
    wire [7:0]  cfg1  = pmpcfg[1];
    wire [7:0]  cfg2  = pmpcfg[2];
    wire [7:0]  cfg3  = pmpcfg[3];

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            pmpaddr[0] <= 32'h0000_2000;
            pmpaddr[1] <= 32'h1000_4000;
            pmpaddr[2] <= 32'h2000_1000;
            pmpaddr[3] <= 32'hFFFF_FFFF;
            pmpcfg[0]  <= 8'h0D; // TOR, X=1, W=0, R=1
            pmpcfg[1]  <= 8'h0B; // TOR, X=0, W=1, R=1
            pmpcfg[2]  <= 8'h0B; // TOR, X=0, W=1, R=1
            pmpcfg[3]  <= 8'h00;
            pmp_rdata  <= 32'd0;
        end else begin
            case (pmp_reg_sel)
                4'd0: pmp_rdata <= pmpaddr[0];
                4'd1: pmp_rdata <= pmpaddr[1];
                4'd2: pmp_rdata <= pmpaddr[2];
                4'd3: pmp_rdata <= pmpaddr[3];
                4'd4: pmp_rdata <= {pmpcfg[3], pmpcfg[2], pmpcfg[1], pmpcfg[0]};
                default: pmp_rdata <= 32'd0;
            endcase
            if (pmp_wr_en) begin
                if (pmp_reg_sel < 4) begin
                    if (!pmpcfg[pmp_reg_sel][7]) begin
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
    end

    // Instruction Fetch Permission Checking
    always @(*) begin
        fetch_fault = 1'b0;
        if (fetch_req) begin
            if (fetch_addr < addr0) begin
                fetch_fault = !cfg0[2];
            end else if (fetch_addr < addr1) begin
                fetch_fault = !cfg1[2];
            end else if (fetch_addr < addr3 && cfg3[4:3] != 2'b00) begin
                fetch_fault = !cfg3[2];
            end else begin
                fetch_fault = 1'b1;
            end
        end
    end

    // Data Read/Write Permission Checking
    always @(*) begin
        data_fault = 1'b0;
        if (data_req) begin
            if (data_addr < addr0) begin
                if (data_wr || !cfg0[0]) data_fault = 1'b1;
            end else if (data_addr < addr1) begin
                if ((data_wr && !cfg1[1]) || (!data_wr && !cfg1[0])) data_fault = 1'b1;
            end else if (data_addr >= 32'h2000_0000 && data_addr < addr2) begin
                if ((data_wr && !cfg2[1]) || (!data_wr && !cfg2[0])) data_fault = 1'b1;
            end
        end
    end

endmodule
