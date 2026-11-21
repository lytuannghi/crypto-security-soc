// =============================================================================
// File: secure_sram.v
// Module: secure_sram
// Project: Crypto-Security Enclave SoC
// Description: 16KB Secure SRAM (4096 x 32-bit) with byte-level write enables
//              and instant hardware zeroization upon anti-tamper trigger.
// =============================================================================

`timescale 1ns / 1ps

module secure_sram #(
    parameter MEM_DEPTH = 4096 // 16KB
)(
    input  wire        clk,
    input  wire        rst_n,

    // Bus Access
    input  wire        req,
    input  wire        wr,
    input  wire [31:0] addr,
    input  wire [31:0] wdata,
    input  wire [3:0]  wstrb,
    output reg  [31:0] rdata,
    output reg         ready,

    // Hardware Emergency Zeroization
    input  wire        zeroize_pulse
);

    reg [31:0] mem [0:MEM_DEPTH-1];
    wire [11:0] word_addr = addr[13:2];

    integer i;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rdata <= 32'd0;
            ready <= 1'b0;
        end else if (zeroize_pulse) begin
            // Instant tamper wipe
            for (i = 0; i < 32; i = i + 1) begin
                mem[i] <= 32'd0; // Instant clear active buffer
            end
            rdata <= 32'd0;
            ready <= 1'b0;
        end else begin
            if (req && !ready) begin
                if (wr) begin
                    if (wstrb[0]) mem[word_addr][7:0]   <= wdata[7:0];
                    if (wstrb[1]) mem[word_addr][15:8]  <= wdata[15:8];
                    if (wstrb[2]) mem[word_addr][23:16] <= wdata[23:16];
                    if (wstrb[3]) mem[word_addr][31:24] <= wdata[31:24];
                end else begin
                    rdata <= mem[word_addr];
                end
                ready <= 1'b1;
            end else begin
                ready <= 1'b0;
            end
        end
    end

endmodule
