// =============================================================================
// File: crypto_timer.v
// Module: crypto_timer
// Project: Crypto-Security Enclave SoC
// Description: 32-bit Security Watchdog & High-Precision Monotonic Timer.
// =============================================================================

`timescale 1ns / 1ps

module crypto_timer (
    input  wire        clk,
    input  wire        rst_n,

    // Bus Slave
    input  wire        req,
    input  wire        wr,
    input  wire [31:0] addr,
    input  wire [31:0] wdata,
    output reg  [31:0] rdata,
    output reg         ready,

    output reg         timer_irq
);

    reg [31:0] timer_cnt;
    reg [31:0] timer_cmp;
    reg        timer_en;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            timer_cnt <= 32'd0;
            timer_cmp <= 32'hFFFF_FFFF;
            timer_en  <= 1'b1;
            timer_irq <= 1'b0;
        end else if (timer_en) begin
            timer_cnt <= timer_cnt + 1'b1;
            if (timer_cnt == timer_cmp) begin
                timer_irq <= 1'b1;
            end
        end
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rdata <= 32'd0;
            ready <= 1'b0;
        end else begin
            if (req && !ready) begin
                if (wr) begin
                    case (addr[3:2])
                        2'b00: timer_cnt <= wdata;
                        2'b01: timer_cmp <= wdata;
                        2'b10: timer_en  <= wdata[0];
                        default: ;
                    endcase
                end else begin
                    case (addr[3:2])
                        2'b00: rdata <= timer_cnt;
                        2'b01: rdata <= timer_cmp;
                        2'b10: rdata <= {31'd0, timer_en};
                        default: rdata <= 32'd0;
                    endcase
                end
                ready <= 1'b1;
            end else begin
                ready <= 1'b0;
            end
        end
    end

endmodule
