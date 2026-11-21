// =============================================================================
// File: sha256_core.v
// Module: sha256_core
// Project: Crypto-Security Enclave SoC
// Description: Hardware SHA-256 Hash Accelerator.
//              Processes 512-bit message block over 64 compression rounds.
// =============================================================================

`timescale 1ns / 1ps

module sha256_core (
    input  wire        clk,
    input  wire        rst_n,

    // Bus Slave Interface
    input  wire        req,
    input  wire        wr,
    input  wire [31:0] addr,
    input  wire [31:0] wdata,
    output reg  [31:0] rdata,
    output reg         ready,

    // Interrupt output
    output reg         done_irq
);

    // 16-word input block (512-bit message block)
    reg [31:0] msg_block [0:15];
    reg        init_hash;
    reg        next_block;
    reg        busy;

    // Working variables
    reg [31:0] a, b, c, d, e, f, g, h;
    // Hash state registers
    reg [31:0] h0, h1, h2, h3, h4, h5, h6, h7;

    // Message schedule W[0..15] circular buffer
    reg [31:0] w_sched [0:15];
    reg [5:0]  round_cnt;

    // FSM
    localparam S_IDLE  = 2'b00;
    localparam S_ROUNDS= 2'b01;
    localparam S_ACCUM = 2'b10;
    reg [1:0] state;

    // Round Constant K_t
    wire [31:0] k_val;
    sha256_k_constants u_k (
        .round_idx(round_cnt),
        .k_val    (k_val)
    );

    // Helper functions
    function [31:0] rotr(input [31:0] x, input integer n);
        rotr = (x >> n) | (x << (32 - n));
    endfunction

    // SHA-256 Logic Functions
    wire [31:0] ch_val  = (e & f) ^ (~e & g);
    wire [31:0] maj_val = (a & b) ^ (a & c) ^ (b & c);
    wire [31:0] sigma0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    wire [31:0] sigma1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);

    // Message expansion functions for W_t (rounds 16..63)
    wire [31:0] w_minus_2  = w_sched[14];
    wire [31:0] w_minus_7  = w_sched[9];
    wire [31:0] w_minus_15 = w_sched[1];
    wire [31:0] w_minus_16 = w_sched[0];

    wire [31:0] s0 = rotr(w_minus_15, 7) ^ rotr(w_minus_15, 18) ^ (w_minus_15 >> 3);
    wire [31:0] s1 = rotr(w_minus_2, 17) ^ rotr(w_minus_2, 19) ^ (w_minus_2 >> 10);
    wire [31:0] w_expanded = s1 + w_minus_7 + s0 + w_minus_16;

    wire [31:0] curr_w = (round_cnt < 6'd16) ? w_sched[round_cnt[3:0]] : w_expanded;

    wire [31:0] t1 = h + sigma1 + ch_val + k_val + curr_w;
    wire [31:0] t2 = sigma0 + maj_val;

    integer idx;

    // Compression Engine FSM
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            busy      <= 1'b0;
            done_irq  <= 1'b0;
            round_cnt <= 6'd0;
            a <= 32'd0; b <= 32'd0; c <= 32'd0; d <= 32'd0;
            e <= 32'd0; f <= 32'd0; g <= 32'd0; h <= 32'd0;
            h0 <= 32'h6a09e667; h1 <= 32'hbb67ae85;
            h2 <= 32'h3c6ef372; h3 <= 32'ha54ff53a;
            h4 <= 32'h510e527f; h5 <= 32'h9b05688c;
            h6 <= 32'h1f83d9ab; h7 <= 32'h5be0cd19;
            for (idx = 0; idx < 16; idx = idx + 1) w_sched[idx] <= 32'd0;
        end else begin
            case (state)
                S_IDLE: begin
                    done_irq <= 1'b0;
                    if (init_hash || next_block) begin
                        busy      <= 1'b1;
                        round_cnt <= 6'd0;

                        if (init_hash) begin
                            h0 <= 32'h6a09e667; h1 <= 32'hbb67ae85;
                            h2 <= 32'h3c6ef372; h3 <= 32'ha54ff53a;
                            h4 <= 32'h510e527f; h5 <= 32'h9b05688c;
                            h6 <= 32'h1f83d9ab; h7 <= 32'h5be0cd19;
                            a  <= 32'h6a09e667; b  <= 32'hbb67ae85;
                            c  <= 32'h3c6ef372; d  <= 32'ha54ff53a;
                            e  <= 32'h510e527f; f  <= 32'h9b05688c;
                            g  <= 32'h1f83d9ab; h  <= 32'h5be0cd19;
                        end else begin
                            a <= h0; b <= h1; c <= h2; d <= h3;
                            e <= h4; f <= h5; g <= h6; h <= h7;
                        end

                        for (idx = 0; idx < 16; idx = idx + 1) begin
                            w_sched[idx] <= msg_block[idx];
                        end

                        state <= S_ROUNDS;
                    end else begin
                        busy <= 1'b0;
                    end
                end

                S_ROUNDS: begin
                    // Compute round step
                    h <= g;
                    g <= f;
                    f <= e;
                    e <= d + t1;
                    d <= c;
                    c <= b;
                    b <= a;
                    a <= t1 + t2;

                    // Message schedule shift for rounds 16..63
                    if (round_cnt >= 6'd16) begin
                        for (idx = 0; idx < 15; idx = idx + 1) begin
                            w_sched[idx] <= w_sched[idx+1];
                        end
                        w_sched[15] <= w_expanded;
                    end

                    if (round_cnt == 6'd63) begin
                        state <= S_ACCUM;
                    end else begin
                        round_cnt <= round_cnt + 1'b1;
                    end
                end

                S_ACCUM: begin
                    h0 <= h0 + a;
                    h1 <= h1 + b;
                    h2 <= h2 + c;
                    h3 <= h3 + d;
                    h4 <= h4 + e;
                    h5 <= h5 + f;
                    h6 <= h6 + g;
                    h7 <= h7 + h;
                    busy     <= 1'b0;
                    done_irq <= 1'b1;
                    state    <= S_IDLE;
                end
            endcase
        end
    end

    // Memory-mapped APB Register Access
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rdata      <= 32'd0;
            ready      <= 1'b0;
            init_hash  <= 1'b0;
            next_block <= 1'b0;
            for (idx = 0; idx < 16; idx = idx + 1) msg_block[idx] <= 32'd0;
        end else begin
            init_hash  <= 1'b0;
            next_block <= 1'b0;

            if (req && !ready) begin
                if (wr) begin
                    if (addr[7:0] == 8'h00) begin
                        if (wdata[0]) init_hash  <= 1'b1;
                        if (wdata[1]) next_block <= 1'b1;
                    end else if (addr[7:0] >= 8'h10 && addr[7:0] <= 8'h4C) begin
                        msg_block[(addr[7:0] - 8'h10) >> 2] <= wdata;
                    end
                end else begin
                    case (addr[7:0])
                        8'h00: rdata <= {30'd0, done_irq, busy};
                        8'h50: rdata <= h0;
                        8'h54: rdata <= h1;
                        8'h58: rdata <= h2;
                        8'h5C: rdata <= h3;
                        8'h60: rdata <= h4;
                        8'h64: rdata <= h5;
                        8'h68: rdata <= h6;
                        8'h6C: rdata <= h7;
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
