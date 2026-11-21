// =============================================================================
// File: trng_ring_osc.v
// Module: trng_ring_osc
// Project: Crypto-Security Enclave SoC
// Description: Physical True Random Number Generator (TRNG) utilizing
//              multi-stage asynchronous Ring Oscillator jitter entropy
//              with Von Neumann randomness extraction.
// =============================================================================

`timescale 1ns / 1ps

module trng_ring_osc (
    input  wire        clk,
    input  wire        rst_n,

    // Bus Slave Interface
    input  wire        req,
    input  wire        wr,
    input  wire [31:0] addr,
    input  wire [31:0] wdata,
    output reg  [31:0] rdata,
    output reg         ready,

    // Raw entropy test output
    output wire        entropy_pulse
);

    // Configurable Enable Register
    reg        trng_en;
    reg [31:0] random_word;
    reg [4:0]  bit_count;
    reg        word_valid;

    // Ring Oscillator 1: 3 inverters
    wire ro1_node1, ro1_node2, ro1_out;
    assign ro1_node1 = ~(ro1_out & trng_en);
    assign ro1_node2 = ~ro1_node1;
    assign ro1_out   = ~ro1_node2;

    // Ring Oscillator 2: 5 inverters
    wire ro2_1, ro2_2, ro2_3, ro2_4, ro2_out;
    assign ro2_1   = ~(ro2_out & trng_en);
    assign ro2_2   = ~ro2_1;
    assign ro2_3   = ~ro2_2;
    assign ro2_4   = ~ro2_3;
    assign ro2_out = ~ro2_4;

    // Ring Oscillator 3: 7 inverters
    wire ro3_1, ro3_2, ro3_3, ro3_4, ro3_5, ro3_6, ro3_out;
    assign ro3_1   = ~(ro3_out & trng_en);
    assign ro3_2   = ~ro3_1;
    assign ro3_3   = ~ro3_2;
    assign ro3_4   = ~ro3_3;
    assign ro3_5   = ~ro3_4;
    assign ro3_6   = ~ro3_5;
    assign ro3_out = ~ro3_6;

    // XOR Entropy Combiner
    wire raw_entropy = ro1_out ^ ro2_out ^ ro3_out;
    assign entropy_pulse = raw_entropy;

    // Double Flop Synchronizer
    reg raw_sync1;
    reg raw_sync2;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            raw_sync1 <= 1'b0;
            raw_sync2 <= 1'b0;
        end else begin
            raw_sync1 <= raw_entropy;
            raw_sync2 <= raw_sync1;
        end
    end

    // Von Neumann Extractor
    reg [1:0] vn_pair;
    reg       vn_toggle;
    reg       extracted_bit;
    reg       bit_valid;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            vn_pair       <= 2'b00;
            vn_toggle     <= 1'b0;
            extracted_bit <= 1'b0;
            bit_valid     <= 1'b0;
        end else if (trng_en) begin
            vn_toggle <= ~vn_toggle;
            if (!vn_toggle) begin
                vn_pair[0] <= raw_sync2;
                bit_valid  <= 1'b0;
            end else begin
                vn_pair[1] <= raw_sync2;
                if ({vn_pair[0], raw_sync2} == 2'b01) begin
                    extracted_bit <= 1'b0;
                    bit_valid     <= 1'b1;
                end else if ({vn_pair[0], raw_sync2} == 2'b10) begin
                    extracted_bit <= 1'b1;
                    bit_valid     <= 1'b1;
                end else begin
                    bit_valid     <= 1'b0;
                end
            end
        end else begin
            bit_valid <= 1'b0;
        end
    end

    // Entropy Accumulation into 32-bit Words (with LFSR fallback for fast deterministic simulation)
    reg [31:0] sim_lfsr;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            random_word <= 32'hA5A5_5A5A;
            bit_count   <= 5'd0;
            word_valid  <= 1'b0;
            sim_lfsr    <= 32'hDEAD_BEEF;
        end else if (trng_en) begin
            sim_lfsr <= {sim_lfsr[30:0], sim_lfsr[31] ^ sim_lfsr[21] ^ sim_lfsr[1] ^ sim_lfsr[0]};

            if (bit_valid) begin
                random_word <= {random_word[30:0], extracted_bit ^ sim_lfsr[0]};
                if (bit_count == 5'd31) begin
                    bit_count  <= 5'd0;
                    word_valid <= 1'b1;
                end else begin
                    bit_count <= bit_count + 1'b1;
                end
            end
        end
    end

    // Bus Slave Interface
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rdata   <= 32'd0;
            ready   <= 1'b0;
            trng_en <= 1'b1; // Default enabled
        end else begin
            if (req && !ready) begin
                if (wr) begin
                    if (addr[3:2] == 2'b01) trng_en <= wdata[0];
                end else begin
                    case (addr[3:2])
                        2'b00: rdata <= random_word;
                        2'b01: rdata <= {30'd0, word_valid, trng_en};
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
