// =============================================================================
// File: aes_core.v
// Module: aes_core
// Project: Crypto-Security Enclave SoC
// Description: Hardware AES-128 / AES-256 Block Cipher Accelerator.
//              Iterative round architecture with SubBytes, ShiftRows,
//              MixColumns, and AddRoundKey logic.
// =============================================================================

`timescale 1ns / 1ps

module aes_core (
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

    // Registers
    reg [127:0] block_in;
    reg [255:0] cipher_key;
    reg [127:0] block_out;
    reg         key_256_sel; // 0 = AES-128 (10 rounds), 1 = AES-256 (14 rounds)
    reg         busy;
    reg         start_pulse;

    // FSM States
    localparam S_IDLE  = 2'b00;
    localparam S_ROUND = 2'b01;
    localparam S_DONE  = 2'b10;

    reg [1:0]  state;
    reg [3:0]  round_cnt;
    reg [3:0]  max_rounds;
    reg [127:0] round_state;
    reg [127:0] round_key;

    // SubBytes: 16 S-Boxes
    wire [127:0] sb_out;
    genvar i;
    generate
        for (i = 0; i < 16; i = i + 1) begin : GEN_SBOX
            aes_sbox u_sbox (
                .in_byte (round_state[i*8 +: 8]),
                .out_byte(sb_out[i*8 +: 8])
            );
        end
    endgenerate

    // ShiftRows
    wire [127:0] sr_out;
    // Row 0: no shift
    assign sr_out[0*8 +: 8]   = sb_out[0*8 +: 8];
    assign sr_out[4*8 +: 8]   = sb_out[4*8 +: 8];
    assign sr_out[8*8 +: 8]   = sb_out[8*8 +: 8];
    assign sr_out[12*8 +: 8]  = sb_out[12*8 +: 8];
    // Row 1: circular shift left by 1 byte
    assign sr_out[1*8 +: 8]   = sb_out[5*8 +: 8];
    assign sr_out[5*8 +: 8]   = sb_out[9*8 +: 8];
    assign sr_out[9*8 +: 8]   = sb_out[13*8 +: 8];
    assign sr_out[13*8 +: 8]  = sb_out[1*8 +: 8];
    // Row 2: circular shift left by 2 bytes
    assign sr_out[2*8 +: 8]   = sb_out[10*8 +: 8];
    assign sr_out[6*8 +: 8]   = sb_out[14*8 +: 8];
    assign sr_out[10*8 +: 8]  = sb_out[2*8 +: 8];
    assign sr_out[14*8 +: 8]  = sb_out[6*8 +: 8];
    // Row 3: circular shift left by 3 bytes
    assign sr_out[3*8 +: 8]   = sb_out[15*8 +: 8];
    assign sr_out[7*8 +: 8]   = sb_out[3*8 +: 8];
    assign sr_out[11*8 +: 8]  = sb_out[7*8 +: 8];
    assign sr_out[15*8 +: 8]  = sb_out[11*8 +: 8];

    // MixColumns function
    function [7:0] xtime(input [7:0] b);
        xtime = {b[6:0], 1'b0} ^ (b[7] ? 8'h1b : 8'h00);
    endfunction

    function [31:0] mix_single_col(input [31:0] col);
        reg [7:0] a0, a1, a2, a3;
        reg [7:0] r0, r1, r2, r3;
        begin
            a0 = col[7:0];
            a1 = col[15:8];
            a2 = col[23:16];
            a3 = col[31:24];

            r0 = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            r1 = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            r2 = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            r3 = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);

            mix_single_col = {r3, r2, r1, r0};
        end
    endfunction

    wire [127:0] mc_out;
    assign mc_out[31:0]   = mix_single_col(sr_out[31:0]);
    assign mc_out[63:32]  = mix_single_col(sr_out[63:32]);
    assign mc_out[95:64]  = mix_single_col(sr_out[95:64]);
    assign mc_out[127:96] = mix_single_col(sr_out[127:96]);

    // Round Logic Execution
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= S_IDLE;
            busy        <= 1'b0;
            done_irq    <= 1'b0;
            round_cnt   <= 4'd0;
            round_state <= 128'd0;
            block_out   <= 128'd0;
            round_key   <= 128'd0;
            max_rounds  <= 4'd10;
        end else begin
            case (state)
                S_IDLE: begin
                    done_irq <= 1'b0;
                    if (start_pulse) begin
                        busy        <= 1'b1;
                        round_cnt   <= 4'd1;
                        max_rounds  <= key_256_sel ? 4'd14 : 4'd10;
                        round_key   <= cipher_key[127:0];
                        // Initial AddRoundKey
                        round_state <= block_in ^ cipher_key[127:0];
                        state       <= S_ROUND;
                    end else begin
                        busy <= 1'b0;
                    end
                end

                S_ROUND: begin
                    if (round_cnt < max_rounds) begin
                        // Standard Round: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
                        round_state <= mc_out ^ round_key;
                        round_key   <= {round_key[119:0], round_key[127:120] ^ 8'h1B}; // Key schedule permutation
                        round_cnt   <= round_cnt + 1'b1;
                    end else begin
                        // Final Round: SubBytes -> ShiftRows -> AddRoundKey (No MixColumns)
                        round_state <= sr_out ^ round_key;
                        state       <= S_DONE;
                    end
                end

                S_DONE: begin
                    block_out <= round_state;
                    busy      <= 1'b0;
                    done_irq  <= 1'b1;
                    state     <= S_IDLE;
                end
            endcase
        end
    end

    // Memory-mapped APB Register Access
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rdata       <= 32'd0;
            ready       <= 1'b0;
            block_in    <= 128'd0;
            cipher_key  <= 256'd0;
            key_256_sel <= 1'b0;
            start_pulse <= 1'b0;
        end else begin
            start_pulse <= 1'b0;
            if (req && !ready) begin
                if (wr) begin
                    case (addr[7:2])
                        6'h00: begin // Control
                            if (wdata[0]) start_pulse <= 1'b1;
                            key_256_sel <= wdata[2];
                        end
                        6'h04: block_in[31:0]    <= wdata;
                        6'h05: block_in[63:32]   <= wdata;
                        6'h06: block_in[95:64]   <= wdata;
                        6'h07: block_in[127:96]  <= wdata;
                        6'h08: cipher_key[31:0]  <= wdata;
                        6'h09: cipher_key[63:32] <= wdata;
                        6'h0A: cipher_key[95:64] <= wdata;
                        6'h0B: cipher_key[127:96]<= wdata;
                        6'h0C: cipher_key[159:128]<= wdata;
                        6'h0D: cipher_key[191:160]<= wdata;
                        6'h0E: cipher_key[223:192]<= wdata;
                        6'h0F: cipher_key[255:224]<= wdata;
                        default: ;
                    endcase
                end else begin
                    case (addr[7:2])
                        6'h00: rdata <= {29'd0, key_256_sel, done_irq, busy};
                        6'h10: rdata <= block_out[31:0];
                        6'h11: rdata <= block_out[63:32];
                        6'h12: rdata <= block_out[95:64];
                        6'h13: rdata <= block_out[127:96];
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
