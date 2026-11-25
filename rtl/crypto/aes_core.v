// =============================================================================
// File: aes_core.v
// Module: aes_core
// Project: Crypto-Security Enclave SoC
// Description: FIPS-197 Compliant Hardware AES-128 / AES-256 Block Cipher.
//              Implements SubBytes, ShiftRows, MixColumns, AddRoundKey, and
//              on-the-fly FIPS-197 RotWord/SubWord/Rcon KeyExpansion.
// =============================================================================

`timescale 1ns / 1ps

module aes_core (
    input  wire        clk,
    input  wire        rst_n,

    input  wire        req,
    input  wire        wr,
    input  wire [31:0] addr,
    input  wire [31:0] wdata,
    output reg  [31:0] rdata,
    output reg         ready,

    output reg         done_irq
);

    reg [127:0] block_in;
    reg [255:0] cipher_key;
    reg [127:0] block_out;
    reg         key_256_sel; // 0 = AES-128 (10 rounds), 1 = AES-256 (14 rounds)
    reg         busy;
    reg         start_pulse;

    localparam S_IDLE  = 2'b00;
    localparam S_ROUND = 2'b01;
    localparam S_DONE  = 2'b10;

    reg [1:0]   state;
    reg [3:0]   round_cnt;
    reg [3:0]   max_rounds;
    reg [127:0] round_state;
    reg [127:0] rk_lo;
    reg [127:0] rk_hi;

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

    // ShiftRows (column-major byte layout: byte i -> [i*8 +: 8])
    wire [127:0] sr_out;
    assign sr_out[0*8 +: 8]   = sb_out[0*8 +: 8];
    assign sr_out[4*8 +: 8]   = sb_out[4*8 +: 8];
    assign sr_out[8*8 +: 8]   = sb_out[8*8 +: 8];
    assign sr_out[12*8 +: 8]  = sb_out[12*8 +: 8];

    assign sr_out[1*8 +: 8]   = sb_out[5*8 +: 8];
    assign sr_out[5*8 +: 8]   = sb_out[9*8 +: 8];
    assign sr_out[9*8 +: 8]   = sb_out[13*8 +: 8];
    assign sr_out[13*8 +: 8]  = sb_out[1*8 +: 8];

    assign sr_out[2*8 +: 8]   = sb_out[10*8 +: 8];
    assign sr_out[6*8 +: 8]   = sb_out[14*8 +: 8];
    assign sr_out[10*8 +: 8]  = sb_out[2*8 +: 8];
    assign sr_out[14*8 +: 8]  = sb_out[6*8 +: 8];

    assign sr_out[3*8 +: 8]   = sb_out[15*8 +: 8];
    assign sr_out[7*8 +: 8]   = sb_out[3*8 +: 8];
    assign sr_out[11*8 +: 8]  = sb_out[7*8 +: 8];
    assign sr_out[15*8 +: 8]  = sb_out[11*8 +: 8];

    // MixColumns
    function [7:0] xtime(input [7:0] b);
        xtime = {b[6:0], 1'b0} ^ (b[7] ? 8'h1b : 8'h00);
    endfunction

    function [31:0] mix_single_col(input [31:0] col);
        reg [7:0] a0, a1, a2, a3;
        reg [7:0] r0, r1, r2, r3;
        begin
            a0 = col[7:0];   a1 = col[15:8];
            a2 = col[23:16]; a3 = col[31:24];
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

    // -------------------------------------------------------------------------
    // FIPS-197 KeyExpansion Core (RotWord + SubWord + Rcon)
    // -------------------------------------------------------------------------
    function [7:0] get_rcon(input [3:0] r);
        case (r)
            4'd1:  get_rcon = 8'h01;
            4'd2:  get_rcon = 8'h02;
            4'd3:  get_rcon = 8'h04;
            4'd4:  get_rcon = 8'h08;
            4'd5:  get_rcon = 8'h10;
            4'd6:  get_rcon = 8'h20;
            4'd7:  get_rcon = 8'h40;
            4'd8:  get_rcon = 8'h80;
            4'd9:  get_rcon = 8'h1B;
            4'd10: get_rcon = 8'h36;
            default: get_rcon = 8'h00;
        endcase
    endfunction

    // AES-128 uses rk_lo and rcon(round_cnt).
    // AES-256 alternates: odd rounds (1,3..13) use rk_hi & compute next even
    // into rk_lo from rk_hi[127:96] with RotWord+Rcon(round_cnt>>1 + 1);
    // even rounds (2,4..14) use rk_lo & compute next odd into rk_hi using SubWord(rk_lo[127:96]).
    wire is_256_even = key_256_sel && !round_cnt[0];
    wire [31:0] prev_w3 = key_256_sel ? (round_cnt[0] ? rk_hi[127:96] : rk_lo[127:96]) : rk_lo[127:96];
    wire [31:0] g_word_in = is_256_even ? prev_w3 : {prev_w3[7:0], prev_w3[31:8]};

    wire [31:0] g_word_sub;
    genvar k;
    generate
        for (k = 0; k < 4; k = k + 1) begin : GEN_KEXP_SBOX
            aes_sbox u_kexp_sbox (
                .in_byte (g_word_in[k*8 +: 8]),
                .out_byte(g_word_sub[k*8 +: 8])
            );
        end
    endgenerate

    wire [3:0] rcon_idx = key_256_sel ? ((round_cnt + 4'd1) >> 1) : round_cnt;
    wire [7:0] rcon_byte = is_256_even ? 8'h00 : get_rcon(rcon_idx);
    wire [127:0] base_rk = is_256_even ? rk_hi : rk_lo;

    wire [31:0] nw0 = base_rk[31:0]   ^ g_word_sub ^ {24'h000000, rcon_byte};
    wire [31:0] nw1 = base_rk[63:32]  ^ nw0;
    wire [31:0] nw2 = base_rk[95:64]  ^ nw1;
    wire [31:0] nw3 = base_rk[127:96] ^ nw2;
    wire [127:0] next_rk_block = {nw3, nw2, nw1, nw0};

    // Active round key applied during current round_cnt (1..max_rounds)
    wire [127:0] active_rk = key_256_sel ? (round_cnt[0] ? rk_hi : rk_lo) : next_rk_block;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= S_IDLE;
            busy        <= 1'b0;
            done_irq    <= 1'b0;
            round_cnt   <= 4'd0;
            round_state <= 128'd0;
            block_out   <= 128'd0;
            rk_lo       <= 128'd0;
            rk_hi       <= 128'd0;
            max_rounds  <= 4'd10;
        end else begin
            case (state)
                S_IDLE: begin
                    done_irq <= 1'b0;
                    if (start_pulse) begin
                        busy        <= 1'b1;
                        round_cnt   <= 4'd1;
                        max_rounds  <= key_256_sel ? 4'd14 : 4'd10;
                        rk_lo       <= cipher_key[127:0];
                        rk_hi       <= cipher_key[255:128];
                        round_state <= block_in ^ cipher_key[127:0];
                        state       <= S_ROUND;
                    end else begin
                        busy <= 1'b0;
                    end
                end

                S_ROUND: begin
                    if (round_cnt < max_rounds) begin
                        round_state <= mc_out ^ active_rk;
                        if (!key_256_sel) begin
                            rk_lo <= next_rk_block;
                        end else if (round_cnt[0]) begin
                            rk_lo <= next_rk_block;
                        end else begin
                            rk_hi <= next_rk_block;
                        end
                        round_cnt <= round_cnt + 1'b1;
                    end else begin
                        round_state <= sr_out ^ active_rk;
                        state       <= S_DONE;
                    end
                end

                S_DONE: begin
                    block_out <= round_state;
                    busy      <= 1'b0;
                    done_irq  <= 1'b1;
                    state     <= S_IDLE;
                end

                default: state <= S_IDLE;
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
                        6'h00: begin
                            if (wdata[0]) start_pulse <= 1'b1;
                            key_256_sel <= wdata[2];
                        end
                        6'h04: block_in[31:0]     <= wdata;
                        6'h05: block_in[63:32]    <= wdata;
                        6'h06: block_in[95:64]    <= wdata;
                        6'h07: block_in[127:96]   <= wdata;
                        6'h08: cipher_key[31:0]   <= wdata;
                        6'h09: cipher_key[63:32]  <= wdata;
                        6'h0A: cipher_key[95:64]  <= wdata;
                        6'h0B: cipher_key[127:96] <= wdata;
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
