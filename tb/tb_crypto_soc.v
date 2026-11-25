// =============================================================================
// File: tb_crypto_soc.v
// Module: tb_crypto_soc
// Project: Crypto-Security Enclave SoC
// Description: FIPS-197 AES-128 & FIPS 180-4 SHA-256 KAT Self-Checking Testbench.
// =============================================================================

`timescale 1ns / 1ps

module tb_crypto_soc;

    reg        clk;
    reg        rst_n;
    wire       uart_tx;
    reg        uart_rx;
    reg        tamper_mesh;
    reg        glitch_detect;
    wire       sec_alarm;
    wire       trng_pulse;

    crypto_soc_top dut (
        .pad_clk          (clk),
        .pad_rst_n        (rst_n),
        .pad_uart_tx      (uart_tx),
        .pad_uart_rx      (uart_rx),
        .pad_tamper_mesh  (tamper_mesh),
        .pad_glitch_detect(glitch_detect),
        .pad_sec_alarm    (sec_alarm),
        .pad_trng_pulse   (trng_pulse)
    );

    always #5 clk = ~clk; // 100 MHz

    integer pass_count = 0;
    integer fail_count = 0;

    task test_check(input reg condition, input [80*8-1:0] test_name);
    begin
        if (condition) begin
            $display("[PASS] %0s", test_name);
            pass_count = pass_count + 1;
        end else begin
            $display("[FAIL] %0s", test_name);
            fail_count = fail_count + 1;
        end
    end
    endtask

    // Real External UART Serial Bit-Stream Decoder (baud_div=2 -> 30 ns/bit)
    localparam integer UART_BIT_NS = 30;
    reg [7:0] uart_bytes [0:15];
    integer   uart_cnt = 0;
    reg [7:0] rx_byte;
    integer   b;

    initial begin
        forever begin
            @(negedge uart_tx);
            if (rst_n) begin
                #(UART_BIT_NS / 2);
                if (uart_tx == 1'b0) begin
                    for (b = 0; b < 8; b = b + 1) begin
                        #(UART_BIT_NS);
                        rx_byte[b] = uart_tx;
                    end
                    #(UART_BIT_NS);
                    if (uart_cnt < 16) begin
                        uart_bytes[uart_cnt] = rx_byte;
                        uart_cnt = uart_cnt + 1;
                    end
                end
            end
        end
    end

    reg [8*3-1:0] captured_uart;

    initial begin
        $dumpfile("sim/crypto_soc_waves.vcd");
        $dumpvars(0, tb_crypto_soc);

        $display("==================================================================");
        $display("   CRYPTO-SECURITY ENCLAVE SOC VERIFICATION SUITE (KAT VERIFIED)");
        $display("==================================================================");

        clk           = 0;
        rst_n         = 0;
        uart_rx       = 1;
        tamper_mesh   = 1;
        glitch_detect = 0;

        #100 @(negedge clk) rst_n = 1;

        #500;
        test_check(dut.cpu_pc > 32'h0000_0000, "Test 1: Secure RV32I Instruction Fetch & PC Progression");

        #5000;
        captured_uart = (uart_cnt >= 3) ? {uart_bytes[0], uart_bytes[1], uart_bytes[2]} : 24'd0;
        test_check(captured_uart == "SEC", "Test 2: External pad_uart_tx Serial Pin Decoded (\"SEC\")");

        test_check(dut.u_sram.mem[2] === 32'h0000_0077, "Test 3: Secure SRAM Read/Write Integrity (0x77)");
        test_check(dut.u_trng.random_word !== 32'd0, "Test 4: TRNG Physical Phase Jitter Entropy Active");

        // Exact NIST FIPS-197 Appendix C.1 AES-128 Expected Ciphertext:
        // CT = 69c4e0d8 6a7b0430 d8cdb780 70b4c55a -> LSB-first words: {5ac5b470, 80b7cdd8, 30047b6a, d8e0c469}
        test_check(
            dut.u_aes.block_in === 128'hFFEEDDCC_BBAA9988_77665544_33221100 &&
            dut.u_aes.cipher_key[127:0] === 128'h0F0E0D0C_0B0A0908_07060504_03020100,
            "Test 5: AES-128 FIPS-197 KAT Input & Key Loaded"
        );

        #2000;
        test_check(
            dut.u_aes.block_out === 128'h5AC5B470_80B7CDD8_30047B6A_D8E0C469,
            "Test 6: AES-128 FIPS-197 Ciphertext Exact Match (69c4e0d8..70b4c55a)"
        );

        test_check(
            dut.u_sha.msg_block[0] === 32'h61626380 && dut.u_sha.msg_block[15] === 32'h00000018,
            "Test 7: SHA-256 512-bit Padded Block (\"abc\", len=24) Loaded"
        );

        #8000;
        test_check(
            {dut.u_sha.h0, dut.u_sha.h1, dut.u_sha.h2, dut.u_sha.h3,
             dut.u_sha.h4, dut.u_sha.h5, dut.u_sha.h6, dut.u_sha.h7} ===
            256'hBA7816BF_8F01CFEA_414140DE_5DAE2223_B00361A3_96177A9C_B410FF61_F20015AD,
            "Test 8: SHA-256(\"abc\") FIPS 180-4 Digest Exact Match"
        );

        $display("[SIM] Injecting physical tamper attack (Shield Mesh Cut)...");
        tamper_mesh = 0;
        #200;
        test_check(sec_alarm === 1'b1, "Test 9: Active Anti-Tamper Shield Disruption Alarm Triggered");
        test_check(dut.u_sram.mem[2] === 32'd0, "Test 10: Hardware Instant Zeroization Clears Secure SRAM");

        #500;
        $display("==================================================================");
        $display("   VERIFICATION SUMMARY: %0d PASSED, %0d FAILED", pass_count, fail_count);
        $display("==================================================================");

        if (fail_count == 0) begin
            $display("[STATUS] CRYPTO-SECURITY SOC VERIFICATION: 100%% PASSED");
        end else begin
            $display("[STATUS] CRYPTO-SECURITY SOC VERIFICATION: FAILED");
        end

        $finish;
    end

endmodule
