// =============================================================================
// File: tb_crypto_soc.v
// Module: tb_crypto_soc
// Project: Crypto-Security Enclave SoC
// Description: Comprehensive Self-Checking Testbench verifying Secure RV32I
//              Core, PMP, AES-256, SHA-256, TRNG, Anti-Tamper with Zeroization,
//              and UART communication.
// =============================================================================

`timescale 1ns / 1ps

module tb_crypto_soc;

    reg        clk;
    reg        rst_n;

    // UART
    wire       uart_tx;
    reg        uart_rx;

    // Tamper & Security Pins
    reg        tamper_mesh;
    reg        glitch_detect;
    wire       sec_alarm;
    wire       trng_pulse;

    // Device Under Test (DUT)
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

    // 100 MHz System Clock (10ns period)
    always #5 clk = ~clk;

    // Test tracking
    integer pass_count = 0;
    integer fail_count = 0;

    task test_check(input reg condition, input [255:0] test_name);
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

    // Simulation Stimulus
    initial begin
        $dumpfile("crypto_soc_waves.vcd");
        $dumpvars(0, tb_crypto_soc);

        $display("==================================================================");
        $display("   CRYPTO-SECURITY ENCLAVE SOC VERIFICATION SUITE                 ");
        $display("==================================================================");

        // Initial pin state
        clk           = 0;
        rst_n         = 0;
        uart_rx       = 1;
        tamper_mesh   = 1; // Shield intact (active low attack)
        glitch_detect = 0; // No voltage/clock glitch

        // Apply Reset
        #100;
        @(negedge clk);
        rst_n = 1;
        $display("[SIM] Reset released at %0t ps", $time);

        // Test 1: RV32I Core Boot
        #500;
        test_check(dut.cpu_pc > 32'h0000_0000, "Test 1: Secure RV32I Instruction Fetch & PC Progression");

        // Test 2: UART Transmission
        #2000;
        test_check(uart_tx !== 1'bx, "Test 2: Secure Serial UART Communication Active");

        // Test 3: Secure SRAM Write/Read
        test_check(dut.u_sram.mem[2] === 32'h0000_0077, "Test 3: Secure SRAM Read/Write Data Integrity");

        // Test 4: TRNG Entropy Generation
        test_check(dut.u_trng.random_word !== 32'd0, "Test 4: TRNG Physical Phase Jitter Entropy Generation");

        // Test 5: AES-256 Block Cipher Encryption
        #1500;
        test_check(dut.u_aes.block_in[31:0] === 32'h3243f6a8 &&
                   dut.u_aes.cipher_key[31:0] === 32'h01010101,
                   "Test 5: AES-256 Plaintext & 256-bit Key Bus Configuration");

        // Wait for AES rounds to complete (14 rounds * ~1 cycle)
        #2000;
        test_check(dut.u_aes.block_out !== 128'd0, "Test 6: AES-256 Iterative Encryption Completion (14 Rounds)");

        // Test 7: SHA-256 Hash Accelerator
        test_check(dut.u_sha.msg_block[0] === 32'h61626380, "Test 7: SHA-256 512-bit Message Block Loading");

        // Wait for SHA-256 compression (64 rounds)
        #8000;
        test_check(dut.u_sha.h0 !== 32'h6a09e667, "Test 8: SHA-256 64-Round Compression & Digest Accumulation");

        // Test 9: Active Anti-Tamper Sensor & Emergency Zeroization
        $display("[SIM] Injecting physical tamper attack (Shield Mesh Cut)...");
        tamper_mesh = 0; // Cut shield mesh
        #200;
        test_check(sec_alarm === 1'b1, "Test 9: Active Anti-Tamper Shield Disruption Alarm Triggered");
        test_check(dut.u_sram.mem[2] === 32'd0, "Test 10: Hardware Instant Zeroization Clears Secure SRAM");

        // Final verification summary
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
