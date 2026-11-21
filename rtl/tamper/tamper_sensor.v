// =============================================================================
// File: tamper_sensor.v
// Module: tamper_sensor
// Project: Crypto-Security Enclave SoC
// Description: Active Anti-Tamper Detection Module. Monitors clock glitching,
//              voltage dips, and physical shield mesh disruption. Triggers
//              instant zeroization of secure keys and on-chip SRAM.
// =============================================================================

`timescale 1ns / 1ps

module tamper_sensor (
    input  wire        clk,
    input  wire        rst_n,

    // Bus Slave Interface
    input  wire        req,
    input  wire        wr,
    input  wire [31:0] addr,
    input  wire [31:0] wdata,
    output reg  [31:0] rdata,
    output reg         ready,

    // External Tamper Pins
    input  wire        tamper_mesh_pin,
    input  wire        glitch_detect_pin,

    // Hardware Emergency Response
    output reg         zeroize_pulse,
    output reg         tamper_alarm_irq
);

    reg tamper_mesh_sync;
    reg glitch_detect_sync;
    reg tamper_latched;
    reg tamper_en;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            tamper_mesh_sync   <= 1'b1;
            glitch_detect_sync <= 1'b0;
            tamper_latched     <= 1'b0;
            tamper_en          <= 1'b1;
            zeroize_pulse      <= 1'b0;
            tamper_alarm_irq   <= 1'b0;
        end else begin
            tamper_mesh_sync   <= tamper_mesh_pin;
            glitch_detect_sync <= glitch_detect_pin;
            zeroize_pulse      <= 1'b0;

            if (tamper_en) begin
                // Mesh broken (went low) or voltage glitch detected (went high)
                if (!tamper_mesh_sync || glitch_detect_sync) begin
                    tamper_latched   <= 1'b1;
                    zeroize_pulse    <= 1'b1; // Trigger hardware zeroization
                    tamper_alarm_irq <= 1'b1;
                end
            end
        end
    end

    // Memory-mapped interface
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rdata <= 32'd0;
            ready <= 1'b0;
        end else begin
            if (req && !ready) begin
                if (wr) begin
                    if (addr[3:2] == 2'b00) begin
                        tamper_en <= wdata[0];
                        if (wdata[1]) tamper_latched <= 1'b0; // Clear latched status
                    end
                end else begin
                    case (addr[3:2])
                        2'b00: rdata <= {30'd0, tamper_latched, tamper_en};
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
