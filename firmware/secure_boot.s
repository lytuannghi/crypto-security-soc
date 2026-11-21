/* =============================================================================
 * File: secure_boot.s
 * Project: Crypto-Security Enclave SoC
 * Description: RISC-V RV32I Reset Vector and Secure Runtime Initialization
 * ============================================================================= */

.section .text.init
.globl _start

_start:
    /* Disable interrupts */
    csrw mie, zero

    /* Set up stack pointer to top of 16KB Secure SRAM (0x1000_0000 + 0x4000) */
    li sp, 0x10003FF0

    /* Clear BSS section */
    la a0, _bss_start
    la a1, _bss_end
clear_bss_loop:
    bge a0, a1, clear_bss_done
    sw zero, 0(a0)
    addi a0, a0, 4
    j clear_bss_loop

clear_bss_done:
    /* Call secure main entry point */
    call main

trap_loop:
    wfi
    j trap_loop
