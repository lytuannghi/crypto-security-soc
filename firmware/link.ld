/* =============================================================================
 * File: link.ld
 * Project: Crypto-Security Enclave SoC
 * Description: Linker script mapping text to 8KB Secure ROM and data to 16KB SRAM
 * ============================================================================= */

MEMORY
{
    ROM (rx)  : ORIGIN = 0x00000000, LENGTH = 8K
    RAM (rwx) : ORIGIN = 0x10000000, LENGTH = 16K
}

ENTRY(_start)

SECTIONS
{
    .text : {
        . = ALIGN(4);
        *(.text.init)
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
    } > ROM

    .data : {
        . = ALIGN(4);
        _data_start = .;
        *(.data*)
        *(.sdata*)
        . = ALIGN(4);
        _data_end = .;
    } > RAM AT > ROM

    .bss : {
        . = ALIGN(4);
        _bss_start = .;
        *(.bss*)
        *(.sbss*)
        *(COMMON)
        . = ALIGN(4);
        _bss_end = .;
    } > RAM
}
