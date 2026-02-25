/* Example linker script for a Cortex-M4 target (vuln_demo) */

_stack_size = 0x800;  /* 2KB stack */
_heap_size  = 0x1000; /* 4KB heap  */

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 256K
    RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 20K
}

SECTIONS
{
    .text :
    {
        *(.text*)
    } > FLASH

    .data :
    {
        *(.data*)
    } > RAM AT > FLASH

    .bss :
    {
        *(.bss*)
    } > RAM

    ._stack (NOLOAD) :
    {
        . = ALIGN(8);
        . = . + _stack_size;
        . = ALIGN(8);
    } > RAM

    ._heap (NOLOAD) :
    {
        . = ALIGN(8);
        . = . + _heap_size;
        . = ALIGN(8);
    } > RAM
}
