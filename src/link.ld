/* file: link.ld */
ENTRY(z_start)

SECTIONS
{
  . = 0x300000;

  .text : {
    *(.text .text.*)
  }

  .rodata : {
    *(.rodata .rodata.*)
  }

  .data : {
    *(.data .data.*)
  }

  .bss : {
    *(.bss .bss.*)
    *(COMMON)
  }

  /DISCARD/ : {
    *(.eh_frame)
    *(.note*)
  }
}
