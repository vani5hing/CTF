SECTIONS
{
  . = ALIGN(0x10000);
  .safezone ALIGN(0x10000) : { *(.safezone) }
}
INSERT AFTER .text;
