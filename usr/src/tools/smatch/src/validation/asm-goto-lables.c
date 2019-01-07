static inline int __static_cpu_has(unsigned char bit)
{
       asm goto("1: jmp %l[t_no]\n"
                "2:\n"
                ".section .altinstructions,\"a\"\n"
                "\n"
                "1b\n"
                "0\n"         /* no replacement */
                " .byte %P0\n"         /* feature bit */
                " .byte 2b - 1b\n"     /* source len */
                " .byte 0\n"           /* replacement len */
                " .byte 0xff + 0 - (2b-1b)\n"  /* padding */
                ".previous\n"
                : : "i" (bit) : : t_no, ble);
       return 1;
t_no:
       return 0;
}
/*
 *  check-name: Asm with goto labels.
 */

