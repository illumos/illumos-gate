/* Created by build_access.py */
/* returns string of length 0 if invalid arg */
const char * dwarf_get_elf_relocname_x86_64(unsigned long);
#ifndef R_X86_64_NONE
#define R_X86_64_NONE        0
#endif /* R_X86_64_NONE */
#ifndef R_X86_64_64
#define R_X86_64_64          1
#endif /* R_X86_64_64 */
#ifndef R_X86_64_PC32
#define R_X86_64_PC32        2
#endif /* R_X86_64_PC32 */
#ifndef R_X86_64_GOT32
#define R_X86_64_GOT32       3
#endif /* R_X86_64_GOT32 */
#ifndef R_X86_64_PLT32
#define R_X86_64_PLT32       4
#endif /* R_X86_64_PLT32 */
#ifndef R_X86_64_COPY
#define R_X86_64_COPY        5
#endif /* R_X86_64_COPY */
#ifndef R_X86_64_GLOB_DAT
#define R_X86_64_GLOB_DAT    6
#endif /* R_X86_64_GLOB_DAT */
#ifndef R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT   7
#endif /* R_X86_64_JUMP_SLOT */
#ifndef R_X86_64_RELATIVE
#define R_X86_64_RELATIVE    8
#endif /* R_X86_64_RELATIVE */
#ifndef R_X86_64_GOTPCREL
#define R_X86_64_GOTPCREL    9
#endif /* R_X86_64_GOTPCREL */
#ifndef R_X86_64_32
#define R_X86_64_32          10
#endif /* R_X86_64_32 */
#ifndef R_X86_64_32S
#define R_X86_64_32S         11
#endif /* R_X86_64_32S */
#ifndef R_X86_64_16
#define R_X86_64_16          12
#endif /* R_X86_64_16 */
#ifndef R_X86_64_PC16
#define R_X86_64_PC16        13
#endif /* R_X86_64_PC16 */
#ifndef R_X86_64_8
#define R_X86_64_8           14
#endif /* R_X86_64_8 */
#ifndef R_X86_64_PC8
#define R_X86_64_PC8         15
#endif /* R_X86_64_PC8 */
#ifndef R_X86_64_DTPMOD64
#define R_X86_64_DTPMOD64    16
#endif /* R_X86_64_DTPMOD64 */
#ifndef R_X86_64_DTPOFF64
#define R_X86_64_DTPOFF64    17
#endif /* R_X86_64_DTPOFF64 */
#ifndef R_X86_64_TPOFF64
#define R_X86_64_TPOFF64     18
#endif /* R_X86_64_TPOFF64 */
#ifndef R_X86_64_TLSGD
#define R_X86_64_TLSGD       19
#endif /* R_X86_64_TLSGD */
#ifndef R_X86_64_TLSLD
#define R_X86_64_TLSLD       20
#endif /* R_X86_64_TLSLD */
#ifndef R_X86_64_DTPOFF32
#define R_X86_64_DTPOFF32    21
#endif /* R_X86_64_DTPOFF32 */
#ifndef R_X86_64_GOTTPOFF
#define R_X86_64_GOTTPOFF    22
#endif /* R_X86_64_GOTTPOFF */
#ifndef R_X86_64_TPOFF32
#define R_X86_64_TPOFF32     23
#endif /* R_X86_64_TPOFF32 */
#ifndef R_X86_64_PC64
#define R_X86_64_PC64        24
#endif /* R_X86_64_PC64 */
#ifndef R_X86_64_GOTOFF64
#define R_X86_64_GOTOFF64    25
#endif /* R_X86_64_GOTOFF64 */
#ifndef R_X86_64_GOTPC32
#define R_X86_64_GOTPC32     26
#endif /* R_X86_64_GOTPC32 */
#ifndef R_X86_64_GOT64
#define R_X86_64_GOT64       27
#endif /* R_X86_64_GOT64 */
#ifndef R_X86_64_GOTPCREL64
#define R_X86_64_GOTPCREL64  28
#endif /* R_X86_64_GOTPCREL64 */
#ifndef R_X86_64_GOTPC64
#define R_X86_64_GOTPC64     29
#endif /* R_X86_64_GOTPC64 */
#ifndef R_X86_64_GOTPLT64
#define R_X86_64_GOTPLT64    30
#endif /* R_X86_64_GOTPLT64 */
#ifndef R_X86_64_PLTOFF64
#define R_X86_64_PLTOFF64    31
#endif /* R_X86_64_PLTOFF64 */
#ifndef R_X86_64_SIZE32
#define R_X86_64_SIZE32      32
#endif /* R_X86_64_SIZE32 */
#ifndef R_X86_64_SIZE64
#define R_X86_64_SIZE64      33
#endif /* R_X86_64_SIZE64 */
#ifndef R_X86_64_GOTPC32_TLSDESC
#define R_X86_64_GOTPC32_TLSDESC 34
#endif /* R_X86_64_GOTPC32_TLSDESC */
#ifndef R_X86_64_TLSDESC_CALL
#define R_X86_64_TLSDESC_CALL 35
#endif /* R_X86_64_TLSDESC_CALL */
#ifndef R_X86_64_TLSDESC
#define R_X86_64_TLSDESC     36
#endif /* R_X86_64_TLSDESC */
#ifndef R_X86_64_IRELATIVE
#define R_X86_64_IRELATIVE   37
#endif /* R_X86_64_IRELATIVE */
#ifndef R_X86_64_RELATIVE64
#define R_X86_64_RELATIVE64  38
#endif /* R_X86_64_RELATIVE64 */
#ifndef R_X86_64_GOTPCRELX
#define R_X86_64_GOTPCRELX   41
#endif /* R_X86_64_GOTPCRELX */
#ifndef R_X86_64_REX_GOTPCRELX
#define R_X86_64_REX_GOTPCRELX 42
#endif /* R_X86_64_REX_GOTPCRELX */
