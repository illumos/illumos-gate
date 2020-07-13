/* Created by build_access.py */
/* returns string of length 0 if invalid arg */
const char * dwarf_get_elf_relocname_mips(unsigned long);
#ifndef R_MIPS_NONE
#define R_MIPS_NONE          0
#endif /* R_MIPS_NONE */
#ifndef R_MIPS_16
#define R_MIPS_16            1
#endif /* R_MIPS_16 */
#ifndef R_MIPS_32
#define R_MIPS_32            2
#endif /* R_MIPS_32 */
#ifndef R_MIPS_REL
#define R_MIPS_REL           3
#endif /* R_MIPS_REL */
#ifndef R_MIPS_26
#define R_MIPS_26            4
#endif /* R_MIPS_26 */
#ifndef R_MIPS_HI16
#define R_MIPS_HI16          5
#endif /* R_MIPS_HI16 */
#ifndef R_MIPS_LO16
#define R_MIPS_LO16          6
#endif /* R_MIPS_LO16 */
#ifndef R_MIPS_GPREL
#define R_MIPS_GPREL         7
#endif /* R_MIPS_GPREL */
#ifndef R_MIPS_LITERAL
#define R_MIPS_LITERAL       8
#endif /* R_MIPS_LITERAL */
#ifndef R_MIPS_GOT
#define R_MIPS_GOT           9
#endif /* R_MIPS_GOT */
#ifndef R_MIPS_PC16
#define R_MIPS_PC16          10
#endif /* R_MIPS_PC16 */
#ifndef R_MIPS_CALL
#define R_MIPS_CALL          11
#endif /* R_MIPS_CALL */
#ifndef R_MIPS_GPREL32
#define R_MIPS_GPREL32       12
#endif /* R_MIPS_GPREL32 */
#ifndef R_MIPS_UNUSED1
#define R_MIPS_UNUSED1       13
#endif /* R_MIPS_UNUSED1 */
#ifndef R_MIPS_UNUSED2
#define R_MIPS_UNUSED2       14
#endif /* R_MIPS_UNUSED2 */
#ifndef R_MIPS_UNUSED3
#define R_MIPS_UNUSED3       15
#endif /* R_MIPS_UNUSED3 */
#ifndef R_MIPS_SHIFT5
#define R_MIPS_SHIFT5        16
#endif /* R_MIPS_SHIFT5 */
#ifndef R_MIPS_SHIFT6
#define R_MIPS_SHIFT6        17
#endif /* R_MIPS_SHIFT6 */
#ifndef R_MIPS_64
#define R_MIPS_64            18
#endif /* R_MIPS_64 */
#ifndef R_MIPS_GOT_DISP
#define R_MIPS_GOT_DISP      19
#endif /* R_MIPS_GOT_DISP */
#ifndef R_MIPS_GOT_PAGE
#define R_MIPS_GOT_PAGE      20
#endif /* R_MIPS_GOT_PAGE */
#ifndef R_MIPS_GOT_OFST
#define R_MIPS_GOT_OFST      21
#endif /* R_MIPS_GOT_OFST */
#ifndef R_MIPS_GOT_HI16
#define R_MIPS_GOT_HI16      22
#endif /* R_MIPS_GOT_HI16 */
#ifndef R_MIPS_GOT_LO16
#define R_MIPS_GOT_LO16      23
#endif /* R_MIPS_GOT_LO16 */
#ifndef R_MIPS_SUB
#define R_MIPS_SUB           24
#endif /* R_MIPS_SUB */
#ifndef R_MIPS_INSERT_A
#define R_MIPS_INSERT_A      25
#endif /* R_MIPS_INSERT_A */
#ifndef R_MIPS_INSERT_B
#define R_MIPS_INSERT_B      26
#endif /* R_MIPS_INSERT_B */
#ifndef R_MIPS_DELETE
#define R_MIPS_DELETE        27
#endif /* R_MIPS_DELETE */
#ifndef R_MIPS_HIGHER
#define R_MIPS_HIGHER        28
#endif /* R_MIPS_HIGHER */
#ifndef R_MIPS_HIGHEST
#define R_MIPS_HIGHEST       29
#endif /* R_MIPS_HIGHEST */
#ifndef R_MIPS_CALL_HI16
#define R_MIPS_CALL_HI16     30
#endif /* R_MIPS_CALL_HI16 */
#ifndef R_MIPS_CALL_LO16
#define R_MIPS_CALL_LO16     31
#endif /* R_MIPS_CALL_LO16 */
#ifndef R_MIPS_SCN_DISP
#define R_MIPS_SCN_DISP      32
#endif /* R_MIPS_SCN_DISP */
#ifndef R_MIPS_REL16
#define R_MIPS_REL16         33
#endif /* R_MIPS_REL16 */
#ifndef R_MIPS_ADD_IMMEDIATE
#define R_MIPS_ADD_IMMEDIATE 34
#endif /* R_MIPS_ADD_IMMEDIATE */
#ifndef R_MIPS_PJUMP
#define R_MIPS_PJUMP         35
#endif /* R_MIPS_PJUMP */
#ifndef R_MIPS_RELGOT
#define R_MIPS_RELGOT        36
#endif /* R_MIPS_RELGOT */
#ifndef R_MIPS_JALR
#define R_MIPS_JALR          37
#endif /* R_MIPS_JALR */
#ifndef R_MIPS_TLS_DTPMOD32
#define R_MIPS_TLS_DTPMOD32  38
#endif /* R_MIPS_TLS_DTPMOD32 */
#ifndef R_MIPS_TLS_DTPREL32
#define R_MIPS_TLS_DTPREL32  39
#endif /* R_MIPS_TLS_DTPREL32 */
#ifndef R_MIPS_TLS_DTPMOD64
#define R_MIPS_TLS_DTPMOD64  40
#endif /* R_MIPS_TLS_DTPMOD64 */
#ifndef R_MIPS_TLS_DTPREL64
#define R_MIPS_TLS_DTPREL64  41
#endif /* R_MIPS_TLS_DTPREL64 */
#ifndef R_MIPS_TLS_GD
#define R_MIPS_TLS_GD        42
#endif /* R_MIPS_TLS_GD */
#ifndef R_MIPS_TLS_LDM
#define R_MIPS_TLS_LDM       43
#endif /* R_MIPS_TLS_LDM */
#ifndef R_MIPS_TLS_DTPREL_HI16
#define R_MIPS_TLS_DTPREL_HI16 44
#endif /* R_MIPS_TLS_DTPREL_HI16 */
#ifndef R_MIPS_TLS_DTPREL_LO16
#define R_MIPS_TLS_DTPREL_LO16 45
#endif /* R_MIPS_TLS_DTPREL_LO16 */
#ifndef R_MIPS_TLS_GOTTPREL
#define R_MIPS_TLS_GOTTPREL  46
#endif /* R_MIPS_TLS_GOTTPREL */
#ifndef R_MIPS_TLS_TPREL32
#define R_MIPS_TLS_TPREL32   47
#endif /* R_MIPS_TLS_TPREL32 */
#ifndef R_MIPS_TLS_TPREL_HI16
#define R_MIPS_TLS_TPREL_HI16 49
#endif /* R_MIPS_TLS_TPREL_HI16 */
#ifndef R_MIPS_TLS_TPREL_LO16
#define R_MIPS_TLS_TPREL_LO16 50
#endif /* R_MIPS_TLS_TPREL_LO16 */
#ifndef R_MIPS_GLOB_DAT
#define R_MIPS_GLOB_DAT      51
#endif /* R_MIPS_GLOB_DAT */
#ifndef R_MIPS_COPY
#define R_MIPS_COPY          126
#endif /* R_MIPS_COPY */
#ifndef R_MIPS_JUMP_SLOT
#define R_MIPS_JUMP_SLOT     127
#endif /* R_MIPS_JUMP_SLOT */
#ifndef R_MIPS_NUM
#define R_MIPS_NUM           128
#endif /* R_MIPS_NUM */
