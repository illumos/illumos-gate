/* Created by build_access.py */
/* returns string of length 0 if invalid arg */
const char * dwarf_get_elf_relocname_arm(unsigned long);
#ifndef R_ARM_NONE
#define R_ARM_NONE           0
#endif /* R_ARM_NONE */
#ifndef R_ARM_PC24
#define R_ARM_PC24           1
#endif /* R_ARM_PC24 */
#ifndef R_ARM_ABS32
#define R_ARM_ABS32          2
#endif /* R_ARM_ABS32 */
#ifndef R_ARM_REL32
#define R_ARM_REL32          3
#endif /* R_ARM_REL32 */
#ifndef R_ARM_LDR_PC_G0
#define R_ARM_LDR_PC_G0      4
#endif /* R_ARM_LDR_PC_G0 */
#ifndef R_ARM_ABS16
#define R_ARM_ABS16          5
#endif /* R_ARM_ABS16 */
#ifndef R_ARM_ABS12
#define R_ARM_ABS12          6
#endif /* R_ARM_ABS12 */
#ifndef R_ARM_THM_ABS5
#define R_ARM_THM_ABS5       7
#endif /* R_ARM_THM_ABS5 */
#ifndef R_ARM_ABS8
#define R_ARM_ABS8           8
#endif /* R_ARM_ABS8 */
#ifndef R_ARM_SBREL32
#define R_ARM_SBREL32        9
#endif /* R_ARM_SBREL32 */
#ifndef R_ARM_THM_CALL
#define R_ARM_THM_CALL       10
#endif /* R_ARM_THM_CALL */
#ifndef R_ARM_THM_PC8
#define R_ARM_THM_PC8        11
#endif /* R_ARM_THM_PC8 */
#ifndef R_ARM_BREL_ADJ
#define R_ARM_BREL_ADJ       12
#endif /* R_ARM_BREL_ADJ */
#ifndef R_ARM_TLS_DESC
#define R_ARM_TLS_DESC       13
#endif /* R_ARM_TLS_DESC */
#ifndef R_ARM_THM_SWI8
#define R_ARM_THM_SWI8       14
#endif /* R_ARM_THM_SWI8 */
#ifndef R_ARM_XPC25
#define R_ARM_XPC25          15
#endif /* R_ARM_XPC25 */
#ifndef R_ARM_THM_XPC22
#define R_ARM_THM_XPC22      16
#endif /* R_ARM_THM_XPC22 */
#ifndef R_ARM_TLS_DTPMOD32
#define R_ARM_TLS_DTPMOD32   17
#endif /* R_ARM_TLS_DTPMOD32 */
#ifndef R_ARM_TLS_DTPOFF32
#define R_ARM_TLS_DTPOFF32   18
#endif /* R_ARM_TLS_DTPOFF32 */
#ifndef R_ARM_TLS_TPOFF32
#define R_ARM_TLS_TPOFF32    19
#endif /* R_ARM_TLS_TPOFF32 */
#ifndef R_ARM_COPY
#define R_ARM_COPY           20
#endif /* R_ARM_COPY */
#ifndef R_ARM_GLOB_DAT
#define R_ARM_GLOB_DAT       21
#endif /* R_ARM_GLOB_DAT */
#ifndef R_ARM_JUMP_SLOT
#define R_ARM_JUMP_SLOT      22
#endif /* R_ARM_JUMP_SLOT */
#ifndef R_ARM_RELATIVE
#define R_ARM_RELATIVE       23
#endif /* R_ARM_RELATIVE */
#ifndef R_ARM_GOTOFF32
#define R_ARM_GOTOFF32       24
#endif /* R_ARM_GOTOFF32 */
#ifndef R_ARM_BASE_PREL
#define R_ARM_BASE_PREL      25
#endif /* R_ARM_BASE_PREL */
#ifndef R_ARM_GOT_BREL
#define R_ARM_GOT_BREL       26
#endif /* R_ARM_GOT_BREL */
#ifndef R_ARM_PLT32
#define R_ARM_PLT32          27
#endif /* R_ARM_PLT32 */
#ifndef R_ARM_CALL
#define R_ARM_CALL           28
#endif /* R_ARM_CALL */
#ifndef R_ARM_JUMP24
#define R_ARM_JUMP24         29
#endif /* R_ARM_JUMP24 */
#ifndef R_ARM_THM_JUMP24
#define R_ARM_THM_JUMP24     30
#endif /* R_ARM_THM_JUMP24 */
#ifndef R_ARM_BASE_ABS
#define R_ARM_BASE_ABS       31
#endif /* R_ARM_BASE_ABS */
#ifndef R_ARM_ALU_PCREL_7_0
#define R_ARM_ALU_PCREL_7_0  32
#endif /* R_ARM_ALU_PCREL_7_0 */
#ifndef R_ARM_ALU_PCREL_15_8
#define R_ARM_ALU_PCREL_15_8 33
#endif /* R_ARM_ALU_PCREL_15_8 */
#ifndef R_ARM_ALU_PCREL_23_15
#define R_ARM_ALU_PCREL_23_15 34
#endif /* R_ARM_ALU_PCREL_23_15 */
#ifndef R_ARM_LDR_SBREL_11_0_NC
#define R_ARM_LDR_SBREL_11_0_NC 35
#endif /* R_ARM_LDR_SBREL_11_0_NC */
#ifndef R_ARM_ALU_SBREL_19_12_NC
#define R_ARM_ALU_SBREL_19_12_NC 36
#endif /* R_ARM_ALU_SBREL_19_12_NC */
#ifndef R_ARM_ALU_SBREL_27_20_CK
#define R_ARM_ALU_SBREL_27_20_CK 37
#endif /* R_ARM_ALU_SBREL_27_20_CK */
#ifndef R_ARM_TARGET1
#define R_ARM_TARGET1        38
#endif /* R_ARM_TARGET1 */
#ifndef R_ARM_SBREL31
#define R_ARM_SBREL31        39
#endif /* R_ARM_SBREL31 */
#ifndef R_ARM_V4BX
#define R_ARM_V4BX           40
#endif /* R_ARM_V4BX */
#ifndef R_ARM_TARGET2
#define R_ARM_TARGET2        41
#endif /* R_ARM_TARGET2 */
#ifndef R_ARM_PREL31
#define R_ARM_PREL31         42
#endif /* R_ARM_PREL31 */
#ifndef R_ARM_MOVW_ABS_NC
#define R_ARM_MOVW_ABS_NC    43
#endif /* R_ARM_MOVW_ABS_NC */
#ifndef R_ARM_MOVT_ABS
#define R_ARM_MOVT_ABS       44
#endif /* R_ARM_MOVT_ABS */
#ifndef R_ARM_MOVW_PREL_NC
#define R_ARM_MOVW_PREL_NC   45
#endif /* R_ARM_MOVW_PREL_NC */
#ifndef R_ARM_MOVT_PREL
#define R_ARM_MOVT_PREL      46
#endif /* R_ARM_MOVT_PREL */
#ifndef R_ARM_THM_MOVW_ABS_NC
#define R_ARM_THM_MOVW_ABS_NC 47
#endif /* R_ARM_THM_MOVW_ABS_NC */
#ifndef R_ARM_THM_MOVT_ABS
#define R_ARM_THM_MOVT_ABS   48
#endif /* R_ARM_THM_MOVT_ABS */
#ifndef R_ARM_THM_MOVW_PREL_NC
#define R_ARM_THM_MOVW_PREL_NC 49
#endif /* R_ARM_THM_MOVW_PREL_NC */
#ifndef R_ARM_THM_MOVT_PREL
#define R_ARM_THM_MOVT_PREL  50
#endif /* R_ARM_THM_MOVT_PREL */
#ifndef R_ARM_THM_JUMP19
#define R_ARM_THM_JUMP19     51
#endif /* R_ARM_THM_JUMP19 */
#ifndef R_ARM_THM_JUMP6
#define R_ARM_THM_JUMP6      52
#endif /* R_ARM_THM_JUMP6 */
#ifndef R_ARM_THM_ALU_PREL_11_0
#define R_ARM_THM_ALU_PREL_11_0 53
#endif /* R_ARM_THM_ALU_PREL_11_0 */
#ifndef R_ARM_THM_PC12
#define R_ARM_THM_PC12       54
#endif /* R_ARM_THM_PC12 */
#ifndef R_ARM_ABS32_NOI
#define R_ARM_ABS32_NOI      55
#endif /* R_ARM_ABS32_NOI */
#ifndef R_ARM_REL32_NOI
#define R_ARM_REL32_NOI      56
#endif /* R_ARM_REL32_NOI */
#ifndef R_ARM_ALU_PC_G0_NC
#define R_ARM_ALU_PC_G0_NC   57
#endif /* R_ARM_ALU_PC_G0_NC */
#ifndef R_ARM_ALU_PC_G0
#define R_ARM_ALU_PC_G0      58
#endif /* R_ARM_ALU_PC_G0 */
#ifndef R_ARM_ALU_PC_G1_NC
#define R_ARM_ALU_PC_G1_NC   59
#endif /* R_ARM_ALU_PC_G1_NC */
#ifndef R_ARM_ALU_PC_G1
#define R_ARM_ALU_PC_G1      60
#endif /* R_ARM_ALU_PC_G1 */
#ifndef R_ARM_ALU_PC_G2
#define R_ARM_ALU_PC_G2      61
#endif /* R_ARM_ALU_PC_G2 */
#ifndef R_ARM_LDR_PC_G1
#define R_ARM_LDR_PC_G1      62
#endif /* R_ARM_LDR_PC_G1 */
#ifndef R_ARM_LDR_PC_G2
#define R_ARM_LDR_PC_G2      63
#endif /* R_ARM_LDR_PC_G2 */
#ifndef R_ARM_LDRS_PC_G0
#define R_ARM_LDRS_PC_G0     64
#endif /* R_ARM_LDRS_PC_G0 */
#ifndef R_ARM_LDRS_PC_G1
#define R_ARM_LDRS_PC_G1     65
#endif /* R_ARM_LDRS_PC_G1 */
#ifndef R_ARM_LDRS_PC_G2
#define R_ARM_LDRS_PC_G2     66
#endif /* R_ARM_LDRS_PC_G2 */
#ifndef R_ARM_LDC_PC_G0
#define R_ARM_LDC_PC_G0      67
#endif /* R_ARM_LDC_PC_G0 */
#ifndef R_ARM_LDC_PC_G1
#define R_ARM_LDC_PC_G1      68
#endif /* R_ARM_LDC_PC_G1 */
#ifndef R_ARM_LDC_PC_G2
#define R_ARM_LDC_PC_G2      69
#endif /* R_ARM_LDC_PC_G2 */
#ifndef R_ARM_ALU_SB_G0_NC
#define R_ARM_ALU_SB_G0_NC   70
#endif /* R_ARM_ALU_SB_G0_NC */
#ifndef R_ARM_ALU_SB_G0
#define R_ARM_ALU_SB_G0      71
#endif /* R_ARM_ALU_SB_G0 */
#ifndef R_ARM_ALU_SB_G1_NC
#define R_ARM_ALU_SB_G1_NC   72
#endif /* R_ARM_ALU_SB_G1_NC */
#ifndef R_ARM_ALU_SB_G1
#define R_ARM_ALU_SB_G1      73
#endif /* R_ARM_ALU_SB_G1 */
#ifndef R_ARM_ALU_SB_G2
#define R_ARM_ALU_SB_G2      74
#endif /* R_ARM_ALU_SB_G2 */
#ifndef R_ARM_LDR_SB_G0
#define R_ARM_LDR_SB_G0      75
#endif /* R_ARM_LDR_SB_G0 */
#ifndef R_ARM_LDR_SB_G1
#define R_ARM_LDR_SB_G1      76
#endif /* R_ARM_LDR_SB_G1 */
#ifndef R_ARM_LDR_SB_G2
#define R_ARM_LDR_SB_G2      77
#endif /* R_ARM_LDR_SB_G2 */
#ifndef R_ARM_LDRS_SB_G0
#define R_ARM_LDRS_SB_G0     78
#endif /* R_ARM_LDRS_SB_G0 */
#ifndef R_ARM_LDRS_SB_G1
#define R_ARM_LDRS_SB_G1     79
#endif /* R_ARM_LDRS_SB_G1 */
#ifndef R_ARM_LDRS_SB_G2
#define R_ARM_LDRS_SB_G2     80
#endif /* R_ARM_LDRS_SB_G2 */
#ifndef R_ARM_LDC_SB_G0
#define R_ARM_LDC_SB_G0      81
#endif /* R_ARM_LDC_SB_G0 */
#ifndef R_ARM_LDC_SB_G1
#define R_ARM_LDC_SB_G1      82
#endif /* R_ARM_LDC_SB_G1 */
#ifndef R_ARM_LDC_SB_G2
#define R_ARM_LDC_SB_G2      83
#endif /* R_ARM_LDC_SB_G2 */
#ifndef R_ARM_MOVW_BREL_NC
#define R_ARM_MOVW_BREL_NC   84
#endif /* R_ARM_MOVW_BREL_NC */
#ifndef R_ARM_MOVT_BREL
#define R_ARM_MOVT_BREL      85
#endif /* R_ARM_MOVT_BREL */
#ifndef R_ARM_MOVW_BREL
#define R_ARM_MOVW_BREL      86
#endif /* R_ARM_MOVW_BREL */
#ifndef R_ARM_THM_MOVW_BREL_NC
#define R_ARM_THM_MOVW_BREL_NC 87
#endif /* R_ARM_THM_MOVW_BREL_NC */
#ifndef R_ARM_THM_MOVT_BREL
#define R_ARM_THM_MOVT_BREL  88
#endif /* R_ARM_THM_MOVT_BREL */
#ifndef R_ARM_THM_MOVW_BREL
#define R_ARM_THM_MOVW_BREL  89
#endif /* R_ARM_THM_MOVW_BREL */
#ifndef R_ARM_TLS_GOTDESC
#define R_ARM_TLS_GOTDESC    90
#endif /* R_ARM_TLS_GOTDESC */
#ifndef R_ARM_TLS_CALL
#define R_ARM_TLS_CALL       91
#endif /* R_ARM_TLS_CALL */
#ifndef R_ARM_TLS_DESCSEQ
#define R_ARM_TLS_DESCSEQ    92
#endif /* R_ARM_TLS_DESCSEQ */
#ifndef R_ARM_THM_TLS_CALL
#define R_ARM_THM_TLS_CALL   93
#endif /* R_ARM_THM_TLS_CALL */
#ifndef R_ARM_PLT32_ABS
#define R_ARM_PLT32_ABS      94
#endif /* R_ARM_PLT32_ABS */
#ifndef R_ARM_GOT_ABS
#define R_ARM_GOT_ABS        95
#endif /* R_ARM_GOT_ABS */
#ifndef R_ARM_GOT_PREL
#define R_ARM_GOT_PREL       96
#endif /* R_ARM_GOT_PREL */
#ifndef R_ARM_GOT_BREL12
#define R_ARM_GOT_BREL12     97
#endif /* R_ARM_GOT_BREL12 */
#ifndef R_ARM_GOTOFF12
#define R_ARM_GOTOFF12       98
#endif /* R_ARM_GOTOFF12 */
#ifndef R_ARM_GOTRELAX
#define R_ARM_GOTRELAX       99
#endif /* R_ARM_GOTRELAX */
#ifndef R_ARM_GNU_VTENTRY
#define R_ARM_GNU_VTENTRY    100
#endif /* R_ARM_GNU_VTENTRY */
#ifndef R_ARM_GNU_VTINHERIT
#define R_ARM_GNU_VTINHERIT  101
#endif /* R_ARM_GNU_VTINHERIT */
#ifndef R_ARM_THM_JUMP11
#define R_ARM_THM_JUMP11     102
#endif /* R_ARM_THM_JUMP11 */
#ifndef R_ARM_THM_JUMP8
#define R_ARM_THM_JUMP8      103
#endif /* R_ARM_THM_JUMP8 */
#ifndef R_ARM_TLS_GD32
#define R_ARM_TLS_GD32       104
#endif /* R_ARM_TLS_GD32 */
#ifndef R_ARM_TLS_LDM32
#define R_ARM_TLS_LDM32      105
#endif /* R_ARM_TLS_LDM32 */
#ifndef R_ARM_TLS_LDO32
#define R_ARM_TLS_LDO32      106
#endif /* R_ARM_TLS_LDO32 */
#ifndef R_ARM_TLS_IE32
#define R_ARM_TLS_IE32       107
#endif /* R_ARM_TLS_IE32 */
#ifndef R_ARM_TLS_LE32
#define R_ARM_TLS_LE32       108
#endif /* R_ARM_TLS_LE32 */
#ifndef R_ARM_TLS_LDO12
#define R_ARM_TLS_LDO12      109
#endif /* R_ARM_TLS_LDO12 */
#ifndef R_ARM_TLS_LE12
#define R_ARM_TLS_LE12       110
#endif /* R_ARM_TLS_LE12 */
#ifndef R_ARM_TLS_IE12GP
#define R_ARM_TLS_IE12GP     111
#endif /* R_ARM_TLS_IE12GP */
#ifndef R_ARM_ME_TOO
#define R_ARM_ME_TOO         128
#endif /* R_ARM_ME_TOO */
#ifndef R_ARM_THM_TLS_DESCSEQ16
#define R_ARM_THM_TLS_DESCSEQ16 129
#endif /* R_ARM_THM_TLS_DESCSEQ16 */
#ifndef R_ARM_THM_TLS_DESCSEQ32
#define R_ARM_THM_TLS_DESCSEQ32 130
#endif /* R_ARM_THM_TLS_DESCSEQ32 */
#ifndef R_ARM_RXPC25
#define R_ARM_RXPC25         249
#endif /* R_ARM_RXPC25 */
#ifndef R_ARM_RSBREL32
#define R_ARM_RSBREL32       250
#endif /* R_ARM_RSBREL32 */
#ifndef R_ARM_THM_RPC22
#define R_ARM_THM_RPC22      251
#endif /* R_ARM_THM_RPC22 */
#ifndef R_ARM_RREL32
#define R_ARM_RREL32         252
#endif /* R_ARM_RREL32 */
#ifndef R_ARM_RABS32
#define R_ARM_RABS32         253
#endif /* R_ARM_RABS32 */
#ifndef R_ARM_RPC24
#define R_ARM_RPC24          254
#endif /* R_ARM_RPC24 */
#ifndef R_ARM_RBASE
#define R_ARM_RBASE          255
#endif /* R_ARM_RBASE */
#ifndef R_ARM_NUM
#define R_ARM_NUM            256
#endif /* R_ARM_NUM */
#ifndef R_AARCH64_ABS64
#define R_AARCH64_ABS64      0x101
#endif /* R_AARCH64_ABS64 */
#ifndef R_AARCH64_ABS32
#define R_AARCH64_ABS32      0x102
#endif /* R_AARCH64_ABS32 */
