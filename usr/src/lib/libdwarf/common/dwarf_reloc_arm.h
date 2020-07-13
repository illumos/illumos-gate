/*
  Copyright (C) 2007-2012 David Anderson. All Rights Reserved.
  Portions Copyright (C) 2012 SN Systems Ltd. All rights reserved.

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2.1 of the GNU Lesser General Public License
  as published by the Free Software Foundation.

  This program is distributed in the hope that it would be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

  Further, this software is distributed without any warranty that it is
  free of the rightful claim of any third person regarding infringement
  or the like.  Any license provided herein, whether implied or
  otherwise, applies only to this software file.  Patent licenses, if
  any, provided herein do not apply to combinations of this program with
  other software, or any other product whatsoever.

  You should have received a copy of the GNU Lesser General Public License along
  with this program; if not, write the Free Software Foundation, Inc., 51
  Franklin Street - Fifth Floor, Boston MA 02110-1301, USA.
*/

#ifndef DWARF_RELOC_ARM_H
#define DWARF_RELOC_ARM_H

/* Definitions for ARM */
#define DWARF_RELOC_ARM

#ifndef EM_AARCH64
#define EM_AARCH64 183  /* Arm 64 */
#endif


/* Include the definitions only in the case of Windows */
#ifdef _WIN32
/* Relocation types for ARM */
#define R_ARM_NONE                    0
#define R_ARM_PC24                    1
#define R_ARM_ABS32                   2
#define R_ARM_REL32                   3
#define R_ARM_LDR_PC_G0               4
#define R_ARM_ABS16                   5
#define R_ARM_ABS12                   6
#define R_ARM_THM_ABS5                7
#define R_ARM_ABS8                    8
#define R_ARM_SBREL32                 9
#define R_ARM_THM_CALL               10
#define R_ARM_THM_PC8                11
#define R_ARM_BREL_ADJ               12
#define R_ARM_TLS_DESC               13
#define R_ARM_THM_SWI8               14
#define R_ARM_XPC25                  15
#define R_ARM_THM_XPC22              16
#define R_ARM_TLS_DTPMOD32           17
#define R_ARM_TLS_DTPOFF32           18
#define R_ARM_TLS_TPOFF32            19
#define R_ARM_COPY                   20
#define R_ARM_GLOB_DAT               21
#define R_ARM_JUMP_SLOT              22
#define R_ARM_RELATIVE               23
#define R_ARM_GOTOFF32               24
#define R_ARM_BASE_PREL              25
#define R_ARM_GOT_BREL               26
#define R_ARM_PLT32                  27
#define R_ARM_CALL                   28
#define R_ARM_JUMP24                 29
#define R_ARM_THM_JUMP24             30
#define R_ARM_BASE_ABS               31
#define R_ARM_ALU_PCREL_7_0          32
#define R_ARM_ALU_PCREL_15_8         33
#define R_ARM_ALU_PCREL_23_15        34
#define R_ARM_LDR_SBREL_11_0_NC      35
#define R_ARM_ALU_SBREL_19_12_NC     36
#define R_ARM_ALU_SBREL_27_20_CK     37
#define R_ARM_TARGET1                38
#define R_ARM_SBREL31                39
#define R_ARM_V4BX                   40
#define R_ARM_TARGET2                41
#define R_ARM_PREL31                 42
#define R_ARM_MOVW_ABS_NC            43
#define R_ARM_MOVT_ABS               44
#define R_ARM_MOVW_PREL_NC           45
#define R_ARM_MOVT_PREL              46
#define R_ARM_THM_MOVW_ABS_NC        47
#define R_ARM_THM_MOVT_ABS           48
#define R_ARM_THM_MOVW_PREL_NC       49
#define R_ARM_THM_MOVT_PREL          50
#define R_ARM_THM_JUMP19             51
#define R_ARM_THM_JUMP6              52
#define R_ARM_THM_ALU_PREL_11_0      53
#define R_ARM_THM_PC12               54
#define R_ARM_ABS32_NOI              55
#define R_ARM_REL32_NOI              56
#define R_ARM_ALU_PC_G0_NC           57
#define R_ARM_ALU_PC_G0              58
#define R_ARM_ALU_PC_G1_NC           59
#define R_ARM_ALU_PC_G1              60
#define R_ARM_ALU_PC_G2              61
#define R_ARM_LDR_PC_G1              62
#define R_ARM_LDR_PC_G2              63
#define R_ARM_LDRS_PC_G0             64
#define R_ARM_LDRS_PC_G1             65
#define R_ARM_LDRS_PC_G2             66
#define R_ARM_LDC_PC_G0              67
#define R_ARM_LDC_PC_G1              68
#define R_ARM_LDC_PC_G2              69
#define R_ARM_ALU_SB_G0_NC           70
#define R_ARM_ALU_SB_G0              71
#define R_ARM_ALU_SB_G1_NC           72
#define R_ARM_ALU_SB_G1              73
#define R_ARM_ALU_SB_G2              74
#define R_ARM_LDR_SB_G0              75
#define R_ARM_LDR_SB_G1              76
#define R_ARM_LDR_SB_G2              77
#define R_ARM_LDRS_SB_G0             78
#define R_ARM_LDRS_SB_G1             79
#define R_ARM_LDRS_SB_G2             80
#define R_ARM_LDC_SB_G0              81
#define R_ARM_LDC_SB_G1              82
#define R_ARM_LDC_SB_G2              83
#define R_ARM_MOVW_BREL_NC           84
#define R_ARM_MOVT_BREL              85
#define R_ARM_MOVW_BREL              86
#define R_ARM_THM_MOVW_BREL_NC       87
#define R_ARM_THM_MOVT_BREL          88
#define R_ARM_THM_MOVW_BREL          89
#define R_ARM_TLS_GOTDESC            90
#define R_ARM_TLS_CALL               91
#define R_ARM_TLS_DESCSEQ            92
#define R_ARM_THM_TLS_CALL           93
#define R_ARM_PLT32_ABS              94
#define R_ARM_GOT_ABS                95
#define R_ARM_GOT_PREL               96
#define R_ARM_GOT_BREL12             97
#define R_ARM_GOTOFF12               98
#define R_ARM_GOTRELAX               99
#define R_ARM_GNU_VTENTRY           100
#define R_ARM_GNU_VTINHERIT         101
#define R_ARM_THM_JUMP11            102
#define R_ARM_THM_JUMP8             103
#define R_ARM_TLS_GD32              104
#define R_ARM_TLS_LDM32             105
#define R_ARM_TLS_LDO32             106
#define R_ARM_TLS_IE32              107
#define R_ARM_TLS_LE32              108
#define R_ARM_TLS_LDO12             109
#define R_ARM_TLS_LE12              110
#define R_ARM_TLS_IE12GP            111
#define R_ARM_ME_TOO                128
#define R_ARM_THM_TLS_DESCSEQ16     129
#define R_ARM_THM_TLS_DESCSEQ32     130
#define R_ARM_RXPC25                249
#define R_ARM_RSBREL32              250
#define R_ARM_THM_RPC22             251
#define R_ARM_RREL32                252
#define R_ARM_RABS32                253
#define R_ARM_RPC24                 254
#define R_ARM_RBASE                 255

/*  Keep this the last entry.  */
#define R_ARM_NUM                   256
#endif /* _WIN32 */

/* ARM relocations defined by the ABIs */
static const char *reloc_type_names_ARM[] = {
    "R_ARM_NONE",                 /*  00 */
    "R_ARM_PC24",                 /*  01 */
    "R_ARM_ABS32",                /*  02 */
    "R_ARM_REL32",                /*  03 */
    "R_ARM_LDR_PC_G0",            /*  04 */
    "R_ARM_ABS16",                /*  05 */
    "R_ARM_ABS12",                /*  06 */
    "R_ARM_THM_ABS5",             /*  07 */
    "R_ARM_ABS8",                 /*  08 */
    "R_ARM_SBREL32",              /*  09 */
    "R_ARM_THM_CALL",             /*  10 */
    "R_ARM_THM_PC8",              /*  11 */
    "R_ARM_BREL_ADJ",             /*  12 */
    "R_ARM_TLS_DESC",             /*  13 */
    "R_ARM_THM_SWI8",             /*  14 */
    "R_ARM_XPC25",                /*  15 */
    "R_ARM_THM_XPC22",            /*  16 */
    "R_ARM_TLS_DTPMOD32",         /*  17 */
    "R_ARM_TLS_DTPOFF32",         /*  18 */
    "R_ARM_TLS_TPOFF32",          /*  19 */
    "R_ARM_COPY",                 /*  20 */
    "R_ARM_GLOB_DAT",             /*  21 */
    "R_ARM_JUMP_SLOT",            /*  22 */
    "R_ARM_RELATIVE",             /*  23 */
    "R_ARM_GOTOFF32",             /*  24 */
    "R_ARM_BASE_PREL",            /*  25 */
    "R_ARM_GOT_BREL",             /*  26 */
    "R_ARM_PLT32",                /*  27 */
    "R_ARM_CALL",                 /*  28 */
    "R_ARM_JUMP24",               /*  29 */
    "R_ARM_THM_JUMP24",           /*  30 */
    "R_ARM_BASE_ABS",             /*  31 */
    "R_ARM_ALU_PCREL_7_0",        /*  32 */
    "R_ARM_ALU_PCREL_15_8",       /*  33 */
    "R_ARM_ALU_PCREL_23_15",      /*  34 */
    "R_ARM_LDR_SBREL_11_0_NC",    /*  35 */
    "R_ARM_ALU_SBREL_19_12_NC",   /*  36 */
    "R_ARM_ALU_SBREL_27_20_CK",   /*  37 */
    "R_ARM_TARGET1",              /*  38 */
    "R_ARM_SBREL31",              /*  39 */
    "R_ARM_V4BX",                 /*  40 */
    "R_ARM_TARGET2",              /*  41 */
    "R_ARM_PREL31",               /*  42 */
    "R_ARM_MOVW_ABS_NC",          /*  43 */
    "R_ARM_MOVT_ABS",             /*  44 */
    "R_ARM_MOVW_PREL_NC",         /*  45 */
    "R_ARM_MOVT_PREL",            /*  46 */
    "R_ARM_THM_MOVW_ABS_NC",      /*  47 */
    "R_ARM_THM_MOVT_ABS",         /*  48 */
    "R_ARM_THM_MOVW_PREL_NC",     /*  49 */
    "R_ARM_THM_MOVT_PREL",        /*  50 */
    "R_ARM_THM_JUMP19",           /*  51 */
    "R_ARM_THM_JUMP6",            /*  52 */
    "R_ARM_THM_ALU_PREL_11_0",    /*  53 */
    "R_ARM_THM_PC12",             /*  54 */
    "R_ARM_ABS32_NOI",            /*  55 */
    "R_ARM_REL32_NOI",            /*  56 */
    "R_ARM_ALU_PC_G0_NC",         /*  57 */
    "R_ARM_ALU_PC_G0",            /*  58 */
    "R_ARM_ALU_PC_G1_NC",         /*  59 */
    "R_ARM_ALU_PC_G1",            /*  60 */
    "R_ARM_ALU_PC_G2",            /*  61 */
    "R_ARM_LDR_PC_G1",            /*  62 */
    "R_ARM_LDR_PC_G2",            /*  63 */
    "R_ARM_LDRS_PC_G0",           /*  64 */
    "R_ARM_LDRS_PC_G1",           /*  65 */
    "R_ARM_LDRS_PC_G2",           /*  66 */
    "R_ARM_LDC_PC_G0",            /*  67 */
    "R_ARM_LDC_PC_G1",            /*  68 */
    "R_ARM_LDC_PC_G2",            /*  69 */
    "R_ARM_ALU_SB_G0_NC",         /*  70 */
    "R_ARM_ALU_SB_G0",            /*  71 */
    "R_ARM_ALU_SB_G1_NC",         /*  72 */
    "R_ARM_ALU_SB_G1",            /*  73 */
    "R_ARM_ALU_SB_G2",            /*  74 */
    "R_ARM_LDR_SB_G0",            /*  75 */
    "R_ARM_LDR_SB_G1",            /*  76 */
    "R_ARM_LDR_SB_G2",            /*  77 */
    "R_ARM_LDRS_SB_G0",           /*  78 */
    "R_ARM_LDRS_SB_G1",           /*  79 */
    "R_ARM_LDRS_SB_G2",           /*  80 */
    "R_ARM_LDC_SB_G0",            /*  81 */
    "R_ARM_LDC_SB_G1",            /*  82 */
    "R_ARM_LDC_SB_G2",            /*  83 */
    "R_ARM_MOVW_BREL_NC",         /*  84 */
    "R_ARM_MOVT_BREL",            /*  85 */
    "R_ARM_MOVW_BREL",            /*  86 */
    "R_ARM_THM_MOVW_BREL_NC",     /*  87 */
    "R_ARM_THM_MOVT_BREL",        /*  88 */
    "R_ARM_THM_MOVW_BREL",        /*  89 */
    "R_ARM_TLS_GOTDESC",          /*  90 */
    "R_ARM_TLS_CALL",             /*  91 */
    "R_ARM_TLS_DESCSEQ",          /*  92 */
    "R_ARM_THM_TLS_CALL",         /*  93 */
    "R_ARM_PLT32_ABS",            /*  94 */
    "R_ARM_GOT_ABS",              /*  95 */
    "R_ARM_GOT_PREL",             /*  96 */
    "R_ARM_GOT_BREL12",           /*  97 */
    "R_ARM_GOTOFF12",             /*  98 */
    "R_ARM_GOTRELAX",             /*  99 */
    "R_ARM_GNU_VTENTRY",          /* 100 */
    "R_ARM_GNU_VTINHERIT",        /* 101 */
    "R_ARM_THM_JUMP11",           /* 102 */
    "R_ARM_THM_JUMP8",            /* 103 */
    "R_ARM_TLS_GD32",             /* 104 */
    "R_ARM_TLS_LDM32",            /* 105 */
    "R_ARM_TLS_LDO32",            /* 106 */
    "R_ARM_TLS_IE32",             /* 107 */
    "R_ARM_TLS_LE32",             /* 108 */
    "R_ARM_TLS_LDO12",            /* 109 */
    "R_ARM_TLS_LE12",             /* 110 */
    "R_ARM_TLS_IE12GP",           /* 111 */
    "R_ARM_TLS_MOVT_TPOFF32",     /* 112 */   /* "R_ARM_PRIVATE_0" */
    "R_ARM_TLS_MOVW_TPOFF32",     /* 113 */   /* "R_ARM_PRIVATE_1" */
    "R_ARM_THM_TLS_MOVT_TPOFF32", /* 114 */   /* "R_ARM_PRIVATE_2" */
    "R_ARM_THM_TLS_MOVT_TPOFF32", /* 115 */   /* "R_ARM_PRIVATE_3" */
    "R_ARM_PRIVATE_4",            /* 116 */
    "R_ARM_PRIVATE_5",            /* 117 */
    "R_ARM_PRIVATE_6",            /* 118 */
    "R_ARM_PRIVATE_7",            /* 119 */
    "R_ARM_PRIVATE_8",            /* 120 */
    "R_ARM_PRIVATE_9",            /* 121 */
    "R_ARM_PRIVATE_10",           /* 122 */
    "R_ARM_PRIVATE_11",           /* 123 */
    "R_ARM_PRIVATE_12",           /* 124 */
    "R_ARM_PRIVATE_13",           /* 125 */
    "R_ARM_PRIVATE_14",           /* 126 */
    "R_ARM_PRIVATE_15",           /* 127 */
    "R_ARM_ME_TOO",               /* 128 */
    "R_ARM_THM_TLS_DESCSEQ16",    /* 129 */
    "R_ARM_THM_TLS_DESCSEQ32",    /* 130 */
};

#ifndef R_AARCH64_ABS64
#define R_AARCH64_ABS64 0x101
#endif
#ifndef R_AARCH64_ABS32
#define R_AARCH64_ABS32 0x102
#endif

#endif /* DWARF_RELOC_ARM_H */
