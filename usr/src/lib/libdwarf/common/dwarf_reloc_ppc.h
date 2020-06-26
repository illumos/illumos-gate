/*
  Copyright (C) 2007-2012 David Anderson. All Rights Reserved.
  Portions Copyright (C) 2012 SN Systems Ltd. All rights reserved.

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2.1 of the GNU Lesser General Public License
  published by the Free Software Foundation.

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
/* The address of the Free Software Foundation is
   Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
   Boston, MA 02110-1301, USA.
*/

#ifndef DWARF_RELOC_PPC_H
#define DWARF_RELOC_PPC_H

/* Definitions for PPC */
#define DWARF_RELOC_PPC

/* Include the definitions only in the case of Windows */
#ifdef _WIN32
/* PowerPC relocations defined by the ABIs */
#define R_PPC_NONE                   0
#define R_PPC_ADDR32                 1 /* 32bit absolute address */
#define R_PPC_ADDR24                 2 /* 26bit address, 2 bits ignored.  */
#define R_PPC_ADDR16                 3 /* 16bit absolute address */
#define R_PPC_ADDR16_LO              4 /* lower 16bit of absolute address */
#define R_PPC_ADDR16_HI              5 /* high 16bit of absolute address */
#define R_PPC_ADDR16_HA              6 /* adjusted high 16bit */
#define R_PPC_ADDR14                 7 /* 16bit address, 2 bits ignored */
#define R_PPC_ADDR14_BRTAKEN         8
#define R_PPC_ADDR14_BRNTAKEN        9
#define R_PPC_REL24                 10 /* PC relative 26 bit */
#define R_PPC_REL14                 11 /* PC relative 16 bit */
#define R_PPC_REL14_BRTAKEN         12
#define R_PPC_REL14_BRNTAKEN        13
#define R_PPC_GOT16                 14
#define R_PPC_GOT16_LO              15
#define R_PPC_GOT16_HI              16
#define R_PPC_GOT16_HA              17
#define R_PPC_PLTREL24              18
#define R_PPC_COPY                  19
#define R_PPC_GLOB_DAT              20
#define R_PPC_JMP_SLOT              21
#define R_PPC_RELATIVE              22
#define R_PPC_LOCAL24PC             23
#define R_PPC_UADDR32               24
#define R_PPC_UADDR16               25
#define R_PPC_REL32                 26
#define R_PPC_PLT32                 27
#define R_PPC_PLTREL32              28
#define R_PPC_PLT16_LO              29
#define R_PPC_PLT16_HI              30
#define R_PPC_PLT16_HA              31
#define R_PPC_SDAREL16              32
#define R_PPC_SECTOFF               33
#define R_PPC_SECTOFF_LO            34
#define R_PPC_SECTOFF_HI            35
#define R_PPC_SECTOFF_HA            36

/* Unused types */
#define R_PPC_37                    37
#define R_PPC_38                    38
#define R_PPC_39                    39
#define R_PPC_40                    40
#define R_PPC_41                    41
#define R_PPC_42                    42
#define R_PPC_43                    43
#define R_PPC_44                    44
#define R_PPC_45                    45
#define R_PPC_46                    46
#define R_PPC_47                    47
#define R_PPC_48                    48
#define R_PPC_49                    49
#define R_PPC_50                    50
#define R_PPC_51                    51
#define R_PPC_52                    52
#define R_PPC_53                    53
#define R_PPC_54                    54
#define R_PPC_55                    55

/* Unused types */
#define R_PPC_56                    56
#define R_PPC_57                    57
#define R_PPC_58                    58
#define R_PPC_59                    59
#define R_PPC_60                    60
#define R_PPC_61                    61
#define R_PPC_62                    62
#define R_PPC_63                    63
#define R_PPC_64                    64
#define R_PPC_65                    65
#define R_PPC_66                    66

/* PowerPC relocations defined for the TLS access ABI.  */
#define R_PPC_TLS                   67 /* none      (sym+add)@tls */
#define R_PPC_DTPMOD32              68 /* word32    (sym+add)@dtpmod */
#define R_PPC_TPREL16               69 /* half16*   (sym+add)@tprel */
#define R_PPC_TPREL16_LO            70 /* half16    (sym+add)@tprel@l */
#define R_PPC_TPREL16_HI            71 /* half16    (sym+add)@tprel@h */
#define R_PPC_TPREL16_HA            72 /* half16    (sym+add)@tprel@ha */
#define R_PPC_TPREL32               73 /* word32    (sym+add)@tprel */
#define R_PPC_DTPREL16              74 /* half16*   (sym+add)@dtprel */
#define R_PPC_DTPREL16_LO           75 /* half16    (sym+add)@dtprel@l */
#define R_PPC_DTPREL16_HI           76 /* half16    (sym+add)@dtprel@h */
#define R_PPC_DTPREL16_HA           77 /* half16    (sym+add)@dtprel@ha */
#define R_PPC_DTPREL32              78 /* word32    (sym+add)@dtprel */
#define R_PPC_GOT_TLSGD16           79 /* half16*   (sym+add)@got@tlsgd */
#define R_PPC_GOT_TLSGD16_LO        80 /* half16    (sym+add)@got@tlsgd@l */
#define R_PPC_GOT_TLSGD16_HI        81 /* half16    (sym+add)@got@tlsgd@h */
#define R_PPC_GOT_TLSGD16_HA        82 /* half16    (sym+add)@got@tlsgd@ha */
#define R_PPC_GOT_TLSLD16           83 /* half16*   (sym+add)@got@tlsld */
#define R_PPC_GOT_TLSLD16_LO        84 /* half16    (sym+add)@got@tlsld@l */
#define R_PPC_GOT_TLSLD16_HI        85 /* half16    (sym+add)@got@tlsld@h */
#define R_PPC_GOT_TLSLD16_HA        86 /* half16    (sym+add)@got@tlsld@ha */
#define R_PPC_GOT_TPREL16           87 /* half16*   (sym+add)@got@tprel */
#define R_PPC_GOT_TPREL16_LO        88 /* half16    (sym+add)@got@tprel@l */
#define R_PPC_GOT_TPREL16_HI        89 /* half16    (sym+add)@got@tprel@h */
#define R_PPC_GOT_TPREL16_HA        90 /* half16    (sym+add)@got@tprel@ha */
#define R_PPC_GOT_DTPREL16          91 /* half16*   (sym+add)@got@dtprel */
#define R_PPC_GOT_DTPREL16_LO       92 /* half16*   (sym+add)@got@dtprel@l */
#define R_PPC_GOT_DTPREL16_HI       93 /* half16*   (sym+add)@got@dtprel@h */
#define R_PPC_GOT_DTPREL16_HA       94 /* half16*   (sym+add)@got@dtprel@ha */

/* Keep this the last entry.  */
#define R_PPC_NUM                   95
#endif /* _WIN32 */

/* PowerPC relocations defined by the ABIs */
static const char *reloc_type_names_PPC[] = {
    "R_PPC_NONE",                 /*  00 */
    "R_PPC_ADDR32",               /*  01 */
    "R_PPC_ADDR24",               /*  02 */
    "R_PPC_ADDR16",               /*  03 */
    "R_PPC_ADDR16_LO",            /*  04 */
    "R_PPC_ADDR16_HI",            /*  05 */
    "R_PPC_ADDR16_HA",            /*  06 */
    "R_PPC_ADDR14",               /*  07 */
    "R_PPC_ADDR14_BRTAKEN",       /*  08 */
    "R_PPC_ADDR14_BRNTAKEN",      /*  09 */
    "R_PPC_REL24",                /*  10 */
    "R_PPC_REL14",                /*  11 */
    "R_PPC_REL14_BRTAKEN",        /*  12 */
    "R_PPC_REL14_BRNTAKEN",       /*  13 */
    "R_PPC_GOT16",                /*  14 */
    "R_PPC_GOT16_LO",             /*  15 */
    "R_PPC_GOT16_HI",             /*  16 */
    "R_PPC_GOT16_HA",             /*  17 */
    "R_PPC_PLTREL24",             /*  18 */
    "R_PPC_COPY",                 /*  19 */
    "R_PPC_GLOB_DAT",             /*  20 */
    "R_PPC_JMP_SLOT",             /*  21 */
    "R_PPC_RELATIVE",             /*  22 */
    "R_PPC_LOCAL24PC",            /*  23 */
    "R_PPC_UADDR32",              /*  24 */
    "R_PPC_UADDR16",              /*  25 */
    "R_PPC_REL32",                /*  26 */
    "R_PPC_PLT32",                /*  27 */
    "R_PPC_PLTREL32",             /*  28 */
    "R_PPC_PLT16_LO",             /*  29 */
    "R_PPC_PLT16_HI",             /*  30 */
    "R_PPC_PLT16_HA",             /*  31 */
    "R_PPC_SDAREL16",             /*  32 */
    "R_PPC_SECTOFF",              /*  33 */
    "R_PPC_SECTOFF_LO",           /*  34 */
    "R_PPC_SECTOFF_HI",           /*  35 */
    "R_PPC_SECTOFF_HA",           /*  36 */
    "R_PPC_37",                   /*  37 */
    "R_PPC_38",                   /*  38 */
    "R_PPC_39",                   /*  39 */
    "R_PPC_40",                   /*  40 */
    "R_PPC_41",                   /*  41 */
    "R_PPC_42",                   /*  42 */
    "R_PPC_43",                   /*  43 */
    "R_PPC_44",                   /*  44 */
    "R_PPC_45",                   /*  45 */
    "R_PPC_46",                   /*  46 */
    "R_PPC_47",                   /*  47 */
    "R_PPC_48",                   /*  48 */
    "R_PPC_49",                   /*  49 */
    "R_PPC_50",                   /*  50 */
    "R_PPC_51",                   /*  51 */
    "R_PPC_52",                   /*  52 */
    "R_PPC_53",                   /*  53 */
    "R_PPC_54",                   /*  54 */
    "R_PPC_55",                   /*  55 */
    "R_PPC_56",                   /*  56 */
    "R_PPC_57",                   /*  57 */
    "R_PPC_58",                   /*  58 */
    "R_PPC_59",                   /*  59 */
    "R_PPC_60",                   /*  60 */
    "R_PPC_61",                   /*  61 */
    "R_PPC_62",                   /*  62 */
    "R_PPC_63",                   /*  63 */
    "R_PPC_64",                   /*  64 */
    "R_PPC_65",                   /*  65 */
    "R_PPC_66",                   /*  66 */
    "R_PPC_TLS",                  /*  67 */
    "R_PPC_DTPMOD32",             /*  68 */
    "R_PPC_TPREL16",              /*  69 */
    "R_PPC_TPREL16_LO",           /*  70 */
    "R_PPC_TPREL16_HI",           /*  71 */
    "R_PPC_TPREL16_HA",           /*  72 */
    "R_PPC_TPREL32",              /*  73 */
    "R_PPC_DTPREL16",             /*  74 */
    "R_PPC_DTPREL16_LO",          /*  75 */
    "R_PPC_DTPREL16_HI",          /*  76 */
    "R_PPC_DTPREL16_HA",          /*  77 */
    "R_PPC_DTPREL64",             /*  78 */
    "R_PPC_GOT_TLSGD16",          /*  79 */
    "R_PPC_GOT_TLSGD16_LO",       /*  80 */
    "R_PPC_GOT_TLSGD16_HI",       /*  81 */
    "R_PPC_GOT_TLSGD16_HA",       /*  82 */
    "R_PPC_GOT_TLSLD16",          /*  83 */
    "R_PPC_GOT_TLSLD16_LO",       /*  84 */
    "R_PPC_GOT_TLSLD16_HI",       /*  85 */
    "R_PPC_GOT_TLSLD16_HA",       /*  86 */
    "R_PPC_GOT_TPREL16_DS",       /*  87 */
    "R_PPC_GOT_TPREL16_LO",       /*  88 */
    "R_PPC_GOT_TPREL16_HI",       /*  89 */
    "R_PPC_GOT_TPREL16_HA",       /*  90 */
    "R_PPC_GOT_DTPREL16",         /*  91 */
    "R_PPC_GOT_DTPREL16_LO",      /*  92 */
    "R_PPC_GOT_DTPREL16_HI",      /*  93 */
    "R_PPC_GOT_DTPREL16_HA",      /*  94 */
};
#endif /* DWARF_RELOC_PPC_H */
