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

#ifndef DWARF_RELOC_PPC64_H
#define DWARF_RELOC_PPC64_H

/* Definitions for PPC64 */
#define DWARF_RELOC_PPC64

/* Include the definitions only in the case of Windows */
#ifdef _WIN32

#include "dwarf_reloc_ppc.h"

/* PowerPC64 relocations defined by the ABIs */
#define R_PPC64_NONE                R_PPC_NONE
#define R_PPC64_ADDR32              R_PPC_ADDR32 /* 32bit absolute address.  */
#define R_PPC64_ADDR24              R_PPC_ADDR24 /* 26bit address, word aligned.  */
#define R_PPC64_ADDR16              R_PPC_ADDR16 /* 16bit absolute address. */
#define R_PPC64_ADDR16_LO           R_PPC_ADDR16_LO /* lower 16bits of abs. address.  */
#define R_PPC64_ADDR16_HI           R_PPC_ADDR16_HI /* high 16bits of abs. address. */
#define R_PPC64_ADDR16_HA           R_PPC_ADDR16_HA /* adjusted high 16bits.  */
#define R_PPC64_ADDR14              R_PPC_ADDR14  /* 16bit address, word aligned.  */
#define R_PPC64_ADDR14_BRTAKEN      R_PPC_ADDR14_BRTAKEN
#define R_PPC64_ADDR14_BRNTAKEN     R_PPC_ADDR14_BRNTAKEN
#define R_PPC64_REL24               R_PPC_REL24 /* PC relative 26 bit, word aligned.  */
#define R_PPC64_REL14               R_PPC_REL14 /* PC relative 16 bit. */
#define R_PPC64_REL14_BRTAKEN       R_PPC_REL14_BRTAKEN
#define R_PPC64_REL14_BRNTAKEN      R_PPC_REL14_BRNTAKEN
#define R_PPC64_GOT16               R_PPC_GOT16
#define R_PPC64_GOT16_LO            R_PPC_GOT16_LO
#define R_PPC64_GOT16_HI            R_PPC_GOT16_HI
#define R_PPC64_GOT16_HA            R_PPC_GOT16_HA

#define R_PPC64_COPY                R_PPC_COPY
#define R_PPC64_GLOB_DAT            R_PPC_GLOB_DAT
#define R_PPC64_JMP_SLOT            R_PPC_JMP_SLOT
#define R_PPC64_RELATIVE            R_PPC_RELATIVE

#define R_PPC64_UADDR32             R_PPC_UADDR32
#define R_PPC64_UADDR16             R_PPC_UADDR16
#define R_PPC64_REL32               R_PPC_REL32
#define R_PPC64_PLT32               R_PPC_PLT32
#define R_PPC64_PLTREL32            R_PPC_PLTREL32
#define R_PPC64_PLT16_LO            R_PPC_PLT16_LO
#define R_PPC64_PLT16_HI            R_PPC_PLT16_HI
#define R_PPC64_PLT16_HA            R_PPC_PLT16_HA

#define R_PPC64_SECTOFF             R_PPC_SECTOFF
#define R_PPC64_SECTOFF_LO          R_PPC_SECTOFF_LO
#define R_PPC64_SECTOFF_HI          R_PPC_SECTOFF_HI
#define R_PPC64_SECTOFF_HA          R_PPC_SECTOFF_HA
#define R_PPC64_ADDR30              37 /* word30 (S + A - P) >> 2.  */
#define R_PPC64_ADDR64              38 /* doubleword64 S + A.  */
#define R_PPC64_ADDR16_HIGHER       39 /* half16 #higher(S + A).  */
#define R_PPC64_ADDR16_HIGHERA      40 /* half16 #highera(S + A).  */
#define R_PPC64_ADDR16_HIGHEST      41 /* half16 #highest(S + A).  */
#define R_PPC64_ADDR16_HIGHESTA     42 /* half16 #highesta(S + A). */
#define R_PPC64_UADDR64             43 /* doubleword64 S + A.  */
#define R_PPC64_REL64               44 /* doubleword64 S + A - P.  */
#define R_PPC64_PLT64               45 /* doubleword64 L + A.  */
#define R_PPC64_PLTREL64            46 /* doubleword64 L + A - P.  */
#define R_PPC64_TOC16               47 /* half16* S + A - .TOC.  */
#define R_PPC64_TOC16_LO            48 /* half16 #lo(S + A - .TOC.).  */
#define R_PPC64_TOC16_HI            49 /* half16 #hi(S + A - .TOC.).  */
#define R_PPC64_TOC16_HA            50 /* half16 #ha(S + A - .TOC.).  */
#define R_PPC64_TOC                 51 /* doubleword64 .TOC. */
#define R_PPC64_PLTGOT16            52 /* half16* M + A.  */
#define R_PPC64_PLTGOT16_LO         53 /* half16 #lo(M + A).  */
#define R_PPC64_PLTGOT16_HI         54 /* half16 #hi(M + A).  */
#define R_PPC64_PLTGOT16_HA         55 /* half16 #ha(M + A).  */

#define R_PPC64_ADDR16_DS           56 /* half16ds* (S + A) >> 2.  */
#define R_PPC64_ADDR16_LO_DS        57 /* half16ds  #lo(S + A) >> 2.  */
#define R_PPC64_GOT16_DS            58 /* half16ds* (G + A) >> 2.  */
#define R_PPC64_GOT16_LO_DS         59 /* half16ds  #lo(G + A) >> 2.  */
#define R_PPC64_PLT16_LO_DS         60 /* half16ds  #lo(L + A) >> 2.  */
#define R_PPC64_SECTOFF_DS          61 /* half16ds* (R + A) >> 2.  */
#define R_PPC64_SECTOFF_LO_DS       62 /* half16ds  #lo(R + A) >> 2.  */
#define R_PPC64_TOC16_DS            63 /* half16ds* (S + A - .TOC.) >> 2.  */
#define R_PPC64_TOC16_LO_DS         64 /* half16ds  #lo(S + A - .TOC.) >> 2.  */
#define R_PPC64_PLTGOT16_DS         65 /* half16ds* (M + A) >> 2.  */
#define R_PPC64_PLTGOT16_LO_DS      66 /* half16ds  #lo(M + A) >> 2.  */

/* PowerPC64 relocations defined for the TLS access ABI.  */
#define R_PPC64_TLS                 67 /* none      (sym+add)@tls */
#define R_PPC64_DTPMOD64            68 /* doubleword64 (sym+add)@dtpmod */
#define R_PPC64_TPREL16             69 /* half16*   (sym+add)@tprel */
#define R_PPC64_TPREL16_LO          70 /* half16    (sym+add)@tprel@l */
#define R_PPC64_TPREL16_HI          71 /* half16    (sym+add)@tprel@h */
#define R_PPC64_TPREL16_HA          72 /* half16    (sym+add)@tprel@ha */
#define R_PPC64_TPREL64             73 /* doubleword64 (sym+add)@tprel */
#define R_PPC64_DTPREL16            74 /* half16*   (sym+add)@dtprel */
#define R_PPC64_DTPREL16_LO         75 /* half16    (sym+add)@dtprel@l */
#define R_PPC64_DTPREL16_HI         76 /* half16    (sym+add)@dtprel@h */
#define R_PPC64_DTPREL16_HA         77 /* half16    (sym+add)@dtprel@ha */
#define R_PPC64_DTPREL64            78 /* doubleword64 (sym+add)@dtprel */
#define R_PPC64_GOT_TLSGD16         79 /* half16*   (sym+add)@got@tlsgd */
#define R_PPC64_GOT_TLSGD16_LO      80 /* half16    (sym+add)@got@tlsgd@l */
#define R_PPC64_GOT_TLSGD16_HI      81 /* half16    (sym+add)@got@tlsgd@h */
#define R_PPC64_GOT_TLSGD16_HA      82 /* half16    (sym+add)@got@tlsgd@ha */
#define R_PPC64_GOT_TLSLD16         83 /* half16*   (sym+add)@got@tlsld */
#define R_PPC64_GOT_TLSLD16_LO      84 /* half16    (sym+add)@got@tlsld@l */
#define R_PPC64_GOT_TLSLD16_HI      85 /* half16    (sym+add)@got@tlsld@h */
#define R_PPC64_GOT_TLSLD16_HA      86 /* half16    (sym+add)@got@tlsld@ha */
#define R_PPC64_GOT_TPREL16_DS      87 /* half16ds* (sym+add)@got@tprel */
#define R_PPC64_GOT_TPREL16_LO_DS   88 /* half16ds (sym+add)@got@tprel@l */
#define R_PPC64_GOT_TPREL16_HI      89 /* half16    (sym+add)@got@tprel@h */
#define R_PPC64_GOT_TPREL16_HA      90 /* half16    (sym+add)@got@tprel@ha */
#define R_PPC64_GOT_DTPREL16_DS     91 /* half16ds* (sym+add)@got@dtprel */
#define R_PPC64_GOT_DTPREL16_LO_DS  92 /* half16ds (sym+add)@got@dtprel@l */
#define R_PPC64_GOT_DTPREL16_HI     93 /* half16    (sym+add)@got@dtprel@h */
#define R_PPC64_GOT_DTPREL16_HA     94 /* half16    (sym+add)@got@dtprel@ha */
#define R_PPC64_TPREL16_DS          95 /* half16ds* (sym+add)@tprel */
#define R_PPC64_TPREL16_LO_DS       96 /* half16ds  (sym+add)@tprel@l */
#define R_PPC64_TPREL16_HIGHER      97 /* half16    (sym+add)@tprel@higher */
#define R_PPC64_TPREL16_HIGHERA     98 /* half16    (sym+add)@tprel@highera */
#define R_PPC64_TPREL16_HIGHEST     99 /* half16    (sym+add)@tprel@highest */
#define R_PPC64_TPREL16_HIGHESTA   100 /* half16  (sym+add)@tprel@highesta */
#define R_PPC64_DTPREL16_DS        101 /* half16ds* (sym+add)@dtprel */
#define R_PPC64_DTPREL16_LO_DS     102 /* half16ds (sym+add)@dtprel@l */
#define R_PPC64_DTPREL16_HIGHER    103 /* half16   (sym+add)@dtprel@higher */
#define R_PPC64_DTPREL16_HIGHERA   104 /* half16  (sym+add)@dtprel@highera */
#define R_PPC64_DTPREL16_HIGHEST   105 /* half16  (sym+add)@dtprel@highest */
#define R_PPC64_DTPREL16_HIGHESTA  106 /* half16 (sym+add)@dtprel@highesta */

/*  Additional relocation types */
#define R_PPC64_TOC32              107
#define R_PPC64_DTPMOD32           108
#define R_PPC64_TPREL32            109
#define R_PPC64_DTPREL32           110

/*  Keep this the last entry.  */
#define R_PPC64_NUM                111
#endif /* _WIN32 */

/* PowerPC64 relocations defined by the ABIs */
static const char *reloc_type_names_PPC64[] = {
    "R_PPC64_NONE",                 /*  00 */
    "R_PPC64_ADDR32",               /*  01 */
    "R_PPC64_ADDR24",               /*  02 */
    "R_PPC64_ADDR16",               /*  03 */
    "R_PPC64_ADDR16_LO",            /*  04 */
    "R_PPC64_ADDR16_HI",            /*  05 */
    "R_PPC64_ADDR16_HA",            /*  06 */
    "R_PPC64_ADDR14",               /*  07 */
    "R_PPC64_ADDR14_BRTAKEN",       /*  08 */
    "R_PPC64_ADDR14_BRNTAKEN",      /*  09 */
    "R_PPC64_REL24",                /*  10 */
    "R_PPC64_REL14",                /*  11 */
    "R_PPC64_REL14_BRTAKEN",        /*  12 */
    "R_PPC64_REL14_BRNTAKEN",       /*  13 */
    "R_PPC64_GOT16",                /*  14 */
    "R_PPC64_GOT16_LO",             /*  15 */
    "R_PPC64_GOT16_HI",             /*  16 */
    "R_PPC64_GOT16_HA",             /*  17 */
    "R_PPC64_PLTREL24",             /*  18 */
    "R_PPC64_COPY",                 /*  19 */
    "R_PPC64_GLOB_DAT",             /*  20 */
    "R_PPC64_JMP_SLOT",             /*  21 */
    "R_PPC64_RELATIVE",             /*  22 */
    "R_PPC64_LOCAL24PC",            /*  23 */
    "R_PPC64_UADDR32",              /*  24 */
    "R_PPC64_UADDR16",              /*  25 */
    "R_PPC64_REL32",                /*  26 */
    "R_PPC64_PLT32",                /*  27 */
    "R_PPC64_PLTREL32",             /*  28 */
    "R_PPC64_PLT16_LO",             /*  29 */
    "R_PPC64_PLT16_HI",             /*  30 */
    "R_PPC64_PLT16_HA",             /*  31 */
    "R_PPC64_SDAREL16",             /*  32 */
    "R_PPC64_SECTOFF",              /*  33 */
    "R_PPC64_SECTOFF_LO",           /*  34 */
    "R_PPC64_SECTOFF_HI",           /*  35 */
    "R_PPC64_SECTOFF_HA",           /*  36 */
    "R_PPC64_REL30",                /*  37 */
    "R_PPC64_ADDR64",               /*  38 */
    "R_PPC64_ADDR16_HIGHER",        /*  39 */
    "R_PPC64_ADDR16_HIGHERA",       /*  40 */
    "R_PPC64_ADDR16_HIGHEST",       /*  41 */
    "R_PPC64_ADDR16_HIGHESTA",      /*  42 */
    "R_PPC64_UADDR64",              /*  43 */
    "R_PPC64_REL64",                /*  44 */
    "R_PPC64_PLT64",                /*  45 */
    "R_PPC64_PLTREL64",             /*  46 */
    "R_PPC64_TOC16",                /*  47 */
    "R_PPC64_TOC16_LO",             /*  48 */
    "R_PPC64_TOC16_HI",             /*  49 */
    "R_PPC64_TOC16_HA",             /*  50 */
    "R_PPC64_TOC",                  /*  51 */
    "R_PPC64_PLTGOT16",             /*  52 */
    "R_PPC64_PLTGOT16_LO",          /*  53 */
    "R_PPC64_PLTGOT16_HI",          /*  54 */
    "R_PPC64_PLTGOT16_HA",          /*  55 */
    "R_PPC64_ADDR16_DS",            /*  56 */
    "R_PPC64_ADDR16_LO_DS",         /*  57 */
    "R_PPC64_GOT16_DS",             /*  58 */
    "R_PPC64_GOT16_LO_DS",          /*  59 */
    "R_PPC64_PLT16_LO_DS",          /*  60 */
    "R_PPC64_SECTOFF_DS",           /*  61 */
    "R_PPC64_SECTOFF_LO_DS",        /*  62 */
    "R_PPC64_TOC16_DS",             /*  63 */
    "R_PPC64_TOC16_LO_DS",          /*  64 */
    "R_PPC64_PLTGOT16_DS",          /*  65 */
    "R_PPC64_PLTGOT16_LO_DS",       /*  66 */
    "R_PPC64_TLS",                  /*  67 */
    "R_PPC64_DTPMOD32",             /*  68 */
    "R_PPC64_TPREL16",              /*  69 */
    "R_PPC64_TPREL16_LO",           /*  70 */
    "R_PPC64_TPREL16_HI",           /*  71 */
    "R_PPC64_TPREL16_HA",           /*  72 */
    "R_PPC64_TPREL32",              /*  73 */
    "R_PPC64_DTPREL16",             /*  74 */
    "R_PPC64_DTPREL16_LO",          /*  75 */
    "R_PPC64_DTPREL16_HI",          /*  76 */
    "R_PPC64_DTPREL16_HA",          /*  77 */
    "R_PPC64_DTPREL64",             /*  78 */
    "R_PPC64_GOT_TLSGD16",          /*  79 */
    "R_PPC64_GOT_TLSGD16_LO",       /*  80 */
    "R_PPC64_GOT_TLSGD16_HI",       /*  81 */
    "R_PPC64_GOT_TLSGD16_HA",       /*  82 */
    "R_PPC64_GOT_TLSLD16",          /*  83 */
    "R_PPC64_GOT_TLSLD16_LO",       /*  84 */
    "R_PPC64_GOT_TLSLD16_HI",       /*  85 */
    "R_PPC64_GOT_TLSLD16_HA",       /*  86 */
    "R_PPC64_GOT_TPREL16_DS",       /*  87 */
    "R_PPC64_GOT_TPREL16_LO",       /*  88 */
    "R_PPC64_GOT_TPREL16_HI",       /*  89 */
    "R_PPC64_GOT_TPREL16_HA",       /*  90 */
    "R_PPC64_GOT_DTPREL16",         /*  91 */
    "R_PPC64_GOT_DTPREL16_LO",      /*  92 */
    "R_PPC64_GOT_DTPREL16_HI",      /*  93 */
    "R_PPC64_GOT_DTPREL16_HA",      /*  94 */
    "R_PPC64_TPREL16_DS",           /*  95 */
    "R_PPC64_TPREL16_LO_DS",        /*  96 */
    "R_PPC64_TPREL16_HIGHER",       /*  97 */
    "R_PPC64_TPREL16_HIGHERA",      /*  98 */
    "R_PPC64_TPREL16_HIGHEST",      /*  99 */
    "R_PPC64_TPREL16_HIGHESTA",     /* 100 */
    "R_PPC64_DTPREL16_DS",          /* 101 */
    "R_PPC64_DTPREL16_LO_DS",       /* 102 */
    "R_PPC64_DTPREL16_HIGHER",      /* 103 */
    "R_PPC64_DTPREL16_HIGHERA",     /* 104 */
    "R_PPC64_DTPREL16_HIGHEST",     /* 105 */
    "R_PPC64_DTPREL16_HIGHESTA",    /* 106 */
    "R_PPC64_TOC32",                /* 107 */
    "R_PPC64_DTPMOD32",             /* 108 */
    "R_PPC64_TPREL32",              /* 109 */
    "R_PPC64_DTPREL32",             /* 110 */
};
#endif /* DWARF_RELOC_PPC64_H */
