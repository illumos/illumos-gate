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

#ifndef DWARF_RELOC_X86_64_H
#define DWARF_RELOC_X86_64_H

/* Definitions for X86_64 */
#define DWARF_RELOC_X86_64

/* Include the definitions only in the case of Windows */
#ifdef _WIN32
/* Relocation types for AMD x86-64 architecture */
#define R_X86_64_NONE             0 /* No reloc */
#define R_X86_64_64               1 /* Direct 64 bit  */
#define R_X86_64_PC32             2 /* PC relative 32 bit signed */
#define R_X86_64_GOT32            3 /* 32 bit GOT entry */
#define R_X86_64_PLT32            4 /* 32 bit PLT address */
#define R_X86_64_COPY             5 /* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT         6 /* Create GOT entry */
#define R_X86_64_JUMP_SLOT        7 /* Create PLT entry */
#define R_X86_64_RELATIVE	      8 /* Adjust by program base */
#define R_X86_64_GOTPCREL	      9 /* 32 bit signed pc relative offset to GOT */
#define R_X86_64_32		         10 /* Direct 32 bit zero extended */
#define R_X86_64_32S		     11 /* Direct 32 bit sign extended */
#define R_X86_64_16		         12 /* Direct 16 bit zero extended */
#define R_X86_64_PC16		     13 /* 16 bit sign extended pc relative */
#define R_X86_64_8		         14 /* Direct 8 bit sign extended  */
#define R_X86_64_PC8		     15 /* 8 bit sign extended pc relative */
#define R_X86_64_DTPMOD64        16 /* ID of module containing symbol */
#define R_X86_64_DTPOFF64        17 /* Offset in module's TLS block */
#define R_X86_64_TPOFF64         18 /* Offset in initial TLS block */
#define R_X86_64_TLSGD           19 /* 32 bit signed PC relative offset
                                        to two GOT entries for GD symbol */
#define R_X86_64_TLSLD           20 /* 32 bit signed PC relative offset
                                        to two GOT entries for LD symbol */
#define R_X86_64_DTPOFF32        21 /* Offset in TLS block */
#define R_X86_64_GOTTPOFF        22 /* 32 bit signed PC relative offset
                                        to GOT entry for IE symbol */
#define R_X86_64_TPOFF32         23 /* Offset in initial TLS block */
#define R_X86_64_PC64            24 /* PC relative 64 bit */
#define R_X86_64_GOTOFF64        25 /* 64 bit offset to GOT */
#define R_X86_64_GOTPC32         26 /* 32 bit signed pc relative offset to GOT */
#define R_X86_64_GOT64           27 /* 64-bit GOT entry offset */
#define R_X86_64_GOTPCREL64      28 /* 64-bit PC relative offset to GOT entry */
#define R_X86_64_GOTPC64         29 /* 64-bit PC relative offset to GOT */
#define R_X86_64_GOTPLT64        30 /* like GOT64, says PLT entry needed */
#define R_X86_64_PLTOFF64        31 /* 64-bit GOT relative offset to PLT entry */
#define R_X86_64_SIZE32          32 /* Size of symbol plus 32-bit addend */
#define R_X86_64_SIZE64          33 /* Size of symbol plus 64-bit addend */
#define R_X86_64_GOTPC32_TLSDESC 34 /* GOT offset for TLS descriptor */
#define R_X86_64_TLSDESC_CALL    35 /* Marker for call through TLS descriptor */
#define R_X86_64_TLSDESC         36 /* TLS descriptor */
#define R_X86_64_IRELATIVE       37 /* Adjust indirectly by program base */
#define R_X86_64_RELATIVE64      38 /* 64bit adjust by program base */

/*  Keep this the last entry.  */
#define R_X86_64_NUM             39
#endif /* _WIN32 */

/* Relocation types for X86_64 */
static const char *reloc_type_names_X86_64[] = {
    "R_X86_64_NONE",            /* 00 */
    "R_X86_64_64",              /* 01 */
    "R_X86_64_PC32",            /* 02 */
    "R_X86_64_GOT32",           /* 03 */
    "R_X86_64_PLT32",           /* 04 */
    "R_X86_64_COPY",            /* 05 */
    "R_X86_64_GLOB_DAT",        /* 06 */
    "R_X86_64_JUMP_SLOT",       /* 07 */
    "R_X86_64_RELATIVE",        /* 08 */
    "R_X86_64_GOTPCREL",        /* 09 */
    "R_X86_64_32",              /* 10 */
    "R_X86_64_32S",             /* 11 */
    "R_X86_64_16",              /* 12 */
    "R_X86_64_PC16",            /* 13 */
    "R_X86_64_8",               /* 14 */
    "R_X86_64_PC8",             /* 15 */
    "R_X86_64_DTPMOD64",        /* 16 */
    "R_X86_64_DTPOFF64",        /* 17 */
    "R_X86_64_TPOFF64",         /* 18 */
    "R_X86_64_TLSGD",           /* 19 */
    "R_X86_64_TLSLD",           /* 20 */
    "R_X86_64_DTPOFF32",        /* 21 */
    "R_X86_64_GOTTPOFF",        /* 22 */
    "R_X86_64_TPOFF32",         /* 23 */
    "R_X86_64_PC64",            /* 24 */
    "R_X86_64_GOTOFF64",        /* 25 */
    "R_X86_64_GOTPC32",         /* 26 */
    "R_X86_64_GOT64",           /* 27 */
    "R_X86_64_GOTPCREL64",      /* 28 */
    "R_X86_64_GOTPC64",         /* 29 */
    "R_X86_64_GOTPLT64",        /* 30 */
    "R_X86_64_PLTOFF64",        /* 31 */
    "R_X86_64_SIZE32",          /* 32 */
    "R_X86_64_SIZE64",          /* 33 */
    "R_X86_64_GOTPC32_TLSDESC", /* 34 */
    "R_X86_64_TLSDESC_CALL",    /* 35 */
    "R_X86_64_TLSDESC",         /* 36 */
    "R_X86_64_IRELATIVE",       /* 37 */
    "R_X86_64_RELATIVE64",      /* 38 */
};
#endif /* DWARF_RELOC_X86_64_H */
