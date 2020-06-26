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

#ifndef DWARF_RELOC_MIPS_H
#define DWARF_RELOC_MIPS_H

/* Definitions for MIPS */
#define DWARF_RELOC_MIPS

/* Include the definitions only in the case of Windows */
#ifdef _WIN32
/* Relocation types for MIPS */
#define R_MIPS_NONE                   0
#define R_MIPS_16                     1
#define R_MIPS_32                     2
#define R_MIPS_ADD                    R_MIPS_32
#define R_MIPS_REL                    3
#define R_MIPS_REL32                  R_MIPS_REL
#define R_MIPS_26                     4
#define R_MIPS_HI16                   5
#define R_MIPS_LO16                   6
#define R_MIPS_GPREL                  7
#define R_MIPS_GPREL16                R_MIPS_GPREL
#define R_MIPS_LITERAL                8
#define R_MIPS_GOT                    9
#define R_MIPS_GOT16                  R_MIPS_GOT
#define R_MIPS_PC16                  10
#define R_MIPS_CALL                  11
#define R_MIPS_CALL16                R_MIPS_CALL
#define R_MIPS_GPREL32               12
#define R_MIPS_UNUSED1               13
#define R_MIPS_UNUSED2               14
#define R_MIPS_UNUSED3               15
#define R_MIPS_SHIFT5                16
#define R_MIPS_SHIFT6                17
#define R_MIPS_64                    18
#define R_MIPS_GOT_DISP              19
#define R_MIPS_GOT_PAGE              20
#define R_MIPS_GOT_OFST              21
#define R_MIPS_GOT_HI16              22
#define R_MIPS_GOT_LO16              23
#define R_MIPS_SUB                   24
#define R_MIPS_INSERT_A              25
#define R_MIPS_INSERT_B              26
#define R_MIPS_DELETE                27
#define R_MIPS_HIGHER                28
#define R_MIPS_HIGHEST               29
#define R_MIPS_CALL_HI16             30
#define R_MIPS_CALL_LO16             31
#define R_MIPS_SCN_DISP              32
#define	R_MIPS_REL16                 33
#define R_MIPS_ADD_IMMEDIATE         34

/*  Keep this the last entry.  */
#define R_MIPS_NUM                   35
#endif /* _WIN32 */

/* Relocation types for MIPS */
static const char *reloc_type_names_MIPS[] = {
    "R_MIPS_NONE",              /* 00 */
    "R_MIPS_16",                /* 01 */
    "R_MIPS_32",                /* 02 */
    "R_MIPS_REL32",             /* 03 */
    "R_MIPS_26",                /* 04 */
    "R_MIPS_HI16",              /* 05 */
    "R_MIPS_LO16",              /* 06 */
    "R_MIPS_GPREL16",           /* 07 */
    "R_MIPS_LITERAL",           /* 08 */
    "R_MIPS_GOT16",             /* 09 */
    "R_MIPS_PC16",              /* 10 */
    "R_MIPS_CALL16",            /* 11 */
    "R_MIPS_GPREL32",           /* 12 */
    "R_MIPS_UNUSED1",           /* 13 */
    "R_MIPS_UNUSED2",           /* 14 */
    "R_MIPS_UNUSED3",           /* 15 */
    "R_MIPS_SHIFT5",            /* 16 */
    "R_MIPS_SHIFT6",            /* 17 */
    "R_MIPS_64",                /* 18 */
    "R_MIPS_GOT_DISP",          /* 19 */
    "R_MIPS_GOT_PAGE",          /* 20 */
    "R_MIPS_GOT_OFST",          /* 21 */
    "R_MIPS_GOT_HI16",          /* 22 */
    "R_MIPS_GOT_LO16",          /* 23 */
    "R_MIPS_SUB",               /* 24 */
    "R_MIPS_INSERT_A",          /* 25 */
    "R_MIPS_INSERT_B",          /* 26 */
    "R_MIPS_DELETE",            /* 27 */
    "R_MIPS_HIGHER",            /* 28 */
    "R_MIPS_HIGHEST",           /* 29 */
    "R_MIPS_CALL_HI16",         /* 30 */
    "R_MIPS_CALL_LO16",         /* 31 */
    "R_MIPS_SCN_DISP",          /* 32 */
    "R_MIPS_REL16",             /* 33 */
    "R_MIPS_ADD_IMMEDIATE",     /* 34 */
};
#endif /* DWARF_RELOC_MIPS_H */
