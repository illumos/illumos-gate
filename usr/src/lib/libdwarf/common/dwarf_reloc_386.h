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

#ifndef DWARF_RELOC_386_H
#define DWARF_RELOC_386_H

/* Include the definitions only in the case of Windows */
#ifdef _WIN32
/* Relocation types for i386 architecture */
#define R_386_NONE         0
#define R_386_32           1
#define R_386_PC32         2
#define R_386_GOT32        3
#define R_386_PLT32        4
#define R_386_COPY         5
#define R_386_GLOB_DAT     6
#define R_386_JMP_SLOT     7
#define R_386_RELATIVE     8
#define R_386_GOTOFF       9
#define R_386_GOTPC        10
#define R_386_32PLT        11
#define R_386_TLS_TPOFF    14
#define R_386_TLS_IE       15
#define R_386_TLS_GOTIE    16
#define R_386_TLS_LE       17
#define R_386_TLS_LDM      19
#define R_386_16           20
#define R_386_PC16         21
#define R_386_8            22
#define R_386_PC8          23
#define R_386_TLS_GD_32    24
#define R_386_TLS_GD_PUSH  25
#define R_386_TLS_GD_CALL  26
#define R_386_TLS_GD_POP   27
#define R_386_TLS_LDM_32   28
#define R_386_TLS_LDM_PUSH 29
#define R_386_TLS_LDM_CALL 30
#define R_386_TLS_LDM_POP  31
#define R_386_TLS_LDO_32   32
#define R_386_TLS_IE_32    33
#define R_386_TLS_LE_32    34
#define R_386_TLS_DTPMOD32 35
#define R_386_TLS_DTPOFF32 36
#define R_386_TLS_TPOFF32  37
#define R_386_SIZE32       38
#define R_386_TLS_GOTDESC  39
#define R_386_TLS_DESC_CALL 40
#define R_386_TLS_DESC     41
#define R_386_IRELATIVE    42
#define R_386_NUM          43


/*  Keep this the last entry.  */
#define R_X86_64_NUM             39
#endif /* _WIN32 */

/* Relocation types for X86_64 */
static const char *reloc_type_names_386[] = {
"R_386_NONE",
"R_386_32",
"R_386_PC32",
"R_386_GOT32",
"R_386_PLT32",
"R_386_COPY",        /* 5 */
"R_386_GLOB_DAT",
"R_386_JMP_SLOT",
"R_386_RELATIVE",
"R_386_GOTOFF",
"R_386_GOTPC",      /*  10 */
"R_386_32PLT",
"R_386_TLS_TPOFF",
"R_386_TLS_IE",
"R_386_TLS_GOTIE",
"R_386_TLS_LE",
"R_386_TLS_LDM",
"R_386_16",         /*  20 */
"R_386_PC16",
"R_386_8",
"R_386_PC8",
"R_386_TLS_GD_32",
"R_386_TLS_GD_PUSH", /* 25 */
"R_386_TLS_GD_CALL",
"R_386_TLS_GD_POP",
"R_386_TLS_LDM_32",
"R_386_TLS_LDM_PUSH",
"R_386_TLS_LDM_CALL", /* 30 */
"R_386_TLS_LDM_POP",
"R_386_TLS_LDO_32",
"R_386_TLS_IE_32",
"R_386_TLS_LE_32",
"R_386_TLS_DTPMOD32", /* 35 */
"R_386_TLS_DTPOFF32",
"R_386_TLS_TPOFF32",
"R_386_SIZE32",
"R_386_TLS_GOTDESC",
"R_386_TLS_DESC_CALL", /* 40 */
"R_386_TLS_DESC",
"R_386_IRELATIVE",   /* 42 */
};
#endif /* DWARF_RELOC_386_H */
