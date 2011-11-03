/*

  Copyright (C) 2000 Silicon Graphics, Inc.  All Rights Reserved.

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

  You should have received a copy of the GNU Lesser General Public 
  License along with this program; if not, write the Free Software 
  Foundation, Inc., 59 Temple Place - Suite 330, Boston MA 02111-1307, 
  USA.

  Contact information:  Silicon Graphics, Inc., 1600 Amphitheatre Pky,
  Mountain View, CA 94043, or:

  http://www.sgi.com

  For further information regarding this notice, see:

  http://oss.sgi.com/projects/GenInfo/NoticeExplan

*/




#define IS_64BIT(dbg) 	((dbg)->de_flags & DW_DLC_SIZE_64 ? 1 : 0)
#define ISA_IA64(dbg) 	((dbg)->de_flags & DW_DLC_ISA_IA64 ? 1 : 0)

/* definition of sizes of types, given target machine */
#define sizeof_sbyte(dbg) 	sizeof(Dwarf_Sbyte)
#define sizeof_ubyte(dbg)	sizeof(Dwarf_Ubyte)
#define sizeof_uhalf(dbg)	sizeof(Dwarf_Half)
/* certain sizes not defined here, but set in dbg record.
   See pro_init.c
*/

/* Computes amount of padding necessary to align n to a k-boundary. */
/* Important: Assumes n, k both GREATER than zero. */
#define PADDING(n, k) ( (k)-1 - ((n)-1)%(k) )

/* The following defines are only important for users of the
** producer part of libdwarf, and such should have these
** defined correctly (as necessary) 
** by the #include <elf.h> done in pro_incl.h
** before the #include "pro_util.h".
** For others producer macros do not matter so 0 is a usable value, and
** zero values let compilation succeed on more non-MIPS architectures.
** A better approach would be welcome.
*/
/* R_MIPS* are #define so #ifndef works */
/* R_IA_64* are not necessarily #define (might be enum) so #ifndef
   is useless, we use the configure script generating 
   HAVE_R_IA_64_DIR32LSB.
*/
#ifndef R_MIPS_64
#define R_MIPS_64 0
#endif
#ifndef R_MIPS_32
#define R_MIPS_32 0
#endif
#ifndef R_MIPS_SCN_DISP
#define R_MIPS_SCN_DISP 0
#endif

#ifndef HAVE_R_IA_64_DIR32LSB
#define R_IA_64_DIR32LSB 0
#define R_IA_64_DIR64LSB 0
#define R_IA_64_SEGREL64LSB 0
#define R_IA_64_SEGREL32LSB 0
#endif

#ifdef HAVE_SYS_IA64_ELF_H
#define Get_REL64_isa(dbg)         (ISA_IA64(dbg) ? \
				R_IA_64_DIR64LSB : R_MIPS_64)
#define Get_REL32_isa(dbg)         (ISA_IA64(dbg) ? \
				R_IA_64_DIR32LSB : R_MIPS_32)


/* ia64 uses 32bit dwarf offsets for sections */
#define Get_REL_SEGREL_isa(dbg)    (ISA_IA64(dbg) ? \
				R_IA_64_SEGREL32LSB : R_MIPS_SCN_DISP)
#else

#if !defined(linux) && !defined(__BEOS__)
#define Get_REL64_isa(dbg)         (R_MIPS_64)
#define Get_REL32_isa(dbg)         (R_MIPS_32)
#define Get_REL_SEGREL_isa(dbg)    (R_MIPS_SCN_DISP)
#else
#define Get_REL64_isa(dbg)	(R_IA_64_DIR64LSB)
#define Get_REL32_isa(dbg)	(R_IA_64_DIR32LSB)
#define Get_REL_SEGREL_isa(dbg)	(R_IA_64_SEGREL64LSB)
#endif

#endif
