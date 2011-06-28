/*

  Copyright (C) 2000,2003,2004 Silicon Graphics, Inc.  All Rights Reserved.

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



/* Define to 1 if the elf64_getshdr function is in libelf.a */
#undef HAVE_ELF64_GETSHDR

/* Define to 1 if the elf64_getehdr function is in libelf.a */
#undef HAVE_ELF64_GETEHDR


/* see if __uint32_t is predefined in the compiler */
#undef HAVE___UINT32_T

/* see if __uint64_t is predefined in the compiler */
#undef HAVE___UINT64_T

/* Define 1 if sys/types.h defines __uint32_t */
#undef HAVE___UINT32_T_IN_SYS_TYPES_H

/* Define 1 if  R_IA_64_DIR32LSB is defined (might be enum value) */
#undef HAVE_R_IA_64_DIR32LSB

/* Define 1 if sys/ia64/elf.h exists*/
#undef HAVE_SYS_IA64_ELF_H

/* Define 1 if want to build with 32/64bit section offsets for ia64 */
/* per the dwarf2 committee proposal adopted Dec 1999 */
#undef HAVE_DWARF2_99_EXTENSION

/* Define 1 if want only 32bit section offsets per pure dwarf2.0.0 spec */
/* Only one of HAVE_OLD_DWARF2_32BIT_OFFSET or HAVE_DWARF2_99_EXTENSION */
/* may be defined */
#undef HAVE_OLD_DWARF2_32BIT_OFFSET

