/*

  Copyright (C) 2000,2004,2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2011 David Anderson. All Rights Reserved.


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
  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston MA 02110-1301,
  USA.

*/




typedef struct Dwarf_Global_Context_s *Dwarf_Global_Context;

/*
    This struct contains header information for a set of pubnames.
    Essentially, they contain the context for a set of pubnames
    belonging to a compilation-unit.

    This is also used for the sgi-specific
    weaknames, typenames, varnames, funcnames data:
    the structs for those are incomplete and
    instances of this are used instead.

    Also used for DWARF3 .debug_pubtypes.

    These never refer to .debug_types, only to .debug_info.

*/
struct Dwarf_Global_Context_s {

    /*  For this context, size of a length. 4 or 8 */
    unsigned char pu_length_size;

    /* Size of the pubnames data for the CU */
    unsigned char pu_length;

    /*  For this CU, size of the extension 0 except for dwarf2 extension
        64bit, in which case is 4. */
    unsigned char pu_extension_size;

    Dwarf_Half pu_version; /* 2,3, or 4 */

    /*  offset in pubnames of the  pu header. */
    Dwarf_Off      pu_pub_offset;

    /*  Offset into .debug_info of the compilation-unit header (not DIE)
        for this set of pubnames. */
    Dwarf_Off pu_offset_of_cu_header;

    /*  Size of compilation-unit that these pubnames are in. */
    Dwarf_Unsigned pu_info_length;

    Dwarf_Debug pu_dbg;
};


/* This struct contains information for a single pubname. */
struct Dwarf_Global_s {

    /*  Offset from the start of the corresponding compilation-unit of
        the DIE for the given pubname CU. */
    Dwarf_Off gl_named_die_offset_within_cu;

    /* Points to the given pubname. */
    Dwarf_Small *gl_name;

    /* Context for this pubname. */
    Dwarf_Global_Context gl_context;

};

int _dwarf_internal_get_pubnames_like_data(Dwarf_Debug dbg,
    Dwarf_Small *
    section_data_ptr,
    Dwarf_Unsigned
    section_length,
    Dwarf_Global ** globals,
    Dwarf_Signed * return_count,
    Dwarf_Error * error,
    int context_code,
    int global_code,
    int length_err_num,
    int version_err_num);

void
_dwarf_internal_globals_dealloc( Dwarf_Debug dbg, Dwarf_Global *dwgl,
    Dwarf_Signed count,
    int context_code,
    int global_code,
    int list_code);


#ifdef __sgi  /* __sgi should only be defined for IRIX/MIPS. */
void _dwarf_fix_up_offset_irix(Dwarf_Debug dbg,
    Dwarf_Unsigned *varp,
    char *caller_site_name);
#define FIX_UP_OFFSET_IRIX_BUG(ldbg,var,name) _dwarf_fix_up_offset_irix(ldbg,&var,name)
#else  /* ! __sgi */
#define FIX_UP_OFFSET_IRIX_BUG(ldbg,var,name)
#endif  /* __sgi */
