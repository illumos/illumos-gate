/*

  Copyright (C) 2000 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2008-2011  David Anderson. All Rights Reserved.

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




/*
    This struct holds information about an abbreviation.
    It is put in the hash table for abbreviations for
    a compile-unit.

    It's by dwarf_finish().
*/
struct Dwarf_Abbrev_List_s {
    Dwarf_Unsigned abl_code;
    Dwarf_Half abl_tag;
    Dwarf_Half abl_has_child;
    /* Section global offset of this abbrev entry. */
    Dwarf_Off      abl_goffset;

    /*  Singly linked synonym list in case of duplicate
        hash. */
    struct Dwarf_Abbrev_List_s *abl_next;

    /*  Points to start of attribute/form pairs in
        the .debug_abbrev section for the abbrev. */
    Dwarf_Byte_Ptr abl_abbrev_ptr;

    /*  The number of at/form[/implicitvalue] pairs
        in this abbrev. */
    Dwarf_Unsigned abl_count;
};
