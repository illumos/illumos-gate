/*
  Copyright (C) 2018 David Anderson  All Rights Reserved.

  This program is free software; you can redistribute it
  and/or modify it under the terms of version 2.1 of the
  GNU Lesser General Public License as published by the Free
  Software Foundation.

  This program is distributed in the hope that it would be
  useful, but WITHOUT ANY WARRANTY; without even the implied
  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.

  Further, this software is distributed without any warranty
  that it is free of the rightful claim of any third person
  regarding infringement or the like.  Any license provided
  herein, whether implied or otherwise, applies only to this
  software file.  Patent licenses, if any, provided herein
  do not apply to combinations of this program with other
  software, or any other product whatsoever.

  You should have received a copy of the GNU Lesser General
  Public License along with this program; if not, write the
  Free Software Foundation, Inc., 51 Franklin Street - Fifth
  Floor, Boston MA 02110-1301, USA.

*/

/*  The numbers here are almost all 32 bits.
    Not long  long ever.
    In the public function interfaces we'll use Dwarf_Unsigned though,
    for call consistency with everything else.
    Here we use Dwarf_Unsigned to avoid having to
    even know what is or is not 32 bits. */

typedef Dwarf_Unsigned dn_type;

struct Dwarf_P_Dnames_Head_s {
    Dwarf_Unsigned dh_unit_length;
    unsigned       dh_version;
    dn_type dh_comp_unit_count;
    dn_type dh_local_type_unit_count;
    dn_type dh_foreign_type_unit_count;
    dn_type dh_bucket_count;
    dn_type dh_name_count;
    dn_type dh_abbrev_table_size;
    dn_type dh_augmentation_string_size;
    const char *   dh_augmentation_string;
};

struct Dwarf_P_Dnames_uarray_s {
    dn_type  dne_allocated;
    dn_type  dne_used;
    dn_type  *dne_values;
};
struct Dwarf_P_Dnames_sarray_s {
    dn_type     dne_allocated;
    dn_type     dne_used;
    Dwarf_Sig8 *dne_values;
};


struct Dwarf_P_Dnames_s {
    Dwarf_Small dn_create_section;
    struct Dwarf_P_Dnames_Head_s dn_header;
    struct Dwarf_P_Dnames_uarray_s dn_cunit_offset;
    struct Dwarf_P_Dnames_uarray_s dn_tunit_offset;
    struct Dwarf_P_Dnames_sarray_s dn_sunit_sigs;

    struct Dwarf_P_Dnames_uarray_s dn_buckets;

    /* Hashes count applies to string offsets and entry offsets arrays too. */
    struct Dwarf_P_Dnames_uarray_s dn_hashes;
    struct Dwarf_P_Dnames_uarray_s dn_string_offsets;
    struct Dwarf_P_Dnames_uarray_s dn_entry_pool;

    Dwarf_Small *dn_index_entry_pool;
    Dwarf_Small  dn_index_entry_pool_size;
    Dwarf_Small  dn_index_entry_pool_used;

};
