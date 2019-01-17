/*

  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2008-2010 David Anderson, Inc. All rights reserved.

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

  Contact information:  Silicon Graphics, Inc., 1500 Crittenden Lane,
  Mountain View, CA 94043, or:

  http://www.sgi.com

  For further information regarding this notice, see:

  http://oss.sgi.com/projects/GenInfo/NoticeExplan

*/



#include "config.h"
#include "libdwarfdefs.h"
#include <stdio.h>
#include <string.h>
/*#include <elfaccess.h> */
#include "pro_incl.h"


/*Do initial alloc of newslots slots.
  Fails only if malloc fails.

  Supposed to be called before any relocs allocated.
  Ignored if after any allocated.

  Part of an optimization, so that for a known 'newslots' 
  relocations count we can preallocate the right size block.
  Called from just 2 places.

  returns DW_DLV_OK or  DW_DLV_ERROR
*/
int
_dwarf_pro_pre_alloc_n_reloc_slots(Dwarf_P_Debug dbg,
    int rel_sec_index,
    Dwarf_Unsigned newslots)
{
    unsigned long len = 0;
    struct Dwarf_P_Relocation_Block_s *data = 0;
    Dwarf_P_Per_Reloc_Sect prel = &dbg->de_reloc_sect[rel_sec_index];
    unsigned long slots_in_blk = (unsigned long) newslots;
    unsigned long rel_rec_size = dbg->de_relocation_record_size;

    if (prel->pr_first_block)
        return DW_DLV_OK;       /* do nothing */

    len = sizeof(struct Dwarf_P_Relocation_Block_s) +
        slots_in_blk * rel_rec_size;


    data = (struct Dwarf_P_Relocation_Block_s *)
        _dwarf_p_get_alloc(dbg, len);
    if (!data) {
        return DW_DLV_ERROR;
    }
    data->rb_slots_in_block = slots_in_blk;     /* could use default
                                                   here, as fallback in 
                                                   case our origininal
                                                   estimate wrong. When 
                                                   we call this we
                                                   presumably know what 
                                                   we are doing, so
                                                   keep this count for
                                                   now */
    data->rb_next_slot_to_use = 0;
    data->rb_where_to_add_next =
        ((char *) data) + sizeof(struct Dwarf_P_Relocation_Block_s);
    data->rb_data = data->rb_where_to_add_next;

    prel->pr_first_block = data;
    prel->pr_last_block = data;
    prel->pr_block_count = 1;


    return DW_DLV_OK;
}


/*Do alloc of slots.
  Fails only if malloc fails.

  Only allocator used.

  returns DW_DLV_OK or  DW_DLV_ERROR
*/
int
_dwarf_pro_alloc_reloc_slots(Dwarf_P_Debug dbg, int rel_sec_index)
{
    unsigned long len = 0;
    struct Dwarf_P_Relocation_Block_s *data = 0;
    Dwarf_P_Per_Reloc_Sect prel = &dbg->de_reloc_sect[rel_sec_index];
    unsigned long slots_in_blk = prel->pr_slots_per_block_to_alloc;
    unsigned long rel_rec_size = dbg->de_relocation_record_size;

    len = sizeof(struct Dwarf_P_Relocation_Block_s) +
        slots_in_blk * rel_rec_size;

    data = (struct Dwarf_P_Relocation_Block_s *)
        _dwarf_p_get_alloc(dbg, len);
    if (!data) {
        return DW_DLV_ERROR;
    }

    if (prel->pr_first_block) {
        prel->pr_last_block->rb_next = data;
        prel->pr_last_block = data;
        prel->pr_block_count += 1;

    } else {

        prel->pr_first_block = data;
        prel->pr_last_block = data;
        prel->pr_block_count = 1;
    }

    data->rb_slots_in_block = slots_in_blk;
    data->rb_next_slot_to_use = 0;
    data->rb_where_to_add_next =
        ((char *) data) + sizeof(struct Dwarf_P_Relocation_Block_s);
    data->rb_data = data->rb_where_to_add_next;

    return DW_DLV_OK;

}

/*
        Reserve a slot. return DW_DLV_OK if succeeds.

        Return DW_DLV_ERROR if fails (malloc error).

        Use the relrec_to_fill to pass back a pointer to
        a slot space to use.
*/
int
_dwarf_pro_reloc_get_a_slot(Dwarf_P_Debug dbg,
    int base_sec_index, void **relrec_to_fill)
{
    struct Dwarf_P_Relocation_Block_s *data = 0;
    Dwarf_P_Per_Reloc_Sect prel = &dbg->de_reloc_sect[base_sec_index];
    unsigned long rel_rec_size = dbg->de_relocation_record_size;

    char *ret_addr = 0;

    data = prel->pr_last_block;
    if ((data == 0) ||
        (data->rb_next_slot_to_use >= data->rb_slots_in_block)) {
        int res;

        res = _dwarf_pro_alloc_reloc_slots(dbg, base_sec_index);
        if (res != DW_DLV_OK) {
            return res;
        }
    }

    data = prel->pr_last_block;
    /* now we have an empty slot */
    ret_addr = data->rb_where_to_add_next;

    data->rb_where_to_add_next += rel_rec_size;
    data->rb_next_slot_to_use += 1;

    prel->pr_reloc_total_count += 1;

    *relrec_to_fill = (void *) ret_addr;

    return DW_DLV_OK;

}

/*
   On success  returns count of
   .rel.* sections that are symbolic 
   thru count_of_relocation_sections.

   On success, returns DW_DLV_OK.

   If this is not a 'symbolic' run, returns
    DW_DLV_NO_ENTRY.

   No errors are possible.




*/

 /*ARGSUSED*/ int
dwarf_get_relocation_info_count(Dwarf_P_Debug dbg,
    Dwarf_Unsigned *
    count_of_relocation_sections,
    int *drd_buffer_version,
    Dwarf_Error * error)
{
    if (dbg->de_flags & DW_DLC_SYMBOLIC_RELOCATIONS) {
        int i;
        unsigned int count = 0;

        for (i = 0; i < NUM_DEBUG_SECTIONS; ++i) {
            if (dbg->de_reloc_sect[i].pr_reloc_total_count > 0) {
                ++count;
            }
        }
        *count_of_relocation_sections = (Dwarf_Unsigned) count;
        *drd_buffer_version = DWARF_DRD_BUFFER_VERSION;
        return DW_DLV_OK;
    }
    return DW_DLV_NO_ENTRY;
}

int
dwarf_get_relocation_info(Dwarf_P_Debug dbg,
    Dwarf_Signed * elf_section_index,
    Dwarf_Signed * elf_section_index_link,
    Dwarf_Unsigned * relocation_buffer_count,
    Dwarf_Relocation_Data * reldata_buffer,
    Dwarf_Error * error)
{
    int next = dbg->de_reloc_next_to_return;

    if (dbg->de_flags & DW_DLC_SYMBOLIC_RELOCATIONS) {
        int i;

        for (i = next; i < NUM_DEBUG_SECTIONS; ++i) {
            Dwarf_P_Per_Reloc_Sect prel = &dbg->de_reloc_sect[i];

            if (prel->pr_reloc_total_count > 0) {
                dbg->de_reloc_next_to_return = i + 1;


                /* ASSERT: prel->.pr_block_count == 1 */

                *elf_section_index = prel->pr_sect_num_of_reloc_sect;
                *elf_section_index_link = dbg->de_elf_sects[i];
                *relocation_buffer_count = prel->pr_reloc_total_count;
                *reldata_buffer = (Dwarf_Relocation_Data)
                    (prel->pr_first_block->rb_data);
                return DW_DLV_OK;
            }
        }
        DWARF_P_DBG_ERROR(dbg, DW_DLE_REL_ALLOC, DW_DLV_ERROR);
    }
    return DW_DLV_NO_ENTRY;
}
