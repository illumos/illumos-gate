/*

  Copyright (C) 2000,2001,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2002-2010 Sun Microsystems, Inc. All rights reserved.
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
#ifdef HAVE_ELFACCESS_H
#include <elfaccess.h>
#else
/* Set r_info  as defined by ELF generic ABI */
#define Set_REL32_info(r,s,t) ((r).r_info = ELF32_R_INFO(s,t))
#define Set_REL64_info(r,s,t) ((r).r_info = ELF64_R_INFO(s,t))
#endif
#include "pro_incl.h"
#include "pro_section.h"
#include "pro_reloc.h"
#include "pro_reloc_stream.h"

/*
        Return DW_DLV_ERROR on malloc error or reltarget_length error.
        Return DW_DLV_OK otherwise



*/
 /*ARGSUSED*/ int
_dwarf_pro_reloc_name_stream64(Dwarf_P_Debug dbg,
    int base_sec_index,
    Dwarf_Unsigned offset,      /* r_offset of reloc */
    Dwarf_Unsigned symidx,
    enum Dwarf_Rel_Type type,
    int reltarget_length)
{
#if HAVE_ELF64_GETEHDR
    REL64 *elf64_reloc = 0;
    void *relrec_to_fill = 0;
    int res = 0;
    int rel_type = 0;

    res = _dwarf_pro_reloc_get_a_slot(dbg, base_sec_index,
                                      &relrec_to_fill);
    if (res != DW_DLV_OK)
        return res;


    if (type == dwarf_drt_data_reloc) {
        if (reltarget_length == dbg->de_offset_size) {
            rel_type = dbg->de_offset_reloc;
        } else if (reltarget_length == dbg->de_pointer_size) {
            rel_type = dbg->de_ptr_reloc;
        } else {
            return DW_DLV_ERROR;
        }
    } else if (type == dwarf_drt_segment_rel) {
        rel_type = dbg->de_exc_reloc;
    } else {
        /* We are in trouble: improper use of stream relocations.
           Someone else will diagnose */
        rel_type = 0;
    }

    elf64_reloc = (REL64 *)relrec_to_fill;
    elf64_reloc->r_offset = offset;
    Set_REL64_info(*elf64_reloc, symidx, rel_type);
    return DW_DLV_OK;
#else /* !HAVE_ELF64_GETEHDR */
    return DW_DLV_ERROR;
#endif /* #if HAVE_ELF64_GETEHDR */
}

/*
        Return DW_DLV_ERROR on malloc error or reltarget_length error.
        Return DW_DLV_OK otherwise
        a binary reloc: 32bit ABI
*/
int
_dwarf_pro_reloc_name_stream32(Dwarf_P_Debug dbg, int base_sec_index, 
    Dwarf_Unsigned offset,      /* r_offset of reloc */
    Dwarf_Unsigned symidx,
    enum Dwarf_Rel_Type type,
    int reltarget_length)
{
    REL32 *elf32_reloc = 0;
    void *relrec_to_fill = 0;
    int res = 0;
    int rel_type = 0;

    res = _dwarf_pro_reloc_get_a_slot(dbg, base_sec_index,
                                      &relrec_to_fill);
    if (res != DW_DLV_OK)
        return res;
    if (type == dwarf_drt_data_reloc) {
        if (reltarget_length == dbg->de_offset_size) {
            rel_type = dbg->de_offset_reloc;
        } else if (reltarget_length == dbg->de_pointer_size) {
            rel_type = dbg->de_ptr_reloc;
        } else {
            return DW_DLV_ERROR;
        }
    } else if (type == dwarf_drt_segment_rel) {
        rel_type = dbg->de_exc_reloc;
    } else {
        /* We are in trouble: improper use of stream relocations.
           Someone else will diagnose */
        rel_type = 0;
    }

    elf32_reloc = (REL32*)relrec_to_fill;
    elf32_reloc->r_offset = (Elf32_Addr) offset;
    Set_REL32_info(*elf32_reloc, (Dwarf_Word) symidx, rel_type);
    return DW_DLV_OK;

    /* get a slot, fill in the slot entry */
}



/*
        Return DW_DLV_OK.
        Never can really do anything: lengths cannot
        be represented as end-start in a stream.

*/
 /*ARGSUSED*/ int
_dwarf_pro_reloc_length_stream(Dwarf_P_Debug dbg, 
    int base_sec_index, 
    Dwarf_Unsigned offset,    /* r_offset of reloc */
    Dwarf_Unsigned start_symidx,
    Dwarf_Unsigned end_symidx,
    enum Dwarf_Rel_Type type,
    int reltarget_length)
{
    /* get a slot, fill in the slot entry */
    return DW_DLV_OK;
}


/* 
        Ensure each stream is a single buffer and
        add that single buffer to the set of stream buffers.

        By creating a new buffer and copying if necessary.

        Free the input set of buffers if we consolidate.
        Return -1 on error (malloc failure)


        Return DW_DLV_OK on success. Any other return indicates 
        malloc failed.
        
*/
int
_dwarf_stream_relocs_to_disk(Dwarf_P_Debug dbg,
    Dwarf_Signed * new_sec_count)
{
    unsigned long total_size = 0;
    Dwarf_Small *data = 0;
    int sec_index = 0;
    unsigned long i = 0;
    Dwarf_Error err = 0;
    Dwarf_Error *error = &err;

    Dwarf_Signed sec_count = 0;

    Dwarf_P_Per_Reloc_Sect p_reloc = &dbg->de_reloc_sect[0];

    for (i = 0; i < NUM_DEBUG_SECTIONS; ++i, ++p_reloc) {
        unsigned long ct = p_reloc->pr_reloc_total_count;
        unsigned len = 0;
        struct Dwarf_P_Relocation_Block_s *p_blk = 0;
        struct Dwarf_P_Relocation_Block_s *p_blk_last = 0;
        Dwarf_P_Per_Reloc_Sect prb = 0;

        if (ct == 0) {
            continue;
        }
        prb = &dbg->de_reloc_sect[i];
        len = dbg->de_relocation_record_size;
        ++sec_count;

        total_size = ct * len;
        sec_index = prb->pr_sect_num_of_reloc_sect;
        if (sec_index == 0) {
            /* Call de_callback_func or de_callback_func_b, getting 
               section number of reloc section. */
            int rel_section_index = 0;
            Dwarf_Unsigned name_idx = 0;
            int int_name = 0;
            int err = 0;

            if (dbg->de_callback_func_b) {
                rel_section_index =
                    dbg->de_callback_func_b(_dwarf_rel_section_names[i],
                                   /* size */
                                   dbg->de_relocation_record_size,
                                   /* type */ SHT_REL,
                                   /* flags */ 0,
                                   /* link to symtab, which we cannot
                                      know */ 0,
                                   /* info == link to sec rels apply to 
                                    */
                                   dbg->de_elf_sects[i],
                                   &name_idx, &err);
            } else {
                rel_section_index =
                    dbg->de_callback_func(_dwarf_rel_section_names[i],
                                 /* size */
                                 dbg->de_relocation_record_size,
                                 /* type */ SHT_REL,
                                 /* flags */ 0,
                                 /* link to symtab, which we cannot
                                    know */ 0,
                                 /* info == link to sec rels apply to */
                                 dbg->de_elf_sects[i], &int_name, &err);
                name_idx = int_name;
            }
            if (rel_section_index == -1) {
                {
                    _dwarf_p_error(dbg, error, DW_DLE_ELF_SECT_ERR);
                    return (DW_DLV_ERROR);
                }

            }
            prb->pr_sect_num_of_reloc_sect = rel_section_index;
            sec_index = rel_section_index;
        }
        GET_CHUNK(dbg, sec_index, data, total_size, &err);
        p_blk = p_reloc->pr_first_block;

        /* following loop executes at least once. Effects the
           consolidation to a single block or, if already a single
           block, simply copies to the output buffer. And frees the
           input block. The new block is in the de_debug_sects list. */
        while (p_blk) {

            unsigned long len =
                p_blk->rb_where_to_add_next - p_blk->rb_data;

            memcpy(data, p_blk->rb_data, len);


            data += len;

            p_blk_last = p_blk;
            p_blk = p_blk->rb_next;

            _dwarf_p_dealloc(dbg, (Dwarf_Small *) p_blk_last);
        }
        /* ASSERT: sum of len copied == total_size */

        /* 
           We have copied the input, now drop the pointers to it. For
           debugging, leave the other data untouched. */
        p_reloc->pr_first_block = 0;
        p_reloc->pr_last_block = 0;
    }

    *new_sec_count = sec_count;
    return DW_DLV_OK;
}
