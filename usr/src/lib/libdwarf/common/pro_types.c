/*
  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2011-2019 David Anderson. All Rights Reserved.

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

#include "config.h"
#include "libdwarfdefs.h"
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_ELFACCESS_H
#include <elfaccess.h>
#endif
#include "pro_incl.h"
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif /* HAVE_STDDEF_H */
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_error.h"
#include "pro_alloc.h"
#include "pro_section.h"
#include "pro_types.h"

#define SIZEOFT32 4

/*
    This function adds another type name to the
    list of type names for the given Dwarf_P_Debug.
    It returns 0 on error, and 1 otherwise.
*/
Dwarf_Unsigned
dwarf_add_typename(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    char *type_name,
    Dwarf_Error * error)
{
    int res = 0;

    res = _dwarf_add_simple_name_entry(dbg, die, type_name,
        dwarf_snk_typename, error);
    if (res != DW_DLV_OK) {
        return 0;
    }
    return 1;

}
int
dwarf_add_typename_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    char *type_name,
    Dwarf_Error * error)
{
    int res = 0;

    res = _dwarf_add_simple_name_entry(dbg, die, type_name,
        dwarf_snk_typename, error);
    return res;
}

/*
  The following is the generic 'add a simple name entry'
  for any of the simple name sections.

  See enum dwarf_sn_kind in pro_opaque.h

*/
int
_dwarf_add_simple_name_entry(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    char *entry_name,
    enum dwarf_sn_kind entrykind,
    Dwarf_Error * error)
{
    Dwarf_P_Simple_nameentry nameentry;
    Dwarf_P_Simple_name_header hdr;
    char *name;
    int uword_size;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    if (die == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }


    nameentry = (Dwarf_P_Simple_nameentry)
        _dwarf_p_get_alloc(dbg,
            sizeof(struct Dwarf_P_Simple_nameentry_s));
    if (nameentry == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    name = _dwarf_p_get_alloc(dbg, strlen(entry_name) + 1);
    if (name == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    strcpy(name, entry_name);

    nameentry->sne_die = die;
    nameentry->sne_name = name;
    nameentry->sne_name_len = strlen(name);
    uword_size = dbg->de_dwarf_offset_size;

    hdr = &dbg->de_simple_name_headers[entrykind];
    if (hdr->sn_head == NULL)
        hdr->sn_head = hdr->sn_tail = nameentry;
    else {
        hdr->sn_tail->sne_next = nameentry;
        hdr->sn_tail = nameentry;
    }
    hdr->sn_count++;
    hdr->sn_net_len += uword_size + nameentry->sne_name_len + 1;

    return DW_DLV_OK;
}



/*
    _dwarf_transform_simplename_to_disk writes
    ".rel.debug_pubnames",
    ".rel.debug_funcnames",       sgi extension
    ".rel.debug_typenames",       sgi extension
    ".rel.debug_varnames",        sgi extension
    ".rel.debug_weaknames",       sgi extension
    to disk.
    section_index indexes one of those sections.
    entrykind is one of those 'kind's.  */
int
_dwarf_transform_simplename_to_disk(Dwarf_P_Debug dbg,
    enum dwarf_sn_kind entrykind,
    int section_index, /* in de_elf_sects etc */
    Dwarf_Signed *nbufs,
    Dwarf_Error * error)
{


    /* Used to fill in 0. */
    const Dwarf_Signed big_zero = 0;

    /* Used to scan the section data buffers. */
    Dwarf_P_Section_Data debug_sect;

    Dwarf_Signed debug_info_size;

    Dwarf_P_Simple_nameentry nameentry_original;
    Dwarf_P_Simple_nameentry nameentry;
    Dwarf_Small *stream_bytes;
    Dwarf_Small *cur_stream_bytes_ptr;
    Dwarf_Unsigned stream_bytes_count;
    Dwarf_Unsigned adjusted_length; /* count excluding length field */


    int uword_size = dbg->de_dwarf_offset_size;
    int extension_size = dbg->de_64bit_extension ? 4 : 0;

    Dwarf_P_Simple_name_header hdr;


    /* ***** BEGIN CODE ***** */

    debug_info_size = 0;
    for (debug_sect = dbg->de_debug_sects; debug_sect != NULL;
        debug_sect = debug_sect->ds_next) {
        /*  We want the size of the .debug_info section for this CU
            because the dwarf spec requires us to output it below so we
            look for it specifically. */
        if (debug_sect->ds_elf_sect_no == dbg->de_elf_sects[DEBUG_INFO]) {
            debug_info_size += debug_sect->ds_nbytes;
        }
    }

    hdr = &dbg->de_simple_name_headers[entrykind];
    /* Size of the .debug_typenames (or similar) section header. */
    stream_bytes_count = extension_size + uword_size +  /* Size of
        length field. */
        DWARF_HALF_SIZE +    /* Size of version field. */
        uword_size +            /* Size of .debug_info offset. */
        uword_size;             /* Size of .debug_names. */



    nameentry_original = hdr->sn_head;
    /* add in the content size */
    stream_bytes_count += hdr->sn_net_len;

    /* Size of the last 0 offset. */
    stream_bytes_count += uword_size;

    /* Now we know how long the entire section is */
    GET_CHUNK(dbg, dbg->de_elf_sects[section_index],
        stream_bytes, (unsigned long) stream_bytes_count, error);
    cur_stream_bytes_ptr = stream_bytes;

    if (extension_size) {
        DISTINGUISHED_VALUE_ARRAY(v4);

        WRITE_UNALIGNED(dbg, cur_stream_bytes_ptr,
            (const void *)&v4[0],SIZEOFT32 , extension_size);
        cur_stream_bytes_ptr += extension_size;

    }
    /* Write the adjusted length of .debug_*names section. */
    adjusted_length = stream_bytes_count - uword_size - extension_size;
    WRITE_UNALIGNED(dbg, cur_stream_bytes_ptr,
        (const void *) &adjusted_length,
        sizeof(adjusted_length), uword_size);
    cur_stream_bytes_ptr += uword_size;

    /* Write the version as 2 bytes. */
    {
        Dwarf_Half verstamp = CURRENT_VERSION_STAMP;

        WRITE_UNALIGNED(dbg, cur_stream_bytes_ptr,
            (const void *) &verstamp,
            sizeof(verstamp), DWARF_HALF_SIZE);
        cur_stream_bytes_ptr += DWARF_HALF_SIZE;
    }

    /* Write the offset of the compile-unit. */
    WRITE_UNALIGNED(dbg, cur_stream_bytes_ptr,
        (const void *) &big_zero,
        sizeof(big_zero), uword_size);
    cur_stream_bytes_ptr += uword_size;

    /* now create the relocation for the compile_unit offset */
    {
        int res = dbg->de_relocate_by_name_symbol(dbg,
            section_index,
            extension_size + uword_size +
            DWARF_HALF_SIZE /* r_offset */ ,
            /* debug_info section name symbol */
            dbg->de_sect_name_idx[DEBUG_INFO],
            dwarf_drt_data_reloc,
            uword_size);

        if (res != DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
    }

    /* Write the size of .debug_info section. */
    WRITE_UNALIGNED(dbg, cur_stream_bytes_ptr,
        (const void *) &debug_info_size,
        sizeof(debug_info_size), uword_size);
    cur_stream_bytes_ptr += uword_size;


    for (nameentry = nameentry_original;
        nameentry != NULL; nameentry = nameentry->sne_next) {

        /* Copy offset of die from start of compile-unit. */
        WRITE_UNALIGNED(dbg, cur_stream_bytes_ptr,
            (const void *) &nameentry->sne_die->di_offset,
            sizeof(nameentry->sne_die->di_offset),
            uword_size);
        cur_stream_bytes_ptr += uword_size;

        /* Copy the type name. */
        strcpy((char *) cur_stream_bytes_ptr, nameentry->sne_name);
        cur_stream_bytes_ptr += nameentry->sne_name_len + 1;
    }

    WRITE_UNALIGNED(dbg, cur_stream_bytes_ptr,
        (const void *) &big_zero,
        sizeof(big_zero), uword_size);
    *nbufs =  dbg->de_n_debug_sect;
    return DW_DLV_OK;
}
