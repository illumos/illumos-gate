/*

  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2011-2019 David Anderson.  All Rights Reserved.

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
#include <string.h>
#ifdef HAVE_ELFACCESS_H
#include <elfaccess.h>
#endif
#include "pro_incl.h"
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_error.h"
#include "pro_alloc.h"
#include "pro_arange.h"
#include "pro_section.h"
#include "pro_reloc.h"


#define SIZEOFT32 4

/*  This function adds another address range
    to the list of address ranges for the
    given Dwarf_P_Debug.  It returns 0 on error,
    and 1 otherwise.  */
Dwarf_Unsigned
dwarf_add_arange(Dwarf_P_Debug dbg,
    Dwarf_Addr begin_address,
    Dwarf_Unsigned length,
    Dwarf_Signed symbol_index, Dwarf_Error * error)
{
    int res = 0;

    res = dwarf_add_arange_b(dbg, begin_address, length, symbol_index,
        /* end_symbol_index */ 0,
        /* offset_from_end_sym */ 0,
        error);
    if (res != DW_DLV_OK) {
        return 0;
    }
    return 1;

}

/*  This function adds another address range
    to the list of address ranges for the
    given Dwarf_P_Debug.  It returns DW_DLV_ERROR on error,
    and DW_DLV_OK otherwise.  */
Dwarf_Unsigned
dwarf_add_arange_b(Dwarf_P_Debug dbg,
    Dwarf_Addr begin_address,
    Dwarf_Unsigned length,
    Dwarf_Unsigned symbol_index,
    Dwarf_Unsigned end_symbol_index,
    Dwarf_Addr offset_from_end_sym,
    Dwarf_Error * error)
{
    int res = 0;

    res = dwarf_add_arange_c(dbg,begin_address,length,
        symbol_index, end_symbol_index,
        offset_from_end_sym,error);
    if (res != DW_DLV_OK) {
        return 0;
    }
    return 1;
}
int
dwarf_add_arange_c(Dwarf_P_Debug dbg,
    Dwarf_Addr begin_address,
    Dwarf_Unsigned length,
    Dwarf_Unsigned symbol_index,
    Dwarf_Unsigned end_symbol_index,
    Dwarf_Addr offset_from_end_sym,
    Dwarf_Error * error)
{
    Dwarf_P_Arange arange;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    arange = (Dwarf_P_Arange)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Arange_s));
    if (arange == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    arange->ag_begin_address = begin_address;
    arange->ag_length = length;
    arange->ag_symbol_index = symbol_index;
    arange->ag_end_symbol_index = end_symbol_index;
    arange->ag_end_symbol_offset = offset_from_end_sym;

    if (dbg->de_arange == NULL)
        dbg->de_arange = dbg->de_last_arange = arange;
    else {
        dbg->de_last_arange->ag_next = arange;
        dbg->de_last_arange = arange;
    }
    dbg->de_arange_count++;
    return DW_DLV_OK;
}


int
_dwarf_transform_arange_to_disk(Dwarf_P_Debug dbg,
    Dwarf_Signed *nbufs, Dwarf_Error * error)
{
    /* Total num of bytes in .debug_aranges section. */
    Dwarf_Unsigned arange_num_bytes = 0;

    /*  Adjustment to align the start of the actual address ranges on a
        boundary aligned with twice the address size. */
    Dwarf_Small remainder = 0;

    /*  Total number of bytes excluding the length field. */
    Dwarf_Unsigned adjusted_length = 0;

    /*  Points to first byte of .debug_aranges buffer. */
    Dwarf_Small *arange = 0;

    /*  Fills in the .debug_aranges buffer. */
    Dwarf_Small *arange_ptr = 0;

    /*  Scans the list of address ranges provided by user. */
    Dwarf_P_Arange given_arange = 0;

    /*  Used to fill in 0. */
    const Dwarf_Signed big_zero = 0;

    int extension_word_size = dbg->de_64bit_extension ? 4 : 0;
    int offset_size = dbg->de_dwarf_offset_size;
    int upointer_size = dbg->de_pointer_size;

    /*  All dwarf versions so far use 2 here. */
    Dwarf_Half version = 2;
    int res = 0;


    /* ***** BEGIN CODE ***** */

    /* Size of the .debug_aranges section header. */
    arange_num_bytes = extension_word_size +
        offset_size +       /* Size of length field.  */
        DWARF_HALF_SIZE +    /* Size of version field. */
        offset_size +            /* Size of .debug_info offset. */
        sizeof(Dwarf_Small) +   /* Size of address size field. */
        sizeof(Dwarf_Small);    /* Size of segment size field. */

    /*  Adjust the size so that the set of aranges begins on a boundary
        that aligned with twice the address size.  This is a Libdwarf
        requirement. */
    remainder = arange_num_bytes % (2 * upointer_size);
    if (remainder != 0)
        arange_num_bytes += (2 * upointer_size) - remainder;


    /* Add the bytes for the actual address ranges. */
    arange_num_bytes += upointer_size * 2 * (dbg->de_arange_count + 1);

    GET_CHUNK(dbg, dbg->de_elf_sects[DEBUG_ARANGES],
        arange, (unsigned long) arange_num_bytes, error);
    arange_ptr = arange;
    if (extension_word_size) {
        DISTINGUISHED_VALUE_ARRAY(v4);
        WRITE_UNALIGNED(dbg, (void *) arange_ptr,
            (const void *)&v4[0] ,
            SIZEOFT32, extension_word_size);
        arange_ptr += extension_word_size;
    }

    /* Write the total length of .debug_aranges section. */
    adjusted_length = arange_num_bytes - offset_size
        - extension_word_size;
    {
        Dwarf_Unsigned du = adjusted_length;

        WRITE_UNALIGNED(dbg, (void *) arange_ptr,
            (const void *) &du, sizeof(du), offset_size);
        arange_ptr += offset_size;
    }

    /* Write the version as 2 bytes. */
    {
        Dwarf_Half verstamp = version;

        WRITE_UNALIGNED(dbg, (void *) arange_ptr,
            (const void *) &verstamp,
            sizeof(verstamp), DWARF_HALF_SIZE);
        arange_ptr += DWARF_HALF_SIZE;
    }


    /* Write the .debug_info offset.  This is always 0. */
    WRITE_UNALIGNED(dbg, (void *) arange_ptr,
        (const void *) &big_zero,
        sizeof(big_zero), offset_size);
    arange_ptr += offset_size;

    {
        unsigned long count = dbg->de_arange_count + 1;
        int res2 = 0;
        Dwarf_P_Per_Reloc_Sect p_reloc =
            &dbg->de_reloc_sect[DEBUG_ARANGES];

        if (dbg->de_relocate_pair_by_symbol) {
            count = (3 * dbg->de_arange_count) + 1;
        }
        /*  The following is a small optimization: not needed for
            correctness.  Does nothing if
            preloc->pr_first_block is non-null */
        res2 = _dwarf_pro_pre_alloc_specific_reloc_slots(dbg,
            p_reloc, count);
        if (res2 != DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
    }

    /* reloc for .debug_info */
    res = dbg->de_relocate_by_name_symbol(dbg,
        DEBUG_ARANGES,
        extension_word_size +
        offset_size + DWARF_HALF_SIZE,
        dbg->de_sect_name_idx[DEBUG_INFO],
        dwarf_drt_data_reloc, offset_size);
    if (res == DW_DLV_NO_ENTRY) {
        return res;
    }
    if (res == DW_DLV_ERROR) {
        _dwarf_p_error(dbg, error,DW_DLE_RELOCS_ERROR);
        return res;
    }

    /* Write the size of addresses. */
    *arange_ptr = dbg->de_pointer_size;
    arange_ptr++;

    /*  Write the size of segment addresses. This is zero for MIPS
        architectures. */
    *arange_ptr = 0;
    arange_ptr++;

    /*  Skip over the padding to align the start of the actual address
        ranges to twice the address size. */
    if (remainder != 0)
        arange_ptr += (2 * upointer_size) - remainder;





    /*  The arange address, length are pointer-size fields of the target
        machine. */
    for (given_arange = dbg->de_arange; given_arange != NULL;
        given_arange = given_arange->ag_next) {

        /* Write relocation record for beginning of address range. */
        res = dbg->de_relocate_by_name_symbol(dbg, DEBUG_ARANGES,
            arange_ptr - arange,       /* r_offset */
            (long) given_arange->ag_symbol_index,
            dwarf_drt_data_reloc, upointer_size);
        if (res != DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }

        /* Copy beginning address of range. */
        WRITE_UNALIGNED(dbg, (void *) arange_ptr,
            (const void *) &given_arange->ag_begin_address,
            sizeof(given_arange->ag_begin_address),
            upointer_size);
        arange_ptr += upointer_size;

        if (dbg->de_relocate_pair_by_symbol &&
            given_arange->ag_end_symbol_index != 0 &&
            given_arange->ag_length == 0) {
            /*  symbolic reloc, need reloc for length What if we really
                know the length? If so, should use the other part of
                'if'. */
            Dwarf_Unsigned val;

            res = dbg->de_relocate_pair_by_symbol(dbg,
                DEBUG_ARANGES,
                arange_ptr - arange,   /* r_offset */
                given_arange->ag_symbol_index,
                given_arange->ag_end_symbol_index,
                dwarf_drt_first_of_length_pair,
                upointer_size);
            if (res != DW_DLV_OK) {
                _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return DW_DLV_ERROR;
            }

            /*  arange pre-calc so assem text can do .word end - begin
                + val (gets val from stream) */
            val = given_arange->ag_end_symbol_offset -
                given_arange->ag_begin_address;
            WRITE_UNALIGNED(dbg, (void *) arange_ptr,
                (const void *) &val,
                sizeof(val), upointer_size);
            arange_ptr += upointer_size;

        } else {
            /* plain old length to copy, no relocation at all */
            WRITE_UNALIGNED(dbg, (void *) arange_ptr,
                (const void *) &given_arange->ag_length,
                sizeof(given_arange->ag_length),
                upointer_size);
            arange_ptr += upointer_size;
        }
    }

    WRITE_UNALIGNED(dbg, (void *) arange_ptr,
        (const void *) &big_zero,
        sizeof(big_zero), upointer_size);

    arange_ptr += upointer_size;
    WRITE_UNALIGNED(dbg, (void *) arange_ptr,
        (const void *) &big_zero,
        sizeof(big_zero), upointer_size);
    *nbufs =  dbg->de_n_debug_sect;
    return DW_DLV_OK;
}
