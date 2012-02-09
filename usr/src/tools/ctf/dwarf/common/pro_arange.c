/*

  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.

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
#endif
#include "pro_incl.h"
#include "pro_arange.h"
#include "pro_section.h"
#include "pro_reloc.h"



/*
    This function adds another address range 
    to the list of address ranges for the
    given Dwarf_P_Debug.  It returns 0 on error,
    and 1 otherwise.
*/
Dwarf_Unsigned
dwarf_add_arange(Dwarf_P_Debug dbg,
                 Dwarf_Addr begin_address,
                 Dwarf_Unsigned length,
                 Dwarf_Signed symbol_index, Dwarf_Error * error)
{
    return dwarf_add_arange_b(dbg, begin_address, length, symbol_index,
                              /* end_symbol_index */ 0,
                              /* offset_from_end_sym */ 0,
                              error);
}

/*
    This function adds another address range 
    to the list of address ranges for the
    given Dwarf_P_Debug.  It returns 0 on error,
    and 1 otherwise.
*/
Dwarf_Unsigned
dwarf_add_arange_b(Dwarf_P_Debug dbg,
                   Dwarf_Addr begin_address,
                   Dwarf_Unsigned length,
                   Dwarf_Unsigned symbol_index,
                   Dwarf_Unsigned end_symbol_index,
                   Dwarf_Addr offset_from_end_sym, Dwarf_Error * error)
{
    Dwarf_P_Arange arange;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return (0);
    }

    arange = (Dwarf_P_Arange)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Arange_s));
    if (arange == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (0);
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

    return (1);
}


int
_dwarf_transform_arange_to_disk(Dwarf_P_Debug dbg, Dwarf_Error * error)
{
    /* Total num of bytes in .debug_aranges section. */
    Dwarf_Unsigned arange_num_bytes;

    /* 
       Adjustment to align the start of the actual address ranges on a
       boundary aligned with twice the address size. */
    Dwarf_Small remainder;

    /* Total number of bytes excluding the length field. */
    Dwarf_Unsigned adjusted_length;

    /* Points to first byte of .debug_aranges buffer. */
    Dwarf_Small *arange;

    /* Fills in the .debug_aranges buffer. */
    Dwarf_Small *arange_ptr;

    /* Scans the list of address ranges provided by user. */
    Dwarf_P_Arange given_arange;

    /* Used to fill in 0. */
    const Dwarf_Signed big_zero = 0;

    int extension_word_size = dbg->de_64bit_extension ? 4 : 0;
    int uword_size = dbg->de_offset_size;
    int upointer_size = dbg->de_pointer_size;
    int res;


    /* ***** BEGIN CODE ***** */

    /* Size of the .debug_aranges section header. */
    arange_num_bytes = extension_word_size + uword_size +       /* Size 
                                                                   of
                                                                   length 
                                                                   field. 
                                                                 */
        sizeof(Dwarf_Half) +    /* Size of version field. */
        uword_size +            /* Size of .debug_info offset. */
        sizeof(Dwarf_Small) +   /* Size of address size field. */
        sizeof(Dwarf_Small);    /* Size of segment size field. */

    /* 
       Adjust the size so that the set of aranges begins on a boundary
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
    if (arange == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (0);
    }
    if (extension_word_size) {
        Dwarf_Word x = DISTINGUISHED_VALUE;

        WRITE_UNALIGNED(dbg, (void *) arange_ptr,
                        (const void *) &x,
                        sizeof(x), extension_word_size);
        arange_ptr += extension_word_size;
    }

    /* Write the total length of .debug_aranges section. */
    adjusted_length = arange_num_bytes - uword_size
        - extension_word_size;
    {
        Dwarf_Unsigned du = adjusted_length;

        WRITE_UNALIGNED(dbg, (void *) arange_ptr,
                        (const void *) &du, sizeof(du), uword_size);
        arange_ptr += uword_size;
    }

    /* Write the version as 2 bytes. */
    {
        Dwarf_Half verstamp = CURRENT_VERSION_STAMP;

        WRITE_UNALIGNED(dbg, (void *) arange_ptr,
                        (const void *) &verstamp,
                        sizeof(verstamp), sizeof(Dwarf_Half));
        arange_ptr += sizeof(Dwarf_Half);
    }


    /* Write the .debug_info offset.  This is always 0. */
    WRITE_UNALIGNED(dbg, (void *) arange_ptr,
                    (const void *) &big_zero,
                    sizeof(big_zero), uword_size);
    arange_ptr += uword_size;

    {
        unsigned long count = dbg->de_arange_count + 1;
        int res;

        if (dbg->de_reloc_pair) {
            count = (3 * dbg->de_arange_count) + 1;
        }
        /* the following is a small optimization: not needed for
           correctness */
        res = _dwarf_pro_pre_alloc_n_reloc_slots(dbg,
                                                 DEBUG_ARANGES, count);
        if (res != DW_DLV_OK) {
            {
                _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return (0);
            }
        }
    }

    /* reloc for .debug_info */
    res = dbg->de_reloc_name(dbg,
                             DEBUG_ARANGES,
                             extension_word_size +
                             uword_size + sizeof(Dwarf_Half),
                             dbg->de_sect_name_idx[DEBUG_INFO],
                             dwarf_drt_data_reloc, uword_size);

    /* Write the size of addresses. */
    *arange_ptr = dbg->de_pointer_size;
    arange_ptr++;

    /* 
       Write the size of segment addresses. This is zero for MIPS
       architectures. */
    *arange_ptr = 0;
    arange_ptr++;

    /* 
       Skip over the padding to align the start of the actual address
       ranges to twice the address size. */
    if (remainder != 0)
        arange_ptr += (2 * upointer_size) - remainder;





    /* The arange address, length are pointer-size fields of the target 
       machine. */
    for (given_arange = dbg->de_arange; given_arange != NULL;
         given_arange = given_arange->ag_next) {

        /* Write relocation record for beginning of address range. */
        res = dbg->de_reloc_name(dbg, DEBUG_ARANGES, arange_ptr - arange,       /* r_offset 
                                                                                 */
                                 (long) given_arange->ag_symbol_index,
                                 dwarf_drt_data_reloc, upointer_size);
        if (res != DW_DLV_OK) {
            {
                _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return (0);
            }
        }

        /* Copy beginning address of range. */
        WRITE_UNALIGNED(dbg, (void *) arange_ptr,
                        (const void *) &given_arange->ag_begin_address,
                        sizeof(given_arange->ag_begin_address),
                        upointer_size);
        arange_ptr += upointer_size;

        if (dbg->de_reloc_pair &&
            given_arange->ag_end_symbol_index != 0 &&
            given_arange->ag_length == 0) {
            /* symbolic reloc, need reloc for length What if we really
               know the length? If so, should use the other part of
               'if'. */
            Dwarf_Unsigned val;

            res = dbg->de_reloc_pair(dbg, DEBUG_ARANGES, arange_ptr - arange,   /* r_offset 
                                                                                 */
                                     given_arange->ag_symbol_index,
                                     given_arange->ag_end_symbol_index,
                                     dwarf_drt_first_of_length_pair,
                                     upointer_size);
            if (res != DW_DLV_OK) {
                {
                    _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
                    return (0);
                }
            }

            /* arrange pre-calc so assem text can do .word end - begin
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
    return (int) dbg->de_n_debug_sect;
}
