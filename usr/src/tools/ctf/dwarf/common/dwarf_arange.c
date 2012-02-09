/*

  Copyright (C) 2000-2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2007-2010 David Anderson. All Rights Reserved.

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
/* The address of the Free Software Foundation is
   Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, 
   Boston, MA 02110-1301, USA.
   SGI has moved from the Crittenden Lane address.
*/






#include "config.h"
#include "dwarf_incl.h"
#include <stdio.h>
#include "dwarf_arange.h"
#include "dwarf_global.h"       /* for _dwarf_fixup_* */


/* Common code for two user-visible routines to share. 
   Errors here result in memory leaks, but errors here
   are serious (making aranges unusable) so we assume
   callers will not repeat the error often or mind the leaks.
*/
static int
dwarf_get_aranges_list(Dwarf_Debug dbg,
    Dwarf_Chain  * chain_out,
    Dwarf_Signed * chain_count_out,
    Dwarf_Error  * error)
{
    /* Sweeps through the arange. */
    Dwarf_Small *arange_ptr = 0;
    Dwarf_Small *arange_ptr_start = 0;

    /* Start of arange header.  Used for rounding offset of arange_ptr
       to twice the tuple size.  Libdwarf requirement. */
    Dwarf_Small *header_ptr = 0;

    /* Version of .debug_aranges header. */
    Dwarf_Half version = 0;

    /* Offset of current set of aranges into .debug_info. */
    Dwarf_Off info_offset = 0;

    /* Size in bytes of addresses in target. */
    Dwarf_Small address_size = 0;

    /* Size in bytes of segment offsets in target. */
    Dwarf_Small segment_size = 0;

    /* Count of total number of aranges. */
    Dwarf_Unsigned arange_count = 0;

    Dwarf_Arange arange = 0;

    /* Used to chain Dwarf_Aranges structs. */
    Dwarf_Chain curr_chain = NULL;
    Dwarf_Chain prev_chain = NULL;
    Dwarf_Chain head_chain = NULL;

    arange_ptr = dbg->de_debug_aranges.dss_data;
    arange_ptr_start = arange_ptr;
    do {
        /* Length of current set of aranges. */
        Dwarf_Unsigned length = 0;
        Dwarf_Small remainder = 0;
        Dwarf_Small *arange_ptr_past_end = 0;
        Dwarf_Unsigned range_entry_size = 0;

        int local_length_size;

         /*REFERENCED*/ /* Not used in this instance of the macro */
        int local_extension_size = 0;

        header_ptr = arange_ptr;

        /* READ_AREA_LENGTH updates arange_ptr for consumed bytes */
        READ_AREA_LENGTH(dbg, length, Dwarf_Unsigned,
            arange_ptr, local_length_size,
            local_extension_size);
        arange_ptr_past_end = arange_ptr + length;


        READ_UNALIGNED(dbg, version, Dwarf_Half,
            arange_ptr, sizeof(Dwarf_Half));
        arange_ptr += sizeof(Dwarf_Half);
        length = length - sizeof(Dwarf_Half);
        if (version != CURRENT_VERSION_STAMP) {
            _dwarf_error(dbg, error, DW_DLE_VERSION_STAMP_ERROR);
            return (DW_DLV_ERROR);
        }

        READ_UNALIGNED(dbg, info_offset, Dwarf_Off,
            arange_ptr, local_length_size);
        arange_ptr += local_length_size;
        length = length - local_length_size;
        if (info_offset >= dbg->de_debug_info.dss_size) {
            FIX_UP_OFFSET_IRIX_BUG(dbg, info_offset,
                "arange info offset.a");
            if (info_offset >= dbg->de_debug_info.dss_size) {
                _dwarf_error(dbg, error, DW_DLE_ARANGE_OFFSET_BAD);
                return (DW_DLV_ERROR);
            }
        }

        address_size = *(Dwarf_Small *) arange_ptr;
        /* It is not an error if the sizes differ.
           Unusual, but not an error. */
        arange_ptr = arange_ptr + sizeof(Dwarf_Small);
        length = length - sizeof(Dwarf_Small);

        segment_size = *(Dwarf_Small *) arange_ptr;
        arange_ptr = arange_ptr + sizeof(Dwarf_Small);
        length = length - sizeof(Dwarf_Small);
        if (segment_size != 0) {
            _dwarf_error(dbg, error, DW_DLE_SEGMENT_SIZE_BAD);
            return (DW_DLV_ERROR);
        }

        range_entry_size = 2*address_size + segment_size;
        /* Round arange_ptr offset to next multiple of address_size. */
        remainder = (Dwarf_Unsigned) (arange_ptr - header_ptr) %
            (range_entry_size);
        if (remainder != 0) {
            arange_ptr = arange_ptr + (2 * address_size) - remainder;
            length = length - ((2 * address_size) - remainder);
        }
        do {
            Dwarf_Addr range_address = 0;
            Dwarf_Unsigned segment_selector = 0;
            Dwarf_Unsigned range_length = 0;
            /* For segmented address spaces, the first field to
               read is a segment selector (new in DWARF4) */
            if(version == 4 && segment_size != 0) {
                READ_UNALIGNED(dbg, segment_selector, Dwarf_Unsigned,
                    arange_ptr, segment_size);
                arange_ptr += address_size;
                length = length - address_size;
            }

            READ_UNALIGNED(dbg, range_address, Dwarf_Addr,
                arange_ptr, address_size);
            arange_ptr += address_size;
            length = length - address_size;

            READ_UNALIGNED(dbg, range_length, Dwarf_Unsigned,
                arange_ptr, address_size);
            arange_ptr += address_size;
            length = length - address_size;

            { /* We used to suppress all-zero entries, but
                 now we return all aranges entries so we show
                 the entire content.  March 31, 2010. */

                arange = (Dwarf_Arange)
                    _dwarf_get_alloc(dbg, DW_DLA_ARANGE, 1);
                if (arange == NULL) {
                    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                    return (DW_DLV_ERROR);
                }

                arange->ar_segment_selector = segment_selector;
                arange->ar_segment_selector_size = segment_size;
                arange->ar_address = range_address;
                arange->ar_length = range_length;
                arange->ar_info_offset = info_offset;
                arange->ar_dbg = dbg;
                arange_count++;

                curr_chain = (Dwarf_Chain)
                    _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
                if (curr_chain == NULL) {
                    _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                    return (DW_DLV_ERROR);
                }

                curr_chain->ch_item = arange;
                if (head_chain == NULL)
                    head_chain = prev_chain = curr_chain;
                else {
                    prev_chain->ch_next = curr_chain;
                    prev_chain = curr_chain;
                }
            }
            /* The current set of ranges is terminated by
               range_address 0 and range_length 0, but that
               does not necessarily terminate the ranges for this CU! 
               There can be multiple sets in that DWARF
               does not explicitly forbid multiple sets. 
               DWARF2,3,4 section 7.20 
               We stop short to avoid overrun of the end of the CU.
               */
              
        } while (arange_ptr_past_end >= (arange_ptr + range_entry_size));

        /* A compiler could emit some padding bytes here. dwarf2/3
           (dwarf4 sec 7.20) does not clearly make extra padding 
           bytes illegal. */
        if (arange_ptr_past_end < arange_ptr) {
            char buf[200];
            Dwarf_Unsigned pad_count = arange_ptr - arange_ptr_past_end;
            Dwarf_Unsigned offset = arange_ptr - arange_ptr_start;
            snprintf(buf,sizeof(buf),"DW_DLE_ARANGE_LENGTH_BAD."
                " 0x%" DW_PR_DUx 
                " pad bytes at offset 0x%" DW_PR_DUx 
                " in .debug_aranges",
                pad_count, offset);
            dwarf_insert_harmless_error(dbg,buf);
        }
        /* For most compilers, arange_ptr == arange_ptr_past_end at
           this point. But not if there were padding bytes */
        arange_ptr = arange_ptr_past_end;
    } while (arange_ptr <
        dbg->de_debug_aranges.dss_data + dbg->de_debug_aranges.dss_size);

    if (arange_ptr !=
        dbg->de_debug_aranges.dss_data + dbg->de_debug_aranges.dss_size) {
        _dwarf_error(dbg, error, DW_DLE_ARANGE_DECODE_ERROR);
        return (DW_DLV_ERROR);
    }
    *chain_out = head_chain;
    *chain_count_out = arange_count;
    return DW_DLV_OK;
}

/*
    This function returns the count of the number of
    aranges in the .debug_aranges section.  It sets
    aranges to point to a block of Dwarf_Arange's 
    describing the arange's.  It returns DW_DLV_ERROR
    on error.

    Must be identical in most aspects to
        dwarf_get_aranges_addr_offsets!

*/
int
dwarf_get_aranges(Dwarf_Debug dbg,
    Dwarf_Arange ** aranges,
    Dwarf_Signed * returned_count, Dwarf_Error * error)
{
    /* Count of total number of aranges. */
    Dwarf_Signed arange_count = 0;

    Dwarf_Arange *arange_block = 0;

    /* Used to chain Dwarf_Aranges structs. */
    Dwarf_Chain curr_chain = NULL;
    Dwarf_Chain prev_chain = NULL;
    Dwarf_Chain head_chain = NULL;
    Dwarf_Unsigned i = 0;
    int res = DW_DLV_ERROR;

    /* ***** BEGIN CODE ***** */

    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    res = _dwarf_load_section(dbg, &dbg->de_debug_aranges, error);
    if (res != DW_DLV_OK) {
        return res;
    }

    res = dwarf_get_aranges_list(dbg,&head_chain,&arange_count,error);
    if(res != DW_DLV_OK) {
        return res;
    }

    arange_block = (Dwarf_Arange *)
        _dwarf_get_alloc(dbg, DW_DLA_LIST, arange_count);
    if (arange_block == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }

    curr_chain = head_chain;
    for (i = 0; i < arange_count; i++) {
        *(arange_block + i) = curr_chain->ch_item;
        prev_chain = curr_chain;
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN);
    }

    *aranges = arange_block;
    *returned_count = (arange_count);
    return DW_DLV_OK;
}

/*
    This function returns DW_DLV_OK if it succeeds
    and DW_DLV_ERR or DW_DLV_OK otherwise.
    count is set to the number of addresses in the
    .debug_aranges section. 
    For each address, the corresponding element in
    an array is set to the address itself(aranges) and
    the section offset (offsets).
    Must be identical in most aspects to
        dwarf_get_aranges!
*/
int
_dwarf_get_aranges_addr_offsets(Dwarf_Debug dbg,
    Dwarf_Addr ** addrs,
    Dwarf_Off ** offsets,
    Dwarf_Signed * count,
    Dwarf_Error * error)
{
    Dwarf_Unsigned i = 0;

    /* Used to chain Dwarf_Aranges structs. */
    Dwarf_Chain curr_chain = NULL;
    Dwarf_Chain prev_chain = NULL;
    Dwarf_Chain head_chain = NULL;

    Dwarf_Signed arange_count = 0;
    Dwarf_Addr *arange_addrs = 0;
    Dwarf_Off *arange_offsets = 0;

    int res = DW_DLV_ERROR;

    /* ***** BEGIN CODE ***** */

    if (error != NULL)
        *error = NULL;

    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    res = _dwarf_load_section(dbg, &dbg->de_debug_aranges,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    res = dwarf_get_aranges_list(dbg,&head_chain,&arange_count,error);
    if(res != DW_DLV_OK) {
        return res;
    }

    arange_addrs = (Dwarf_Addr *)
        _dwarf_get_alloc(dbg, DW_DLA_ADDR, arange_count);
    if (arange_addrs == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }
    arange_offsets = (Dwarf_Off *)
        _dwarf_get_alloc(dbg, DW_DLA_ADDR, arange_count);
    if (arange_offsets == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }

    curr_chain = head_chain;
    for (i = 0; i < arange_count; i++) {
        Dwarf_Arange ar = curr_chain->ch_item;

        arange_addrs[i] = ar->ar_address;
        arange_offsets[i] = ar->ar_info_offset;
        prev_chain = curr_chain;
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, ar, DW_DLA_ARANGE);
        dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN);
    }
    *count = arange_count;
    *offsets = arange_offsets;
    *addrs = arange_addrs;
    return (DW_DLV_OK);
}


/*
    This function takes a pointer to a block
    of Dwarf_Arange's, and a count of the
    length of the block.  It checks if the
    given address is within the range of an
    address range in the block.  If yes, it
    returns the appropriate Dwarf_Arange.
    Otherwise, it returns DW_DLV_ERROR.
*/
int
dwarf_get_arange(Dwarf_Arange * aranges,
    Dwarf_Unsigned arange_count,
    Dwarf_Addr address,
    Dwarf_Arange * returned_arange, Dwarf_Error * error)
{
    Dwarf_Arange curr_arange = 0;
    Dwarf_Unsigned i = 0;

    if (aranges == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ARANGES_NULL);
        return (DW_DLV_ERROR);
    }
    for (i = 0; i < arange_count; i++) {
        curr_arange = *(aranges + i);
        if (address >= curr_arange->ar_address &&
            address <
            curr_arange->ar_address + curr_arange->ar_length) {
            *returned_arange = curr_arange;
            return (DW_DLV_OK);
        }
    }

    return (DW_DLV_NO_ENTRY);
}


/*
    This function takes an Dwarf_Arange,
    and returns the offset of the first
    die in the compilation-unit that the
    arange belongs to.  Returns DW_DLV_ERROR
    on error.
*/
int
dwarf_get_cu_die_offset(Dwarf_Arange arange,
    Dwarf_Off * returned_offset,
    Dwarf_Error * error)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Off offset = 0;

    if (arange == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ARANGE_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = arange->ar_dbg;
    offset = arange->ar_info_offset;
    if (!dbg->de_debug_info.dss_data) {
        int res = _dwarf_load_debug_info(dbg, error);

        if (res != DW_DLV_OK) {
            return res;
        }
    }
    *returned_offset = offset + _dwarf_length_of_cu_header(dbg, offset);
    return DW_DLV_OK;
}

/*
    This function takes an Dwarf_Arange,
    and returns the offset of the CU header
    in the compilation-unit that the
    arange belongs to.  Returns DW_DLV_ERROR
    on error.   
    Ensures .debug_info loaded so
    the cu_offset is meaningful.
*/
int
dwarf_get_arange_cu_header_offset(Dwarf_Arange arange,
    Dwarf_Off * cu_header_offset_returned,
    Dwarf_Error * error)
{
    Dwarf_Debug dbg = 0;
    if (arange == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ARANGE_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = arange->ar_dbg;
    /* Like dwarf_get_arange_info this ensures debug_info loaded:
       the cu_header is in debug_info and will be used else
       we would not call dwarf_get_arange_cu_header_offset. */
    if (!dbg->de_debug_info.dss_data) {
        int res = _dwarf_load_debug_info(dbg, error);
        if (res != DW_DLV_OK) {
                return res;
        }
    }
    *cu_header_offset_returned = arange->ar_info_offset;
    return DW_DLV_OK;
}




/*
    This function takes a Dwarf_Arange, and returns
    true if it is not NULL.  It also stores the start
    address of the range in *start, the length of the
    range in *length, and the offset of the first die
    in the compilation-unit in *cu_die_offset.  It
    returns false on error.
    If cu_die_offset returned ensures .debug_info loaded so
    the cu_die_offset is meaningful.
*/
int
dwarf_get_arange_info(Dwarf_Arange arange,
    Dwarf_Addr * start,
    Dwarf_Unsigned * length,
    Dwarf_Off * cu_die_offset, Dwarf_Error * error)
{
    if (arange == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ARANGE_NULL);
        return (DW_DLV_ERROR);
    }

    if (start != NULL)
        *start = arange->ar_address;
    if (length != NULL)
        *length = arange->ar_length;
    if (cu_die_offset != NULL) {
        Dwarf_Debug dbg = arange->ar_dbg;
        Dwarf_Off offset = arange->ar_info_offset;

        if (!dbg->de_debug_info.dss_data) {
            int res = _dwarf_load_debug_info(dbg, error);
            if (res != DW_DLV_OK) {
                return res;
            }
        }
        *cu_die_offset =
            offset + _dwarf_length_of_cu_header(dbg, offset);
    }
    return (DW_DLV_OK);
}


/* New for DWARF4, entries may have segment information. 
   *segment is only meaningful if *segment_entry_size is non-zero. */
int 
dwarf_get_arange_info_b(Dwarf_Arange arange,
    Dwarf_Unsigned*  segment,
    Dwarf_Unsigned*  segment_entry_size,
    Dwarf_Addr    * start,
    Dwarf_Unsigned* length,
    Dwarf_Off     * cu_die_offset, 
    Dwarf_Error   * error)
{   
    if (arange == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ARANGE_NULL);
        return (DW_DLV_ERROR);
    }
    
    if(segment != NULL) {
       *segment = arange->ar_segment_selector;
    }
    if(segment_entry_size != NULL) {
       *segment_entry_size = arange->ar_segment_selector_size;
    }
    if (start != NULL)
        *start = arange->ar_address;
    if (length != NULL)
        *length = arange->ar_length;
    if (cu_die_offset != NULL) {
        Dwarf_Debug dbg = arange->ar_dbg;
        Dwarf_Off offset = arange->ar_info_offset;

        if (!dbg->de_debug_info.dss_data) {
            int res = _dwarf_load_debug_info(dbg, error);
            if (res != DW_DLV_OK) {
                return res;
            }
        }
        *cu_die_offset =
            offset + _dwarf_length_of_cu_header(dbg, offset);
    }
    return (DW_DLV_OK);
}   
