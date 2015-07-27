/*

  Copyright (C) 2008-2010 David Anderson. All Rights Reserved.

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
#include <stdlib.h>
#include "dwarf_incl.h"

struct ranges_entry {
   struct ranges_entry *next;
   Dwarf_Ranges cur;
};


#define MAX_ADDR ((address_size == 8)?0xffffffffffffffffULL:0xffffffff)
int dwarf_get_ranges_a(Dwarf_Debug dbg,
    Dwarf_Off rangesoffset,
    Dwarf_Die die,
    Dwarf_Ranges ** rangesbuf,
    Dwarf_Signed * listlen,
    Dwarf_Unsigned * bytecount,
    Dwarf_Error * error)
{
    Dwarf_Small *rangeptr = 0;
    Dwarf_Small *beginrangeptr = 0;
    Dwarf_Small *section_end = 0;
    unsigned entry_count = 0;
    struct ranges_entry *base = 0;
    struct ranges_entry *last = 0;
    struct ranges_entry *curre = 0;
    Dwarf_Ranges * ranges_data_out = 0;
    unsigned copyindex = 0;
    Dwarf_Half address_size = 0;
    int res = DW_DLV_ERROR;

    res = _dwarf_load_section(dbg, &dbg->de_debug_ranges,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if(rangesoffset >= dbg->de_debug_ranges.dss_size) {
        _dwarf_error(dbg, error, DW_DLE_DEBUG_RANGES_OFFSET_BAD);
        return (DW_DLV_ERROR);

    }
    address_size = _dwarf_get_address_size(dbg, die);
    section_end = dbg->de_debug_ranges.dss_data + 
        dbg->de_debug_ranges.dss_size;
    rangeptr = dbg->de_debug_ranges.dss_data + rangesoffset;
    beginrangeptr = rangeptr;

    for(;;) {
        struct ranges_entry * re = calloc(sizeof(struct ranges_entry),1);
        if(!re) {
            _dwarf_error(dbg, error, DW_DLE_DEBUG_RANGES_OUT_OF_MEM);
            return (DW_DLV_ERROR);
        }
        if(rangeptr  >= section_end) {
            return (DW_DLV_NO_ENTRY);
        }
        if((rangeptr + (2*address_size)) > section_end) {
            _dwarf_error(dbg, error, DW_DLE_DEBUG_RANGES_OFFSET_BAD);
            return (DW_DLV_ERROR);
        }
        entry_count++;
        READ_UNALIGNED(dbg,re->cur.dwr_addr1,
                       Dwarf_Addr, rangeptr,
                       address_size);
        rangeptr +=  address_size;
        READ_UNALIGNED(dbg,re->cur.dwr_addr2 ,
                       Dwarf_Addr, rangeptr,
                       address_size);
        rangeptr +=  address_size;
        if(!base) {
           base = re;
           last = re;
        } else {
           last->next = re;
           last = re;
        }
        if(re->cur.dwr_addr1 == 0 && re->cur.dwr_addr2 == 0) {
            re->cur.dwr_type =  DW_RANGES_END;
            break;
        } else if ( re->cur.dwr_addr1 == MAX_ADDR) {
            re->cur.dwr_type =  DW_RANGES_ADDRESS_SELECTION;
        } else {
            re->cur.dwr_type =  DW_RANGES_ENTRY;
        }
    }

    ranges_data_out =   (Dwarf_Ranges *)
    _dwarf_get_alloc(dbg,DW_DLA_RANGES,entry_count);
    if(!ranges_data_out) {
            _dwarf_error(dbg, error, DW_DLE_DEBUG_RANGES_OUT_OF_MEM);
            return (DW_DLV_ERROR);
    }
    curre = base;
    *rangesbuf = ranges_data_out;
    *listlen = entry_count;
    for( copyindex = 0; curre && (copyindex < entry_count); 
        ++copyindex,++ranges_data_out) {

        struct ranges_entry *r = curre;
        *ranges_data_out = curre->cur;
        curre = curre->next;
        free(r);
    }
    /* Callers will often not care about the bytes used. */
    if(bytecount) {
        *bytecount = rangeptr - beginrangeptr;
    }
    return DW_DLV_OK; 
}
int dwarf_get_ranges(Dwarf_Debug dbg,
    Dwarf_Off rangesoffset,
    Dwarf_Ranges ** rangesbuf,
    Dwarf_Signed * listlen,
    Dwarf_Unsigned * bytecount,
    Dwarf_Error * error)
{
    Dwarf_Die die = 0;
    int res = dwarf_get_ranges_a(dbg,rangesoffset,die,
        rangesbuf,listlen,bytecount,error);
    return res;
}

void 
dwarf_ranges_dealloc(Dwarf_Debug dbg, Dwarf_Ranges * rangesbuf,
    Dwarf_Signed rangecount)
{
    dwarf_dealloc(dbg,rangesbuf, DW_DLA_RANGES);
   
}

