/*
  Copyright (C) 2008-2020 David Anderson. All Rights Reserved.
  Portions Copyright 2012 SN Systems Ltd. All rights reserved.

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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarfstring.h"

struct ranges_entry {
   struct ranges_entry *next;
   Dwarf_Ranges cur;
};


static void
free_allocated_ranges( struct ranges_entry *base)
{
    struct ranges_entry *cur = 0;
    struct ranges_entry *next = 0;
    for ( cur = base ; cur ; cur = next ) {
        next = cur->next;
        free(cur);
    }
}

/*  We encapsulate the macro use so we can
    free local malloc resources that would otherwise
    leak. See the call points below. */
static int
read_unaligned_addr_check(Dwarf_Debug dbg,
    Dwarf_Addr *addr_out,
    Dwarf_Small *rangeptr,
    unsigned address_size,
    Dwarf_Error *error,
    Dwarf_Small *section_end)
{
    Dwarf_Addr a = 0;

    READ_UNALIGNED_CK(dbg,a,
        Dwarf_Addr, rangeptr,
        address_size,
        error,section_end);
    *addr_out = a;
    return DW_DLV_OK;
}
/*  As of DWARF5 the ranges section each range list set has
    a range-list-table header. See "7.28 Range List Table"
    in the DWARF5 standard.
    For DWARF5 the offset should be the offset of
    the range-list-table-header for that range list.
    For DWARF3 and DWARF4 the offset has to be that
    of a range list.
*/
/*  Ranges and pc values can be in a split dwarf object.
    In that case the appropriate values need to be
    incremented by data from the executable in
    the compilation unit with the same dwo_id.

    We return an error which is on the incoming dbg, not
    the possibly-tied-dbg localdbg.
    If incoming die is NULL there is no context, so do not look
    for a tied file, and address_size is the size
    of the overall object, not the address_size of the context. */
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
    Dwarf_Unsigned ranges_base = 0;
    Dwarf_Unsigned addr_base = 0;
    Dwarf_Debug localdbg = dbg;
    Dwarf_Error localerror = 0;
    Dwarf_Half die_version = 3; /* default for dwarf_get_ranges() */
    UNUSEDARG Dwarf_Half offset_size = 4;
    Dwarf_CU_Context cucontext = 0;

    if (!dbg) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    address_size = localdbg->de_pointer_size; /* default  */
    if (die) {
        /*  If we wind up using the tied file the die_version
            had better match! It cannot be other than a match. */
        /*  Can return DW_DLV_ERROR, not DW_DLV_NO_ENTRY.
            Add err code if error.  Version comes from the
            cu context, not the DIE itself. */
        res = dwarf_get_version_of_die(die,&die_version,
            &offset_size);
        if (res == DW_DLV_ERROR) {
            _dwarf_error(dbg, error, DW_DLE_DIE_NO_CU_CONTEXT);
            return DW_DLV_ERROR;
        }
        if (!die->di_cu_context) {
            _dwarf_error(dbg, error, DW_DLE_DIE_NO_CU_CONTEXT);
            return DW_DLV_ERROR;
        }
        cucontext = die->di_cu_context;
        /*  The DW4 ranges base was never used in GNU
            but did get emitted.
            http://llvm.1065342.n5.nabble.com/DebugInfo-DW-AT-GNU-ranges-base-in-non-fission-td64194.html
            */
#if 0
        if (cucontext->cc_unit_type != DW_UT_skeleton &&
            cucontext->cc_version_stamp != DW_CU_VERSION4 &&
            cucontext->cc_ranges_base_present) {
            /* Never needed. See DW_AT_GNU_ranges_base
            in find_cu_die_base_fields() in dwarf_die_deliv.c */
            ranges_base = cucontext->cc_ranges_base;
        }
#endif
        address_size = cucontext->cc_address_size;
    }

    /*  If tied object exists,
        base object is DWP and tied object is the
        skeleton/executabl CU containing a skeleton CU
        with DW_AT_addr_base/DW_AT_GNU_addr_base and
        DW_AT_rnglists_base/DW_AT_GNU_ranges base. */
    if (die &&dbg->de_tied_data.td_tied_object) {

        int restied = 0;

        /*  dwo/dwp CU  may have (DW5 pg 63)
            DW_AT_name
            DW_AT_language
            DW_AT_macros
            DW_AT_producer
            DW_AT_identifier_case
            DW_AT_main_subprogram
            DW_AT_entry_pc
            DW_AT_ranges if DW5 offset of header (see
                ranges_base/rnglists_base below),
                else of ranges
            DW_AT_GNU_pubnames
            DW_AT_stmt_list, a trivial stmt list with
                the list of directories and file names
                where needed for Type Units (DW5 pg 64)
            and must have
            DW_AT_[GNU_]dwo_id
            and inherited from skeleton:
            DW_AT_low_pc, DW_AT_high_pc, DW_AT_ranges,
            DW_AT_stmt_list, DW_AT_comp_dir,
            DW_AT_use_UTF8, DW_AT_str_offsets_base,
            DW_AT_addr_base and DW_AT_rnglists_base.

            skeleton CU may have (DW5 pg 62)
            DW_AT_[GNU_]addr_base   possibly needed by dwp
            DW_AT_str_offsets_base  possibly needed by dwp
            DW_AT_GNU_ranges_base (GNU)possibly needed by dwp
            DW_AT_rnglists_base   (DWARF5)possibly needed by dwp
            DW_AT_low_pc
            DW_AT_high_pc
            DW_AT_ranges
            DW_AT_str_offsets_base
            DW_AT_[GNU_]dwo_name
            DW_AT_stmt_list
            DW_AT_comp_dir
            DW_AT_use_UTF8
            and must have
            DW_AT_[GNU_]dwo_id
            .debug_ranges does not
            exist in the DWP, it is only in the executable.
        */
        restied = _dwarf_get_ranges_base_attr_from_tied(dbg,
            cucontext,
            &ranges_base,
            &addr_base,
            error);
        if (restied == DW_DLV_ERROR ) {
            if(!error) {
                return restied;
            }
            dwarf_dealloc(localdbg,*error,DW_DLA_ERROR);
            *error = 0;
            /* Nothing else to do. Look in original dbg. */
        } else if (restied == DW_DLV_NO_ENTRY ) {
            /* Nothing else to do. Look in original dbg. */
        } else {
            /*  Ranges are never in a split dwarf object.
                In the base object
                instead. Use the tied_object */
            localdbg = dbg->de_tied_data.td_tied_object;
        }
    }
#if 0
FIXME Implement debug_rnglists!
    /*  de_debug_ranges is DW 3,4.
        de_debug_rnglists is DW5. */
    if (die_version >= DW_CU_VERSION5) {
        res = _dwarf_load_section(localdbg,
            &localdbg->de_debug_rngslists,&localerror);
    } else {
        res = _dwarf_load_section(localdbg,
            &localdbg->de_debug_ranges,&localerror);
    }
#endif
    res = _dwarf_load_section(localdbg, &localdbg->de_debug_ranges,&localerror);
    if (res == DW_DLV_ERROR) {
        _dwarf_error_mv_s_to_t(localdbg,&localerror,dbg,error);
        return res;
    } else if (res == DW_DLV_NO_ENTRY) {
        return res;
    }

    /*  Be safe in case adding rangesoffset and rangebase
        overflows. */
    if (rangesoffset  == localdbg->de_debug_ranges.dss_size) {
        return DW_DLV_NO_ENTRY;
    }
    if (rangesoffset  > localdbg->de_debug_ranges.dss_size) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
            " rangesoffset is 0x%lx ",rangesoffset);
        dwarfstring_append_printf_u(&m,
            " and section size is 0x%lx.",
            localdbg->de_debug_ranges.dss_size);
        _dwarf_error_string(dbg, error,
            DW_DLE_DEBUG_RANGES_OFFSET_BAD,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    if (ranges_base >= localdbg->de_debug_ranges.dss_size) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
            " ranges base is 0x%lx ",ranges_base);
        dwarfstring_append_printf_u(&m,
            " and section size is 0x%lx.",
            localdbg->de_debug_ranges.dss_size);
        _dwarf_error_string(dbg, error,
            DW_DLE_DEBUG_RANGES_OFFSET_BAD,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    if ((rangesoffset +ranges_base) >=
        localdbg->de_debug_ranges.dss_size) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
            " ranges base+offset  is 0x%lx ",
            ranges_base+rangesoffset);
        dwarfstring_append_printf_u(&m,
            " and section size is 0x%lx.",
            localdbg->de_debug_ranges.dss_size);
        _dwarf_error_string(dbg, error,
            DW_DLE_DEBUG_RANGES_OFFSET_BAD,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }

    /*  tied address_size must match the dwo address_size */
    section_end = localdbg->de_debug_ranges.dss_data +
        localdbg->de_debug_ranges.dss_size;
    rangeptr = localdbg->de_debug_ranges.dss_data +
        rangesoffset + ranges_base;
    beginrangeptr = rangeptr;

    for (;;) {
        struct ranges_entry * re = 0;

        if (rangeptr == section_end) {
            break;
        }
        if (rangeptr  > section_end) {
            dwarfstring m;

            free_allocated_ranges(base);
            dwarfstring_constructor(&m);
            dwarfstring_append(&m,
                "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
                " ranges pointer ran off the end "
                "of the  section");
            _dwarf_error_string(dbg, error,
                DW_DLE_DEBUG_RANGES_OFFSET_BAD,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        re = calloc(sizeof(struct ranges_entry),1);
        if (!re) {
            free_allocated_ranges(base);
            _dwarf_error(dbg, error, DW_DLE_DEBUG_RANGES_OUT_OF_MEM);
            return DW_DLV_ERROR;
        }
        if ((rangeptr + (2*address_size)) > section_end) {
            free(re);
            free_allocated_ranges(base);
            _dwarf_error_string(dbg, error,
                DW_DLE_DEBUG_RANGES_OFFSET_BAD,
                "DW_DLE_DEBUG_RANGES_OFFSET_BAD: "
                " Not at the end of the ranges section "
                " but there is not enough room in the section "
                " for the next ranges entry");
            return  DW_DLV_ERROR;
        }
        entry_count++;
        res = read_unaligned_addr_check(localdbg,&re->cur.dwr_addr1,
            rangeptr, address_size,error,section_end);
        if (res != DW_DLV_OK) {
            free(re);
            free_allocated_ranges(base);
            return res;
        }
        rangeptr +=  address_size;
        res = read_unaligned_addr_check(localdbg,&re->cur.dwr_addr2,
            rangeptr, address_size,error,section_end);
        if (res != DW_DLV_OK) {
            free(re);
            free_allocated_ranges(base);
            return res;
        }
        rangeptr +=  address_size;
        if (!base) {
            base = re;
            last = re;
        } else {
            last->next = re;
            last = re;
        }
        if (re->cur.dwr_addr1 == 0 && re->cur.dwr_addr2 == 0) {
            re->cur.dwr_type =  DW_RANGES_END;
            break;
        } else if (re->cur.dwr_addr1 == MAX_ADDR) {
            re->cur.dwr_type =  DW_RANGES_ADDRESS_SELECTION;
        } else {
            re->cur.dwr_type =  DW_RANGES_ENTRY;
        }
    }

    /* We return ranges on dbg, so use that to allocate. */
    ranges_data_out =   (Dwarf_Ranges *)
        _dwarf_get_alloc(dbg,DW_DLA_RANGES,entry_count);
    if (!ranges_data_out) {
        /* Error, apply to original, not local dbg. */
        free_allocated_ranges(base);
        _dwarf_error(dbg, error, DW_DLE_DEBUG_RANGES_OUT_OF_MEM);
        return (DW_DLV_ERROR);
    }
    curre = base;
    *rangesbuf = ranges_data_out;
    *listlen = entry_count;
    for (copyindex = 0; curre && (copyindex < entry_count);
        ++copyindex,++ranges_data_out) {

        *ranges_data_out = curre->cur;
        curre = curre->next;
    }
    /* ASSERT: curre == NULL */
    free_allocated_ranges(base);
    base = 0;
    /* Callers will often not care about the bytes used. */
    if (bytecount) {
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
    UNUSEDARG Dwarf_Signed rangecount)
{
    dwarf_dealloc(dbg,rangesbuf, DW_DLA_RANGES);
}
