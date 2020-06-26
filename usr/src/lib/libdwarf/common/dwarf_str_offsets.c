/*
    Copyright (C) 2018-2018 David Anderson. All Rights Reserved.

    This program is free software; you can redistribute it
    and/or modify it under the terms of version 2.1 of
    the GNU Lesser General Public License
    as published by the Free Software Foundation.

    This program is distributed in the hope that it would be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    Further, this software is distributed without any warranty
    that it is free of the rightful claim of any third person
    regarding infringement or the like.
    Any license provided herein, whether implied or
    otherwise, applies only to this software file.
    Patent licenses, if any, provided herein do not
    apply to combinations of this program with
    other software, or any other product whatsoever.

    You should have received a copy of the GNU Lesser General Public
    License along with this program; if not, write the Free Software
    Foundation, Inc., 51 Franklin Street - Fifth Floor,
    Boston MA 02110-1301,
    USA.
*/

#include "config.h"
#include <stdio.h>
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarfstring.h"
#include "dwarf_str_offsets.h"

#define TRUE 1
#define FALSE 0

#define STR_OFFSETS_MAGIC 0x2feed2

#define VALIDATE_SOT(xsot)                                            \
    if (!xsot) {                                                      \
        _dwarf_error(NULL,error,DW_DLE_STR_OFFSETS_NULLARGUMENT);     \
        return DW_DLV_ERROR;                                          \
    }                                                                 \
    if (!xsot->so_dbg) {                                              \
        _dwarf_error(NULL,error,DW_DLE_STR_OFFSETS_NULL_DBG);         \
        return DW_DLV_ERROR;                                          \
    }                                                                 \
    if (xsot->so_magic_value !=  STR_OFFSETS_MAGIC) {                 \
        _dwarf_error(xsot->so_dbg,error,DW_DLE_STR_OFFSETS_NO_MAGIC); \
        return DW_DLV_ERROR;                                          \
    }

#if 0
static void
dump_bytes(char * msg,Dwarf_Small * start, long len)
{
    Dwarf_Small *end = start + len;
    Dwarf_Small *cur = start;

    printf("%s ",msg);
    for (; cur < end; cur++) {
        printf("%02x ", *cur);
    }
    printf("\n");
}
#endif

int
dwarf_open_str_offsets_table_access(Dwarf_Debug dbg,
    Dwarf_Str_Offsets_Table * table_data,
    Dwarf_Error             * error)
{
    int res = 0;
    Dwarf_Str_Offsets_Table local_table_data = 0;
    Dwarf_Small *offsets_start_ptr = 0;
    Dwarf_Unsigned sec_size = 0;

    if (!dbg) {
        _dwarf_error(NULL,error,DW_DLE_STR_OFFSETS_NULL_DBG);         \
        return DW_DLV_ERROR;                                          \
    }
    if (!table_data) {
        _dwarf_error(dbg,error,DW_DLE_STR_OFFSETS_NULLARGUMENT);     \
        return DW_DLV_ERROR;                                          \
    }
    /*  Considered testing for *table_data being NULL, but
        not doing such a test. */

    res = _dwarf_load_section(dbg, &dbg->de_debug_str_offsets,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    offsets_start_ptr = dbg->de_debug_str_offsets.dss_data;
    if (!offsets_start_ptr) {
        return DW_DLV_NO_ENTRY;
    }
    sec_size = dbg->de_debug_str_offsets.dss_size;
    local_table_data = (Dwarf_Str_Offsets_Table)_dwarf_get_alloc(dbg,
        DW_DLA_STR_OFFSETS,1);
    if(!local_table_data) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    local_table_data->so_dbg = dbg;
    local_table_data->so_magic_value  = STR_OFFSETS_MAGIC;
    local_table_data->so_section_start_ptr = offsets_start_ptr;
    local_table_data->so_section_end_ptr = offsets_start_ptr +sec_size;
    local_table_data->so_section_size = sec_size;
    local_table_data->so_next_table_offset = 0;
    local_table_data->so_wasted_section_bytes = 0;
    /*  get_alloc zeroed all the bits, no need to repeat that here. */
    *table_data = local_table_data;
    return DW_DLV_OK;
}

int
dwarf_close_str_offsets_table_access(
    Dwarf_Str_Offsets_Table  table_data,
    Dwarf_Error             * error)
{
    Dwarf_Debug dbg = 0;

    VALIDATE_SOT(table_data)
    dbg = table_data->so_dbg;
    table_data->so_magic_value = 0xdead;
    dwarf_dealloc(dbg,table_data, DW_DLA_STR_OFFSETS);
    return DW_DLV_OK;
}


int
dwarf_str_offsets_value_by_index(Dwarf_Str_Offsets_Table sot,
    Dwarf_Unsigned index,
    Dwarf_Unsigned *stroffset,
    Dwarf_Error *error)
{
    Dwarf_Small *entryptr = 0;
    Dwarf_Unsigned val = 0;

    VALIDATE_SOT(sot)
    if (index >= sot->so_array_entry_count) {
        _dwarf_error(sot->so_dbg,error, DW_DLE_STR_OFFSETS_ARRAY_INDEX_WRONG);
        return DW_DLV_ERROR;
    }
    entryptr = sot->so_array_ptr + (index * sot->so_array_entry_size);
    READ_UNALIGNED_CK(sot->so_dbg, val, Dwarf_Unsigned,
        entryptr, sot->so_array_entry_size,error,sot->so_end_cu_ptr);
    *stroffset = val;
    return DW_DLV_OK;
}

/*  We are assuming we can look for a str_offsets table
    header on 32bit boundaries.  Any non-zero value
    suggests we are at a table.  So we assume it is a table.
    Later we'll check for validity.
    This is just so that unused zeroed 32bit words, if any,
    do not stop our processing. */
static int
find_next_str_offsets_tab(Dwarf_Str_Offsets_Table sot,
    Dwarf_Unsigned starting_offset,
    Dwarf_Unsigned *table_offset_out,
    Dwarf_Error *error)
{
    Dwarf_Small *word_ptra = 0;
    Dwarf_Small *word_ptrb = 0;
    Dwarf_Unsigned offset  = starting_offset;

    word_ptra = word_ptrb = sot->so_section_start_ptr +offset;
    for ( ; ; word_ptrb += DWARF_32BIT_SIZE) {
        Dwarf_Unsigned one32bit = 0;
        if (word_ptrb >= sot->so_section_end_ptr) {
            sot->so_wasted_section_bytes += (word_ptrb - word_ptra);
            return DW_DLV_NO_ENTRY;
        }
        READ_UNALIGNED_CK(sot->so_dbg, one32bit, Dwarf_Unsigned,
            word_ptrb, DWARF_32BIT_SIZE,
            error,sot->so_section_end_ptr);
        if (one32bit) {
            /* Found a value */
            break;
        }
        offset += DWARF_32BIT_SIZE;
    }
    sot->so_wasted_section_bytes += (word_ptrb - word_ptra);
    *table_offset_out = offset;
    return DW_DLV_OK;
}

/* The minimum possible area .debug_str_offsets header . */
#define MIN_HEADER_LENGTH  8

/*  New April 2018.
    Beginning at starting_offset zero,
    returns data about the first table found.
    The value *next_table_offset is the value
    of the next table (if any), one byte past
    the end of the table whose data is returned..
    Returns DW_DLV_NO_ENTRY if the starting offset
    is past the end of valid data.

    There is no guarantee that there are no non-0 nonsense
    bytes in the section outside of useful tables,
    so this can fail and return nonsense or
    DW_DLV_ERROR  if such garbage exists.
*/

static int
is_all_zeroes(Dwarf_Small*start,
    Dwarf_Small*end)
{
    if (start >= end) {
        /*  We should not get here, this is just
            a defensive test. */
        return TRUE;
    }
    for( ; start < end; ++start) {
        if (!*start) {
            /* There is some garbage here. */
            return FALSE;
        }
    }
    /* All just zero bytes. */
    return TRUE;
}

int
dwarf_next_str_offsets_table(Dwarf_Str_Offsets_Table sot,
    Dwarf_Unsigned *unit_length_out,
    Dwarf_Unsigned *unit_length_offset_out,
    Dwarf_Unsigned *table_start_offset_out,
    Dwarf_Half     *entry_size_out,
    Dwarf_Half     *version_out,
    Dwarf_Half     *padding_out,
    Dwarf_Unsigned *table_value_count_out,
    Dwarf_Error    * error)
{

    Dwarf_Small *table_start_ptr = 0;
    Dwarf_Small *table_end_ptr = 0;
    Dwarf_Unsigned table_offset = 0;
    Dwarf_Unsigned local_length_size = 0;
    UNUSEDARG Dwarf_Unsigned local_extension_size = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Half version = 0;
    Dwarf_Half padding = 0;
    int res = 0;

    VALIDATE_SOT(sot)

    res = find_next_str_offsets_tab(sot,
        sot->so_next_table_offset,
        &table_offset,error);
    if (res != DW_DLV_OK) {
        /*  As a special case, if unused zero bytess at the end,
            count as wasted space. */
        if (res == DW_DLV_NO_ENTRY) {
            if (table_offset > sot->so_next_table_offset) {
                sot->so_wasted_section_bytes +=
                    (table_offset - sot->so_next_table_offset);
            }
        }
        return res;
    }
    if (table_offset > sot->so_next_table_offset) {
        sot->so_wasted_section_bytes +=
            (table_offset - sot->so_next_table_offset);
    }
    table_start_ptr = sot->so_section_start_ptr + table_offset;
    sot->so_header_ptr = table_start_ptr;
    if (table_start_ptr >= sot->so_section_end_ptr) {
        if (table_start_ptr == sot->so_section_end_ptr) {
            /* At end of section. Done. */
            return DW_DLV_NO_ENTRY;
        } else {
            /* bogus table offset. */
            ptrdiff_t len = table_start_ptr -
                sot->so_section_end_ptr;
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_i(&m,
                "DW_DLE_STR_OFFSETS_EXTRA_BYTES: "
                "Table Offset is %"   DW_PR_DSd
                " bytes past end of section",len);
            _dwarf_error_string(sot->so_dbg,error,
                DW_DLE_STR_OFFSETS_EXTRA_BYTES,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
        }
    }

    if ((table_start_ptr + MIN_HEADER_LENGTH) >
        sot->so_section_end_ptr) {

        /*  We have a too-short section it appears.
            Should we generate error? Or ignore?
            As of March 10 2020 we check for garbage
            bytes in-section. */
        ptrdiff_t len = 0;
        dwarfstring m;

        if (is_all_zeroes(table_start_ptr,sot->so_section_end_ptr)){
            return DW_DLV_NO_ENTRY;
        }
        len = sot->so_section_end_ptr -
            table_start_ptr;
        dwarfstring_constructor(&m);
        dwarfstring_append_printf_i(&m,
            "DW_DLE_STR_OFFSETS_EXTRA_BYTES: "
            "Table Offset plus a minimal header is %"
            DW_PR_DSd
            " bytes past end of section"
            " and some bytes in-section are non-zero",len);
        _dwarf_error_string(sot->so_dbg,error,
            DW_DLE_STR_OFFSETS_EXTRA_BYTES,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    READ_AREA_LENGTH_CK(sot->so_dbg,length,Dwarf_Unsigned,
        table_start_ptr,local_length_size,
        local_extension_size,error,
        sot->so_section_size,sot->so_section_end_ptr);

    /*  The 'length' part of any header is
        local_extension_size + local_length_size.
        Standard DWARF2 sums to 4.
        Standard DWARF3,4,5 sums to 4 or 12.
        Nonstandard SGI IRIX 64bit dwarf sums to 8 (SGI IRIX
        was all DWARF2 and could not have a .debug_str_offsets
        section).
        The header includes 2 bytes of version and two bytes
        of padding. */

    /*  table_start_ptr was incremented past the length data. */
    table_end_ptr = table_start_ptr + length;
    READ_UNALIGNED_CK(sot->so_dbg, version, Dwarf_Half,
        table_start_ptr, DWARF_HALF_SIZE,
        error,sot->so_section_end_ptr);
    table_start_ptr += DWARF_HALF_SIZE;
    READ_UNALIGNED_CK(sot->so_dbg, padding, Dwarf_Half,
        table_start_ptr, DWARF_HALF_SIZE,
        error,sot->so_section_end_ptr);
    table_start_ptr += DWARF_HALF_SIZE;

    if (version != DW_STR_OFFSETS_VERSION5) {
        _dwarf_error(sot->so_dbg,error,
            DW_DLE_STR_OFFSETS_VERSION_WRONG);
        return DW_DLV_ERROR;
    }

    /*  So now table_start_ptr points to a table of local_length_size
        entries.
        Each entry in this table is local_length_size bytes
        long: 4 or 8. */
    {
        Dwarf_Unsigned entrycount = 0;
        Dwarf_Unsigned entrybytes = 0;

        entrybytes = table_end_ptr - table_start_ptr;
        if (entrybytes % local_length_size) {
            _dwarf_error(sot->so_dbg,error,
                DW_DLE_STR_OFFSETS_ARRAY_SIZE);
            return DW_DLV_ERROR;
        }
        entrycount = entrybytes/local_length_size;
        sot->so_next_table_offset = table_end_ptr -
            sot->so_section_start_ptr;

        sot->so_end_cu_ptr =  table_end_ptr;
        sot->so_array_ptr = table_start_ptr;
        sot->so_table_start_offset = table_offset;
        sot->so_array_start_offset = table_start_ptr -
            sot->so_section_start_ptr;
        sot->so_array_entry_count = entrycount;
        sot->so_array_entry_size = local_length_size;
        sot->so_table_count += 1;

        /*  The data length  in bytes following the unit_length field
            of the header. */
        *unit_length_out = length;

        /*  Where the unit_length field starts in the section. */
        *unit_length_offset_out = sot->so_table_start_offset;

        /*  Where the table of offsets starts in the section. */
        *table_start_offset_out = sot->so_array_start_offset;

        /*   Entrysize: 4 or 8 */
        *entry_size_out  = local_length_size;

        /*   Version is 5. */
        *version_out  = version;

        /*   This is supposed to be zero. */
        *padding_out  = padding;

        /*  How many entry_size entries are in the array. */
        *table_value_count_out = entrycount;
        return DW_DLV_OK;
    }
}

/*  Meant to be called after all tables accessed using
    dwarf_next_str_offsets_table(). */
int
dwarf_str_offsets_statistics(Dwarf_Str_Offsets_Table table_data,
    Dwarf_Unsigned * wasted_byte_count,
    Dwarf_Unsigned * table_count,
    Dwarf_Error    * error)
{
    VALIDATE_SOT(table_data)
    if(wasted_byte_count) {
        *wasted_byte_count = table_data->so_wasted_section_bytes;
    }
    if(table_count) {
        *table_count = table_data->so_table_count;
    }
    return DW_DLV_OK;
}
