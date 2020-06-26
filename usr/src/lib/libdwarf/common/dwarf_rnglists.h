/*
Copyright (c) 2020, David Anderson
All rights reserved.

Redistribution and use in source and binary forms, with
or without modification, are permitted provided that the
following conditions are met:

    Redistributions of source code must retain the above
    copyright notice, this list of conditions and the following
    disclaimer.

    Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials
    provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef DWARF_RNGLISTS_H
#define DWARF_RNGLISTS_H
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*  Rangelists header for a CU. The
    type is never visible to libdwarf callers  */
struct Dwarf_Rnglists_Context_s {
    Dwarf_Debug    rc_dbg;
    Dwarf_Unsigned rc_index; /* An index  assigned by
        libdwarf to each rnglists context. Starting
        with zero at the zero offset in .debug_rnglists. */

    /* Offset of the .debug_rnglists header involved. */
    Dwarf_Unsigned  rc_header_offset;
    Dwarf_Unsigned  rc_length;

    /* Many places in in libdwarf this is called length_size. */
    Dwarf_Small     rc_offset_size;

    /*  rc_extension_size is zero unless this is standard
        DWARF3 and later 64bit dwarf using the extension mechanism.
        64bit DWARF3 and later: rc_extension_size is 4.
        64bit DWARF2 MIPS/IRIX: rc_extension_size is zero.
        32bit DWARF:            rc_extension_size is zero.  */
    Dwarf_Small     rc_extension_size;

    unsigned        rc_version; /* 5 */
    Dwarf_Small     rc_address_size;
    Dwarf_Small     rc_segment_selector_size;
    Dwarf_Unsigned  rc_offset_entry_count;

    /* offset in the section of the offset entries */
    Dwarf_Unsigned  rc_offsets_off_in_sect;

    /* Do not free. Points into section memory */
    Dwarf_Small   * rc_offsets_array;

    /*  Offset in the .debug_rnglists section of the
        first rangelist in the set of rangelists for the
        CU. */
    Dwarf_Unsigned  rc_first_rnglist_offset;
    Dwarf_Unsigned  rc_past_last_rnglist_offset;

    /* pointer to 1st byte of rangelist header*/
    Dwarf_Small *  rc_rnglists_header;
    /*  pointer to first byte of the rnglist data
        for rnglist involved. Do not free. */
    Dwarf_Small    *rc_startaddr;
    /*  pointer one past end of the rnglist data. */
    Dwarf_Small    *rc_endaddr;
};

struct Dwarf_Rnglists_Entry_s {
    unsigned       rle_entrylen;
    unsigned       rle_code;
    Dwarf_Unsigned rle_raw1;
    Dwarf_Unsigned rle_raw2;
    /*  Cooked means the raw values from the .debug_rnglists
        section translated to DIE-specific addresses. */
    Dwarf_Unsigned rle_cooked1;
    Dwarf_Unsigned rle_cooked2;
    Dwarf_Rnglists_Entry rle_next;
};


struct Dwarf_Rnglists_Head_s {
    Dwarf_Rnglists_Entry *rh_rnglists;
    /*  rh_last and rh_first used during build-up.
        Zero when array rh_rnglists built. */
    Dwarf_Rnglists_Entry  rh_first;
    Dwarf_Rnglists_Entry  rh_last;
    Dwarf_Unsigned        rh_count;
    Dwarf_Unsigned        rh_bytes_total;

    /*  A global Rnglists Context, */
    Dwarf_CU_Context      rh_context;
    Dwarf_Debug           rh_dbg;
    Dwarf_Rnglists_Context rh_localcontext;
    Dwarf_Unsigned         rh_version;
    Dwarf_Unsigned         rh_index;
    Dwarf_Unsigned         rh_offset_size;
    Dwarf_Unsigned         rh_address_size;
    unsigned               rh_segment_selector_size;

    /*  DW_AT_rnglists_base */
    Dwarf_Bool      rh_at_rnglists_base_present;
    Dwarf_Unsigned  rh_at_rnglists_base;

    /* DW_AT_low_pc of CU or zero if none. */
    Dwarf_Bool      rh_cu_base_address_present;
    Dwarf_Unsigned  rh_cu_base_address;

    /*  DW_AT_addr_base, so we can use .debug_addr
        if such is needed. */
    Dwarf_Bool      rh_cu_addr_base_present;
    Dwarf_Unsigned  rh_cu_addr_base;
    Dwarf_Small    * rh_rlepointer;
    Dwarf_Unsigned   rh_rlearea_offset;
    Dwarf_Small    * rh_end_data_area;
};

void _dwarf_rnglists_head_destructor(void *m);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* DWARF_RNGLISTS_H */
