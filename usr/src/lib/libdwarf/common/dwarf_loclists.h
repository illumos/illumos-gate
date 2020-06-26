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
#ifndef DWARF_LOCLISTS_H
#define DWARF_LOCLISTS_H
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#if 0
/*  THIS IS NOT IN FINAL FORM!! BE WARNED! */

/*  Loclists header for a CU. The
    type is never visible to libdwarf callers  */
typedef struct Dwarf_Loclists_Context_s *Dwarf_Loclists_Context;
struct Dwarf_Loclists_Context_s {
    Dwarf_Debug    lc_dbg;
    Dwarf_Unsigned lc_index; /* An index  assigned by
        libdwarf to each loclists context. Starting
        with zero at the zero offset in .debug_loclists. */

    /* Offset of the .debug_loclists header involved. */
    Dwarf_Unsigned  lc_header_offset;
    Dwarf_Unsigned  lc_length;

    /* Many places in in libdwarf this is called length_size. */
    Dwarf_Small     lc_offset_size;

    /*  rc_extension_size is zero unless this is standard
        DWARF3 and later 64bit dwarf using the extension mechanism.
        64bit DWARF3 and later: rc_extension_size is 4.
        64bit DWARF2 MIPS/IRIX: rc_extension_size is zero.
        32bit DWARF:            rc_extension_size is zero.  */
    Dwarf_Small     lc_extension_size;

    unsigned        lc_version; /* 5 */
    Dwarf_Small     lc_address_size;
    Dwarf_Small     lc_segment_selector_size;
    Dwarf_Unsigned  lc_offset_entry_count;

    /* offset in the section of the offset entries */
    Dwarf_Unsigned  lc_offsets_off_in_sect;

    /* Do not free. Points into section memory */
    Dwarf_Small   * lc_offsets_array;

    /*  Offset in the .debug_loclists section of the
        first loclist in the set of loclists for the
        CU. */
    Dwarf_Unsigned  lc_first_loclist_offset;
    Dwarf_Unsigned  lc_past_last_loclist_offset;

    /* pointer to 1st byte of loclist header*/
    Dwarf_Small *  lc_loclists_header;
    /*  pointer to first byte of the loclist data
        for loclist involved. Do not free. */
    Dwarf_Small    *lc_startaddr;
    /*  pointer one past end of the loclist data. */
    Dwarf_Small    *lc_endaddr;
};

typedef struct Dwarf_Loclists_Entry_s *Dwarf_Loclists_Entry;
struct Dwarf_Loclists_Entry_s {
    unsigned       lle_entrylen;
    unsigned       lle_code;
    Dwarf_Unsigned lle_raw1;
    Dwarf_Unsigned lle_raw2;
    /*  Cooked means the raw values from the .debug_loclists
        section translated to DIE-specific addresses. */
    Dwarf_Unsigned lle_cooked1;
    Dwarf_Unsigned lle_cooked2;
    Dwarf_Loclists_Entry lle_next;
};


struct Dwarf_Loclists_Head_s {
    Dwarf_Loclists_Entry *lh_loclists;
    /*  rh_last and rh_first used during build-up.
        Zero when array rh_loclists built. */
    Dwarf_Loclists_Entry  lh_first;
    Dwarf_Loclists_Entry  lh_last;
    Dwarf_Unsigned        lh_count;
    Dwarf_Unsigned        lh_bytes_total;

    /*  A global Loclists  Context, */
    Dwarf_CU_Context      lh_context;
    Dwarf_Debug           lh_dbg;
    Dwarf_Loclists_Context lh_localcontext;
    Dwarf_Unsigned         lh_version;
    Dwarf_Unsigned         lh_index;
    Dwarf_Unsigned         lh_offset_size;
    Dwarf_Unsigned         lh_address_size;
    unsigned               lh_segment_selector_size;

    /*  DW_AT_loclists_base */
    Dwarf_Bool      lh_at_loclists_base_present;
    Dwarf_Unsigned  lh_at_loclists_base;

    /* DW_AT_low_pc of CU or zero if none. */
    Dwarf_Bool      lh_cu_base_address_present;
    Dwarf_Unsigned  lh_cu_base_address;

    /*  DW_AT_addr_base, so we can use .debug_addr
        if such is needed. */
    Dwarf_Bool      lh_cu_addr_base_present;
    Dwarf_Unsigned  lh_cu_addr_base;
    Dwarf_Small    * lh_rlepointer;
    Dwarf_Unsigned   lh_rlearea_offset;
    Dwarf_Small    * lh_end_data_area;
};
#endif

void _dwarf_loclists_head_destructor(void *l);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* DWARF_LOCLISTS_H */
