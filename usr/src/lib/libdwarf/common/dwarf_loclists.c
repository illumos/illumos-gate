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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarfstring.h"
#include "dwarf_loc.h"

#define SIZEOFT8 1
#define SIZEOFT16 2
#define SIZEOFT32 4
#define SIZEOFT64 8
#define TRUE 1
#define FALSE 0


/*  Used in case of error reading the
    loclists headers (not referring to Dwarf_Loc_Head_c
    here), to clean up. */
static void
free_loclists_chain(Dwarf_Debug dbg, Dwarf_Chain head)
{
    Dwarf_Chain cur = head;
    Dwarf_Chain next = 0;

    if(!head) {
        return;
    }
    for( ;cur; cur = next) {
        next = cur->ch_next;
        if (cur->ch_item) {
            free(cur->ch_item);
            cur->ch_item = 0;
            dwarf_dealloc(dbg,cur,DW_DLA_CHAIN);
        }
    }
}

static int
counted_loc_descr(Dwarf_Debug dbg,
    Dwarf_Small *data,
    Dwarf_Small *enddata,
    Dwarf_Unsigned offset,
    Dwarf_Unsigned *loc_ops_overall_size,
    Dwarf_Unsigned *loc_ops_count_len,
    Dwarf_Unsigned *loc_ops_len,
    Dwarf_Small    **opsdata,
    Dwarf_Unsigned *opsoffset,
    Dwarf_Error *  err)
{
    Dwarf_Unsigned ops_len = 0;
    Dwarf_Unsigned leblen = 0;
    DECODE_LEB128_UWORD_LEN_CK(data,ops_len,leblen,
        dbg,err,enddata);
    *loc_ops_count_len = leblen;
    *loc_ops_overall_size = ops_len+leblen;
    *loc_ops_len = ops_len;
    *opsdata = data;
    *opsoffset = offset +leblen;
    return DW_DLV_OK;
}

static int
read_single_lle_entry(Dwarf_Debug dbg,
    Dwarf_Small    *data,
    Dwarf_Unsigned  dataoffset,
    Dwarf_Small    *enddata,
    unsigned        address_size,
    unsigned       *bytes_count_out,
    unsigned       *entry_kind,
    Dwarf_Unsigned *entry_operand1,
    Dwarf_Unsigned *entry_operand2,
    Dwarf_Unsigned *opsblocksize, /* Just the  expr data */
    Dwarf_Unsigned *opsoffset, /* Just the expr ops data */
    Dwarf_Small   **ops, /*  pointer to expr ops ops */
    Dwarf_Error* err)
{
    Dwarf_Unsigned count = 0;
    unsigned int   leblen = 0;
    unsigned int   code = 0;
    Dwarf_Unsigned val1 = 0;
    Dwarf_Unsigned val2 = 0;
    Dwarf_Unsigned loc_ops_overall_size = 0;
    Dwarf_Unsigned loc_ops_count_len = 0;
    Dwarf_Unsigned loc_ops_len = 0;
    Dwarf_Small   *lopsdata = 0;
    Dwarf_Unsigned lopsoffset = 0;

    /*  Some of these have a  Counted Location Description
        in them. */
    code = *data;
    ++data;
    ++count;
    switch(code) {
    case DW_LLE_end_of_list: break;
    case DW_LLE_base_addressx:{
        DECODE_LEB128_UWORD_LEN_CK(data,val1,leblen,
            dbg,err,enddata);
        count += leblen;
        }
        break;
    case DW_LLE_startx_endx:
    case DW_LLE_startx_length:
    case DW_LLE_offset_pair: {
        int res = 0;

        DECODE_LEB128_UWORD_LEN_CK(data,val1,leblen,
            dbg,err,enddata);
        count += leblen;
        DECODE_LEB128_UWORD_LEN_CK(data,val2,leblen,
            dbg,err,enddata);
        count += leblen;
        res = counted_loc_descr(dbg,data,enddata,
            dataoffset,
            &loc_ops_overall_size,
            &loc_ops_count_len,
            &loc_ops_len,
            &lopsdata,
            &lopsoffset,
            err);
        if (res != DW_DLV_OK) {
            return res;
        }
        count += loc_ops_overall_size;
        data  += loc_ops_overall_size;

        }
        break;
    case DW_LLE_default_location: {
        int res = 0;

        res = counted_loc_descr(dbg,data,enddata,
            dataoffset,
            &loc_ops_overall_size,
            &loc_ops_count_len,
            &loc_ops_len,
            &lopsdata,
            &lopsoffset,
            err);
        if (res != DW_DLV_OK) {
            return res;
        }
        data +=  loc_ops_overall_size;
        count +=  loc_ops_overall_size;
        }
        break;
    case DW_LLE_base_address: {
        READ_UNALIGNED_CK(dbg,val1, Dwarf_Unsigned,
            data,address_size,err,enddata);
        data += address_size;
        count += address_size;
        }
        break;
    case DW_LLE_start_end: {
        int res = 0;

        READ_UNALIGNED_CK(dbg,val1, Dwarf_Unsigned,
            data,address_size,err,enddata);
        data += address_size;
        count += address_size;
        READ_UNALIGNED_CK(dbg,val2, Dwarf_Unsigned,
            data,address_size,err,enddata);
        data += address_size;
        count += address_size;
        res = counted_loc_descr(dbg,data,enddata,
            dataoffset,
            &loc_ops_overall_size,
            &loc_ops_count_len,
            &loc_ops_len,
            &lopsdata,
            &lopsoffset,
            err);
        if (res != DW_DLV_OK) {
            return res;
        }
        count += loc_ops_overall_size;
        data +=  loc_ops_overall_size;
        }
        break;
    case DW_LLE_start_length: {
        int res = 0;

        READ_UNALIGNED_CK(dbg,val1, Dwarf_Unsigned,
            data,address_size,err,enddata);
        data += address_size;
        count += address_size;
        DECODE_LEB128_UWORD_LEN_CK(data,val2,leblen,
            dbg,err,enddata);
        count += leblen;
        res = counted_loc_descr(dbg,data,enddata,
            dataoffset,
            &loc_ops_overall_size,
            &loc_ops_count_len,
            &loc_ops_len,
            &lopsdata,
            &lopsoffset,
            err);
        if (res != DW_DLV_OK) {
            return res;
        }
        count += loc_ops_overall_size;
        data +=  loc_ops_overall_size;
        }
        break;
    default: {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_LOCLISTS_ERROR: "
            "The loclists entry at .debug_loclists"
            " offset 0x%x" ,dataoffset);
        dwarfstring_append_printf_u(&m,
            " has code 0x%x which is unknown",code);
        _dwarf_error_string(dbg,err,DW_DLE_LOCLISTS_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
        }
        break;
    }
    *bytes_count_out = count;
    *entry_kind      = code;
    *entry_operand1  = val1;
    *entry_operand2  = val2;
    *opsblocksize    = loc_ops_len;
    *opsoffset = lopsoffset;
    *ops       = lopsdata;
    return DW_DLV_OK;
}

/*  Reads the header. Determines the
    various offsets, including offset
    of the next header. Does no memory
    allocations here. */
static int
internal_read_header(Dwarf_Debug dbg,
    Dwarf_Unsigned contextnum,
    Dwarf_Unsigned sectionlength,
    Dwarf_Small *data,
    Dwarf_Small *end_data,
    Dwarf_Unsigned offset,
    Dwarf_Loclists_Context  buildhere,
    Dwarf_Unsigned *next_offset,
    Dwarf_Error *error)
{
    Dwarf_Small *startdata = data;
    Dwarf_Unsigned arealen = 0;
    int length_size = 0;
    int exten_size = 0;
    Dwarf_Unsigned version = 0;
    unsigned address_size = 0;
    unsigned segment_selector_size=  0;
    Dwarf_Unsigned offset_entry_count = 0;
    Dwarf_Unsigned localoff = 0;
    Dwarf_Unsigned lists_len = 0;

    READ_AREA_LENGTH_CK(dbg,arealen,Dwarf_Unsigned,
        data,length_size,exten_size,
        error,
        sectionlength,end_data);
    if (arealen > sectionlength) {
        dwarfstring m;
        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_SECTION_SIZE_ERROR: A .debug_loclists "
            "area size of 0x%x ",arealen);
        dwarfstring_append_printf_u(&m,
            "at offset 0x%x ",offset);
        dwarfstring_append_printf_u(&m,
            "is larger than the entire section size of "
            "0x%x. Corrupt DWARF.",sectionlength);
        _dwarf_error_string(dbg,error,DW_DLE_SECTION_SIZE_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }

    buildhere->lc_length = arealen +length_size+exten_size;
    buildhere->lc_dbg = dbg;
    buildhere->lc_index = contextnum;
    buildhere->lc_header_offset = offset;
    buildhere->lc_offset_size = length_size;
    buildhere->lc_extension_size = exten_size;
    READ_UNALIGNED_CK(dbg,version,Dwarf_Unsigned,data,
        SIZEOFT16,error,end_data);
    if (version != DW_CU_VERSION5) {
        dwarfstring m;
        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_VERSION_STAMP_ERROR: The version should be 5 "
            "but we find %u instead.",version);
        _dwarf_error_string(dbg,error,DW_DLE_VERSION_STAMP_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    buildhere->lc_version = version;
    data += SIZEOFT16;

    READ_UNALIGNED_CK(dbg,address_size,unsigned,data,
        SIZEOFT8,error,end_data);
    if (version != DW_CU_VERSION5) {
        dwarfstring m;
        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_VERSION_STAMP_ERROR: The version should be 5 "
            "but we find %u instead.",version);
        _dwarf_error_string(dbg,error,DW_DLE_VERSION_STAMP_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    if (address_size != 4 && address_size != 8 &&
        address_size != 2) {
        dwarfstring m;
        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            " DW_DLE_ADDRESS_SIZE_ERROR: The address size "
            "of %u is not supported.",address_size);
        _dwarf_error_string(dbg,error,DW_DLE_ADDRESS_SIZE_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    buildhere->lc_address_size = address_size;
    data++;

    READ_UNALIGNED_CK(dbg,segment_selector_size,unsigned,data,
        SIZEOFT8,error,end_data);
    buildhere->lc_segment_selector_size = segment_selector_size;
    data++;

    READ_UNALIGNED_CK(dbg,offset_entry_count,Dwarf_Unsigned,data,
        SIZEOFT32,error,end_data);
    buildhere->lc_offset_entry_count = offset_entry_count;
    data += SIZEOFT32;
    if (offset_entry_count ){
        buildhere->lc_offsets_array = data;
    }
    localoff = data - startdata;
    lists_len = address_size *offset_entry_count;

    data += lists_len;

    buildhere->lc_offsets_off_in_sect = offset+localoff;
    buildhere->lc_first_loclist_offset = offset+localoff+
        lists_len;
    buildhere->lc_loclists_header = startdata;
    buildhere->lc_endaddr = startdata +buildhere->lc_length;
    buildhere->lc_past_last_loclist_offset =
        buildhere->lc_header_offset +buildhere->lc_length;
    *next_offset =  buildhere->lc_past_last_loclist_offset;
    return DW_DLV_OK;
}


/*  We return a pointer to an array of contexts
    (not context pointers through *cxt if
    we succeed and are returning DW_DLV_OK.
    We never return DW_DLV_NO_ENTRY here. */
static int
internal_load_loclists_contexts(Dwarf_Debug dbg,
    Dwarf_Loclists_Context **cxt,
    Dwarf_Unsigned *count,
    Dwarf_Error *error)
{
    Dwarf_Unsigned offset = 0;
    Dwarf_Unsigned nextoffset = 0;
    Dwarf_Small  * data = dbg->de_debug_loclists.dss_data;
    Dwarf_Unsigned section_size = dbg->de_debug_loclists.dss_size;
    Dwarf_Small  * startdata = data;
    Dwarf_Small  * end_data = data +section_size;
    Dwarf_Chain curr_chain = 0;
    Dwarf_Chain prev_chain = 0;
    Dwarf_Chain head_chain = 0;
    int res = 0;
    Dwarf_Unsigned chainlength = 0;
    Dwarf_Loclists_Context *fullarray = 0;
    Dwarf_Unsigned i = 0;

    for( ; data < end_data ; ) {
        Dwarf_Loclists_Context newcontext = 0;

        /* sizeof the context struct, not sizeof a pointer */
        newcontext = malloc(sizeof(*newcontext));
        if (!newcontext) {
            free_loclists_chain(dbg,head_chain);
            _dwarf_error_string(dbg,error,
                DW_DLE_ALLOC_FAIL,
                "DW_DLE_ALLOC_FAIL: Allocation of "
                "Loclists_Context failed");
            return DW_DLV_ERROR;
        }
        memset(newcontext,0,sizeof(*newcontext));
        res = internal_read_header(dbg,chainlength,
            section_size,
            data,end_data,offset,
            newcontext,&nextoffset,error);
        if (res == DW_DLV_ERROR) {
            free(newcontext);
            free_loclists_chain(dbg,head_chain);
        }
        curr_chain = (Dwarf_Chain)
            _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
        if (curr_chain == NULL) {
            free_loclists_chain(dbg,head_chain);
            _dwarf_error_string(dbg, error, DW_DLE_ALLOC_FAIL,
                "DW_DLE_ALLOC_FAIL: allocating Loclists_Context"
                " chain entry");
            return DW_DLV_ERROR;
        }
        curr_chain->ch_item = newcontext;
        ++chainlength;
        if (head_chain == NULL) {
            head_chain = prev_chain = curr_chain;
        } else {
            prev_chain->ch_next = curr_chain;
            prev_chain = curr_chain;
        }
        data = startdata+nextoffset;
        offset = nextoffset;
    }
    fullarray= (Dwarf_Loclists_Context *)malloc(
        chainlength *sizeof(Dwarf_Loclists_Context /*pointer*/));
    if (!fullarray) {
        free_loclists_chain(dbg,head_chain);
        _dwarf_error_string(dbg,error,
            DW_DLE_ALLOC_FAIL,"Allocation of "
            "Loclists_Context pointer array failed");
        return DW_DLV_ERROR;
    }
    curr_chain = head_chain;
    for( i = 0; i < chainlength; ++i) {
        fullarray[i] = (Dwarf_Loclists_Context)curr_chain->ch_item;
        curr_chain->ch_item = 0;
        prev_chain = curr_chain;
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN);
    }
    /*  ASSERT: the chain is entirely dealloc'd
        and the array of pointers points to
        individually malloc'd Dwarf_Loclists_Context_s */
    *cxt = fullarray;
    *count = chainlength;
    return DW_DLV_OK;
}



/*  Used by dwarfdump to print raw loclists data.
    Loads all the .debug_loclists[.dwo]  headers and
    returns DW_DLV_NO_ENTRY if the section
    is missing or empty.
    Intended to be done quite early and
    done exactly once.
    Harmless to do more than once.
    With DW_DLV_OK it returns the number of
    loclists headers in the section through
    loclists_count. */
int dwarf_load_loclists(
    Dwarf_Debug dbg,
    Dwarf_Unsigned *loclists_count,
    Dwarf_Error *error)
{
    int res = DW_DLV_ERROR;
    Dwarf_Loclists_Context *cxt = 0;
    Dwarf_Unsigned count = 0;

    if (dbg->de_loclists_context) {
        if (loclists_count) {
            *loclists_count = dbg->de_loclists_context_count;
        }
    }
    if (!dbg->de_debug_loclists.dss_size) {
        /* nothing there. */
        return DW_DLV_NO_ENTRY;
    }
    if (!dbg->de_debug_loclists.dss_data) {
        res = _dwarf_load_section(dbg, &dbg->de_debug_loclists,
            error);
        if (res != DW_DLV_OK) {
            return res;
        }
    }
    res = internal_load_loclists_contexts(dbg,&cxt,&count,error);
    if (res == DW_DLV_ERROR) {
        return res;
    }
    dbg->de_loclists_context = cxt;
    dbg->de_loclists_context_count = count;
    if (loclists_count) {
        *loclists_count = count;
    }
    return DW_DLV_OK;
}

/*  Frees the memory in use in all loclists contexts.
    Done by dwarf_finish()  */
void
_dwarf_dealloc_loclists_context(Dwarf_Debug dbg)
{
    Dwarf_Unsigned i = 0;
    Dwarf_Loclists_Context * loccon = 0;

    if (!dbg->de_loclists_context) {
        return;
    }
    loccon = dbg->de_loclists_context;
    for( ; i < dbg->de_loclists_context_count; ++i,++loccon) {
        Dwarf_Loclists_Context con = *loccon;
        con->lc_offsets_array = 0;
        con->lc_offset_entry_count = 0;
        free(con);
    }
    free(dbg->de_loclists_context);
    dbg->de_loclists_context = 0;
    dbg->de_loclists_context_count = 0;
}

/*  Used by dwarfdump to print raw loclists data. */
int
dwarf_get_loclist_offset_index_value(
    Dwarf_Debug dbg,
    Dwarf_Unsigned context_index,
    Dwarf_Unsigned offsetentry_index,
    Dwarf_Unsigned * offset_value_out,
    Dwarf_Unsigned * global_offset_value_out,
    Dwarf_Error *error)
{
    Dwarf_Loclists_Context con = 0;
    unsigned offset_len = 0;
    Dwarf_Small *offsetptr = 0;
    Dwarf_Unsigned targetoffset = 0;

    if (!dbg->de_loclists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    if (context_index >= dbg->de_loclists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    con = dbg->de_loclists_context[context_index];

    if (offsetentry_index >= con->lc_offset_entry_count) {
        return DW_DLV_NO_ENTRY;
    }
    offset_len = con->lc_offset_size;
    offsetptr = con->lc_offsets_array +
        (offsetentry_index*offset_len);
    READ_UNALIGNED_CK(dbg,targetoffset,Dwarf_Unsigned,
        offsetptr,
        offset_len,error,con->lc_endaddr);
    if (offset_value_out) {
        *offset_value_out = targetoffset;
    }
    if (global_offset_value_out) {
        *global_offset_value_out = targetoffset +
            con->lc_offsets_off_in_sect;
    }
    return DW_DLV_OK;
}

/*  Used by dwarfdump to print basic data from the
    data generated to look at a specific loclist
    as returned by  dwarf_loclists_index_get_rle_head()
    or dwarf_loclists_offset_get_rle_head. */
int dwarf_get_loclist_head_basics(
    Dwarf_Loc_Head_c head,
    Dwarf_Small    * lkind,
    Dwarf_Unsigned * lle_count,
    Dwarf_Unsigned * lle_version,
    Dwarf_Unsigned * loclists_index_returned,
    Dwarf_Unsigned * bytes_total_in_lle,
    Dwarf_Half     * offset_size,
    Dwarf_Half     * address_size,
    Dwarf_Half     * segment_selector_size,
    Dwarf_Unsigned * overall_offset_of_this_context,
    Dwarf_Unsigned * total_length_of_this_context,
    Dwarf_Unsigned * offset_table_offset,
    Dwarf_Unsigned * offset_table_entrycount,
    Dwarf_Bool     * loclists_base_present,
    Dwarf_Unsigned * loclists_base,
    Dwarf_Bool     * loclists_base_address_present,
    Dwarf_Unsigned * loclists_base_address,
    Dwarf_Bool     * loclists_debug_addr_base_present,
    Dwarf_Unsigned * loclists_debug_addr_base,
    Dwarf_Unsigned * loclists_offset_lle_set,
    UNUSEDARG Dwarf_Error *error)
{
    Dwarf_Loclists_Context loccontext = 0;
    *lkind = head->ll_kind;
    *lle_count = head->ll_locdesc_count;
    *lle_version = head->ll_cuversion;
    *loclists_index_returned = head->ll_index;
    *bytes_total_in_lle = head->ll_bytes_total;
    *offset_size = head->ll_offset_size;
    *address_size = head->ll_address_size;
    *segment_selector_size = head->ll_segment_selector_size;
    /*  If a dwarf_expression, no ll_loccontext */
    loccontext = head->ll_localcontext;
    if (loccontext) {
        *overall_offset_of_this_context =
            loccontext->lc_header_offset;
        *total_length_of_this_context = loccontext->lc_length;
        *offset_table_offset =  loccontext->lc_offsets_off_in_sect;
        *offset_table_entrycount = loccontext->lc_offset_entry_count;
    }
    *loclists_base_present = head->ll_at_loclists_base_present;
    *loclists_base= head->ll_at_loclists_base;

    *loclists_base_address_present = head->ll_cu_base_address_present;
    *loclists_base_address= head->ll_cu_base_address;

    *loclists_debug_addr_base_present = head->ll_cu_addr_base_present;
    *loclists_debug_addr_base  = head->ll_cu_addr_base;
    *loclists_offset_lle_set = head->ll_llearea_offset;
    return DW_DLV_OK;
}

/*  Used by dwarfdump to print raw loclists data.
    Enables printing of details about the Range List Table
    Headers, one header per call. Index starting at 0.
    Returns DW_DLV_NO_ENTRY if index is too high for the table.
    A .debug_loclists section may contain any number
    of Range List Table Headers with their details.  */
int dwarf_get_loclist_context_basics(
    Dwarf_Debug dbg,
    Dwarf_Unsigned context_index,
    Dwarf_Unsigned * header_offset,
    Dwarf_Small    * offset_size,
    Dwarf_Small    * extension_size,
    unsigned       * version, /* 5 */
    Dwarf_Small    * address_size,
    Dwarf_Small    * segment_selector_size,
    Dwarf_Unsigned * offset_entry_count,
    Dwarf_Unsigned * offset_of_offset_array,
    Dwarf_Unsigned * offset_of_first_loclistentry,
    Dwarf_Unsigned * offset_past_last_loclistentry,
    UNUSEDARG Dwarf_Error *error)
{
    Dwarf_Loclists_Context con = 0;
    if (!dbg->de_loclists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    if (context_index >= dbg->de_loclists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    con = dbg->de_loclists_context[context_index];

    if (header_offset) {
        *header_offset = con->lc_header_offset;
    }
    if (offset_size) {
        *offset_size = con->lc_offset_size;
    }
    if (offset_size) {
        *extension_size = con->lc_extension_size;
    }
    if (version) {
        *version = con->lc_version;
    }
    if (address_size) {
        *address_size = con->lc_address_size;
    }
    if (segment_selector_size) {
        *segment_selector_size = con->lc_segment_selector_size;
    }
    if (offset_entry_count) {
        *offset_entry_count = con->lc_offset_entry_count;
    }
    if (offset_of_offset_array) {
        *offset_of_offset_array = con->lc_offsets_off_in_sect;
    }
    if (offset_of_first_loclistentry) {
        *offset_of_first_loclistentry = con->lc_first_loclist_offset;
    }
    if (offset_past_last_loclistentry) {
        *offset_past_last_loclistentry =
            con->lc_past_last_loclist_offset;
    }
    return DW_DLV_OK;
}

/*  Used by dwarfdump to print raw loclists data.
    entry offset is offset_of_first_loclistentry.
    Stop when the returned *next_entry_offset
    is == offset_past_last_loclistentry (from
    dwarf_get_loclist_context_plus).
    This only makes sense within those loclists
    This retrieves raw detail from the section,
    no base values or anything are added.
    So this returns raw individual entries
    for a single loclist header, meaning a
    a single Dwarf_Loclists_Context.  */
int dwarf_get_loclist_lle(
    Dwarf_Debug dbg,
    Dwarf_Unsigned contextnumber,
    Dwarf_Unsigned entry_offset,
    Dwarf_Unsigned endoffset,
    unsigned *entrylen,
    unsigned *entry_kind,
    Dwarf_Unsigned *entry_operand1,
    Dwarf_Unsigned *entry_operand2,
    Dwarf_Unsigned *expr_ops_blocksize,
    Dwarf_Unsigned *expr_ops_offset,
    Dwarf_Small   **expr_opsdata,
    Dwarf_Error *err)
{
    Dwarf_Loclists_Context con = 0;
    Dwarf_Small *data = 0;
    Dwarf_Small *enddata = 0;
    int res = 0;
    unsigned address_size = 0;


    if (!dbg->de_loclists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    data = dbg->de_debug_loclists.dss_data +
        entry_offset;
    enddata = dbg->de_debug_loclists.dss_data +
        endoffset;
    if (contextnumber >= dbg->de_loclists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    con = dbg->de_loclists_context[contextnumber];
    address_size = con->lc_address_size;
    res = read_single_lle_entry(dbg,
        data,entry_offset,enddata,
        address_size, entrylen,
        entry_kind, entry_operand1, entry_operand2,
        expr_ops_blocksize,
        expr_ops_offset,
        expr_opsdata,
        err);
    return res;
}


static int
_dwarf_which_loclists_context(Dwarf_Debug dbg,
    Dwarf_CU_Context ctx,
    Dwarf_Unsigned loclist_offset,
    Dwarf_Unsigned *index,
    Dwarf_Error *error)
{
    Dwarf_Unsigned          count = 0;
    Dwarf_Loclists_Context *array = 0;
    Dwarf_Unsigned          i = 0;
    Dwarf_Loclists_Context  rcx = 0;
    Dwarf_Unsigned          rcxoff = 0;
    Dwarf_Unsigned          rcxend = 0;

    array = dbg->de_loclists_context;
    count = dbg->de_loclists_context_count;
    if (!array) {
        return DW_DLV_NO_ENTRY;
    }
    rcx = array[i];
    rcxoff = rcx->lc_header_offset;
    rcxend = rcxoff + rcx->lc_length;
    if (!ctx->cc_loclists_base_present) {
        /* We look at the location of each loclist context
            to find one with the offset the DIE gave us. */
        for ( i = 0 ; i < count; ++i) {
            rcx = array[i];
            rcxoff = rcx->lc_header_offset;
            rcxend = rcxoff +
                rcx->lc_length;
            rcxend = rcxoff +
                rcx->lc_length;
            if (loclist_offset < rcxoff){
                continue;
            }
            if (loclist_offset < rcxend ){
                *index = i;
                return DW_DLV_OK;
            }
        }
        {
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_LOCLISTS_ERROR: loclist ran off end "
                " finding target offset of"
                " 0x%" DW_PR_XZEROS DW_PR_DUx ,loclist_offset);
            dwarfstring_append(&m,
                " Not found anywhere in .debug_loclists "
                "data. Corrupted data?");
            _dwarf_error_string(dbg,error,
                DW_DLE_LOCLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
    } else {
        /*  We have a DW_AT_loclists_base (lc_loclists_base),
            let's use it. */
        Dwarf_Unsigned lookfor = 0;;

        lookfor = ctx->cc_loclists_base;
        for ( i = 0 ; i < count; ++i) {
            dwarfstring m;

            rcx = array[i];
            if (rcx->lc_offsets_off_in_sect == lookfor){
                *index = i;
                return DW_DLV_OK;
            }
            if (rcx->lc_offsets_off_in_sect < lookfor){
                continue;
            }

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_LOCLISTS_ERROR: loclists base of "
                " 0x%" DW_PR_XZEROS DW_PR_DUx ,lookfor);
            dwarfstring_append_printf_u(&m,
                " was not found though we are now at base "
                " 0x%" DW_PR_XZEROS DW_PR_DUx ,
                rcx->lc_offsets_off_in_sect);
            _dwarf_error_string(dbg,error,
                DW_DLE_LOCLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        {
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_LOCLISTS_ERROR: loclist base of "
                " 0x%" DW_PR_XZEROS DW_PR_DUx ,lookfor);
            dwarfstring_append(&m,
                " was not found anywhere in .debug_loclists "
                "data. Corrupted data?");
            _dwarf_error_string(dbg,error,
                DW_DLE_LOCLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
    }
    return DW_DLV_ERROR;
}
#if 0
int
dwarf_dealloc_loclists_head(Dwarf_Loc_Head_c h)
{
    Dwarf_Debug dbg = h->ll_dbg;

    dwarf_dealloc(dbg,h,DW_DLA_LOCLISTS_HEAD);
    return DW_DLV_OK;
}
#endif

/*  Caller will eventually free as appropriate. */
static int
alloc_rle_and_append_to_list(Dwarf_Debug dbg,
    Dwarf_Loc_Head_c rctx,
    Dwarf_Locdesc_c *e_out,
    Dwarf_Error *error)
{
    Dwarf_Locdesc_c e = 0;

    e = malloc(sizeof(struct Dwarf_Locdesc_c_s));
    if (!e) {
        _dwarf_error_string(dbg, error, DW_DLE_ALLOC_FAIL,
            "DW_DLE_ALLOC_FAIL: Out of memory in "
            "building list of loclists entries on a DIE.");
        return DW_DLV_ERROR;
    }
    memset(e,0,sizeof(struct Dwarf_Locdesc_c_s));
    if (rctx->ll_first) {
        rctx->ll_last->ld_next = e;
        rctx->ll_last = e;
    } else {
        rctx->ll_first = e;
        rctx->ll_last = e;
    }
    rctx->ll_locdesc_count++;
    *e_out = e;
    return DW_DLV_OK;
}

/*  Read the group of loclists entries, and
    finally build an array of Dwarf_Locdesc_c
    records. Attach to rctx here.
    Since on error the caller will destruct the rctx
    and we ensure to attach allocations there
    the caller will destruct the allocations here
    in case we return DW_DLV_ERROR*/
static int
build_array_of_lle(Dwarf_Debug dbg,
    Dwarf_Loc_Head_c rctx,
    Dwarf_Error *error)
{
    int res = 0;
    Dwarf_Small   *data         = rctx->ll_llepointer;
    Dwarf_Unsigned dataoffset   = rctx->ll_llearea_offset;
    Dwarf_Small   *enddata      = rctx->ll_end_data_area;
    unsigned int   offset_size  = rctx->ll_offset_size;
    unsigned int   address_size = rctx->ll_address_size;
    Dwarf_Unsigned bytescounttotal= 0;
    Dwarf_Unsigned latestbaseaddr = 0;
    unsigned int   foundbaseaddr  = FALSE;
    int            done           = FALSE;
    Dwarf_Unsigned locdesc_index  = 0;
    Dwarf_Unsigned i              = 0;

    if (rctx->ll_cu_base_address_present) {
        /*  The CU DIE had DW_AT_low_pc
            and it is a base address. */
        latestbaseaddr = rctx->ll_cu_base_address;
        foundbaseaddr  = TRUE;
    }
    for( ; !done  ;++locdesc_index ) {
        unsigned entrylen = 0;
        unsigned code = 0;
        Dwarf_Unsigned val1 = 0;
        Dwarf_Unsigned val2 = 0;
        Dwarf_Addr addr1= 0;
        Dwarf_Addr addr2 = 0;
        Dwarf_Locdesc_c e = 0;
        Dwarf_Unsigned opsblocksize  = 0;
        Dwarf_Unsigned opsoffset  = 0;
        Dwarf_Small *ops = 0;
        Dwarf_Block_c eops;

        memset(&eops,0,sizeof(eops));
        res = read_single_lle_entry(dbg,
            data,dataoffset, enddata,
            address_size,&entrylen,
            &code,&val1, &val2,
            &opsblocksize,&opsoffset,&ops,
            error);
        if (res != DW_DLV_OK) {
            return res;
        }
        res = alloc_rle_and_append_to_list(dbg,rctx,&e,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        eops.bl_len =opsblocksize;
        eops.bl_data = ops;
        eops.bl_kind = rctx->ll_kind;
        eops.bl_section_offset = opsoffset;
        eops.bl_locdesc_offset = dataoffset;
        e->ld_kind = rctx->ll_kind;
        e->ld_lle_value = code,
        e->ld_entrylen = entrylen;
        e->ld_rawlow = val1;
        e->ld_rawhigh = val2;
        e->ld_opsblock = eops;
        bytescounttotal += entrylen;
        data += entrylen;
        if (code == DW_LLE_end_of_list) {
            done = TRUE;
            break;
        }
        /*  Here we create the cooked values from
            the raw values and other data. */
        switch(code) {
        case DW_LLE_base_addressx:
            foundbaseaddr = TRUE;
            res = _dwarf_extract_address_from_debug_addr(
                dbg,rctx->ll_context,val1,
                &addr1,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            e->ld_lopc = addr1;
            latestbaseaddr = addr1;
            break;
        case DW_LLE_startx_endx:
            res = _dwarf_extract_address_from_debug_addr(
                dbg,rctx->ll_context,val1,
                &addr1,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            res = _dwarf_extract_address_from_debug_addr(
                dbg,rctx->ll_context,val2,
                &addr2,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            e->ld_lopc = addr1;
            e->ld_highpc = addr2;
            break;
        case DW_LLE_startx_length:
            res = _dwarf_extract_address_from_debug_addr(
                dbg,rctx->ll_context,val1,
                &addr1,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            e->ld_lopc = addr1;
            e->ld_highpc = val2+addr1;
            break;
        case DW_LLE_offset_pair:
            if(foundbaseaddr) {
                e->ld_lopc = val1+latestbaseaddr;
                e->ld_highpc = val2+latestbaseaddr;
            } else {
                e->ld_lopc = val1+rctx->ll_cu_base_address;
                e->ld_highpc = val2+rctx->ll_cu_base_address;
            }
            break;
        case DW_LLE_base_address:
            foundbaseaddr = TRUE;
            latestbaseaddr = val1;
            e->ld_lopc = val1;
            break;
        case DW_LLE_start_end:
            e->ld_lopc = val1;
            e->ld_highpc = val2;
            break;
        case DW_LLE_start_length:
            e->ld_lopc = val1;
            e->ld_highpc = val2+val1;
            break;
        default: {
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                " DW_DLE_LOCLISTS_ERROR: "
                " The .debug_loclists "
                " loclist code 0x%x is unknown, "
                " DWARF5 is corrupted.",code);
            _dwarf_error_string(dbg, error,
                DW_DLE_LOCLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        }
    }
    if (rctx->ll_locdesc_count > 0) {
        Dwarf_Locdesc_c array = 0;
        Dwarf_Locdesc_c cur = 0;
        Dwarf_Locdesc_c prev = 0;

        /* array of structs. */
        array = (Dwarf_Locdesc_c)_dwarf_get_alloc(dbg,
            DW_DLA_LOCDESC_C, rctx->ll_locdesc_count);
        if (!array) {
            _dwarf_error_string(dbg, error, DW_DLE_ALLOC_FAIL,
                "DW_DLE_ALLOC_FAIL: Out of memory in "
                "copying list of locdescs into array ");
            return DW_DLV_ERROR;
        }
        rctx->ll_locdesc = array;
        cur = rctx->ll_first;
        for (i = 0  ; i < rctx->ll_locdesc_count; ++i) {
            prev = cur;
            array[i] = *cur;
            cur = cur->ld_next;
            free(prev);
        }
        rctx->ll_first = 0;
        rctx->ll_last = 0;
    }
    for (i = 0; i < rctx->ll_locdesc_count; ++i) {
        Dwarf_Locdesc_c ldc = rctx->ll_locdesc + i;

        res = _dwarf_fill_in_locdesc_op_c(dbg,
            i,
            rctx,
            &ldc->ld_opsblock,
            address_size, offset_size,
            rctx->ll_cuversion,
            ldc->ld_lopc, ldc->ld_highpc,
            ldc->ld_lle_value,
            error);
        if (res != DW_DLV_OK) {
            return res;
        }
    }
    rctx->ll_bytes_total = bytescounttotal;
    return DW_DLV_OK;
}

/*  Build a head with all the relevent Entries
    attached, all the locdescs and for each such,
    all its expression operators.
*/
int
_dwarf_loclists_fill_in_lle_head(Dwarf_Debug dbg,
    Dwarf_Attribute attr,
    Dwarf_Loc_Head_c llhead,
    Dwarf_Error         *error)
{
    int res = 0;
    Dwarf_Unsigned loclists_contextnum = 0;
    Dwarf_Small *table_base = 0;
    Dwarf_Small *table_entry = 0;
    Dwarf_Small *enddata = 0;
    Dwarf_Loclists_Context *array = 0;
    Dwarf_Loclists_Context rctx = 0;
    Dwarf_Unsigned entrycount = 0;
    unsigned offsetsize = 0;
    Dwarf_Unsigned lle_global_offset = 0;
    Dwarf_CU_Context ctx = 0;
    Dwarf_Unsigned offset_in_loclists = 0;
    Dwarf_Bool is_loclistx = FALSE;
    int theform = llhead->ll_attrform;
    Dwarf_Unsigned attr_val = 0;

    ctx = attr->ar_cu_context;
    array = dbg->de_loclists_context;
    if ( theform == DW_FORM_sec_offset) {
        /*  DW_FORM_sec_offset is not formudata , often
            seen in in DW5 DW_AT_location etc */
        res = dwarf_global_formref(attr, &attr_val,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        offset_in_loclists = attr_val;
    } else {
        if (theform == DW_FORM_loclistx) {
            is_loclistx = TRUE;
        }
        res = dwarf_formudata(attr,&attr_val,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        /*  the context cc_loclists_base gives the offset
            of the array. of offsets (if cc_loclists_base_present) */
                offset_in_loclists = attr_val;
        if (is_loclistx) {
            if (ctx->cc_loclists_base_present) {
                offset_in_loclists = ctx->cc_loclists_base;
            } else {
                /* FIXME: check in tied file for a cc_loclists_base */
                dwarfstring m;

                dwarfstring_constructor(&m);
                dwarfstring_append_printf_u(&m,
                    "DW_DLE_LOCLISTS_ERROR: loclists table index of"
                    " %u"  ,attr_val);
                dwarfstring_append(&m,
                    " is unusable unless it is in a tied file."
                    " libdwarf is incomplete. FIXME");
                _dwarf_error_string(dbg,error,DW_DLE_LOCLISTS_ERROR,
                    dwarfstring_string(&m));
                dwarfstring_destructor(&m);
                return DW_DLV_ERROR;
            }
        } else {
            offset_in_loclists = attr_val;
        }
    }
    res = _dwarf_which_loclists_context(dbg,ctx,
        offset_in_loclists,
        &loclists_contextnum,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    rctx = array[loclists_contextnum];
    table_base = rctx->lc_offsets_array;
    entrycount = rctx->lc_offset_entry_count;
    offsetsize = rctx->lc_offset_size;
    enddata = rctx->lc_endaddr;

    if (is_loclistx && attr_val >= entrycount) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_LOCLISTS_ERROR: loclists table index of"
            " %u"  ,attr_val);
        dwarfstring_append_printf_u(&m,
            " too large for table of %u "
            "entries.",entrycount);
        _dwarf_error_string(dbg,error,
            DW_DLE_LOCLISTS_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    llhead->ll_localcontext = rctx;
    llhead->ll_index = loclists_contextnum;
    llhead->ll_cuversion = rctx->lc_version;
    llhead->ll_offset_size = offsetsize;
    llhead->ll_address_size  = rctx->lc_address_size;
    llhead->ll_segment_selector_size =
        rctx->lc_segment_selector_size;

    if (is_loclistx) {
        Dwarf_Unsigned table_entryval = 0;

        table_entry = attr_val*offsetsize + table_base;
        /*  No malloc here yet so no leak if the macro returns
            DW_DLV_ERROR */
        READ_UNALIGNED_CK(dbg,table_entryval, Dwarf_Unsigned,
            table_entry,offsetsize,error,enddata);
        lle_global_offset = rctx->lc_offsets_off_in_sect +
            table_entryval;
    } else {
        lle_global_offset = attr_val;
    }

    llhead->ll_llepointer = rctx->lc_offsets_array +
        rctx->lc_offset_entry_count*offsetsize;
    llhead->ll_end_data_area = enddata;

    llhead->ll_llearea_offset = lle_global_offset;
    llhead->ll_llepointer = lle_global_offset +
        dbg->de_debug_loclists.dss_data;

    res = build_array_of_lle(dbg,llhead,error);
    if (res != DW_DLV_OK) {
        dwarf_dealloc(dbg,llhead,DW_DLA_LOCLISTS_HEAD);
        return res;
    }
    return DW_DLV_OK;
}


int
dwarf_get_loclists_entry_fields(
    Dwarf_Loc_Head_c head,
    Dwarf_Unsigned entrynum,
    unsigned *entrylen,
    unsigned *code,
    Dwarf_Unsigned *raw1,
    Dwarf_Unsigned *raw2,
    Dwarf_Unsigned *cooked1,
    Dwarf_Unsigned *cooked2,
    /*  FIXME not right for loclists or their loc exprs */
    UNUSEDARG Dwarf_Error *err)
{
    Dwarf_Locdesc_c e = 0;

    if (entrynum >= head->ll_locdesc_count) {
        return DW_DLV_NO_ENTRY;
    }
    e = head->ll_locdesc + entrynum;
    *entrylen  = e->ld_entrylen;
    *code      = e->ld_lle_value;
    *raw1      = e->ld_rawlow;
    *raw2      = e->ld_rawhigh;
    *cooked1   = e->ld_lopc;
    *cooked2   = e->ld_highpc;
    return DW_DLV_OK;
}

/*  Deals with both fully and partially build head */
void
_dwarf_free_loclists_head(Dwarf_Loc_Head_c head)
{
    Dwarf_Debug dbg = head->ll_dbg;

    if (head->ll_first) {
        /* partially built head. */
        /*  ASSERT: ll_loclists is NULL */
        Dwarf_Locdesc_c cur = head->ll_first;
        Dwarf_Locdesc_c next = 0;

        for ( ; cur ; cur = next) {
            next = cur->ld_next;
            free(cur);
        }
        head->ll_first = 0;
        head->ll_last = 0;
        head->ll_locdesc_count = 0;
    } else {
        Dwarf_Locdesc_c desc = head->ll_locdesc;
        /*  ASSERT: ll_first and ll_last are NULL */
        /* fully built head. */
        Dwarf_Unsigned listlen = head->ll_locdesc_count;
        Dwarf_Unsigned i = 0;
        for ( ; i < listlen; ++i) {
            Dwarf_Loc_Expr_Op loc = desc[i].ld_s;
            if(loc) {
                dwarf_dealloc(dbg,loc,DW_DLA_LOC_BLOCK_C);
            }
        }
        dwarf_dealloc(dbg,head->ll_locdesc,DW_DLA_LOCDESC_C);
        head->ll_locdesc = 0;
        head->ll_locdesc_count = 0;
    }
}

void
_dwarf_loclists_head_destructor(void *head)
{
    Dwarf_Loc_Head_c h = head;

    _dwarf_free_loclists_head(h);
}
