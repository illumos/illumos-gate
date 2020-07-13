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
#include "dwarf_rnglists.h"

#define SIZEOFT8 1
#define SIZEOFT16 2
#define SIZEOFT32 4
#define SIZEOFT64 8
#define TRUE 1
#define FALSE 0


/*  Used in case of error reading the
    rnglists headers (not referring to Dwarf_Rnglists_Head
    here), to clean up. */
static void
free_rnglists_chain(Dwarf_Debug dbg, Dwarf_Chain head)
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
read_single_rle_entry(Dwarf_Debug dbg,
    Dwarf_Small   *data,
    Dwarf_Unsigned dataoffset,
    Dwarf_Small   *enddata,
    unsigned       address_size,
    unsigned       *bytes_count_out,
    unsigned       *entry_kind,
    Dwarf_Unsigned *entry_operand1,
    Dwarf_Unsigned *entry_operand2,
    Dwarf_Error* err)
{
    Dwarf_Unsigned count = 0;
    unsigned leblen = 0;
    unsigned code = 0;
    Dwarf_Unsigned val1 = 0;
    Dwarf_Unsigned val2 = 0;

    code = *data;
    ++data;
    ++count;
    switch(code) {
    case DW_RLE_end_of_list: break;
    case DW_RLE_base_addressx:{
        DECODE_LEB128_UWORD_LEN_CK(data,val1,leblen,
            dbg,err,enddata);
        count += leblen;
        }
        break;
    case DW_RLE_startx_endx:
    case DW_RLE_startx_length:
    case DW_RLE_offset_pair: {
        DECODE_LEB128_UWORD_LEN_CK(data,val1,leblen,
            dbg,err,enddata);
        count += leblen;
        DECODE_LEB128_UWORD_LEN_CK(data,val2,leblen,
            dbg,err,enddata);
        count += leblen;
        }
        break;
    case DW_RLE_base_address: {
        READ_UNALIGNED_CK(dbg,val1, Dwarf_Unsigned,
            data,address_size,err,enddata);
        data += address_size;
        count += address_size;
        }
        break;
    case DW_RLE_start_end: {
        READ_UNALIGNED_CK(dbg,val1, Dwarf_Unsigned,
            data,address_size,err,enddata);
        data += address_size;
        count += address_size;
        READ_UNALIGNED_CK(dbg,val2, Dwarf_Unsigned,
            data,address_size,err,enddata);
        data += address_size;
        count += address_size;
        }
        break;
    case DW_RLE_start_length: {
        READ_UNALIGNED_CK(dbg,val1, Dwarf_Unsigned,
            data,address_size,err,enddata);
        data += address_size;
        count += address_size;
        DECODE_LEB128_UWORD_LEN_CK(data,val2,leblen,
            dbg,err,enddata);
        count += leblen;
        }
        break;
    default: {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_RNGLISTS_ERROR: "
            "The rangelists entry at .debug_rnglists"
            " offset 0x%x" ,dataoffset);
        dwarfstring_append_printf_u(&m,
            " has code 0x%x which is unknown",code);
        _dwarf_error_string(dbg,err,DW_DLE_RNGLISTS_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
        }
        break;
    }
    *bytes_count_out = count;
    *entry_kind = code;
    *entry_operand1 = val1;
    *entry_operand2 = val2;
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
    Dwarf_Rnglists_Context  buildhere,
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
            "DW_DLE_SECTION_SIZE_ERROR: A .debug_rnglists "
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

    buildhere->rc_length = arealen +length_size+exten_size;
    buildhere->rc_dbg = dbg;
    buildhere->rc_index = contextnum;
    buildhere->rc_header_offset = offset;
    buildhere->rc_offset_size = length_size;
    buildhere->rc_extension_size = exten_size;
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
    buildhere->rc_version = version;
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
    buildhere->rc_address_size = address_size;
    data++;

    READ_UNALIGNED_CK(dbg,segment_selector_size,unsigned,data,
        SIZEOFT8,error,end_data);
    buildhere->rc_segment_selector_size = segment_selector_size;
    data++;

    READ_UNALIGNED_CK(dbg,offset_entry_count,Dwarf_Unsigned,data,
        SIZEOFT32,error,end_data);
    buildhere->rc_offset_entry_count = offset_entry_count;
    data += SIZEOFT32;
    if (offset_entry_count ){
        buildhere->rc_offsets_array = data;
    }
    localoff = data - startdata;
    lists_len = address_size *offset_entry_count;

    data += lists_len;

    buildhere->rc_offsets_off_in_sect = offset+localoff;
    buildhere->rc_first_rnglist_offset = offset+localoff+
        lists_len;
    buildhere->rc_rnglists_header = startdata;
    buildhere->rc_endaddr = startdata +buildhere->rc_length;
    buildhere->rc_past_last_rnglist_offset =
        buildhere->rc_header_offset +buildhere->rc_length;
    *next_offset =  buildhere->rc_past_last_rnglist_offset;
    return DW_DLV_OK;
}


/*  We return a pointer to an array of contexts
    (not context pointers through *cxt if
    we succeed and are returning DW_DLV_OK.
    We never return DW_DLV_NO_ENTRY here. */
static int
internal_load_rnglists_contexts(Dwarf_Debug dbg,
    Dwarf_Rnglists_Context **cxt,
    Dwarf_Unsigned *count,
    Dwarf_Error *error)
{
    Dwarf_Unsigned offset = 0;
    Dwarf_Unsigned nextoffset = 0;
    Dwarf_Small  * data = dbg->de_debug_rnglists.dss_data;
    Dwarf_Unsigned section_size = dbg->de_debug_rnglists.dss_size;
    Dwarf_Small  * startdata = data;
    Dwarf_Small  * end_data = data +section_size;
    Dwarf_Chain curr_chain = 0;
    Dwarf_Chain prev_chain = 0;
    Dwarf_Chain head_chain = 0;
    int res = 0;
    Dwarf_Unsigned chainlength = 0;
    Dwarf_Rnglists_Context *fullarray = 0;
    Dwarf_Unsigned i = 0;

    for( ; data < end_data ; ) {
        Dwarf_Rnglists_Context newcontext = 0;

        /* sizeof the context struct, not sizeof a pointer */
        newcontext = malloc(sizeof(*newcontext));
        if (!newcontext) {
            free_rnglists_chain(dbg,head_chain);
            _dwarf_error_string(dbg,error,
                DW_DLE_ALLOC_FAIL,
                "DW_DLE_ALLOC_FAIL: Allocation of "
                "Rnglists_Context failed");
            return DW_DLV_ERROR;
        }
        memset(newcontext,0,sizeof(*newcontext));
        res = internal_read_header(dbg,chainlength,
            section_size,
            data,end_data,offset,
            newcontext,&nextoffset,error);
        if (res == DW_DLV_ERROR) {
            free(newcontext);
            free_rnglists_chain(dbg,head_chain);
        }
        curr_chain = (Dwarf_Chain)
            _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
        if (curr_chain == NULL) {
            free_rnglists_chain(dbg,head_chain);
            _dwarf_error_string(dbg, error, DW_DLE_ALLOC_FAIL,
                "DW_DLE_ALLOC_FAIL: allocating Rnglists_Context"
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
    fullarray= (Dwarf_Rnglists_Context *)malloc(
        chainlength *sizeof(Dwarf_Rnglists_Context /*pointer*/));
    if (!fullarray) {
        free_rnglists_chain(dbg,head_chain);
        _dwarf_error_string(dbg,error,
            DW_DLE_ALLOC_FAIL,"Allocation of "
            "Rnglists_Context pointer array failed");
        return DW_DLV_ERROR;
    }
    curr_chain = head_chain;
    for( i = 0; i < chainlength; ++i) {
        fullarray[i] = (Dwarf_Rnglists_Context)curr_chain->ch_item;
        curr_chain->ch_item = 0;
        prev_chain = curr_chain;
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN);
    }
    /*  ASSERT: the chain is entirely dealloc'd
        and the array of pointers points to
        individually malloc'd Dwarf_Rnglists_Context_s */
    *cxt = fullarray;
    *count = chainlength;
    return DW_DLV_OK;
}



/*  Used by dwarfdump to print raw rnglists data.
    Loads all the .debug_rnglists[.dwo]  headers and
    returns DW_DLV_NO_ENTRY if the section
    is missing or empty.
    Intended to be done quite early and
    done exactly once.
    Harmless to do more than once.
    With DW_DLV_OK it returns the number of
    rnglists headers in the section through
    rnglists_count. */
int dwarf_load_rnglists(
    Dwarf_Debug dbg,
    Dwarf_Unsigned *rnglists_count,
    UNUSEDARG Dwarf_Error *error)
{
    int res = DW_DLV_ERROR;
    Dwarf_Rnglists_Context *cxt = 0;
    Dwarf_Unsigned count = 0;

    if (dbg->de_rnglists_context) {
        if (rnglists_count) {
            *rnglists_count = dbg->de_rnglists_context_count;
        }
    }
    if (!dbg->de_debug_rnglists.dss_size) {
        /* nothing there. */
        return DW_DLV_NO_ENTRY;
    }
    if (!dbg->de_debug_rnglists.dss_data) {
        res = _dwarf_load_section(dbg, &dbg->de_debug_rnglists,
            error);
        if (res != DW_DLV_OK) {
            return res;
        }
    }
    res = internal_load_rnglists_contexts(dbg,&cxt,&count,error);
    if (res == DW_DLV_ERROR) {
        return res;
    }
    dbg->de_rnglists_context = cxt;
    dbg->de_rnglists_context_count = count;
    if (rnglists_count) {
        *rnglists_count = count;
    }
    return DW_DLV_OK;
}

/*  Frees the memory in use in all rnglists contexts.
    Done by dwarf_finish()  */
void
_dwarf_dealloc_rnglists_context(Dwarf_Debug dbg)
{
    Dwarf_Unsigned i = 0;
    Dwarf_Rnglists_Context * rngcon = 0;

    if (!dbg->de_rnglists_context) {
        return;
    }
    rngcon = dbg->de_rnglists_context;
    for( ; i < dbg->de_rnglists_context_count; ++i,++rngcon) {
        Dwarf_Rnglists_Context con = *rngcon;
        con->rc_offsets_array = 0;
        con->rc_offset_entry_count = 0;
        free(con);
    }
    free(dbg->de_rnglists_context);
    dbg->de_rnglists_context = 0;
    dbg->de_rnglists_context_count = 0;
}

/*  Used by dwarfdump to print raw rnglists data. */
int
dwarf_get_rnglist_offset_index_value(
    Dwarf_Debug dbg,
    Dwarf_Unsigned context_index,
    Dwarf_Unsigned offsetentry_index,
    Dwarf_Unsigned * offset_value_out,
    Dwarf_Unsigned * global_offset_value_out,
    Dwarf_Error *error)
{
    Dwarf_Rnglists_Context con = 0;
    unsigned offset_len = 0;
    Dwarf_Small *offsetptr = 0;
    Dwarf_Unsigned targetoffset = 0;

    if (!dbg->de_rnglists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    if (context_index >= dbg->de_rnglists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    con = dbg->de_rnglists_context[context_index];

    if (offsetentry_index >= con->rc_offset_entry_count) {
        return DW_DLV_NO_ENTRY;
    }
    offset_len = con->rc_offset_size;
    offsetptr = con->rc_offsets_array +
        (offsetentry_index*offset_len);
    READ_UNALIGNED_CK(dbg,targetoffset,Dwarf_Unsigned,
        offsetptr,
        offset_len,error,con->rc_endaddr);
    if (offset_value_out) {
        *offset_value_out = targetoffset;
    }
    if (global_offset_value_out) {
        *global_offset_value_out = targetoffset +
            con->rc_offsets_off_in_sect;
    }
    return DW_DLV_OK;
}

/*  Used by dwarfdump to print basic data from the
    data generated to look at a specific rangelist
    as returned by  dwarf_rnglists_index_get_rle_head()
    or dwarf_rnglists_offset_get_rle_head. */
int dwarf_get_rnglist_head_basics(
    Dwarf_Rnglists_Head head,
    Dwarf_Unsigned * rle_count,
    Dwarf_Unsigned * rle_version,
    Dwarf_Unsigned * rnglists_index_returned,
    Dwarf_Unsigned * bytes_total_in_rle,
    Dwarf_Half     * offset_size,
    Dwarf_Half     * address_size,
    Dwarf_Half     * segment_selector_size,
    Dwarf_Unsigned * overall_offset_of_this_context,
    Dwarf_Unsigned * total_length_of_this_context,
    Dwarf_Unsigned * offset_table_offset,
    Dwarf_Unsigned * offset_table_entrycount,
    Dwarf_Bool     * rnglists_base_present,
    Dwarf_Unsigned * rnglists_base,
    Dwarf_Bool     * rnglists_base_address_present,
    Dwarf_Unsigned * rnglists_base_address,
    Dwarf_Bool     * rnglists_debug_addr_base_present,
    Dwarf_Unsigned * rnglists_debug_addr_base,
    UNUSEDARG Dwarf_Error *error)
{
    Dwarf_Rnglists_Context rngcontext = 0;
    *rle_count = head->rh_count;
    *rle_version = head->rh_version;
    *rnglists_index_returned = head->rh_index;
    *bytes_total_in_rle = head->rh_bytes_total;
    *offset_size = head->rh_offset_size;
    *address_size = head->rh_address_size;
    *segment_selector_size = head->rh_segment_selector_size;
    rngcontext = head->rh_localcontext;
    if (rngcontext) {
        *overall_offset_of_this_context = rngcontext->rc_header_offset;
        *total_length_of_this_context = rngcontext->rc_length;
        *offset_table_offset = rngcontext->rc_offsets_off_in_sect;
        *offset_table_entrycount = rngcontext->rc_offset_entry_count;
    }
    *rnglists_base_present = head->rh_at_rnglists_base_present;
    *rnglists_base= head->rh_at_rnglists_base;

    *rnglists_base_address_present = head->rh_cu_base_address_present;
    *rnglists_base_address= head->rh_cu_base_address;

    *rnglists_debug_addr_base_present = head->rh_cu_addr_base_present;
    *rnglists_debug_addr_base  = head->rh_cu_addr_base;
    return DW_DLV_OK;
}

/*  Used by dwarfdump to print raw rnglists data.
    Enables printing of details about the Range List Table
    Headers, one header per call. Index starting at 0.
    Returns DW_DLV_NO_ENTRY if index is too high for the table.
    A .debug_rnglists section may contain any number
    of Range List Table Headers with their details.  */
int dwarf_get_rnglist_context_basics(
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
    Dwarf_Unsigned * offset_of_first_rangeentry,
    Dwarf_Unsigned * offset_past_last_rangeentry,
    UNUSEDARG Dwarf_Error *error)
{
    Dwarf_Rnglists_Context con = 0;
    if (!dbg->de_rnglists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    if (context_index >= dbg->de_rnglists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    con = dbg->de_rnglists_context[context_index];

    if (header_offset) {
        *header_offset = con->rc_header_offset;
    }
    if (offset_size) {
        *offset_size = con->rc_offset_size;
    }
    if (offset_size) {
        *extension_size = con->rc_extension_size;
    }
    if (version) {
        *version = con->rc_version;
    }
    if (address_size) {
        *address_size = con->rc_address_size;
    }
    if (segment_selector_size) {
        *segment_selector_size = con->rc_segment_selector_size;
    }
    if (offset_entry_count) {
        *offset_entry_count = con->rc_offset_entry_count;
    }
    if (offset_of_offset_array) {
        *offset_of_offset_array = con->rc_offsets_off_in_sect;
    }
    if (offset_of_first_rangeentry) {
        *offset_of_first_rangeentry = con->rc_first_rnglist_offset;
    }
    if (offset_past_last_rangeentry) {
        *offset_past_last_rangeentry =
            con->rc_past_last_rnglist_offset;
    }
    return DW_DLV_OK;
}

/*  Used by dwarfdump to print raw rnglists data.
    entry offset is offset_of_first_rangeentry.
    Stop when the returned *next_entry_offset
    is == offset_past_last_rangentry (from
    dwarf_get_rnglist_context_plus).
    This only makes sense within those ranges.
    This retrieves raw detail from the section,
    no base values or anything are added.
    So this returns raw individual entries
    for a single rnglist header, meaning a
    a single Dwarf_Rnglists_Context.  */
int dwarf_get_rnglist_rle(
    Dwarf_Debug dbg,
    Dwarf_Unsigned contextnumber,
    Dwarf_Unsigned entry_offset,
    Dwarf_Unsigned endoffset,
    unsigned *entrylen,
    unsigned *entry_kind,
    Dwarf_Unsigned *entry_operand1,
    Dwarf_Unsigned *entry_operand2,
    Dwarf_Error *err)
{
    Dwarf_Rnglists_Context con = 0;
    Dwarf_Small *data = 0;
    Dwarf_Small *enddata = 0;
    int res = 0;
    unsigned address_size = 0;

    if (!dbg->de_rnglists_context_count) {
        return DW_DLV_NO_ENTRY;
    }
    data = dbg->de_debug_rnglists.dss_data +
        entry_offset;
    enddata = dbg->de_debug_rnglists.dss_data +
        endoffset;
    if (contextnumber >= dbg->de_rnglists_context_count) {
        return DW_DLV_NO_ENTRY;
    }

    con = dbg->de_rnglists_context[contextnumber];
    address_size = con->rc_address_size;

    res = read_single_rle_entry(dbg,
        data,entry_offset,enddata,
        address_size,entrylen,
        entry_kind, entry_operand1, entry_operand2,
        err);
    return res;
}


static int
_dwarf_which_rnglists_context(Dwarf_Debug dbg,
    Dwarf_CU_Context ctx,
    Dwarf_Unsigned rnglist_offset,
    Dwarf_Unsigned *index,
    Dwarf_Error *error)
{
    Dwarf_Unsigned count;
    Dwarf_Rnglists_Context *array;
    Dwarf_Unsigned i = 0;

    array = dbg->de_rnglists_context;
    count = dbg->de_rnglists_context_count;
    /*  Using the slow way, a simple linear search. */
    if (!ctx->cc_rnglists_base_present) {
        /* We look at the location of each rnglist context
            to find one with the offset the DIE gave us. */
        for ( i = 0 ; i < count; ++i) {
            Dwarf_Rnglists_Context rcx = array[i];
            Dwarf_Unsigned rcxoff = rcx->rc_header_offset;
            Dwarf_Unsigned rcxend = rcxoff +
                rcx->rc_length;

            if (rnglist_offset < rcxoff){
                continue;
            }
            if (rnglist_offset < rcxend ){
                *index = i;
                return DW_DLV_OK;
            }
        }
        {
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_RNGLISTS_ERROR: rnglist ran off end "
                " finding target offset of"
                " 0x%" DW_PR_XZEROS DW_PR_DUx ,rnglist_offset);
            dwarfstring_append(&m,
                " Not found anywhere in .debug_rnglists "
                "data. Corrupted data?");
            _dwarf_error_string(dbg,error,
                DW_DLE_RNGLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
    } else {
        /*  We have a DW_AT_rnglists_base (cc_rangelists_base),
            let's use it. */
        Dwarf_Unsigned lookfor = 0;;

        lookfor = ctx->cc_rnglists_base;
        for ( i = 0 ; i < count; ++i) {
            dwarfstring m;

            Dwarf_Rnglists_Context rcx = array[i];
            if (rcx->rc_offsets_off_in_sect == lookfor){
                *index = i;
                return DW_DLV_OK;
            }
            if (rcx->rc_offsets_off_in_sect < lookfor){
                continue;
            }

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_RNGLISTS_ERROR: rnglists base of "
                " 0x%" DW_PR_XZEROS DW_PR_DUx ,lookfor);
            dwarfstring_append_printf_u(&m,
                " was not found though we are now at base "
                " 0x%" DW_PR_XZEROS DW_PR_DUx ,
                rcx->rc_offsets_off_in_sect);
            _dwarf_error_string(dbg,error,
                DW_DLE_RNGLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        {
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_RNGLISTS_ERROR: rnglist base of "
                " 0x%" DW_PR_XZEROS DW_PR_DUx ,lookfor);
            dwarfstring_append(&m,
                " was not found anywhere in .debug_rnglists "
                "data. Corrupted data?");
            _dwarf_error_string(dbg,error,
                DW_DLE_RNGLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
    }
    return DW_DLV_ERROR;
}

int
dwarf_dealloc_rnglists_head(Dwarf_Rnglists_Head h)
{
    Dwarf_Debug dbg = h->rh_dbg;

    dwarf_dealloc(dbg,h,DW_DLA_RNGLISTS_HEAD);
    return DW_DLV_OK;
}

/*  Caller will eventually free as appropriate. */
static int
alloc_rle_and_append_to_list(Dwarf_Debug dbg,
    Dwarf_Rnglists_Head rctx,
    Dwarf_Rnglists_Entry *e_out,
    Dwarf_Error *error)
{
    Dwarf_Rnglists_Entry e = 0;

    e = malloc(sizeof(struct Dwarf_Rnglists_Entry_s));
    if (!e) {
        _dwarf_error_string(dbg, error, DW_DLE_ALLOC_FAIL,
            "DW_DLE_ALLOC_FAIL: Out of memory in "
            "building list of rnglists entries on a DIE.");
        return DW_DLV_ERROR;
    }
    memset(e,0,sizeof(struct Dwarf_Rnglists_Entry_s));
    if (rctx->rh_first) {
        rctx->rh_last->rle_next = e;
        rctx->rh_last = e;
    } else {
        rctx->rh_first = e;
        rctx->rh_last = e;
    }
    rctx->rh_count++;
    *e_out = e;
    return DW_DLV_OK;
}

/*  Read the group of rangelists entries, and
    finally build an array of Dwarf_Rnglists_Entry
    records. Attach to rctx here.
    Since on error the caller will destruct the rctx
    and we ensure to attach allocations there
    the caller will destruct the allocations here
    in case we return DW_DLV_ERROR*/
static int
build_array_of_rle(Dwarf_Debug dbg,
    Dwarf_Rnglists_Head rctx,
    Dwarf_Error *error)
{
    int res = 0;
    Dwarf_Small * data        = rctx->rh_rlepointer;
    Dwarf_Unsigned dataoffset = rctx->rh_rlearea_offset;
    Dwarf_Small *enddata      = rctx->rh_end_data_area;
    unsigned address_size     = rctx->rh_address_size;
    Dwarf_Unsigned bytescounttotal= 0;
    Dwarf_Unsigned latestbaseaddr = 0;
    unsigned foundbaseaddr        = FALSE;
    int done = FALSE;

    if (rctx->rh_cu_base_address_present) {
        /*  The CU DIE had DW_AT_low_pc
            and it is a base address. */
        latestbaseaddr = rctx->rh_cu_base_address;
        foundbaseaddr  = TRUE;
    }
    for( ; !done  ; ) {
        unsigned entrylen = 0;
        unsigned code = 0;
        Dwarf_Unsigned val1 = 0;
        Dwarf_Unsigned val2 = 0;
        Dwarf_Addr addr1= 0;
        Dwarf_Addr addr2 = 0;
        Dwarf_Rnglists_Entry e = 0;

        res = read_single_rle_entry(dbg,
            data,dataoffset, enddata,
            address_size,&entrylen,
            &code,&val1, &val2,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        res = alloc_rle_and_append_to_list(dbg,rctx,&e,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        e->rle_code = code,
        e->rle_entrylen = entrylen;
        e->rle_raw1 = val1;
        e->rle_raw2 = val2;
        bytescounttotal += entrylen;
        data += entrylen;
        if (code == DW_RLE_end_of_list) {
            done = TRUE;
            break;
        }
        switch(code) {
        case DW_RLE_base_addressx:
            foundbaseaddr = TRUE;
            res = _dwarf_extract_address_from_debug_addr(
                dbg,rctx->rh_context,val1,
                &addr1,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            e->rle_cooked1 = addr1;
            latestbaseaddr = addr1;
            break;
        case DW_RLE_startx_endx:
            res = _dwarf_extract_address_from_debug_addr(
                dbg,rctx->rh_context,val1,
                &addr1,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            res = _dwarf_extract_address_from_debug_addr(
                dbg,rctx->rh_context,val2,
                &addr2,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            e->rle_cooked1 = addr1;
            e->rle_cooked2 = addr2;
            break;
        case DW_RLE_startx_length:
            res = _dwarf_extract_address_from_debug_addr(
                dbg,rctx->rh_context,val1,
                &addr1,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            e->rle_cooked1 = addr1;
            e->rle_cooked2 = val2+addr1;
            break;
        case DW_RLE_offset_pair:
            if(foundbaseaddr) {
                e->rle_cooked1 = val1+latestbaseaddr;
                e->rle_cooked2 = val2+latestbaseaddr;
            } else {
                e->rle_cooked1 = val1+rctx->rh_cu_base_address;
                e->rle_cooked2 = val2+rctx->rh_cu_base_address;
            }
            break;
        case DW_RLE_base_address:
            foundbaseaddr = TRUE;
            latestbaseaddr = val1;
            e->rle_cooked1 = val1;
            break;
        case DW_RLE_start_end:
            e->rle_cooked1 = val1;
            e->rle_cooked2 = val2;
            break;
        case DW_RLE_start_length:
            e->rle_cooked1 = val1;
            e->rle_cooked2 = val2+val1;
            break;
        default: {
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                " DW_DLE_RNGLISTS_ERROR: "
                " The .debug_rnglists "
                " rangelist code 0x%x is unknown, "
                " DWARF5 is corrupted.",code);
            _dwarf_error_string(dbg, error,
                DW_DLE_RNGLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        }
    }
    if (rctx->rh_count > 0) {
        Dwarf_Rnglists_Entry* array = 0;
        Dwarf_Rnglists_Entry cur = 0;
        Dwarf_Unsigned i = 0;

        /*  Creating an array of pointers. */
        array = (Dwarf_Rnglists_Entry*)malloc(
            rctx->rh_count *sizeof(Dwarf_Rnglists_Entry));
        if (!array) {
            _dwarf_error_string(dbg, error, DW_DLE_ALLOC_FAIL,
                "DW_DLE_ALLOC_FAIL: Out of memory in "
                "turning list of rnglists entries on a DIE"
                "into a pointer array");
            return DW_DLV_ERROR;
        }
        cur = rctx->rh_first;
        for (  ; i < rctx->rh_count; ++i) {
            array[i] = cur;
            cur = cur->rle_next;
        }
        rctx->rh_rnglists = array;
        rctx->rh_first = 0;
        rctx->rh_last = 0;
    }
    rctx->rh_bytes_total = bytescounttotal;
    return DW_DLV_OK;
}

/*  Build a head with all the relevent Entries
    attached.
*/
int
dwarf_rnglists_get_rle_head(
    Dwarf_Attribute attr,
    Dwarf_Half     theform,
    Dwarf_Unsigned attr_val,
    Dwarf_Rnglists_Head *head_out,
    Dwarf_Unsigned      *entries_count_out,
    Dwarf_Unsigned      *global_offset_of_rle_set,
    Dwarf_Error         *error)
{
    int res = 0;
    Dwarf_Unsigned rnglists_contextnum = 0;
    Dwarf_Small *table_base = 0;
    Dwarf_Small *table_entry = 0;
    Dwarf_Small *enddata = 0;
    Dwarf_Rnglists_Context *array = 0;
    Dwarf_Rnglists_Context rctx = 0;
    Dwarf_Unsigned entrycount = 0;
    unsigned offsetsize = 0;
    Dwarf_Unsigned rle_global_offset = 0;
    Dwarf_Rnglists_Head lhead = 0;
    Dwarf_CU_Context ctx = 0;
    struct Dwarf_Rnglists_Head_s shead;
    Dwarf_Unsigned offset_in_rnglists = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Bool is_rnglistx = FALSE;

    memset(&shead,0,sizeof(shead));
    ctx = attr->ar_cu_context;
    dbg = ctx->cc_dbg;
    array = dbg->de_rnglists_context;
    if (theform == DW_FORM_rnglistx) {
        is_rnglistx = TRUE;
    }
    /*  ASSERT:  the 3 pointers just set are non-null */
    /*  the context cc_rnglists_base gives the offset
        of the array. of offsets (if cc_rnglists_base_present) */
            offset_in_rnglists = attr_val;
    if (is_rnglistx) {
        if (ctx->cc_rnglists_base_present) {
            offset_in_rnglists = ctx->cc_rnglists_base;

        } else {
            /* FIXME: check in tied file for a cc_rnglists_base */
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_RNGLISTS_ERROR: rnglists table index of"
                " %u"  ,attr_val);
            dwarfstring_append(&m,
                " is unusable unless it is in a tied file."
                " libdwarf is incomplete. FIXME");
            _dwarf_error_string(dbg,error,DW_DLE_RNGLISTS_ERROR,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
    } else {
        offset_in_rnglists = attr_val;
    }
    res = _dwarf_which_rnglists_context(dbg,ctx,
        offset_in_rnglists,
        &rnglists_contextnum,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    rctx = array[rnglists_contextnum];
    table_base = rctx->rc_offsets_array;
    entrycount = rctx->rc_offset_entry_count;
    offsetsize = rctx->rc_offset_size;
    enddata = rctx->rc_endaddr;

    if (is_rnglistx && attr_val >= entrycount) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_RNGLISTS_ERROR: rnglists table index of"
            " %u"  ,attr_val);
        dwarfstring_append_printf_u(&m,
            " too large for table of %u "
            "entries.",entrycount);
        _dwarf_error_string(dbg,error,
            DW_DLE_RNGLISTS_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    shead.rh_context = ctx;
    shead.rh_localcontext = rctx;
    shead.rh_index = rnglists_contextnum;
    shead.rh_version = rctx->rc_version;
    shead.rh_offset_size = offsetsize;
    shead.rh_address_size  = rctx->rc_address_size;
    shead.rh_segment_selector_size =
        rctx->rc_segment_selector_size;

    /*  DW_AT_rnglists_base from CU */
    shead.rh_at_rnglists_base_present =
        ctx->cc_rnglists_base_present;
    shead.rh_at_rnglists_base =  ctx->cc_rnglists_base;

    /*  DW_AT_low_pc, if present.  From CU */
    shead.rh_cu_base_address_present = ctx->cc_low_pc_present;
    shead.rh_cu_base_address = ctx->cc_low_pc;

    /*  base address DW_AT_addr_base of our part of
        .debug_addr, from CU */
    shead.rh_cu_addr_base = ctx->cc_addr_base;
    shead.rh_cu_addr_base_present = ctx->cc_addr_base_present;
    if (is_rnglistx) {
        Dwarf_Unsigned table_entryval = 0;

        table_entry = attr_val*offsetsize + table_base;
        /*  No malloc here yet so no leak if the macro returns
            DW_DLV_ERROR */
        READ_UNALIGNED_CK(dbg,table_entryval, Dwarf_Unsigned,
            table_entry,offsetsize,error,enddata);
        rle_global_offset = rctx->rc_offsets_off_in_sect +
            table_entryval;
    } else {
        rle_global_offset = attr_val;
    }

    shead.rh_rlepointer = rctx->rc_offsets_array +
        rctx->rc_offset_entry_count*offsetsize;
    shead.rh_end_data_area = enddata;

    shead.rh_rlearea_offset = rle_global_offset;
    shead.rh_rlepointer = rle_global_offset +
        dbg->de_debug_rnglists.dss_data;
    lhead = (Dwarf_Rnglists_Head)
        _dwarf_get_alloc(dbg,DW_DLA_RNGLISTS_HEAD,1);
    if (!lhead) {
        _dwarf_error_string(dbg, error, DW_DLE_ALLOC_FAIL,
            "Allocating a Dwarf_Rnglists_Head struct fails"
            " in libdwarf function dwarf_rnglists_index_get_rle_head()");
        return DW_DLV_ERROR;
    }
    shead.rh_dbg = dbg;
    *lhead = shead;
    res = build_array_of_rle(dbg,lhead,error);
    if (res != DW_DLV_OK) {
        dwarf_dealloc(dbg,lhead,DW_DLA_RNGLISTS_HEAD);
        return res;
    }
    if(global_offset_of_rle_set) {
        *global_offset_of_rle_set = rle_global_offset;
    }
    /*  Caller needs the head pointer else there will be leaks. */
    *head_out = lhead;
    if (entries_count_out) {
        *entries_count_out = lhead->rh_count;
    }
    return DW_DLV_OK;
}

int
dwarf_get_rnglists_entry_fields(
    Dwarf_Rnglists_Head head,
    Dwarf_Unsigned entrynum,
    unsigned *entrylen,
    unsigned *code,
    Dwarf_Unsigned *raw1,
    Dwarf_Unsigned *raw2,
    Dwarf_Unsigned *cooked1,
    Dwarf_Unsigned *cooked2,
    UNUSEDARG Dwarf_Error *err)
{
    Dwarf_Rnglists_Entry e = 0;

    if (entrynum >= head->rh_count) {
        return DW_DLV_NO_ENTRY;
    }
    e = head->rh_rnglists[entrynum];
    *entrylen  = e->rle_entrylen;
    *code      = e->rle_code;
    *raw1      = e->rle_raw1;
    *raw2      = e->rle_raw2;
    *cooked1   = e->rle_cooked1;
    *cooked2   = e->rle_cooked2;
    return DW_DLV_OK;
}

/*  Deals with both fully and partially build head */
static void
_dwarf_free_rnglists_head(Dwarf_Rnglists_Head head)
{
    if (head->rh_first) {
        /* partially built head. */
        /*  ASSERT: rh_rnglists is NULL */
        Dwarf_Rnglists_Entry cur = head->rh_first;
        Dwarf_Rnglists_Entry next = 0;

        for ( ; cur ; cur = next) {
            next = cur->rle_next;
            free(cur);
        }
        head->rh_first = 0;
        head->rh_last = 0;
        head->rh_count = 0;
    } else {
        /*  ASSERT: rh_first and rh_last are NULL */
        /* fully built head. */
        Dwarf_Unsigned i = 0;

        /* Deal with the array form. */
        for( ; i < head->rh_count; ++i) {
            free(head->rh_rnglists[i]);
        }
        free(head->rh_rnglists);
        head->rh_rnglists = 0;
    }
}

void
_dwarf_rnglists_head_destructor(void *head)
{
    Dwarf_Rnglists_Head h = head;

    _dwarf_free_rnglists_head(h);
}
