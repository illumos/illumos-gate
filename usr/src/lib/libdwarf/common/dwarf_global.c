/*

  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2007-2011 David Anderson. All Rights Reserved.

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
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarfstring.h"
#include "dwarf_global.h"


#ifdef __sgi  /* __sgi should only be defined for IRIX/MIPS. */
/* The 'fixup' here intended for IRIX targets only.
   With a  2+GB Elf64 IRIX executable (under 4GB in size),
   some DIE offsets wrongly
   got the 32bit upper bit sign extended.  For the cu-header
   offset in the .debug_pubnames section  and in the
   .debug_aranges section.
   the 'varp' here is a pointer to an offset into .debug_info.
   We fix up the offset here if it seems advisable..

   As of June 2005 we have identified a series of mistakes
   in ldx64 that can cause this (64 bit values getting passed
   thru 32-bit signed knothole).
*/
void
_dwarf_fix_up_offset_irix(Dwarf_Debug dbg,
    Dwarf_Unsigned * varp, char *caller_site_name)
{

    Dwarf_Unsigned var = *varp;

#define UPPER33 0xffffffff80000000LL
#define LOWER32         0xffffffffLL
    /*  Restrict the hack to the known case. Upper 32 bits erroneously
        sign extended from lower 32 upper bit. */
    if ((var & UPPER33) == UPPER33) {
        var &= LOWER32;
        /* Apply the fix. Dreadful hack. */
        *varp = var;
    }
#undef UPPER33
#undef LOWER32
    return;
}
#endif  /* __sgi */

static void
dealloc_globals_chain(Dwarf_Debug dbg,
    Dwarf_Chain head_chain)
{
    Dwarf_Chain curr_chain = 0;
    Dwarf_Chain prev_chain = 0;
    int chaintype = DW_DLA_CHAIN;

    curr_chain = head_chain;
    for (; curr_chain; ) {
        void *item = curr_chain->ch_item;
        int itemtype = curr_chain->ch_itemtype;

        prev_chain = curr_chain;
        dwarf_dealloc(dbg, item,itemtype);
        prev_chain->ch_item = 0;
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, prev_chain, chaintype);
    }
}

int
dwarf_get_globals(Dwarf_Debug dbg,
    Dwarf_Global ** globals,
    Dwarf_Signed * return_count, Dwarf_Error * error)
{
    int res = _dwarf_load_section(dbg, &dbg->de_debug_pubnames,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if (!dbg->de_debug_pubnames.dss_size) {
        return DW_DLV_NO_ENTRY;
    }

    res = _dwarf_internal_get_pubnames_like_data(dbg,
        dbg->de_debug_pubnames.dss_data,
        dbg->de_debug_pubnames.dss_size,
        globals,
        return_count,
        error,
        DW_DLA_GLOBAL_CONTEXT,
        DW_DLA_GLOBAL,
        DW_DLE_PUBNAMES_LENGTH_BAD,
        DW_DLE_PUBNAMES_VERSION_ERROR);
    return res;

}

/* Deallocating fully requires deallocating the list
   and all entries.  But some internal data is
   not exposed, so we need a function with internal knowledge.
*/

void
dwarf_globals_dealloc(Dwarf_Debug dbg, Dwarf_Global * dwgl,
    Dwarf_Signed count)
{
    _dwarf_internal_globals_dealloc(dbg, dwgl,
        count,
        DW_DLA_GLOBAL_CONTEXT,
        DW_DLA_GLOBAL, DW_DLA_LIST);
    return;
}

void
_dwarf_internal_globals_dealloc(Dwarf_Debug dbg, Dwarf_Global * dwgl,
    Dwarf_Signed count,
    int context_DLA_code,
    int global_DLA_code, int list_DLA_code)
{
    Dwarf_Signed i;
    struct Dwarf_Global_Context_s *glcp = 0;
    struct Dwarf_Global_Context_s *lastglcp = 0;

    if(!dwgl) {
        return;
    }
    for (i = 0; i < count; i++) {
        Dwarf_Global dgb = dwgl[i];

        if (!dgb) {
            continue;
        }
        /*  Avoids duplicate frees of repeated
            use of contexts (while assuming that
            all uses of a particular gl_context
            will appear next to each other. */
        glcp = dgb->gl_context;
        if (lastglcp != glcp) {
            lastglcp = glcp;
            dwarf_dealloc(dbg, glcp, context_DLA_code);
        }
        dwarf_dealloc(dbg, dgb, global_DLA_code);
    }
    dwarf_dealloc(dbg, dwgl, list_DLA_code);
    return;
}

/* Sweeps the complete  section.  */
int
_dwarf_internal_get_pubnames_like_data(Dwarf_Debug dbg,
    Dwarf_Small * section_data_ptr,
    Dwarf_Unsigned section_length,
    Dwarf_Global ** globals,
    Dwarf_Signed * return_count,
    Dwarf_Error * error,
    int context_DLA_code,
    int global_DLA_code,
    int length_err_num,
    int version_err_num)
{
    Dwarf_Small *pubnames_like_ptr = 0;
    Dwarf_Off pubnames_section_offset = 0;
    Dwarf_Small *section_end_ptr = section_data_ptr +section_length;

    /*  Points to the context for the current set of global names, and
        contains information to identify the compilation-unit that the
        set refers to. */
    Dwarf_Global_Context pubnames_context = 0;

    Dwarf_Unsigned version = 0;

    /*  Offset from the start of compilation-unit for the current
        global. */
    Dwarf_Off die_offset_in_cu = 0;

    Dwarf_Unsigned global_count = 0;

    /* Points to the current global read. */
    Dwarf_Global global = 0;

    /*  Used to chain the Dwarf_Global_s structs for creating contiguous
        list of pointers to the structs. */
    Dwarf_Chain curr_chain = 0;
    Dwarf_Chain prev_chain = 0;
    Dwarf_Chain head_chain = 0;

    /* Points to contiguous block of Dwarf_Global's to be returned. */
    Dwarf_Global *ret_globals = 0;
    int mres = 0;

    /* Temporary counter. */
    Dwarf_Unsigned i = 0;

    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    /* We will eventually need the .debug_info data. Load it now. */
    if (!dbg->de_debug_info.dss_data) {
        int res = _dwarf_load_debug_info(dbg, error);

        if (res != DW_DLV_OK) {
            return res;
        }
    }
    if (section_data_ptr == NULL) {
        return (DW_DLV_NO_ENTRY);
    }
    pubnames_like_ptr = section_data_ptr;
    do {
        Dwarf_Unsigned length = 0;
        int local_extension_size = 0;
        int local_length_size = 0;

        /*  Some compilers emit padding at the end of each cu's area.
            pubnames_ptr_past_end_cu records the true area end for the
            pubnames(like) content of a cu.
            Essentially the length in the header and the 0
            terminator of the data are redundant information. The
            dwarf2/3 spec does not mention what to do if the length is
            past the 0 terminator. So we take any bytes left after the 0
            as padding and ignore them. */
        Dwarf_Small *pubnames_ptr_past_end_cu = 0;


        pubnames_context = (Dwarf_Global_Context)
            _dwarf_get_alloc(dbg, context_DLA_code, 1);
        if (pubnames_context == NULL) {
            dealloc_globals_chain(dbg,head_chain);
            _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        /*  READ_AREA_LENGTH updates pubnames_like_ptr for consumed
            bytes. */
        mres = _dwarf_read_area_length_ck_wrapper(dbg,
            &length,&pubnames_like_ptr,&local_length_size,
            &local_extension_size,section_length,section_end_ptr,
            error);
        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            return mres;
        }
        pubnames_context->pu_length_size = local_length_size;
        pubnames_context->pu_length = length;
        pubnames_context->pu_extension_size = local_extension_size;
        pubnames_context->pu_dbg = dbg;
        pubnames_context->pu_pub_offset = pubnames_section_offset;
        pubnames_ptr_past_end_cu = pubnames_like_ptr + length;

        mres = _dwarf_read_unaligned_ck_wrapper(dbg,
            &version,pubnames_like_ptr,DWARF_HALF_SIZE,
            section_end_ptr,error);
        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            return mres;
        }
        pubnames_context->pu_version = version;
        pubnames_like_ptr += DWARF_HALF_SIZE;
        /* ASSERT: DW_PUBNAMES_VERSION2 == DW_PUBTYPES_VERSION2 */
        if (version != DW_PUBNAMES_VERSION2) {
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            _dwarf_error(dbg, error, version_err_num);
            return DW_DLV_ERROR;
        }

        /* Offset of CU header in debug section. */
        mres = _dwarf_read_unaligned_ck_wrapper(dbg,
            &pubnames_context->pu_offset_of_cu_header,
            pubnames_like_ptr,
            pubnames_context->pu_length_size,
            section_end_ptr,error);
        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            return mres;
        }

        pubnames_like_ptr += pubnames_context->pu_length_size;

        FIX_UP_OFFSET_IRIX_BUG(dbg,
            pubnames_context->pu_offset_of_cu_header,
            "pubnames cu header offset");
        mres = _dwarf_read_unaligned_ck_wrapper(dbg,
            &pubnames_context->pu_info_length,
            pubnames_like_ptr,
            pubnames_context->pu_length_size,
            section_end_ptr,error);
        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            return mres;
        }
        pubnames_like_ptr += pubnames_context->pu_length_size;

        if (pubnames_like_ptr > (section_data_ptr + section_length)) {
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            _dwarf_error(dbg, error, length_err_num);
            return (DW_DLV_ERROR);
        }

        /*  Read initial offset (of DIE within CU) of a pubname, final
            entry is not a pair, just a zero offset. */
        mres = _dwarf_read_unaligned_ck_wrapper(dbg,
            &die_offset_in_cu,
            pubnames_like_ptr,
            pubnames_context->pu_length_size,
            section_end_ptr,error);
        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            return mres;
        }
        pubnames_like_ptr += pubnames_context->pu_length_size;
        FIX_UP_OFFSET_IRIX_BUG(dbg,
            die_offset_in_cu, "offset of die in cu");
        if (pubnames_like_ptr > (section_data_ptr + section_length)) {
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            _dwarf_error(dbg, error, length_err_num);
            return DW_DLV_ERROR;
        }

        /* Loop thru pairs. DIE off with CU followed by string. */
        if (dbg->de_return_empty_pubnames && die_offset_in_cu == 0) {
            /*  Here we have a pubnames CU with no actual
                entries so we fake up an entry to hold the
                header data.  There are no 'pairs' here,
                just the end of list zero value.  We do this
                only if de_return_empty_pubnames is set
                so that we by default return exactly the same
                data this always returned, yet dwarfdump can
                request the empty-cu records get created
                to test that feature.
                see dwarf_get_globals_header()  */
            global =
                (Dwarf_Global) _dwarf_get_alloc(dbg, global_DLA_code, 1);
            if (global == NULL) {
                dealloc_globals_chain(dbg,head_chain);
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
                _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return (DW_DLV_ERROR);
            }
            global_count++;
            global->gl_context = pubnames_context;
            global->gl_named_die_offset_within_cu = 0;
            global->gl_name = (Dwarf_Small *)"";
            /* Finish off current entry chain */
            curr_chain =
                (Dwarf_Chain) _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
            if (curr_chain == NULL) {
                dealloc_globals_chain(dbg,head_chain);
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
                _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return DW_DLV_ERROR;
            }
            /* Put current global on singly_linked list. */
            curr_chain->ch_itemtype = global_DLA_code;
            curr_chain->ch_item = (Dwarf_Global) global;
            if (head_chain == NULL)
                head_chain = prev_chain = curr_chain;
            else {
                prev_chain->ch_next = curr_chain;
                prev_chain = curr_chain;
            }
            /* There is no next entry, we are at it already */
        } else if (!die_offset_in_cu) {
            /*  The section is empty.
                Nowhere to record pubnames_context); */
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            pubnames_context = 0;
            continue;
        }
        while (die_offset_in_cu) {
            int res = 0;

            /*  Already read offset, pubnames_like_ptr
                now points to the string. */
            global =
                (Dwarf_Global) _dwarf_get_alloc(dbg, global_DLA_code, 1);
            if (global == NULL) {
                dealloc_globals_chain(dbg,head_chain);
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
                _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return (DW_DLV_ERROR);
            }
            global_count++;
            global->gl_context = pubnames_context;
            global->gl_named_die_offset_within_cu = die_offset_in_cu;
            global->gl_name = pubnames_like_ptr;
            res = _dwarf_check_string_valid(dbg,section_data_ptr,
                pubnames_like_ptr,section_end_ptr,
                DW_DLE_STRING_OFF_END_PUBNAMES_LIKE,error);
            if (res != DW_DLV_OK) {
                dealloc_globals_chain(dbg,head_chain);
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
                return res;
            }
            pubnames_like_ptr = pubnames_like_ptr +
                strlen((char *) pubnames_like_ptr) + 1;

            /* Finish off current entry chain */
            curr_chain =
                (Dwarf_Chain) _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
            if (curr_chain == NULL) {
                dealloc_globals_chain(dbg,head_chain);
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
                _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return (DW_DLV_ERROR);
            }
            /* Put current global on singly_linked list. */
            curr_chain->ch_item = (Dwarf_Global) global;
            curr_chain->ch_itemtype = global_DLA_code;
            if (head_chain == NULL)
                head_chain = prev_chain = curr_chain;
            else {
                prev_chain->ch_next = curr_chain;
                prev_chain = curr_chain;
            }

            /* Read offset for the *next* entry */
            mres = _dwarf_read_unaligned_ck_wrapper(dbg,
                &die_offset_in_cu,
                pubnames_like_ptr,
                pubnames_context->pu_length_size,
                section_end_ptr,error);
            if (mres != DW_DLV_OK) {
                dealloc_globals_chain(dbg,head_chain);
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
                return mres;
            }
            pubnames_like_ptr += pubnames_context->pu_length_size;
            FIX_UP_OFFSET_IRIX_BUG(dbg,
                die_offset_in_cu, "offset of next die in cu");
            if (pubnames_like_ptr > (section_data_ptr + section_length)) {
                dealloc_globals_chain(dbg,head_chain);
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
                _dwarf_error(dbg, error, length_err_num);
                return DW_DLV_ERROR;
            }
        }
        /* ASSERT: die_offset_in_cu == 0 */
        if (pubnames_like_ptr > pubnames_ptr_past_end_cu) {
            /* This is some kind of error. This simply cannot happen.
            The encoding is wrong or the length in the header for
            this cu's contribution is wrong. */
            _dwarf_error(dbg, error, length_err_num);
            dealloc_globals_chain(dbg,head_chain);
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            return DW_DLV_ERROR;
        }
        /*  If there is some kind of padding at the end of the section,
            as emitted by some compilers, skip over that padding and
            simply ignore the bytes thus passed-over.  With most
            compilers, pubnames_like_ptr == pubnames_ptr_past_end_cu at
            this point */
        {
            Dwarf_Unsigned increment =
                pubnames_context->pu_length_size +
                pubnames_context->pu_length +
                pubnames_context->pu_extension_size;
            pubnames_section_offset += increment;
        }
        pubnames_like_ptr = pubnames_ptr_past_end_cu;
    } while (pubnames_like_ptr < section_end_ptr);

    /* Points to contiguous block of Dwarf_Global's. */
    ret_globals = (Dwarf_Global *)
        _dwarf_get_alloc(dbg, DW_DLA_LIST, global_count);
    if (ret_globals == NULL) {
        dealloc_globals_chain(dbg,head_chain);
        dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    /*  Store pointers to Dwarf_Global_s structs in contiguous block,
        and deallocate the chain.  This ignores the various
        headers */
    curr_chain = head_chain;
    for (i = 0; i < global_count; i++) {
        *(ret_globals + i) = curr_chain->ch_item;
        prev_chain = curr_chain;
        curr_chain = curr_chain->ch_next;
        prev_chain->ch_item = 0; /* Not actually necessary. */
        dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN);
    }
    *globals = ret_globals;
    *return_count = (Dwarf_Signed) global_count;
    return DW_DLV_OK;
}


/*  Given a pubnames entry (or other like section entry)
    return thru the ret_name pointer
    a pointer to the string which is the entry name.  */
int
dwarf_globname(Dwarf_Global glob, char **ret_name, Dwarf_Error * error)
{
    if (glob == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return (DW_DLV_ERROR);
    }

    *ret_name = (char *) (glob->gl_name);
    return DW_DLV_OK;
}


/*  Given a pubnames entry (or other like section entry)
    return thru the ret_off pointer the
    global offset of the DIE for this entry.
    The global offset is the offset within the .debug_info
    section as a whole.  */
int
dwarf_global_die_offset(Dwarf_Global global,
    Dwarf_Off * ret_off, Dwarf_Error * error)
{
    if (global == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return (DW_DLV_ERROR);
    }

    if (global->gl_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_CONTEXT_NULL);
        return (DW_DLV_ERROR);
    }

    *ret_off = (global->gl_named_die_offset_within_cu +
        global->gl_context->pu_offset_of_cu_header);
    return DW_DLV_OK;
}

/*  Given a pubnames entry (or other like section entry)
    return thru the ret_off pointer the
    offset of the compilation unit header of the
    compilation unit the global is part of.

    In early versions of this, the value returned was
    the offset of the compilation unit die, and
    other cu-local die offsets were faked so adding this to
    such a cu-local offset got a true section offset.
    Now things do as they say (adding *cu_header_offset to
    a cu-local offset gets the section offset).  */
int
dwarf_global_cu_offset(Dwarf_Global global,
    Dwarf_Off * cu_header_offset,
    Dwarf_Error * error)
{
    Dwarf_Global_Context con = 0;

    if (global == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return (DW_DLV_ERROR);
    }

    con = global->gl_context;

    if (con == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_CONTEXT_NULL);
        return (DW_DLV_ERROR);
    }

    /*  In early libdwarf, this incorrectly returned the offset of the
        CU DIE. Now correctly returns the header offset. */
    *cu_header_offset = con->pu_offset_of_cu_header;

    return DW_DLV_OK;
}

static void
build_off_end_msg(Dwarf_Unsigned offval,
   Dwarf_Unsigned withincr,
   Dwarf_Unsigned secsize,
   dwarfstring *m)
{
    const char *msg = "past";
    if (offval < secsize){
        msg = "too near";
    }
    dwarfstring_append_printf_u(m,"DW_DLE_OFFSET_BAD: "
        "The CU header offset of %u in a pubnames-like entry ",
        withincr);
    dwarfstring_append_printf_s(m,
        "would put us %s the end of .debug_info. "
        "No room for a DIE there... "
        "Corrupt Dwarf.",(char *)msg);
    return;
}


/*
  Give back the pubnames entry (or any other like section)
  name, symbol DIE offset, and the cu-DIE offset.

  Various errors are possible.

  The string pointer returned thru ret_name is not
  dwarf_get_alloc()ed, so no dwarf_dealloc()
  DW_DLA_STRING should be applied to it.

*/
int
dwarf_global_name_offsets(Dwarf_Global global,
    char **ret_name,
    Dwarf_Off * die_offset,
    Dwarf_Off * cu_die_offset,
    Dwarf_Error * error)
{
    Dwarf_Global_Context con = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Off cuhdr_off = 0;

    if (global == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return (DW_DLV_ERROR);
    }

    con = global->gl_context;

    if (con == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_CONTEXT_NULL);
        return (DW_DLV_ERROR);
    }

    cuhdr_off = con->pu_offset_of_cu_header;
    /*  The offset had better not be too close to the end. If it is,
        _dwarf_length_of_cu_header() will step off the end and therefore
        must not be used. 10 is a meaningless heuristic, but no CU
        header is that small so it is safe. An erroneous offset is due
        to a bug in the tool chain. A bug like this has been seen on
        IRIX with MIPSpro 7.3.1.3 and an executable > 2GB in size and
        with 2 million pubnames entries. */
#define MIN_CU_HDR_SIZE 10
    dbg = con->pu_dbg;
    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    /* Cannot refer to debug_types */
    if (dbg->de_debug_info.dss_size &&
        ((cuhdr_off + MIN_CU_HDR_SIZE) >= dbg->de_debug_info.dss_size)) {
        dwarfstring m;
        dwarfstring_constructor(&m);
        build_off_end_msg(cuhdr_off,cuhdr_off+MIN_CU_HDR_SIZE,
            dbg->de_debug_info.dss_size,&m);
        _dwarf_error_string(dbg, error, DW_DLE_OFFSET_BAD,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return (DW_DLV_ERROR);
    }
#undef MIN_CU_HDR_SIZE
    /*  If global->gl_named_die_offset_within_cu
        is zero then this is a fake global for
        a pubnames CU with no pubnames. The offset is from the
        start of the CU header, so no die can have a zero
        offset, all valid offsets are positive numbers */
    if (die_offset) {
        if(global->gl_named_die_offset_within_cu) {
            *die_offset = global->gl_named_die_offset_within_cu + cuhdr_off;
        } else {
            *die_offset = 0;
        }
    }
    *ret_name = (char *) global->gl_name;
    if (cu_die_offset) {
        /* Globals cannot refer to debug_types */
        int cres = 0;
        Dwarf_Unsigned headerlen = 0;
        int res = _dwarf_load_debug_info(dbg, error);

        if (res != DW_DLV_OK) {
            return res;
        }
        /*  The offset had better not be too close to the end.
            If it is,
            _dwarf_length_of_cu_header() will step off the end and
            therefore must not be used. 10 is a meaningless heuristic,
            but no CU header is that small so it is safe. */
        /* Globals cannot refer to debug_types */
        if ((cuhdr_off + 10) >= dbg->de_debug_info.dss_size) {
            dwarfstring m;

            dwarfstring_constructor(&m);
            build_off_end_msg(cuhdr_off,cuhdr_off+10,
                dbg->de_debug_info.dss_size,&m);
            _dwarf_error_string(dbg, error, DW_DLE_OFFSET_BAD,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return (DW_DLV_ERROR);
        }
        cres = _dwarf_length_of_cu_header(dbg, cuhdr_off,true,
            &headerlen,error);
        if(cres != DW_DLV_OK) {
            return cres;
        }
        *cu_die_offset = cuhdr_off + headerlen;
    }
    return DW_DLV_OK;
}


/*  New February 2019 from better dwarfdump printing
    of debug_pubnames and pubtypes.
    For ao the Dwarf_Global records in one pubnames
    CU group exactly the same data will be returned.

*/
int
dwarf_get_globals_header(Dwarf_Global global,
    Dwarf_Off      *pub_section_hdr_offset,
    Dwarf_Unsigned *pub_offset_size,
    Dwarf_Unsigned *pub_cu_length,
    Dwarf_Unsigned *version,
    Dwarf_Off      *info_header_offset,
    Dwarf_Unsigned *info_length,
    Dwarf_Error*   error)
{
    Dwarf_Global_Context con = 0;
    Dwarf_Debug dbg = 0;

    if (global == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return DW_DLV_ERROR;
    }
    con = global->gl_context;
    if (con == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_CONTEXT_NULL);
        return DW_DLV_ERROR;
    }
    dbg = con->pu_dbg;
    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    if(pub_section_hdr_offset) {
        *pub_section_hdr_offset = con->pu_pub_offset;
    }
    if (pub_offset_size) {
        *pub_offset_size = con->pu_length_size;
    }
    if (pub_cu_length) {
        *pub_cu_length = con->pu_length;
    }
    if (version) {
        *version = con->pu_version;
    }
    if(info_header_offset) {
        *info_header_offset = con->pu_offset_of_cu_header;
    }
    if (info_length) {
        *info_length = con->pu_info_length;
    }
    return DW_DLV_OK;
}


/*  We have the offset to a CU header.
    Return thru outFileOffset the offset of the CU DIE.

    New June, 2001.
    Used by SGI IRIX debuggers.
    No error used to be possible.
    As of May 2016 an error is possible if the DWARF is
    corrupted! (IRIX debuggers are no longer built ...)

    See also dwarf_CU_dieoffset_given_die().

    This is assumed to never apply to data in .debug_types, it
    only refers to .debug_info.

*/

/* ARGSUSED */
int
dwarf_get_cu_die_offset_given_cu_header_offset(Dwarf_Debug dbg,
    Dwarf_Off in_cu_header_offset,
    Dwarf_Off * out_cu_die_offset,
    UNUSEDARG Dwarf_Error * err)
{
    Dwarf_Off headerlen = 0;
    int cres = 0;

    cres = _dwarf_length_of_cu_header(dbg, in_cu_header_offset,true,
        &headerlen,err);
    if (cres != DW_DLV_OK) {
        return cres;
    }
    *out_cu_die_offset = in_cu_header_offset + headerlen;
    return DW_DLV_OK;
}

/*  The following version new in October 2011, does allow finding
    the offset if one knows whether debug_info or debug_types.

    However, it is not accurate in DWARF5 because
    there are two different header lengths (CU and TU)
    in DWARF5 .debug_info.  In that case, pretend
    that it's .debug_types (here) and pass is_info zero for
    a TU (as if it was in .debug_types).
    */
int
dwarf_get_cu_die_offset_given_cu_header_offset_b(Dwarf_Debug dbg,
    Dwarf_Off in_cu_header_offset,
    Dwarf_Bool is_info,
    Dwarf_Off * out_cu_die_offset,
    UNUSEDARG Dwarf_Error * err)
{
    Dwarf_Off headerlen = 0;
    int cres = 0;

    cres = _dwarf_length_of_cu_header(dbg, in_cu_header_offset,is_info,
        &headerlen,err);
    if (cres != DW_DLV_OK) {
        return cres;
    }
    *out_cu_die_offset = in_cu_header_offset + headerlen;
    return DW_DLV_OK;
}
/*  dwarf_CU_dieoffset_given_die returns
    the global debug_info section offset of the CU die
    that is the CU containing the given (passed-in) die.
    This information makes it possible for a consumer to
    find and print context information for any die.

    Use dwarf_offdie() passing in the offset this returns
    to get a die pointer to the CU die.  */
int
dwarf_CU_dieoffset_given_die(Dwarf_Die die,
    Dwarf_Off*       return_offset,
    Dwarf_Error*     error)
{
    Dwarf_Off  dieoff = 0;
    Dwarf_CU_Context cucontext = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    cucontext = die->di_cu_context;
    dieoff =  cucontext->cc_debug_offset;
    /*  The following call cannot fail, so no error check. */
    dwarf_get_cu_die_offset_given_cu_header_offset_b(
        cucontext->cc_dbg, dieoff,
        die->di_is_info, return_offset,error);
    return DW_DLV_OK;
}

/*  We do not want to screw up error in case
    it has something important.  So not touching it now. */
int dwarf_return_empty_pubnames(Dwarf_Debug dbg,
    int flag, UNUSEDARG Dwarf_Error *err )
{
    if (dbg == NULL) {
        return DW_DLV_OK;
    }
    if (flag && flag != 1) {
        return DW_DLV_OK;
    }
    dbg->de_return_empty_pubnames = (unsigned char)flag;
    return DW_DLV_OK;
}
