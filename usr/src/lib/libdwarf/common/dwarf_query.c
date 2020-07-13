/*
  Copyright (C) 2000,2002,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2007-2020 David Anderson. All Rights Reserved.
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
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarf_die_deliv.h"
#include "dwarfstring.h"

#define TRUE 1
static int _dwarf_die_attr_unsigned_constant(Dwarf_Die die,
    Dwarf_Half attr,
    Dwarf_Unsigned * return_val,
    Dwarf_Error * error);

static int _dwarf_get_ranges_base_attr_value(Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned * rabase_out,
    Dwarf_Error    * error);

static int _dwarf_get_address_base_attr_value(Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned *abase_out,
    Dwarf_Error *error);

int dwarf_get_offset_size(Dwarf_Debug dbg,
    Dwarf_Half  *    offset_size,
    Dwarf_Error *    error)
{
    if (dbg == 0) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    *offset_size = dbg->de_length_size;
    return DW_DLV_OK;
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

/* This is normally reliable.
But not always.
If different compilation
units have different address sizes
this may not give the correct value in all contexts.
If the Elf offset size != address_size
(for example if address_size = 4 but recorded in elf64 object)
this may not give the correct value in all contexts.
*/
int
dwarf_get_address_size(Dwarf_Debug dbg,
    Dwarf_Half * ret_addr_size, Dwarf_Error * error)
{
    Dwarf_Half address_size = 0;

    if (dbg == 0) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    address_size = dbg->de_pointer_size;
    *ret_addr_size = address_size;
    return DW_DLV_OK;
}

/* This will be correct in all contexts where the
   CU context of a DIE is known.
*/
int
dwarf_get_die_address_size(Dwarf_Die die,
    Dwarf_Half * ret_addr_size, Dwarf_Error * error)
{
    Dwarf_Half address_size = 0;
    CHECK_DIE(die, DW_DLV_ERROR);
    address_size = die->di_cu_context->cc_address_size;
    *ret_addr_size = address_size;
    return DW_DLV_OK;
}

int
dwarf_dieoffset(Dwarf_Die die,
    Dwarf_Off * ret_offset, Dwarf_Error * error)
{
    Dwarf_Small *dataptr = 0;
    Dwarf_Debug dbg = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    dbg = die->di_cu_context->cc_dbg;
    dataptr = die->di_is_info? dbg->de_debug_info.dss_data:
        dbg->de_debug_types.dss_data;

    *ret_offset = (die->di_debug_ptr - dataptr);
    return DW_DLV_OK;
}


/*  This function returns the offset of
    the die relative to the start of its
    compilation-unit rather than .debug_info.
    Returns DW_DLV_ERROR on error.  */
int
dwarf_die_CU_offset(Dwarf_Die die,
    Dwarf_Off * cu_off, Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Small *dataptr = 0;
    Dwarf_Debug dbg = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    cu_context = die->di_cu_context;
    dbg = die->di_cu_context->cc_dbg;
    dataptr = die->di_is_info? dbg->de_debug_info.dss_data:
        dbg->de_debug_types.dss_data;

    *cu_off = (die->di_debug_ptr - dataptr - cu_context->cc_debug_offset);
    return DW_DLV_OK;
}

/*  A common function to get both offsets (local and global)
    It's unusual in that it sets both return offsets
    to zero on entry.  Normally we only set any
    output-args (through their pointers) in case
    of success.  */
int
dwarf_die_offsets(Dwarf_Die die,
    Dwarf_Off *off,
    Dwarf_Off *cu_off,
    Dwarf_Error *error)
{
    int res = 0;
    Dwarf_Off lcuoff = 0;
    Dwarf_Off loff = 0;

    res = dwarf_dieoffset(die,&loff,error);
    if (res == DW_DLV_OK) {
        res = dwarf_die_CU_offset(die,&lcuoff,error);
    }
    if (res == DW_DLV_OK) {
        /*  Waiting till both succeed before
            returning any value at all to retain
            normal libdwarf call semantics. */
        *off = loff;
        *cu_off = lcuoff;
    } else {
        *off = 0;
        *cu_off = 0;
    }
    return res;
}

/*  This function returns the global offset
    (meaning the section offset) and length of
    the CU that this die is a part of.
    Used for correctness checking by dwarfdump.  */
int
dwarf_die_CU_offset_range(Dwarf_Die die,
    Dwarf_Off * cu_off,
    Dwarf_Off * cu_length,
    Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    cu_context = die->di_cu_context;

    *cu_off = cu_context->cc_debug_offset;
    *cu_length = cu_context->cc_length + cu_context->cc_length_size
        + cu_context->cc_extension_size;
    return DW_DLV_OK;
}



int
dwarf_tag(Dwarf_Die die, Dwarf_Half * tag, Dwarf_Error * error)
{
    CHECK_DIE(die, DW_DLV_ERROR);
    *tag = die->di_abbrev_list->abl_tag;
    return DW_DLV_OK;
}

/* Returns the children offsets for the given offset */
int
dwarf_offset_list(Dwarf_Debug dbg,
    Dwarf_Off offset, Dwarf_Bool is_info,
    Dwarf_Off **offbuf, Dwarf_Unsigned *offcnt,
    Dwarf_Error * error)
{
    Dwarf_Die die = 0;
    Dwarf_Die child = 0;
    Dwarf_Die sib_die = 0;
    Dwarf_Die cur_die = 0;
    Dwarf_Unsigned off_count = 0;
    int res = 0;

    /* Temporary counter. */
    Dwarf_Unsigned i = 0;

    /* Points to contiguous block of Dwarf_Off's to be returned. */
    Dwarf_Off *ret_offsets = 0;

    Dwarf_Chain_2 curr_chain = 0;
    Dwarf_Chain_2 prev_chain = 0;
    Dwarf_Chain_2 head_chain = 0;

    *offbuf = NULL;
    *offcnt = 0;

    /* Get DIE for offset */
    res = dwarf_offdie_b(dbg,offset,is_info,&die,error);
    if (DW_DLV_OK != res) {
        return res;
    }

    /* Get first child for die */
    res = dwarf_child(die,&child,error);
    if (DW_DLV_ERROR == res || DW_DLV_NO_ENTRY == res) {
        return res;
    }

    cur_die = child;
    for (;;) {
        if (DW_DLV_OK == res) {
            int dres = 0;
            Dwarf_Off cur_off = 0;

            /* Get Global offset for current die */
            dres = dwarf_dieoffset(cur_die,&cur_off,error);
            if (dres == DW_DLV_OK) {
                /* Normal. use cur_off. */
            } else if (dres == DW_DLV_ERROR) {
                /* Should be impossible unless... */
                /* avoid leak. */
                /*  Just leave cur_off as zero. */
                /* dwarf_dealloc(dbg,*error,DW_DLA_ERROR); */
                /* *error = NULL; */
                return DW_DLV_ERROR;
            } else { /* DW_DLV_NO_ENTRY */
                /* Impossible, dwarf_dieoffset never returns this */
            }
            /* Record offset in current entry chain */
            curr_chain = (Dwarf_Chain_2)_dwarf_get_alloc(
                dbg,DW_DLA_CHAIN_2,1);
            if (curr_chain == NULL) {
                _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return (DW_DLV_ERROR);
            }

            /* Put current offset on singly_linked list. */
            curr_chain->ch_item = cur_off;
            ++off_count;

            if (head_chain == NULL) {
                head_chain = prev_chain = curr_chain;
            }
            else {
                prev_chain->ch_next = curr_chain;
                prev_chain = curr_chain;
            }
        }

        /* Process any siblings entries if any */
        sib_die = 0;
        res = dwarf_siblingof_b(dbg,cur_die,is_info,&sib_die,error);
        if (DW_DLV_ERROR == res) {
            return res;
        }
        if (DW_DLV_NO_ENTRY == res) {
            /* Done at this level. */
            break;
        }
        /* res == DW_DLV_OK */
        if (cur_die != die) {
            dwarf_dealloc(dbg,cur_die,DW_DLA_DIE);
        }
        cur_die = sib_die;
    }

    /* Points to contiguous block of Dwarf_Off's. */
    ret_offsets = (Dwarf_Off *) _dwarf_get_alloc(dbg,
        DW_DLA_ADDR, off_count);
    if (ret_offsets == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }

    /*  Store offsets in contiguous block,
        and deallocate the chain. */
    curr_chain = head_chain;
    for (i = 0; i < off_count; i++) {
        *(ret_offsets + i) = curr_chain->ch_item;
        prev_chain = curr_chain;
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, prev_chain, DW_DLA_CHAIN_2);
    }

    *offbuf = ret_offsets;
    *offcnt = off_count;

    return DW_DLV_OK;
}

static void
empty_local_attrlist(Dwarf_Debug dbg,
    Dwarf_Attribute attr)
{
    Dwarf_Attribute cur = 0;
    Dwarf_Attribute next = 0;

    for (cur = attr; cur ; cur = next) {
        next = cur->ar_next;
        dwarf_dealloc(dbg,cur,DW_DLA_ATTR);
    }
}

/*  Now we use *_wrapper here,
    We cannot leak memory.
*/
int
dwarf_attrlist(Dwarf_Die die,
    Dwarf_Attribute ** attrbuf,
    Dwarf_Signed * attrcnt, Dwarf_Error * error)
{
    Dwarf_Unsigned attr_count = 0;
    Dwarf_Unsigned attr = 0;
    Dwarf_Unsigned attr_form = 0;
    Dwarf_Unsigned i = 0;
    Dwarf_Byte_Ptr abbrev_ptr = 0;
    Dwarf_Byte_Ptr abbrev_end = 0;
    Dwarf_Abbrev_List abbrev_list = 0;
    Dwarf_Attribute head_attr = NULL;
    Dwarf_Attribute curr_attr = NULL;
    Dwarf_Attribute *attr_ptr = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_Byte_Ptr die_info_end = 0;
    int lres = 0;
    Dwarf_CU_Context context = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    context = die->di_cu_context;
    dbg = context->cc_dbg;
    die_info_end =
        _dwarf_calculate_info_section_end_ptr(context);

    lres = _dwarf_get_abbrev_for_code(context,
        die->di_abbrev_list->abl_code,
        &abbrev_list,error);
    if (lres == DW_DLV_ERROR) {
        return lres;
    }
    if (lres == DW_DLV_NO_ENTRY) {
        _dwarf_error(dbg, error, DW_DLE_ABBREV_MISSING);
        return DW_DLV_ERROR;
    }

    abbrev_ptr = abbrev_list->abl_abbrev_ptr;
    abbrev_end = _dwarf_calculate_abbrev_section_end_ptr(context);


    info_ptr = die->di_debug_ptr;
    {
        /* SKIP_LEB128_WORD_CK(info_ptr,dbg,error,die_info_end); */
        Dwarf_Unsigned ignore_this = 0;
        Dwarf_Unsigned len = 0;

        lres = _dwarf_decode_u_leb128_chk(info_ptr,
            &len,&ignore_this,die_info_end);
        if (lres == DW_DLV_ERROR) {
            /* Stepped off the end SKIPping the leb  */
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_DIE_BAD: In building an attrlist "
                "we run off the end of the DIE while skipping "
                " the DIE tag, seeing the leb length as 0x%u ",
                len);
            _dwarf_error_string(dbg, error, DW_DLE_DIE_BAD,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        info_ptr += len;
    }

    do {
        Dwarf_Signed implicit_const = 0;
        Dwarf_Attribute new_attr = 0;
        int res = 0;

        /*  The DECODE have to be wrapped in functions to
            catch errors before return. */
        /*DECODE_LEB128_UWORD_CK(abbrev_ptr, utmp2,
            dbg,error,abbrev_end); */
        res = _dwarf_leb128_uword_wrapper(dbg,
            &abbrev_ptr,abbrev_end,&attr,error);
        if (res == DW_DLV_ERROR) {
            empty_local_attrlist(dbg,head_attr);
            return res;
        }
        if (attr > DW_AT_hi_user) {
            empty_local_attrlist(dbg,head_attr);
            _dwarf_error(dbg, error,DW_DLE_ATTR_CORRUPT);
            return DW_DLV_ERROR;
        }
        /*DECODE_LEB128_UWORD_CK(abbrev_ptr, utmp2,
            dbg,error,abbrev_end); */
        res = _dwarf_leb128_uword_wrapper(dbg,
            &abbrev_ptr,abbrev_end,&attr_form,error);
        if (res == DW_DLV_ERROR) {
            empty_local_attrlist(dbg,head_attr);
            return res;
        }
        if (!_dwarf_valid_form_we_know(attr_form,attr)) {
            empty_local_attrlist(dbg,head_attr);
            _dwarf_error(dbg, error, DW_DLE_UNKNOWN_FORM);
            return (DW_DLV_ERROR);
        }
        if (attr_form == DW_FORM_implicit_const) {
            /* The value is here, not in a DIE. */
            res = _dwarf_leb128_sword_wrapper(dbg,&abbrev_ptr,
                abbrev_end, &implicit_const, error);
            if (res == DW_DLV_ERROR) {
                empty_local_attrlist(dbg,head_attr);
                return res;
            }
            /*DECODE_LEB128_SWORD_CK(abbrev_ptr, implicit_const,
                dbg,error,abbrev_end); */
        }

        if (!_dwarf_valid_form_we_know(attr_form,attr)) {
            empty_local_attrlist(dbg,head_attr);
            _dwarf_error(dbg, error, DW_DLE_UNKNOWN_FORM);
            return DW_DLV_ERROR;
        }
        if (attr != 0) {
            new_attr = (Dwarf_Attribute)
                _dwarf_get_alloc(dbg, DW_DLA_ATTR, 1);
            if (new_attr == NULL) {
                empty_local_attrlist(dbg,head_attr);
                _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return DW_DLV_ERROR;
            }
            new_attr->ar_attribute = attr;
            new_attr->ar_attribute_form_direct = attr_form;
            new_attr->ar_attribute_form = attr_form;
            if (attr_form == DW_FORM_indirect) {
                Dwarf_Unsigned utmp6 = 0;

                if (_dwarf_reference_outside_section(die,
                    (Dwarf_Small*) info_ptr,
                    ((Dwarf_Small*) info_ptr )+1)) {
                    dwarf_dealloc(dbg,new_attr,DW_DLA_ATTR);
                    empty_local_attrlist(dbg,head_attr);
                    _dwarf_error_string(dbg, error,
                        DW_DLE_ATTR_OUTSIDE_SECTION,
                        "DW_DLE_ATTR_OUTSIDE_SECTION: "
                        " Reading Attriutes: "
                        "For DW_FORM_indirect there is"
                        " no room for the form. Corrupt Dwarf");
                    return DW_DLV_ERROR;
                }

                /*  DECODE_LEB128_UWORD does info_ptr update
                    DECODE_LEB128_UWORD_CK(info_ptr, utmp6,
                        dbg,error,die_info_end);
                */
                res = _dwarf_leb128_uword_wrapper(dbg,
                    &info_ptr,die_info_end,&utmp6,error);
                attr_form = (Dwarf_Half) utmp6;
                new_attr->ar_attribute_form = attr_form;
            }
            /*  Here the final address must be *inside* the
                section, as we will read from there, and read
                at least one byte, we think.
                We do not want info_ptr to point past end so
                we add 1 to the end-pointer.  */
            if ( attr_form != DW_FORM_implicit_const &&
                _dwarf_reference_outside_section(die,
                (Dwarf_Small*) info_ptr,
                ((Dwarf_Small*) info_ptr )+1)) {
                dwarf_dealloc(dbg,new_attr,DW_DLA_ATTR);
                empty_local_attrlist(dbg,head_attr);
                _dwarf_error_string(dbg, error,
                    DW_DLE_ATTR_OUTSIDE_SECTION,
                    "DW_DLE_ATTR_OUTSIDE_SECTION: "
                    " Reading Attriutes: "
                    "We have run off the end of the section. "
                    "Corrupt Dwarf");
                return DW_DLV_ERROR;
            }
            new_attr->ar_cu_context = die->di_cu_context;
            new_attr->ar_debug_ptr = info_ptr;
            new_attr->ar_die = die;
            new_attr->ar_dbg = dbg;
            if (attr_form == DW_FORM_implicit_const) {
                /*  The value is here, not in a DIE.
                    Do not increment info_ptr */
                new_attr->ar_implicit_const = implicit_const;
            } else {
                Dwarf_Unsigned sov = 0;
                int vres = 0;

                vres = _dwarf_get_size_of_val(dbg,
                    attr_form,
                    die->di_cu_context->cc_version_stamp,
                    die->di_cu_context->cc_address_size,
                    info_ptr,
                    die->di_cu_context->cc_length_size,
                    &sov,
                    die_info_end,
                    error);
                if(vres!= DW_DLV_OK) {
                    dwarf_dealloc(dbg,new_attr,DW_DLA_ATTR);
                    empty_local_attrlist(dbg,head_attr);
                    return vres;
                }
                info_ptr += sov;
            }
            if (head_attr == NULL)
                head_attr = curr_attr = new_attr;
            else {
                curr_attr->ar_next = new_attr;
                curr_attr = new_attr;
            }
            attr_count++;
        }
    } while (attr || attr_form);
    if (!attr_count) {
        *attrbuf = NULL;
        *attrcnt = 0;
        return (DW_DLV_NO_ENTRY);
    }
    attr_ptr = (Dwarf_Attribute *)
        _dwarf_get_alloc(dbg, DW_DLA_LIST, attr_count);
    if (attr_ptr == NULL) {
        empty_local_attrlist(dbg,head_attr);
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }
    curr_attr = head_attr;
    for (i = 0; i < attr_count; i++) {
        *(attr_ptr + i) = curr_attr;
        curr_attr = curr_attr->ar_next;
    }
    *attrbuf = attr_ptr;
    *attrcnt = attr_count;
    return (DW_DLV_OK);
}


/*
    This function takes a die, and an attr, and returns
    a pointer to the start of the value of that attr in
    the given die in the .debug_info section.  The form
    is returned in *attr_form.

    If the attr_form is DW_FORM_implicit_const
    (known signed, so most callers)
    that is fine, but in that case we do not
    need to actually set the *ptr_to_value.

    Returns NULL on error, or if attr is not found.
    However, *attr_form is 0 on error, and positive
    otherwise.
*/
static int
_dwarf_get_value_ptr(Dwarf_Die die,
    Dwarf_Half attr,
    Dwarf_Half * attr_form,
    Dwarf_Byte_Ptr * ptr_to_value,
    Dwarf_Signed *implicit_const_out,
    Dwarf_Error *error)
{
    Dwarf_Byte_Ptr abbrev_ptr = 0;
    Dwarf_Byte_Ptr abbrev_end = 0;
    Dwarf_Abbrev_List abbrev_list;
    Dwarf_Half curr_attr = 0;
    Dwarf_Half curr_attr_form = 0;
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_CU_Context context = die->di_cu_context;
    Dwarf_Byte_Ptr die_info_end = 0;
    Dwarf_Debug dbg = 0;
    int lres = 0;

    if (!context) {
        _dwarf_error(NULL,error,DW_DLE_DIE_NO_CU_CONTEXT);
        return DW_DLV_ERROR;
    }
    dbg = context->cc_dbg;
    die_info_end =
        _dwarf_calculate_info_section_end_ptr(context);

    lres = _dwarf_get_abbrev_for_code(context,
        die->di_abbrev_list->abl_code,
        &abbrev_list,error);
    if (lres == DW_DLV_ERROR) {
        return lres;
    }
    if (lres == DW_DLV_NO_ENTRY) {
        _dwarf_error(dbg,error,DW_DLE_CU_DIE_NO_ABBREV_LIST);
        return DW_DLV_ERROR;
    }

    abbrev_ptr = abbrev_list->abl_abbrev_ptr;
    abbrev_end = _dwarf_calculate_abbrev_section_end_ptr(context);

    info_ptr = die->di_debug_ptr;
    /* This ensures and checks die_info_end >= info_ptr */
    {
        /* SKIP_LEB128_WORD_CK(info_ptr,dbg,error,die_info_end); */
        Dwarf_Unsigned ignore_this = 0;
        Dwarf_Unsigned len = 0;

        lres = _dwarf_decode_u_leb128_chk(info_ptr,
            &len,&ignore_this,die_info_end);
        if (lres == DW_DLV_ERROR) {
            /* Stepped off the end SKIPping the leb  */
            dwarfstring m;
            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_DIE_BAD: In building an attrlist "
                "we run off the end of the DIE while skipping "
                " the DIE tag, seeing the leb length as 0x%u ",
                len);
            _dwarf_error_string(dbg, error, DW_DLE_DIE_BAD,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        info_ptr += len;
    }
    do {
        Dwarf_Unsigned formtmp3 = 0;
        Dwarf_Unsigned atmp3 = 0;
        Dwarf_Unsigned value_size=0;
        Dwarf_Signed implicit_const = 0;
        int res = 0;

        DECODE_LEB128_UWORD_CK(abbrev_ptr, atmp3,dbg,error,abbrev_end);
        if (atmp3 > DW_AT_hi_user) {
            _dwarf_error(dbg, error,DW_DLE_ATTR_CORRUPT);
            return DW_DLV_ERROR;
        }
        curr_attr = (Dwarf_Half) atmp3;

        DECODE_LEB128_UWORD_CK(abbrev_ptr,formtmp3,
            dbg,error,abbrev_end);
        if (!_dwarf_valid_form_we_know(formtmp3,curr_attr)) {
            _dwarf_error(dbg, error, DW_DLE_UNKNOWN_FORM);
            return (DW_DLV_ERROR);
        }

        curr_attr_form = (Dwarf_Half) formtmp3;
        if (curr_attr_form == DW_FORM_indirect) {
            Dwarf_Unsigned utmp6;

            /* DECODE_LEB128_UWORD updates info_ptr */
            DECODE_LEB128_UWORD_CK(info_ptr, utmp6,dbg,error,die_info_end);
            curr_attr_form = (Dwarf_Half) utmp6;
        }
        if (curr_attr_form == DW_FORM_implicit_const) {
            /* The value is here, not in a DIE. */
            DECODE_LEB128_SWORD_CK(abbrev_ptr, implicit_const,
                dbg,error,abbrev_end);
        }
        if (curr_attr == attr) {
            *attr_form = curr_attr_form;
            if(implicit_const_out) {
                *implicit_const_out = implicit_const;
            }
            *ptr_to_value = info_ptr;
            return DW_DLV_OK;
        }
        res = _dwarf_get_size_of_val(dbg,
            curr_attr_form,
            die->di_cu_context->cc_version_stamp,
            die->di_cu_context->cc_address_size,
            info_ptr,
            die->di_cu_context->cc_length_size,
            &value_size,
            die_info_end,
            error);
        if (res != DW_DLV_OK) {
            return res;
        }
        {
            /* ptrdiff_t is signed type, so use DW signed type */
            Dwarf_Signed len = die_info_end - info_ptr;
            if (len < 0 || (value_size > ((Dwarf_Unsigned)len))) {
                /*  Something badly wrong. We point past end
                    of debug_info or debug_types or a
                    section is unreasonably sized or we are
                    pointing to two different sections? */
                _dwarf_error(dbg,error,DW_DLE_DIE_ABBREV_BAD);
                return DW_DLV_ERROR;
            }
        }
        info_ptr+= value_size;
    } while (curr_attr != 0 || curr_attr_form != 0);
    return DW_DLV_NO_ENTRY;
}

int
dwarf_die_text(Dwarf_Die die,
    Dwarf_Half attrnum,
    char **ret_name,
    Dwarf_Error * error)
{
    Dwarf_Debug dbg = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Attribute attr = 0;
    Dwarf_Error lerr = 0;

    CHECK_DIE(die, DW_DLV_ERROR);

    res = dwarf_attr(die,attrnum,&attr,&lerr);
    dbg = die->di_cu_context->cc_dbg;
    if (res == DW_DLV_ERROR) {
        return DW_DLV_NO_ENTRY;
    }
    if (res == DW_DLV_NO_ENTRY) {
        return res;
    }
    res = dwarf_formstring(attr,ret_name,error);
    dwarf_dealloc(dbg,attr, DW_DLA_ATTR);
    attr = 0;
    return res;
}

int
dwarf_diename(Dwarf_Die die,
    char **ret_name,
    Dwarf_Error * error)
{
    return dwarf_die_text(die,DW_AT_name,ret_name,error);
}

int
dwarf_hasattr(Dwarf_Die die,
    Dwarf_Half attr,
    Dwarf_Bool * return_bool, Dwarf_Error * error)
{
    Dwarf_Half attr_form = 0;
    Dwarf_Byte_Ptr info_ptr = 0;
    int res = 0;
    Dwarf_Signed implicit_const;

    CHECK_DIE(die, DW_DLV_ERROR);

    res = _dwarf_get_value_ptr(die, attr, &attr_form,&info_ptr,
        &implicit_const,error);
    if(res == DW_DLV_ERROR) {
        return res;
    }
    if(res == DW_DLV_NO_ENTRY) {
        *return_bool = false;
        return DW_DLV_OK;
    }
    *return_bool = (true);
    return DW_DLV_OK;
}

int
dwarf_attr(Dwarf_Die die,
    Dwarf_Half attr,
    Dwarf_Attribute * ret_attr, Dwarf_Error * error)
{
    Dwarf_Half attr_form = 0;
    Dwarf_Attribute attrib = 0;
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_Debug dbg = 0;
    int res = 0;
    Dwarf_Signed implicit_const = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    dbg = die->di_cu_context->cc_dbg;

    res = _dwarf_get_value_ptr(die, attr, &attr_form,&info_ptr,
        &implicit_const,error);
    if(res == DW_DLV_ERROR) {
        return res;
    }
    if(res == DW_DLV_NO_ENTRY) {
        return res;
    }

    attrib = (Dwarf_Attribute) _dwarf_get_alloc(dbg, DW_DLA_ATTR, 1);
    if (!attrib) {
        _dwarf_error_string(dbg, error, DW_DLE_ALLOC_FAIL,
            "DW_DLE_ALLOC_FAIL allocating a single Dwarf_Attribute"
            " in function dwarf_attr().");
        return DW_DLV_ERROR;
    }

    attrib->ar_attribute = attr;
    attrib->ar_attribute_form = attr_form;
    attrib->ar_attribute_form_direct = attr_form;
    attrib->ar_cu_context = die->di_cu_context;

    /*  Only nonzero if DW_FORM_implicit_const */
    attrib->ar_implicit_const = implicit_const;
    /*  Only nonnull if not DW_FORM_implicit_const */
    attrib->ar_debug_ptr = info_ptr;
    attrib->ar_die = die;
    attrib->ar_dbg = dbg;
    *ret_attr = (attrib);
    return DW_DLV_OK;
}

/*  A DWP (.dwp) package object never contains .debug_addr,
    only a normal .o or executable object.
    Error returned here is on dbg, not tieddbg.
    This looks for DW_AT_addr_base and if present
    adds it in appropriately. */
int
_dwarf_extract_address_from_debug_addr(Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned index_to_addr,
    Dwarf_Addr *addr_out,
    Dwarf_Error *error)
{
    Dwarf_Unsigned address_base = 0;
    Dwarf_Unsigned addrindex = index_to_addr;
    Dwarf_Unsigned addr_offset = 0;
    Dwarf_Unsigned ret_addr = 0;
    int res = 0;
    Dwarf_Byte_Ptr  sectionstart = 0;
    Dwarf_Byte_Ptr  sectionend = 0;
    Dwarf_Unsigned  sectionsize  = 0;

    res = _dwarf_get_address_base_attr_value(dbg,context,
        &address_base, error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = _dwarf_load_section(dbg, &dbg->de_debug_addr,error);
    if (res != DW_DLV_OK) {
        /*  Ignore the inner error, report something meaningful */
        if (res == DW_DLV_ERROR) {
            dwarf_dealloc(dbg,*error, DW_DLA_ERROR);
            *error = 0;
        }
        _dwarf_error(dbg,error,
            DW_DLE_MISSING_NEEDED_DEBUG_ADDR_SECTION);
        return DW_DLV_ERROR;
    }
    /*  DW_FORM_addrx has a base value from the CU die:
        DW_AT_addr_base.  DW_OP_addrx and DW_OP_constx
        rely on DW_AT_addr_base too. */
    /*  DW_FORM_GNU_addr_index  relies on DW_AT_GNU_addr_base
        which is in the CU die. */

    sectionstart = dbg->de_debug_addr.dss_data;
    addr_offset = address_base + (addrindex * context->cc_address_size);
    /*  The offsets table is a series of address-size entries
        but with a base. */
    sectionsize = dbg->de_debug_addr.dss_size;
    sectionend = sectionstart + sectionsize;
    if (addr_offset > (sectionsize - context->cc_address_size)) {
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_SIZE_BAD);
        return (DW_DLV_ERROR);
    }
    READ_UNALIGNED_CK(dbg,ret_addr,Dwarf_Addr,
        sectionstart + addr_offset,
        context->cc_address_size,
        error,sectionend);
    *addr_out = ret_addr;
    return DW_DLV_OK;
}

static int
_dwarf_look_in_local_and_tied_by_index(
    Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned index,
    Dwarf_Addr *return_addr,
    Dwarf_Error *error)
{
    int res2 = 0;

    res2 = _dwarf_extract_address_from_debug_addr(dbg,
        context, index, return_addr, error);
    if (res2 != DW_DLV_OK) {
        if (res2 == DW_DLV_ERROR &&
            error &&
            dwarf_errno(*error) == DW_DLE_MISSING_NEEDED_DEBUG_ADDR_SECTION
            && dbg->de_tied_data.td_tied_object) {
            int res3 = 0;

            /*  We do not want to leak error structs... */
            dwarf_dealloc(dbg,*error,DW_DLA_ERROR);

            *error = 0;
            /* error is returned on dbg, not tieddbg. */
            res3 = _dwarf_get_addr_from_tied(dbg,
                context,index,return_addr,error);
            return res3;
        }
        return res2;
    }
    return DW_DLV_OK;
}

/*  The DIE here can be any DIE in the relevant CU.
    index is an index into .debug_addr */
int
dwarf_debug_addr_index_to_addr(Dwarf_Die die,
    Dwarf_Unsigned index,
    Dwarf_Addr *return_addr,
    Dwarf_Error *error)
{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context context = 0;
    int res = 0;


    CHECK_DIE(die, DW_DLV_ERROR);
    context = die->di_cu_context;
    dbg = context->cc_dbg;

    /* error is returned on dbg, not tieddbg. */
    res = _dwarf_look_in_local_and_tied_by_index(dbg,
        context,
        index,
        return_addr,
        error);
    return res;
}
/* ASSERT:
    attr_form == DW_FORM_GNU_addr_index ||
        attr_form == DW_FORM_addrx
*/
int
_dwarf_look_in_local_and_tied(Dwarf_Half attr_form,
    Dwarf_CU_Context context,
    Dwarf_Small *info_ptr,
    Dwarf_Addr *return_addr,
    Dwarf_Error *error)
{
    int res2 = 0;
    Dwarf_Unsigned index_to_addr = 0;
    Dwarf_Debug dbg = 0;

    /*  We get the index. It might apply here
        or in tied object. Checking that next. */
    dbg = context->cc_dbg;
    res2 = _dwarf_get_addr_index_itself(attr_form,
        info_ptr,dbg,context, &index_to_addr,error);
    if(res2 != DW_DLV_OK) {
        return res2;
    }
    /* error is returned on dbg, not tieddbg. */
    res2 = _dwarf_look_in_local_and_tied_by_index(
        dbg,context,index_to_addr,return_addr,error);
    return res2;

}

int
dwarf_lowpc(Dwarf_Die die,
    Dwarf_Addr * return_addr,
    Dwarf_Error * error)
{
    Dwarf_Addr ret_addr = 0;
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half offset_size = 0;
    int version = 0;
    enum Dwarf_Form_Class class = DW_FORM_CLASS_UNKNOWN;
    int res = 0;
    Dwarf_CU_Context context = die->di_cu_context;
    Dwarf_Small *die_info_end = 0;

    CHECK_DIE(die, DW_DLV_ERROR);

    dbg = context->cc_dbg;
    address_size = context->cc_address_size;
    offset_size = context->cc_length_size;
    res = _dwarf_get_value_ptr(die, DW_AT_low_pc,
        &attr_form,&info_ptr,0,error);
    if(res == DW_DLV_ERROR) {
        return res;
    }
    if(res == DW_DLV_NO_ENTRY) {
        return res;
    }
    version = context->cc_version_stamp;
    class = dwarf_get_form_class(version,DW_AT_low_pc,
        offset_size,attr_form);
    if (class != DW_FORM_CLASS_ADDRESS) {
        /* Not the correct form for DW_AT_low_pc */
        _dwarf_error(dbg, error, DW_DLE_LOWPC_WRONG_CLASS);
        return (DW_DLV_ERROR);
    }

    if(attr_form == DW_FORM_GNU_addr_index ||
        attr_form == DW_FORM_addrx) {
        /* error is returned on dbg, not tieddbg. */
        res = _dwarf_look_in_local_and_tied(
            attr_form,
            context,
            info_ptr,
            return_addr,
            error);
        return res;
    }
    die_info_end = _dwarf_calculate_info_section_end_ptr(context);
    READ_UNALIGNED_CK(dbg, ret_addr, Dwarf_Addr,
        info_ptr, address_size,
        error,die_info_end);

    *return_addr = ret_addr;
    return (DW_DLV_OK);
}


/*  This works for DWARF2 and DWARF3 but fails for DWARF4
    DW_AT_high_pc attributes of class constant.
    It is best to cease using this interface.
    */
int
dwarf_highpc(Dwarf_Die die,
    Dwarf_Addr * return_addr, Dwarf_Error * error)
{
    int res = 0;
    enum Dwarf_Form_Class class = DW_FORM_CLASS_UNKNOWN;
    Dwarf_Half form = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    res = dwarf_highpc_b(die,return_addr,&form,&class,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if (form != DW_FORM_addr) {
        /* Not the correct form for DWARF2/3 DW_AT_high_pc */
        Dwarf_Debug dbg = die->di_cu_context->cc_dbg;
        _dwarf_error(dbg, error, DW_DLE_HIGHPC_WRONG_FORM);
        return (DW_DLV_ERROR);
    }
    return (DW_DLV_OK);
}

/*  If the giving 'die' contains the DW_AT_type attribute, it returns
    the offset referenced by the attribute.
    In case of DW_DLV_NO_ENTRY or DW_DLV_ERROR it sets offset zero. */
int
dwarf_dietype_offset(Dwarf_Die die,
    Dwarf_Off *return_off, Dwarf_Error *error)
{
    int res = 0;
    Dwarf_Off offset = 0;
    Dwarf_Attribute attr = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    res = dwarf_attr(die,DW_AT_type,&attr,error);
    if (res == DW_DLV_OK) {
        res = dwarf_global_formref(attr,&offset,error);
        dwarf_dealloc(die->di_cu_context->cc_dbg,attr,DW_DLA_ATTR);
    }
    *return_off = offset;
    return res;
}



int
_dwarf_get_string_base_attr_value(Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned *sbase_out,
    Dwarf_Error *error)
{
    int res = 0;
    Dwarf_Die cudie = 0;
    Dwarf_Unsigned cu_die_offset = 0;
    Dwarf_Attribute myattr = 0;

    if(context->cc_str_offsets_base_present) {
        *sbase_out = context->cc_str_offsets_base;
        return DW_DLV_OK;
    }
    cu_die_offset = context->cc_cu_die_global_sec_offset;
    context->cc_cu_die_offset_present  = TRUE;
    res = dwarf_offdie_b(dbg,cu_die_offset,
        context->cc_is_info,
        &cudie,
        error);
    if(res != DW_DLV_OK) {
        return res;
    }
    res = dwarf_attr(cudie,DW_AT_str_offsets_base,
        &myattr,error);
    if(res == DW_DLV_ERROR) {
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        return res;
    }
    if (res == DW_DLV_OK) {
        Dwarf_Unsigned val = 0;
        /* Expect DW_FORM_sec_offset */
        if (myattr->ar_attribute_form != DW_FORM_sec_offset) {
            dwarf_dealloc(dbg,myattr,DW_DLA_ATTR);
            dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
            _dwarf_error(dbg, error,DW_DLE_STR_OFFSETS_BASE_WRONG_FORM);
            return (DW_DLV_ERROR);
        }
        res = dwarf_global_formref(myattr,&val,error);
        dwarf_dealloc(dbg,myattr,DW_DLA_ATTR);
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        if(res != DW_DLV_OK) {
            return res;
        }
        *sbase_out  = val;
        context->cc_str_offsets_base = val;
        context->cc_str_offsets_base_present = TRUE;
        return DW_DLV_OK;
    }
    /*  NO ENTRY, No other attr.Not even GNU, this one is standard
        DWARF5 only.  */
    dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
    /*  We do not need a base for a .dwo. We might for .dwp
        and would or .o or executable.
        FIXME: assume we do not need this.
        Should we really return DW_DLV_NO_ENTRY?
    */
    *sbase_out = 0;
    return DW_DLV_OK;
}
/*  Goes to the CU die and finds the DW_AT_GNU_addr_base
    (or DW_AT_addr_base ) and gets the value from that CU die
    and returns it through abase_out. If we cannot find the value
    it is a serious error in the DWARF.
    */
static int
_dwarf_get_address_base_attr_value(Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned *abase_out,
    Dwarf_Error *error)
{
    int res = 0;
    Dwarf_Die cudie = 0;
    Dwarf_Bool cu_die_offset_present = 0;
    Dwarf_Unsigned cu_die_offset = 0;
    Dwarf_Attribute myattr = 0;
    if(context->cc_addr_base_present) {
        *abase_out = context->cc_addr_base;
        return DW_DLV_OK;
    }

    cu_die_offset = context->cc_cu_die_global_sec_offset;
    cu_die_offset_present = context->cc_cu_die_offset_present;
    if(!cu_die_offset_present) {
        _dwarf_error(dbg, error,
            DW_DLE_DEBUG_CU_UNAVAILABLE_FOR_FORM);
        return (DW_DLV_ERROR);

    }
    res = dwarf_offdie_b(dbg,cu_die_offset,
        context->cc_is_info,
        &cudie,
        error);
    if(res != DW_DLV_OK) {
        return res;
    }
    res = dwarf_attr(cudie,DW_AT_addr_base,
        &myattr,error);
    if(res == DW_DLV_ERROR) {
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        return res;
    }
    if (res == DW_DLV_OK) {
        Dwarf_Unsigned val = 0;
        res = dwarf_formudata(myattr,&val,error);
        dwarf_dealloc(dbg,myattr,DW_DLA_ATTR);
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        if(res != DW_DLV_OK) {
            return res;
        }
        *abase_out  = val;
        return DW_DLV_OK;
    }
    /* NO ENTRY, try the other attr. */
    res = dwarf_attr(cudie,DW_AT_GNU_addr_base, &myattr,error);
    if(res == DW_DLV_NO_ENTRY) {
        res = dwarf_attr(cudie,DW_AT_addr_base, &myattr,error);
        if (res == DW_DLV_NO_ENTRY) {
            /*  A .o or .dwp needs a base, but a .dwo does not.
                FIXME: check this claim...
                Assume zero is ok and works. */
            *abase_out = 0;
            dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
            return DW_DLV_OK;
        }
        if (res == DW_DLV_ERROR) {
            dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
            return res;
        }
    } else if (res == DW_DLV_ERROR) {
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        return res;
    }

    {
        Dwarf_Unsigned val = 0;
        res = dwarf_formudata(myattr,&val,error);
        dwarf_dealloc(dbg,myattr,DW_DLA_ATTR);
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        if(res != DW_DLV_OK) {
            return res;
        }
        *abase_out  = val;
    }
    return DW_DLV_OK;
}


/* The dbg here will be the tieddbg, and context will be
   a tied context.  */
static int
_dwarf_get_ranges_base_attr_value(Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned * rangesbase_out,
    Dwarf_Error    * error)
{
    int res = 0;
    Dwarf_Die cudie = 0;
    Dwarf_Bool cu_die_offset_present = 0;
    Dwarf_Unsigned cu_die_offset = 0;
    Dwarf_Attribute myattr = 0;

    if (!context) {
        _dwarf_error(dbg, error,
            DW_DLE_DEBUG_CU_UNAVAILABLE_FOR_FORM);
        return (DW_DLV_ERROR);
    }
    if(context->cc_ranges_base_present) {
        *rangesbase_out = context->cc_ranges_base;
        return DW_DLV_OK;
    }
    cu_die_offset = context->cc_cu_die_global_sec_offset;
    cu_die_offset_present = context->cc_cu_die_offset_present;
    if(!cu_die_offset_present) {
        _dwarf_error(dbg, error,
            DW_DLE_DEBUG_CU_UNAVAILABLE_FOR_FORM);
        return (DW_DLV_ERROR);

    }
    res = dwarf_offdie_b(dbg,cu_die_offset,
        context->cc_is_info,
        &cudie,
        error);
    if(res != DW_DLV_OK) {
        return res;
    }
    res = dwarf_attr(cudie,DW_AT_rnglists_base,
        &myattr,error);
    if(res == DW_DLV_ERROR) {
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        return res;
    }
    if (res == DW_DLV_OK) {
        Dwarf_Unsigned val = 0;
        res = dwarf_formudata(myattr,&val,error);
        dwarf_dealloc(dbg,myattr,DW_DLA_ATTR);
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        if(res != DW_DLV_OK) {
            return res;
        }
        *rangesbase_out  = val;
        return DW_DLV_OK;
    }
    /* NO ENTRY, try the other attr. */
    res = dwarf_attr(cudie,DW_AT_GNU_ranges_base, &myattr,error);
    if(res == DW_DLV_NO_ENTRY) {
        res = dwarf_attr(cudie,DW_AT_rnglists_base, &myattr,error);
        if (res == DW_DLV_NO_ENTRY) {
            /*  A .o or execeutable skeleton  needs
                a base , but a .dwo does not.
                Assume zero is ok and works. */
            *rangesbase_out = 0;
            dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
            return DW_DLV_OK;
        }
        if (res == DW_DLV_ERROR) {
            dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
            return res;
        }
    } else if (res == DW_DLV_ERROR) {
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        return res;
    }

    {
        Dwarf_Unsigned val = 0;
        res = dwarf_formudata(myattr,&val,error);
        dwarf_dealloc(dbg,myattr,DW_DLA_ATTR);
        dwarf_dealloc(dbg,cudie,DW_DLA_DIE);
        if(res != DW_DLV_OK) {
            return res;
        }
        *rangesbase_out  = val;
    }
    return DW_DLV_OK;
}
/*  This works for  all versions of DWARF.
    This is the preferred interface, cease using dwarf_highpc.
    The consumer has to check the return_form or
    return_class to decide if the value returned
    through return_value is an address or an address-offset.

    See  DWARF4 section 2.17.2,
    "Contiguous Address Range".
    */
int
dwarf_highpc_b(Dwarf_Die die,
    Dwarf_Addr * return_value,
    Dwarf_Half * return_form,
    enum Dwarf_Form_Class * return_class,
    Dwarf_Error * error)
{
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Half address_size = 0;
    Dwarf_Half offset_size = 0;
    enum Dwarf_Form_Class class = DW_FORM_CLASS_UNKNOWN;
    Dwarf_Half version = 0;
    Dwarf_Byte_Ptr die_info_end = 0;
    int res = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    dbg = die->di_cu_context->cc_dbg;
    address_size = die->di_cu_context->cc_address_size;

    res = _dwarf_get_value_ptr(die, DW_AT_high_pc,
        &attr_form,&info_ptr,0,error);
    if(res == DW_DLV_ERROR) {
        return res;
    }
    if(res == DW_DLV_NO_ENTRY) {
        return res;
    }
    die_info_end = _dwarf_calculate_info_section_end_ptr(
        die->di_cu_context);

    version = die->di_cu_context->cc_version_stamp;
    offset_size = die->di_cu_context->cc_length_size;
    class = dwarf_get_form_class(version,DW_AT_high_pc,
        offset_size,attr_form);

    if (class == DW_FORM_CLASS_ADDRESS) {
        Dwarf_Addr addr = 0;
        if (dwarf_addr_form_is_indexed(attr_form)) {
            Dwarf_Unsigned addr_out = 0;
            Dwarf_Unsigned index_to_addr = 0;
            int res2 = 0;
            Dwarf_CU_Context context = die->di_cu_context;

            /*  index_to_addr we get here might apply
                to this dbg or to tieddbg. */
            /* error is returned on dbg, not tied */
            res2 = _dwarf_get_addr_index_itself(attr_form,
                info_ptr,dbg,context,&index_to_addr,error);
            if(res2 != DW_DLV_OK) {
                return res2;
            }

            res2 = _dwarf_extract_address_from_debug_addr(dbg,
                context,
                index_to_addr,
                &addr_out,
                error);
            if(res2 != DW_DLV_OK) {
                if (res2 == DW_DLV_ERROR &&
                    error &&
                    dwarf_errno(*error) ==
                    DW_DLE_MISSING_NEEDED_DEBUG_ADDR_SECTION
                    && dbg->de_tied_data.td_tied_object) {
                    /*  .debug_addr is in tied dbg. */
                    int res3 = 0;

                    /*  Do not leak the above error pointer,
                        we have something else to try here. */
                    dwarf_dealloc(dbg,*error, DW_DLA_ERROR);
                    *error = 0;

                    /*  .debug_addr is in tied dbg.
                        Get the index of the addr */
                    res3 = _dwarf_get_addr_from_tied(dbg,
                        context,index_to_addr,&addr_out,error);
                    if ( res3 != DW_DLV_OK) {
                        return res3;
                    }
                } else {
                    return res2;
                }
            }
            *return_value = addr_out;
            /*  Allow null args starting 22 April 2019. */
            if (return_form) {
                *return_form = attr_form;
            }
            if (return_class) {
                *return_class = class;
            }
            return (DW_DLV_OK);
        }

        READ_UNALIGNED_CK(dbg, addr, Dwarf_Addr,
            info_ptr, address_size,
            error,die_info_end);
        *return_value = addr;
    } else {
        int res3 = 0;
        Dwarf_Unsigned v = 0;
        res3 = _dwarf_die_attr_unsigned_constant(die,DW_AT_high_pc,
            &v,error);
        if(res3 != DW_DLV_OK) {
            Dwarf_Byte_Ptr info_ptr2 = 0;

            res3 = _dwarf_get_value_ptr(die, DW_AT_high_pc,
                &attr_form,&info_ptr2,0,error);
            if(res3 == DW_DLV_ERROR) {
                return res3;
            }
            if(res3 == DW_DLV_NO_ENTRY) {
                return res3;
            }
            if (attr_form == DW_FORM_sdata) {
                Dwarf_Signed sval = 0;

                /*  DWARF4 defines the value as an unsigned offset
                    in section 2.17.2. */
                DECODE_LEB128_UWORD_CK(info_ptr2, sval,
                    dbg,error,die_info_end);
                *return_value = (Dwarf_Unsigned)sval;
            } else {
                _dwarf_error(dbg, error, DW_DLE_HIGHPC_WRONG_FORM);
                return DW_DLV_ERROR;
            }
        } else {
            *return_value = v;
        }
    }
    /*  Allow null args starting 22 April 2019. */
    if (return_form) {
        *return_form = attr_form;
    }
    if (return_class) {
        *return_class = class;
    }
    return DW_DLV_OK;
}

/* The dbg and context here are a file with DW_FORM_addrx
    but missing .debug_addr. So go to the tied file
    and using the signature from the current context
    locate the target CU in the tied file Then
    get the address.

*/
int
_dwarf_get_addr_from_tied(Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned index,
    Dwarf_Addr *addr_out,
    Dwarf_Error*error)
{
    Dwarf_Debug tieddbg = 0;
    int res = 0;
    Dwarf_Addr local_addr = 0;
    Dwarf_CU_Context tiedcontext = 0;

    if (!context->cc_signature_present) {
        _dwarf_error(dbg, error, DW_DLE_NO_SIGNATURE_TO_LOOKUP);
        return  DW_DLV_ERROR;
    }
    tieddbg = dbg->de_tied_data.td_tied_object;
    if (!tieddbg) {
        _dwarf_error(dbg, error, DW_DLE_NO_TIED_ADDR_AVAILABLE);
        return  DW_DLV_ERROR;
    }
    if (!context->cc_signature_present) {
        _dwarf_error(dbg, error, DW_DLE_NO_TIED_SIG_AVAILABLE);
        return  DW_DLV_ERROR;
    }
    res = _dwarf_search_for_signature(tieddbg,
        context->cc_signature,
        &tiedcontext,
        error);
    if ( res == DW_DLV_ERROR) {
        /* Associate the error with dbg, not tieddbg */
        _dwarf_error_mv_s_to_t(tieddbg,error,dbg,error);
        return res;
    } else if ( res == DW_DLV_NO_ENTRY) {
        return res;
    }

    res = _dwarf_extract_address_from_debug_addr(tieddbg,
        tiedcontext,
        index,
        &local_addr,
        error);
    if ( res == DW_DLV_ERROR) {
        /* Associate the error with dbg, not tidedbg */
        _dwarf_error_mv_s_to_t(tieddbg,error,dbg,error);
        return res;
    } else if ( res == DW_DLV_NO_ENTRY) {
        return res;
    }
    *addr_out = local_addr;
    return DW_DLV_OK;
}

int
_dwarf_get_ranges_base_attr_from_tied(Dwarf_Debug dbg,
    Dwarf_CU_Context context,
    Dwarf_Unsigned * ranges_base_out,
    Dwarf_Unsigned * addr_base_out,
    Dwarf_Error*error)
{
    Dwarf_Debug tieddbg = 0;
    int res = 0;
    Dwarf_Unsigned tiedbase= 0;
    Dwarf_CU_Context tiedcontext = 0;

    if (!context->cc_signature_present) {
        _dwarf_error(dbg, error, DW_DLE_NO_SIGNATURE_TO_LOOKUP);
        return  DW_DLV_ERROR;
    }
    tieddbg = dbg->de_tied_data.td_tied_object;
    if (!tieddbg) {
        _dwarf_error(dbg, error, DW_DLE_NO_TIED_ADDR_AVAILABLE);
        return  DW_DLV_ERROR;
    }
    if (!context->cc_signature_present) {
        _dwarf_error(dbg, error, DW_DLE_NO_TIED_SIG_AVAILABLE);
        return  DW_DLV_ERROR;
    }
    res = _dwarf_search_for_signature(tieddbg,
        context->cc_signature,
        &tiedcontext,
        error);
    if ( res == DW_DLV_ERROR) {
        /* Associate the error with dbg, not tidedbg */
        _dwarf_error_mv_s_to_t(tieddbg,error,dbg,error);
        return res;
    } else if ( res == DW_DLV_NO_ENTRY) {
        return res;
    }
    res = _dwarf_get_ranges_base_attr_value(tieddbg, tiedcontext,
        &tiedbase, error);
    if (res != DW_DLV_OK) {
        /* Associate the error with dbg, not tidedbg */
        _dwarf_error_mv_s_to_t(tieddbg,error,dbg,error);
        return res;
    }
    *ranges_base_out = tiedbase;
    *addr_base_out =  tiedcontext->cc_addr_base;
    return DW_DLV_OK;
}


/*
    Takes a die, an attribute attr, and checks if attr
    occurs in die.  Attr is required to be an attribute
    whose form is in the "constant" class.  If attr occurs
    in die, the value is returned.

    Returns DW_DLV_OK, DW_DLV_ERROR, or DW_DLV_NO_ENTRY as
    appropriate. Sets the value thru the pointer return_val.

    This function is meant to do all the
    processing for dwarf_bytesize, dwarf_bitsize, dwarf_bitoffset,
    and dwarf_srclang. And it helps in dwarf_highpc_with_form().
*/
static int
_dwarf_die_attr_unsigned_constant(Dwarf_Die die,
    Dwarf_Half attr,
    Dwarf_Unsigned * return_val,
    Dwarf_Error * error)
{
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Unsigned ret_value = 0;
    Dwarf_Debug dbg = 0;
    int res = 0;
    Dwarf_Byte_Ptr die_info_end = 0;

    CHECK_DIE(die, DW_DLV_ERROR);

    die_info_end = _dwarf_calculate_info_section_end_ptr(die->di_cu_context);
    dbg = die->di_cu_context->cc_dbg;
    res = _dwarf_get_value_ptr(die,attr,&attr_form,
        &info_ptr,0,error);
    if(res != DW_DLV_OK) {
        return res;
    }
    switch (attr_form) {
    case DW_FORM_data1:
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned,
            info_ptr, sizeof(Dwarf_Small),
            error,die_info_end);
        *return_val = ret_value;
        return (DW_DLV_OK);

    case DW_FORM_data2:
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned,
            info_ptr, sizeof(Dwarf_Shalf),
            error,die_info_end);
        *return_val = ret_value;
        return (DW_DLV_OK);

    case DW_FORM_data4:
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned,
            info_ptr, DWARF_32BIT_SIZE,
            error,die_info_end);
        *return_val = ret_value;
        return (DW_DLV_OK);

    case DW_FORM_data8:
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned,
            info_ptr, DWARF_64BIT_SIZE,
            error,die_info_end);
        *return_val = ret_value;
        return (DW_DLV_OK);

    case DW_FORM_udata: {
        Dwarf_Unsigned v = 0;

        DECODE_LEB128_UWORD_CK(info_ptr, v,dbg,error,die_info_end);
        *return_val = v;
        return DW_DLV_OK;


    }

    default:
        _dwarf_error(dbg, error, DW_DLE_DIE_BAD);
        return (DW_DLV_ERROR);
    }
}


int
dwarf_bytesize(Dwarf_Die die,
    Dwarf_Unsigned * ret_size, Dwarf_Error * error)
{
    Dwarf_Unsigned luns = 0;
    int res = _dwarf_die_attr_unsigned_constant(die, DW_AT_byte_size,
        &luns, error);
    *ret_size = luns;
    return res;
}


int
dwarf_bitsize(Dwarf_Die die,
    Dwarf_Unsigned * ret_size, Dwarf_Error * error)
{
    Dwarf_Unsigned luns = 0;
    int res = _dwarf_die_attr_unsigned_constant(die, DW_AT_bit_size,
        &luns, error);
    *ret_size = luns;
    return res;
}


int
dwarf_bitoffset(Dwarf_Die die,
    Dwarf_Unsigned * ret_size, Dwarf_Error * error)
{
    Dwarf_Unsigned luns = 0;
    int res = _dwarf_die_attr_unsigned_constant(die,
        DW_AT_bit_offset, &luns, error);
    *ret_size = luns;
    return res;
}


/* Refer section 3.1, page 21 in Dwarf Definition. */
int
dwarf_srclang(Dwarf_Die die,
    Dwarf_Unsigned * ret_size, Dwarf_Error * error)
{
    Dwarf_Unsigned luns = 0;
    int res = _dwarf_die_attr_unsigned_constant(die, DW_AT_language,
        &luns, error);
    *ret_size = luns;
    return res;
}


/* Refer section 5.4, page 37 in Dwarf Definition. */
int
dwarf_arrayorder(Dwarf_Die die,
    Dwarf_Unsigned * ret_size, Dwarf_Error * error)
{
    Dwarf_Unsigned luns = 0;
    int res = _dwarf_die_attr_unsigned_constant(die, DW_AT_ordering,
        &luns, error);
    *ret_size = luns;
    return res;
}

/*  Return DW_DLV_OK if ok
    DW_DLV_ERROR if failure.

    If the die and the attr are not related the result is
    meaningless.  */
int
dwarf_attr_offset(Dwarf_Die die, Dwarf_Attribute attr,
    Dwarf_Off * offset /* return offset thru this ptr */,
    Dwarf_Error * error)
{
    Dwarf_Off attroff = 0;
    Dwarf_Small *dataptr = 0;
    Dwarf_Debug dbg = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    dbg = die->di_cu_context->cc_dbg;
    dataptr = die->di_is_info? dbg->de_debug_info.dss_data:
        dbg->de_debug_types.dss_data;

    attroff = (attr->ar_debug_ptr - dataptr);
    *offset = attroff;
    return DW_DLV_OK;
}

int
dwarf_die_abbrev_code(Dwarf_Die die)
{
    return die->di_abbrev_code;
}

/*  Returns a flag through ablhas_child. Non-zero if
    the DIE has children, zero if it does not.
    It has no Dwarf_Error arg!
*/
int
dwarf_die_abbrev_children_flag(Dwarf_Die die,Dwarf_Half *ab_has_child)
{
    if (die->di_abbrev_list) {
        *ab_has_child = die->di_abbrev_list->abl_has_child;
        return DW_DLV_OK;
    }
    return DW_DLV_ERROR;
}

/* Helper function for finding form class. */
static enum Dwarf_Form_Class
dw_get_special_offset(Dwarf_Half attrnum,
    Dwarf_Half dwversion)
{
    switch (attrnum) {
    case DW_AT_stmt_list:
        return DW_FORM_CLASS_LINEPTR;
    case DW_AT_macro_info: /* DWARF2-DWARF4 */
        return DW_FORM_CLASS_MACPTR;
    case DW_AT_start_scope:
    case DW_AT_ranges: {
        if (dwversion <= 4) {
            return DW_FORM_CLASS_RANGELISTPTR;
        }
        return DW_FORM_CLASS_RNGLIST;
        }
    case DW_AT_rnglists_base: /* DWARF5 */
        return DW_FORM_CLASS_RNGLISTSPTR;
    case DW_AT_macros:        /* DWARF5 */
        return DW_FORM_CLASS_MACROPTR;
    case DW_AT_loclists_base: /* DWARF5 */
        return DW_FORM_CLASS_LOCLISTSPTR;
    case DW_AT_addr_base:     /* DWARF5 */
        return DW_FORM_CLASS_ADDRPTR;
    case DW_AT_str_offsets_base: /* DWARF5 */
        return DW_FORM_CLASS_STROFFSETSPTR;

    case DW_AT_location:
    case DW_AT_string_length:
    case DW_AT_return_addr:
    case DW_AT_data_member_location:
    case DW_AT_frame_base:
    case DW_AT_segment:
    case DW_AT_static_link:
    case DW_AT_use_location:
    case DW_AT_vtable_elem_location: {
        if (dwversion <= 4) {
            return DW_FORM_CLASS_LOCLIST;
        }
        return DW_FORM_CLASS_LOCLISTPTR;
        }
    case DW_AT_sibling:
    case DW_AT_byte_size :
    case DW_AT_bit_offset :
    case DW_AT_bit_size :
    case DW_AT_discr :
    case DW_AT_import :
    case DW_AT_common_reference:
    case DW_AT_containing_type:
    case DW_AT_default_value:
    case DW_AT_lower_bound:
    case DW_AT_bit_stride:
    case DW_AT_upper_bound:
    case DW_AT_abstract_origin:
    case DW_AT_base_types:
    case DW_AT_count:
    case DW_AT_friend:
    case DW_AT_namelist_item:
    case DW_AT_priority:
    case DW_AT_specification:
    case DW_AT_type:
    case DW_AT_allocated:
    case DW_AT_associated:
    case DW_AT_byte_stride:
    case DW_AT_extension:
    case DW_AT_trampoline:
    case DW_AT_small:
    case DW_AT_object_pointer:
    case DW_AT_signature:
        return DW_FORM_CLASS_REFERENCE;
    case DW_AT_MIPS_fde: /* SGI/IRIX extension */
        return DW_FORM_CLASS_FRAMEPTR;
    }
    return DW_FORM_CLASS_UNKNOWN;
}

/* It takes 4 pieces of data (including the FORM)
   to accurately determine the form 'class' as documented
   in the DWARF spec. This is per DWARF4, but will work
   for DWARF2 or 3 as well.  */
enum Dwarf_Form_Class
dwarf_get_form_class(
    Dwarf_Half dwversion,
    Dwarf_Half attrnum,
    Dwarf_Half offset_size,
    Dwarf_Half form)
{
    switch (form) {
    case  DW_FORM_addr:  return DW_FORM_CLASS_ADDRESS;
    case  DW_FORM_data2:  return DW_FORM_CLASS_CONSTANT;

    case  DW_FORM_data4:
        if (dwversion <= 3 && offset_size == 4) {
            enum Dwarf_Form_Class class = dw_get_special_offset(attrnum,
                dwversion);
            if (class != DW_FORM_CLASS_UNKNOWN) {
                return class;
            }
        }
        return DW_FORM_CLASS_CONSTANT;
    case  DW_FORM_data8:
        if (dwversion <= 3 && offset_size == 8) {
            enum Dwarf_Form_Class class = dw_get_special_offset(attrnum,
                dwversion);
            if (class != DW_FORM_CLASS_UNKNOWN) {
                return class;
            }
        }
        return DW_FORM_CLASS_CONSTANT;
    case  DW_FORM_sec_offset:
        {
            enum Dwarf_Form_Class class = dw_get_special_offset(attrnum,
                dwversion);
            if (class != DW_FORM_CLASS_UNKNOWN) {
                return class;
            }
        }
        /* We do not know what this is. */
        break;

    case  DW_FORM_string: return DW_FORM_CLASS_STRING;
    case  DW_FORM_strp:   return DW_FORM_CLASS_STRING;

    case  DW_FORM_block:  return DW_FORM_CLASS_BLOCK;
    case  DW_FORM_block1: return DW_FORM_CLASS_BLOCK;
    case  DW_FORM_block2: return DW_FORM_CLASS_BLOCK;
    case  DW_FORM_block4: return DW_FORM_CLASS_BLOCK;

    case  DW_FORM_data16:  return DW_FORM_CLASS_CONSTANT;
    case  DW_FORM_data1:  return DW_FORM_CLASS_CONSTANT;
    case  DW_FORM_sdata:  return DW_FORM_CLASS_CONSTANT;
    case  DW_FORM_udata:  return DW_FORM_CLASS_CONSTANT;

    case  DW_FORM_ref_addr:    return DW_FORM_CLASS_REFERENCE;
    case  DW_FORM_ref1:        return DW_FORM_CLASS_REFERENCE;
    case  DW_FORM_ref2:        return DW_FORM_CLASS_REFERENCE;
    case  DW_FORM_ref4:        return DW_FORM_CLASS_REFERENCE;
    case  DW_FORM_ref8:        return DW_FORM_CLASS_REFERENCE;
    case  DW_FORM_ref_udata:   return DW_FORM_CLASS_REFERENCE;
    case  DW_FORM_ref_sig8:    return DW_FORM_CLASS_REFERENCE;

    case  DW_FORM_exprloc:      return DW_FORM_CLASS_EXPRLOC;

    case  DW_FORM_flag:         return DW_FORM_CLASS_FLAG;
    case  DW_FORM_flag_present: return DW_FORM_CLASS_FLAG;

    case  DW_FORM_addrx:           return DW_FORM_CLASS_ADDRESS; /* DWARF5 */
    case  DW_FORM_GNU_addr_index:  return DW_FORM_CLASS_ADDRESS;
    case  DW_FORM_strx:            return DW_FORM_CLASS_STRING;  /* DWARF5 */
    case  DW_FORM_GNU_str_index:   return DW_FORM_CLASS_STRING;

    case  DW_FORM_rnglistx:     return DW_FORM_CLASS_RNGLIST;    /* DWARF5 */
    case  DW_FORM_loclistx:     return DW_FORM_CLASS_LOCLIST;    /* DWARF5 */

    case  DW_FORM_GNU_ref_alt:  return DW_FORM_CLASS_REFERENCE;
    case  DW_FORM_GNU_strp_alt: return DW_FORM_CLASS_STRING;
    case  DW_FORM_strp_sup:     return DW_FORM_CLASS_STRING;    /* DWARF5 */
    case  DW_FORM_implicit_const: return DW_FORM_CLASS_CONSTANT; /* DWARF5 */

    case  DW_FORM_indirect:
    default:
        break;
    };
    return DW_FORM_CLASS_UNKNOWN;
}

/*  Given a DIE, figure out what the CU's DWARF version is
    and the size of an offset
    and return it through the *version pointer and return
    DW_DLV_OK.

    If we cannot find a CU,
        return DW_DLV_ERROR on error.
        In case of error no Dwarf_Debug was available,
        so setting a Dwarf_Error is somewhat futile.
    Never returns DW_DLV_NO_ENTRY.
*/
int
dwarf_get_version_of_die(Dwarf_Die die,
    Dwarf_Half *version,
    Dwarf_Half *offset_size)
{
    Dwarf_CU_Context cucontext = 0;
    if (!die) {
        return DW_DLV_ERROR;
    }
    cucontext = die->di_cu_context;
    if (!cucontext) {
        return DW_DLV_ERROR;
    }
    *version = cucontext->cc_version_stamp;
    *offset_size = cucontext->cc_length_size;
    return DW_DLV_OK;
}

Dwarf_Byte_Ptr
_dwarf_calculate_info_section_start_ptr(Dwarf_CU_Context context,
    Dwarf_Unsigned *section_len)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Small *dataptr = 0;
    struct Dwarf_Section_s *sec = 0;

    dbg = context->cc_dbg;
    sec = context->cc_is_info? &dbg->de_debug_info: &dbg->de_debug_types;
    dataptr = sec->dss_data;
    *section_len = sec->dss_size;
    return dataptr;
}

Dwarf_Byte_Ptr
_dwarf_calculate_info_section_end_ptr(Dwarf_CU_Context context)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Byte_Ptr info_end = 0;
    Dwarf_Byte_Ptr info_start = 0;
    Dwarf_Off off2 = 0;
    Dwarf_Small *dataptr = 0;

    dbg = context->cc_dbg;
    dataptr = context->cc_is_info? dbg->de_debug_info.dss_data:
        dbg->de_debug_types.dss_data;
    off2 = context->cc_debug_offset;
    info_start = dataptr + off2;
    info_end = info_start + context->cc_length +
        context->cc_length_size +
        context->cc_extension_size;
    return info_end;
}
Dwarf_Byte_Ptr
_dwarf_calculate_abbrev_section_end_ptr(Dwarf_CU_Context context)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Byte_Ptr abbrev_end = 0;
    Dwarf_Byte_Ptr abbrev_start = 0;
    struct Dwarf_Section_s *sec = 0;

    dbg = context->cc_dbg;
    sec = &dbg->de_debug_abbrev;
    abbrev_start = sec->dss_data;
    abbrev_end = abbrev_start + sec->dss_size;
    return abbrev_end;
}
