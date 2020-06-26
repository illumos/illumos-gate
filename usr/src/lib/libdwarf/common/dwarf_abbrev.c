/*
  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2009-2019 David Anderson. All Rights Reserved.

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

*/

#include "config.h"
#include <stdio.h>
#include "dwarf_incl.h"
#include "dwarf_abbrev.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarfstring.h"

#define TRUE 1
#define FALSE 0

/*  This is used to print a .debug_abbrev section without
    knowing about the DIEs that use the abbrevs.

    dwarf_get_abbrev() and,
    in dwarf_util.c,  _dwarf_get_abbrev_for_code()


    When we have a simple .o
    there is at least a hope of iterating through
    the abbrevs meaningfully without knowing
    a CU context.

    This often fails or gets incorrect info
    because there is no guarantee the .debug_abbrev
    section is free of garbage bytes.

    In an object with multiple CU/TUs the
    output is difficult/impossible to usefully interpret.

    In a dwp (Package File)  it is really impossible
    to associate abbrevs with a CU.

*/

int
_dwarf_count_abbrev_entries(Dwarf_Debug dbg,
    Dwarf_Byte_Ptr abbrev_ptr,
    Dwarf_Byte_Ptr abbrev_section_end,
    Dwarf_Unsigned *abbrev_count_out,
    Dwarf_Byte_Ptr *abbrev_ptr_out,
    Dwarf_Error *error)
{
    Dwarf_Unsigned abbrev_count = 0;
    Dwarf_Unsigned attr_name = 0;
    Dwarf_Unsigned attr_form = 0;
    UNUSEDARG Dwarf_Unsigned implicit_const = 0;

    /*  The abbreviations table ends with an entry with a single
        byte of zero for the abbreviation code.
        Padding bytes following that zero are allowed, but
        here we simply stop looking past that zero abbrev.

        We also stop looking if the block/section ends,
        though the DWARF2 and later standards do not specifically
        allow section/block end to terminate an abbreviations
        list. */

    do {
        DECODE_LEB128_UWORD_CK(abbrev_ptr, attr_name,
            dbg,error,abbrev_section_end);
        if (attr_name > DW_AT_hi_user) {
            _dwarf_error(dbg, error,DW_DLE_ATTR_CORRUPT);
            return DW_DLV_ERROR;
        }
        DECODE_LEB128_UWORD_CK(abbrev_ptr, attr_form,
            dbg,error,abbrev_section_end);
        if (!_dwarf_valid_form_we_know(attr_form,attr_name)) {
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m,
                "DW_DLE_UNKNOWN_FORM: Abbrev invalid form 0x%"
                DW_PR_DUx,attr_form);
            dwarfstring_append_printf_u(&m,
                " with attribute 0x%" DW_PR_DUx,attr_name);
            dwarfstring_append(&m," so abbreviations unusable. ");
            _dwarf_error_string(dbg, error, DW_DLE_UNKNOWN_FORM,
                dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        if (attr_form ==  DW_FORM_implicit_const) {
            /* The value is here, not in a DIE. */
            DECODE_LEB128_SWORD_CK(abbrev_ptr, implicit_const,
                dbg,error,abbrev_section_end);
        }
        abbrev_count++;
    } while ((abbrev_ptr < abbrev_section_end) &&
        (attr_name != 0 || attr_form != 0));
    /* We counted one too high,we included the 0,0 */
    *abbrev_count_out = abbrev_count-1;
    *abbrev_ptr_out = abbrev_ptr;
    return DW_DLV_OK;
}

int
dwarf_get_abbrev(Dwarf_Debug dbg,
    Dwarf_Unsigned offset,
    Dwarf_Abbrev * returned_abbrev,
    Dwarf_Unsigned * length,
    Dwarf_Unsigned * abbr_count, Dwarf_Error * error)
{
    Dwarf_Byte_Ptr abbrev_ptr = 0;
    Dwarf_Byte_Ptr abbrev_ptr_out = 0;
    Dwarf_Byte_Ptr abbrev_section_end = 0;
    Dwarf_Abbrev ret_abbrev = 0;
    Dwarf_Unsigned labbr_count = 0;
    Dwarf_Unsigned utmp     = 0;
    int res = 0;

    if (!dbg) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    if (dbg->de_debug_abbrev.dss_data == 0) {
        /*  Loads abbrev section (and .debug_info as we do those
            together). */
        res = _dwarf_load_debug_info(dbg, error);

        if (res != DW_DLV_OK) {
            return res;
        }
    }

    if (offset >= dbg->de_debug_abbrev.dss_size) {
        return DW_DLV_NO_ENTRY;
    }
    ret_abbrev = (Dwarf_Abbrev) _dwarf_get_alloc(dbg, DW_DLA_ABBREV, 1);
    if (ret_abbrev == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    ret_abbrev->dab_dbg = dbg;
    if (returned_abbrev == 0 || abbr_count == 0) {
        dwarf_dealloc(dbg, ret_abbrev, DW_DLA_ABBREV);
        _dwarf_error(dbg, error, DW_DLE_DWARF_ABBREV_NULL);
        return DW_DLV_ERROR;
    }


    *abbr_count = 0;
    if (length) {
        *length = 1;
    }


    abbrev_ptr = dbg->de_debug_abbrev.dss_data + offset;
    abbrev_section_end =
        dbg->de_debug_abbrev.dss_data + dbg->de_debug_abbrev.dss_size;
#if 0
    DECODE_LEB128_UWORD_CK(abbrev_ptr, utmp,
        dbg,error,abbrev_section_end);
#endif
    res = _dwarf_leb128_uword_wrapper(dbg,&abbrev_ptr,
        abbrev_section_end,&utmp,error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc(dbg, ret_abbrev, DW_DLA_ABBREV);
        return res;
    }
    ret_abbrev->dab_code = utmp;
    if (ret_abbrev->dab_code == 0) {
        *returned_abbrev = ret_abbrev;
        *abbr_count = 0;
        if (length) {
            *length = 1;
        }
        return DW_DLV_OK;
    }

#if 0
    DECODE_LEB128_UWORD_CK(abbrev_ptr, utmp,
        dbg,error,abbrev_section_end);
#endif
    res = _dwarf_leb128_uword_wrapper(dbg,&abbrev_ptr,
        abbrev_section_end,&utmp,error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc(dbg, ret_abbrev, DW_DLA_ABBREV);
        return res;
    }
    if (utmp > DW_TAG_hi_user) {
        return _dwarf_format_TAG_err_msg(dbg,
            utmp,"DW_DLE_TAG_CORRUPT",
            error);
    }
    ret_abbrev->dab_tag = utmp;
    if (abbrev_ptr >= abbrev_section_end) {
        dwarfstring m;
        dwarf_dealloc(dbg, ret_abbrev, DW_DLA_ABBREV);

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m,
            "DW_DLE_ABBREV_DECODE_ERROR: Ran off the end "
            "of the abbrev section reading tag, starting at"
            " abbrev section offset 0x%x",offset);
        _dwarf_error_string(dbg, error,
            DW_DLE_ABBREV_DECODE_ERROR,
            dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }
    ret_abbrev->dab_has_child = *(abbrev_ptr++);
    ret_abbrev->dab_abbrev_ptr = abbrev_ptr;
    ret_abbrev->dab_next_ptr = abbrev_ptr;
    ret_abbrev->dab_next_index = 0;
    res = _dwarf_count_abbrev_entries(dbg,abbrev_ptr,
        abbrev_section_end,&labbr_count,&abbrev_ptr_out,error);
    if (res == DW_DLV_ERROR) {
        dwarf_dealloc(dbg, ret_abbrev, DW_DLA_ABBREV);
        return res;
    }
    abbrev_ptr = abbrev_ptr_out;

    /* Global section offset. */
    ret_abbrev->dab_goffset = offset;
    ret_abbrev->dab_count = labbr_count;
    if (abbrev_ptr > abbrev_section_end) {
        dwarf_dealloc(dbg, ret_abbrev, DW_DLA_ABBREV);
        _dwarf_error_string(dbg, error,
            DW_DLE_ABBREV_DECODE_ERROR,
            "DW_DLE_ABBREV_DECODE_ERROR: Ran off the end "
            "of the abbrev section reading abbrev_entries.");
        _dwarf_error(dbg, error, DW_DLE_ABBREV_DECODE_ERROR);
        return DW_DLV_ERROR;
    }
    if (length) {
        *length = abbrev_ptr - dbg->de_debug_abbrev.dss_data - offset;
    }
    *returned_abbrev = ret_abbrev;
    *abbr_count = labbr_count;
    return DW_DLV_OK;
}

int
dwarf_get_abbrev_code(Dwarf_Abbrev abbrev,
    Dwarf_Unsigned * returned_code,
    Dwarf_Error * error)
{
    if (abbrev == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_ABBREV_NULL);
        return DW_DLV_ERROR;
    }

    *returned_code = abbrev->dab_code;
    return DW_DLV_OK;
}

/*  DWARF defines DW_TAG_hi_user as 0xffff so no tag should be
    over 16 bits.  */
int
dwarf_get_abbrev_tag(Dwarf_Abbrev abbrev,
    Dwarf_Half * returned_tag, Dwarf_Error * error)
{
    if (abbrev == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_ABBREV_NULL);
        return (DW_DLV_ERROR);
    }

    *returned_tag = abbrev->dab_tag;
    return (DW_DLV_OK);
}


int
dwarf_get_abbrev_children_flag(Dwarf_Abbrev abbrev,
    Dwarf_Signed * returned_flag,
    Dwarf_Error * error)
{
    if (abbrev == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_ABBREV_NULL);
        return (DW_DLV_ERROR);
    }

    *returned_flag = abbrev->dab_has_child;
    return (DW_DLV_OK);
}


/*  This does not return the implicit const, nor
    does it return all bits of the uleb attribute
    nor does it return all bits of the uleb form
    value.
    See dwarf_get_abbrev_entry_b().
*/

int
dwarf_get_abbrev_entry(Dwarf_Abbrev abbrev,
    Dwarf_Signed indx,
    Dwarf_Half   * returned_attr_num,
    Dwarf_Signed * returned_form,
    Dwarf_Off    * returned_offset,
    Dwarf_Error * error)
{
    int res;
    Dwarf_Unsigned attr = 0;
    Dwarf_Unsigned form = 0;
    Dwarf_Signed implicitconst = 0;
    Dwarf_Unsigned uindex = (Dwarf_Unsigned)indx;
    Dwarf_Bool filter_outliers = TRUE;

    res = dwarf_get_abbrev_entry_b(abbrev,
        uindex,
        filter_outliers,
        &attr,
        &form,
        &implicitconst,
        returned_offset,
        error);
    if (res != DW_DLV_OK) {
        return res;
    }
    /* returned_offset already set by dwarf_get_abbrev_entry_b; */
    if (returned_attr_num) {
        *returned_attr_num = (Dwarf_Half)attr;
    }
    if (returned_form) {
        *returned_form = (Dwarf_Signed)form;
    }
    return DW_DLV_OK;
}

/*  If filter_outliers is non-zero then
    the routine will return DW_DLV_ERROR
    if the leb reading generates a number that
    is so large it cannot be correct.

    If filter_outliers is 0 the uleb/sleb
    values read are returned, even if
    the values are unreasonable. This is
    a useful option if one wishes to
    have callers examine the return values
    in greater detail than the checking here
    provides.

*/
int
dwarf_get_abbrev_entry_b(Dwarf_Abbrev abbrev,
    Dwarf_Unsigned indx,
    Dwarf_Bool     filter_outliers,
    Dwarf_Unsigned * returned_attr_num,
    Dwarf_Unsigned * returned_form,
    Dwarf_Signed   * returned_implicitconst,
    Dwarf_Off      * offset,
    Dwarf_Error    * error)
{
    Dwarf_Byte_Ptr abbrev_ptr = 0;
    Dwarf_Byte_Ptr abbrev_end = 0;
    Dwarf_Byte_Ptr mark_abbrev_ptr = 0;
    Dwarf_Unsigned attr = 0;
    Dwarf_Unsigned form = 0;
    Dwarf_Unsigned implicitconst = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Signed local_indx = (Dwarf_Signed)indx;

    if (abbrev == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DWARF_ABBREV_NULL);
        return (DW_DLV_ERROR);
    }
    if (abbrev->dab_code == 0) {
        return (DW_DLV_NO_ENTRY);
    }

    if (abbrev->dab_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = abbrev->dab_dbg;
    abbrev_ptr = abbrev->dab_abbrev_ptr;
    abbrev_end = dbg->de_debug_abbrev.dss_data +
        dbg->de_debug_abbrev.dss_size;
    if ((Dwarf_Unsigned)local_indx >=  abbrev->dab_next_index) {
        /*  We want a part not yet scanned ,
            so we can start closer to the desired value. */
        abbrev_ptr   = abbrev->dab_next_ptr;
        local_indx -= abbrev->dab_next_index;
    }

    for (attr = 1, form = 1;
        local_indx >= 0 && abbrev_ptr < abbrev_end &&
        (attr != 0 || form != 0);
        local_indx--) {

        mark_abbrev_ptr = abbrev_ptr;
        DECODE_LEB128_UWORD_CK(abbrev_ptr, attr,dbg,
            error,abbrev_end);
        if (filter_outliers && attr > DW_AT_hi_user) {
            _dwarf_error(dbg, error,DW_DLE_ATTR_CORRUPT);
            return DW_DLV_ERROR;
        }
        DECODE_LEB128_UWORD_CK(abbrev_ptr, form,dbg,
            error,abbrev_end);
        if (filter_outliers &&
            !_dwarf_valid_form_we_know(form,attr)) {
            _dwarf_error(dbg, error, DW_DLE_UNKNOWN_FORM);
            return (DW_DLV_ERROR);
        }
        if (form ==  DW_FORM_implicit_const) {
            /* The value is here, not in a DIE. */
            DECODE_LEB128_SWORD_CK( abbrev_ptr, implicitconst,
                dbg,error,abbrev_end);
        } else {
            implicitconst = 0;
        }
    }

    if (abbrev_ptr >= abbrev_end) {
        _dwarf_error_string(dbg, error,
            DW_DLE_ABBREV_DECODE_ERROR,
            "DW_DLE_ABBREV_DECODE_ERROR: Ran off the end "
            "of the abbrev section reading abbrev entries..");
        return DW_DLV_ERROR;
    }

    if (local_indx >= 0) {
        return DW_DLV_NO_ENTRY;
    }

    if (returned_form != NULL) {
        *returned_form = form;
    }
    if (offset != NULL) {
        *offset = mark_abbrev_ptr - dbg->de_debug_abbrev.dss_data;
    }
    if (returned_attr_num) {
        *returned_attr_num = attr;
    }
    if (returned_implicitconst) {
        /*  Callers should only examine implict const value
            if the form is DW_FORM_implicit_const.  */
        *returned_implicitconst = implicitconst;
    }
    abbrev->dab_next_ptr = abbrev_ptr;
    abbrev->dab_next_index = (Dwarf_Unsigned)local_indx ;
    return DW_DLV_OK;
}

/*  This function is not entirely safe to call.
    The problem is that the DWARF[234] specification does not insist
    that bytes in .debug_abbrev that are not referenced by .debug_info
    or .debug_types need to be initialized to anything specific.
    Any garbage bytes may cause trouble.  Not all compilers/linkers
    leave unreferenced garbage bytes in .debug_abbrev, so this may
    work for most objects.
    In case of error could return a bogus value, there is
    no documented way to detect error.
*/
int
dwarf_get_abbrev_count(Dwarf_Debug dbg)
{
    Dwarf_Abbrev ab;
    Dwarf_Unsigned offset = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Unsigned attr_count = 0;
    Dwarf_Unsigned abbrev_count = 0;
    int abres = DW_DLV_OK;
    Dwarf_Error err = 0;

    while ((abres = dwarf_get_abbrev(dbg, offset, &ab,
        &length, &attr_count,
        &err)) == DW_DLV_OK) {

        ++abbrev_count;
        offset += length;
        dwarf_dealloc(dbg, ab, DW_DLA_ABBREV);
    }
    if (err) {
        dwarf_dealloc(dbg,err,DW_DLA_ERROR);
        err = 0;
    }
    return abbrev_count;
}
