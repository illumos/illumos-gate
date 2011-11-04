/*

  Copyright (C) 2000,2002,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2007-2010 David Anderson. All Rights Reserved.

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
#include "dwarf_incl.h"
#include <stdio.h>
#include "dwarf_die_deliv.h"

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
    CHECK_DIE(die, DW_DLV_ERROR);

    *ret_offset = (die->di_debug_info_ptr -
        die->di_cu_context->cc_dbg->de_debug_info.dss_data);
    return DW_DLV_OK;
}


/*
    This function returns the offset of
    the die relative to the start of its
    compilation-unit rather than .debug_info.
    Returns DW_DLV_ERROR on error.
*/
int
dwarf_die_CU_offset(Dwarf_Die die,
    Dwarf_Off * cu_off, Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    cu_context = die->di_cu_context;

    *cu_off =
        (die->di_debug_info_ptr - cu_context->cc_dbg->de_debug_info.dss_data -
         cu_context->cc_debug_info_offset);
    return DW_DLV_OK;
}

/*
    This function returns the global offset 
    (meaning the section offset) and length of
    the CU that this die is a part of.
    Used for correctness checking by dwarfdump.
*/
int
dwarf_die_CU_offset_range(Dwarf_Die die,
     Dwarf_Off * cu_off, 
     Dwarf_Off * cu_length,
     Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    cu_context = die->di_cu_context;

    *cu_off = cu_context->cc_debug_info_offset;
    *cu_length = cu_context->cc_length + cu_context->cc_length_size
            + cu_context->cc_extension_size;
    return DW_DLV_OK;
}



int
dwarf_tag(Dwarf_Die die, Dwarf_Half * tag, Dwarf_Error * error)
{
    CHECK_DIE(die, DW_DLV_ERROR);
    *tag = (die->di_abbrev_list->ab_tag);
    return DW_DLV_OK;
}


int
dwarf_attrlist(Dwarf_Die die,
    Dwarf_Attribute ** attrbuf,
    Dwarf_Signed * attrcnt, Dwarf_Error * error)
{
    Dwarf_Word attr_count = 0;
    Dwarf_Word i = 0;
    Dwarf_Half attr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Byte_Ptr abbrev_ptr = 0;
    Dwarf_Abbrev_List abbrev_list = 0;
    Dwarf_Attribute new_attr = 0;
    Dwarf_Attribute head_attr = NULL;
    Dwarf_Attribute curr_attr = NULL;
    Dwarf_Attribute *attr_ptr = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Byte_Ptr info_ptr = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    dbg = die->di_cu_context->cc_dbg;

    abbrev_list = _dwarf_get_abbrev_for_code(die->di_cu_context,
                                             die->di_abbrev_list->
                                             ab_code);
    if (abbrev_list == NULL) {
        _dwarf_error(dbg, error, DW_DLE_DIE_ABBREV_BAD);
        return (DW_DLV_ERROR);
    }
    abbrev_ptr = abbrev_list->ab_abbrev_ptr;

    info_ptr = die->di_debug_info_ptr;
    SKIP_LEB128_WORD(info_ptr);

    do {
        Dwarf_Unsigned utmp2;

        DECODE_LEB128_UWORD(abbrev_ptr, utmp2);
        attr = (Dwarf_Half) utmp2;
        DECODE_LEB128_UWORD(abbrev_ptr, utmp2);
        attr_form = (Dwarf_Half) utmp2;

        if (attr != 0) {
            new_attr =
                (Dwarf_Attribute) _dwarf_get_alloc(dbg, DW_DLA_ATTR, 1);
            if (new_attr == NULL) {
                _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
                return (DW_DLV_ERROR);
            }

            new_attr->ar_attribute = attr;
            new_attr->ar_attribute_form_direct = attr_form;
            new_attr->ar_attribute_form = attr_form;
            if (attr_form == DW_FORM_indirect) {
                Dwarf_Unsigned utmp6;

                /* DECODE_LEB128_UWORD does info_ptr update */
                DECODE_LEB128_UWORD(info_ptr, utmp6);
                attr_form = (Dwarf_Half) utmp6;
                new_attr->ar_attribute_form = attr_form;
            }
            new_attr->ar_cu_context = die->di_cu_context;
            new_attr->ar_debug_info_ptr = info_ptr;

            {
                Dwarf_Unsigned sov = _dwarf_get_size_of_val(dbg, 
                    attr_form, 
                    die->di_cu_context->cc_address_size,
                    info_ptr,
                    die->di_cu_context->cc_length_size);
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
    } while (attr != 0 || attr_form != 0);

    if (attr_count == 0) {
        *attrbuf = NULL;
        *attrcnt = 0;
        return (DW_DLV_NO_ENTRY);
    }

    attr_ptr = (Dwarf_Attribute *)
        _dwarf_get_alloc(dbg, DW_DLA_LIST, attr_count);
    if (attr_ptr == NULL) {
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

    Returns NULL on error, or if attr is not found.
    However, *attr_form is 0 on error, and positive 
    otherwise.
*/
static Dwarf_Byte_Ptr
_dwarf_get_value_ptr(Dwarf_Die die,
    Dwarf_Half attr, Dwarf_Half * attr_form)
{
    Dwarf_Byte_Ptr abbrev_ptr = 0;
    Dwarf_Abbrev_List abbrev_list;
    Dwarf_Half curr_attr = 0;
    Dwarf_Half curr_attr_form = 0;
    Dwarf_Byte_Ptr info_ptr = 0;

    abbrev_list = _dwarf_get_abbrev_for_code(die->di_cu_context,
        die->di_abbrev_list->ab_code);
    if (abbrev_list == NULL) {
        *attr_form = 0;
        return (NULL);
    }
    abbrev_ptr = abbrev_list->ab_abbrev_ptr;

    info_ptr = die->di_debug_info_ptr;
    SKIP_LEB128_WORD(info_ptr);

    do {
        Dwarf_Unsigned utmp3;

        DECODE_LEB128_UWORD(abbrev_ptr, utmp3);
        curr_attr = (Dwarf_Half) utmp3;
        DECODE_LEB128_UWORD(abbrev_ptr, utmp3);
        curr_attr_form = (Dwarf_Half) utmp3;
        if (curr_attr_form == DW_FORM_indirect) {
            Dwarf_Unsigned utmp6;

            /* DECODE_LEB128_UWORD updates info_ptr */
            DECODE_LEB128_UWORD(info_ptr, utmp6);
            curr_attr_form = (Dwarf_Half) utmp6;
        }

        if (curr_attr == attr) {
            *attr_form = curr_attr_form;
            return (info_ptr);
        }

        info_ptr += _dwarf_get_size_of_val(die->di_cu_context->cc_dbg,
                         curr_attr_form, 
                         die->di_cu_context->cc_address_size,
                         info_ptr, 
                         die->di_cu_context->cc_length_size);
    } while (curr_attr != 0 || curr_attr_form != 0);

    *attr_form = 1;
    return (NULL);
}


int
dwarf_diename(Dwarf_Die die, char **ret_name, Dwarf_Error * error)
{
    Dwarf_Half attr_form = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_Unsigned string_offset = 0;
    int res = DW_DLV_ERROR;

    CHECK_DIE(die, DW_DLV_ERROR);

    info_ptr = _dwarf_get_value_ptr(die, DW_AT_name, &attr_form);
    if (info_ptr == NULL) {
        if (attr_form == 0) {
            _dwarf_error(die->di_cu_context->cc_dbg, error,
                         DW_DLE_DIE_BAD);
            return (DW_DLV_ERROR);
        }
        return DW_DLV_NO_ENTRY;
    }

    if (attr_form == DW_FORM_string) {
        *ret_name = (char *) (info_ptr);
        return DW_DLV_OK;
    }

    dbg = die->di_cu_context->cc_dbg;
    if (attr_form != DW_FORM_strp) {
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_BAD);
        return (DW_DLV_ERROR);
    }

    READ_UNALIGNED(dbg, string_offset, Dwarf_Unsigned,
        info_ptr, die->di_cu_context->cc_length_size);

    if (string_offset >= dbg->de_debug_str.dss_size) {
        _dwarf_error(dbg, error, DW_DLE_STRING_OFFSET_BAD);
        return (DW_DLV_ERROR);
    }

    res = _dwarf_load_section(dbg, &dbg->de_debug_str,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    *ret_name = (char *) (dbg->de_debug_str.dss_data + string_offset);
    return DW_DLV_OK;
}


int
dwarf_hasattr(Dwarf_Die die,
    Dwarf_Half attr,
    Dwarf_Bool * return_bool, Dwarf_Error * error)
{
    Dwarf_Half attr_form = 0;

    CHECK_DIE(die, DW_DLV_ERROR);

    if (_dwarf_get_value_ptr(die, attr, &attr_form) == NULL) {
        if (attr_form == 0) {
            _dwarf_error(die->di_cu_context->cc_dbg, error,
                DW_DLE_DIE_BAD);
            return (DW_DLV_ERROR);
        }
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

    CHECK_DIE(die, DW_DLV_ERROR);
    dbg = die->di_cu_context->cc_dbg;

    info_ptr = _dwarf_get_value_ptr(die, attr, &attr_form);
    if (info_ptr == NULL) {
        if (attr_form == 0) {
            _dwarf_error(dbg, error, DW_DLE_DIE_BAD);
            return (DW_DLV_ERROR);
        }
        return DW_DLV_NO_ENTRY;
    }

    attrib = (Dwarf_Attribute) _dwarf_get_alloc(dbg, DW_DLA_ATTR, 1);
    if (attrib == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }

    attrib->ar_attribute = attr;
    attrib->ar_attribute_form = attr_form;
    attrib->ar_attribute_form_direct = attr_form;
    attrib->ar_cu_context = die->di_cu_context;
    attrib->ar_debug_info_ptr = info_ptr;
    *ret_attr = (attrib);
    return DW_DLV_OK;
}


int
dwarf_lowpc(Dwarf_Die die,
    Dwarf_Addr * return_addr, Dwarf_Error * error)
{
    Dwarf_Addr ret_addr = 0;
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Half address_size = 0;

    CHECK_DIE(die, DW_DLV_ERROR);

    dbg = die->di_cu_context->cc_dbg;
    address_size = die->di_cu_context->cc_address_size;
    info_ptr = _dwarf_get_value_ptr(die, DW_AT_low_pc, &attr_form);
    if ((info_ptr == NULL && attr_form == 0) ||
        (info_ptr != NULL && attr_form != DW_FORM_addr)) {
        _dwarf_error(dbg, error, DW_DLE_DIE_BAD);
        return (DW_DLV_ERROR);
    }
    if (info_ptr == NULL) {
        return (DW_DLV_NO_ENTRY);
    }


    READ_UNALIGNED(dbg, ret_addr, Dwarf_Addr,
                   info_ptr, address_size);

    *return_addr = ret_addr;
    return (DW_DLV_OK);
}


int
dwarf_highpc(Dwarf_Die die,
    Dwarf_Addr * return_addr, Dwarf_Error * error)
{
    Dwarf_Addr ret_addr = 0;
    Dwarf_Byte_Ptr info_ptr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Half address_size = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    dbg = die->di_cu_context->cc_dbg;
    address_size = die->di_cu_context->cc_address_size;
    info_ptr = _dwarf_get_value_ptr(die, DW_AT_high_pc, &attr_form);
    if ((info_ptr == NULL && attr_form == 0) ||
        (info_ptr != NULL && attr_form != DW_FORM_addr)) {
        _dwarf_error(dbg, error, DW_DLE_DIE_BAD);
        return (DW_DLV_ERROR);
    }
    if (info_ptr == NULL) {
        return (DW_DLV_NO_ENTRY);
    }

    READ_UNALIGNED(dbg, ret_addr, Dwarf_Addr,
                   info_ptr, address_size);

    *return_addr = ret_addr;
    return (DW_DLV_OK);
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
    and dwarf_srclang.
*/
static int
_dwarf_die_attr_unsigned_constant(Dwarf_Die die,
    Dwarf_Half attr,
    Dwarf_Unsigned * return_val,
    Dwarf_Error * error)
{
    Dwarf_Byte_Ptr info_ptr;
    Dwarf_Half attr_form;
    Dwarf_Unsigned ret_value;
    Dwarf_Debug dbg;

    CHECK_DIE(die, DW_DLV_ERROR);

    dbg = die->di_cu_context->cc_dbg;
    info_ptr = _dwarf_get_value_ptr(die, attr, &attr_form);
    if (info_ptr != NULL) {
        switch (attr_form) {

        case DW_FORM_data1:
            *return_val = (*(Dwarf_Small *) info_ptr);
            return (DW_DLV_OK);

        case DW_FORM_data2:
            READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                           info_ptr, sizeof(Dwarf_Shalf));
            *return_val = ret_value;
            return (DW_DLV_OK);

        case DW_FORM_data4:
            READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                           info_ptr, sizeof(Dwarf_sfixed));
            *return_val = ret_value;
            return (DW_DLV_OK);

        case DW_FORM_data8:
            READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                           info_ptr, sizeof(Dwarf_Unsigned));
            *return_val = ret_value;
            return (DW_DLV_OK);

        case DW_FORM_udata:
            *return_val = (_dwarf_decode_u_leb128(info_ptr, NULL));
            return (DW_DLV_OK);

        default:
            _dwarf_error(dbg, error, DW_DLE_DIE_BAD);
            return (DW_DLV_ERROR);
        }
    }
    if (attr_form == 0) {
        _dwarf_error(dbg, error, DW_DLE_DIE_BAD);
        return (DW_DLV_ERROR);
    }
    return DW_DLV_NO_ENTRY;
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

/*
        Return DW_DLV_OK if ok
        DW_DLV_ERROR if failure.

        If the die and the attr are not related the result is
        meaningless.
*/
int
dwarf_attr_offset(Dwarf_Die die, Dwarf_Attribute attr, 
    Dwarf_Off * offset /* return offset thru this ptr */,
    Dwarf_Error * error)
{
    Dwarf_Off attroff = 0;

    CHECK_DIE(die, DW_DLV_ERROR);

    attroff = (attr->ar_debug_info_ptr -
               die->di_cu_context->cc_dbg->de_debug_info.dss_data);
    *offset = attroff;
    return DW_DLV_OK;
}

int
dwarf_die_abbrev_code(Dwarf_Die die)
{
    return die->di_abbrev_code;
}

/* Helper function for finding form class. */
static enum Dwarf_Form_Class 
dw_get_special_offset(Dwarf_Half attrnum)
{
    switch(attrnum) {
    case DW_AT_stmt_list:
             return DW_FORM_CLASS_LINEPTR;
    case DW_AT_macro_info:
             return DW_FORM_CLASS_MACPTR;
    case DW_AT_ranges:
             return DW_FORM_CLASS_RANGELISTPTR;
    case DW_AT_location:
    case DW_AT_string_length:
    case DW_AT_return_addr:
    case DW_AT_data_member_location:
    case DW_AT_frame_base:
    case DW_AT_segment:
    case DW_AT_static_link:
    case DW_AT_use_location:
    case DW_AT_vtable_elem_location:
             return DW_FORM_CLASS_LOCLISTPTR;
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
enum Dwarf_Form_Class dwarf_get_form_class(
    Dwarf_Half dwversion,
    Dwarf_Half attrnum, 
    Dwarf_Half offset_size, 
    Dwarf_Half form)
{
    switch(form) {
    case  DW_FORM_addr: return DW_FORM_CLASS_ADDRESS;

    case  DW_FORM_data2:  return DW_FORM_CLASS_CONSTANT;

    case  DW_FORM_data4: 
        if(dwversion <= 3 && offset_size == 4) {
            enum Dwarf_Form_Class class = dw_get_special_offset(attrnum);
            if(class != DW_FORM_CLASS_UNKNOWN) {
                return class;
            }
        }
        return DW_FORM_CLASS_CONSTANT;
    case  DW_FORM_data8:
        if(dwversion <= 3 && offset_size == 8) {
            enum Dwarf_Form_Class class = dw_get_special_offset(attrnum);
            if(class != DW_FORM_CLASS_UNKNOWN) {
                return class;
            }
        }
        return DW_FORM_CLASS_CONSTANT;

    case  DW_FORM_sec_offset:
        {
            enum Dwarf_Form_Class class = dw_get_special_offset(attrnum);
            if(class != DW_FORM_CLASS_UNKNOWN) {
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

   
    case  DW_FORM_indirect: 
    default: 
        break;
    };
    return DW_FORM_CLASS_UNKNOWN;
}

