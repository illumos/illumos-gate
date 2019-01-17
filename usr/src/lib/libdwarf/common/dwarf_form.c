/*

  Copyright (C) 2000,2002,2004,2005 Silicon Graphics, Inc. All Rights Reserved.
  Portions Copyright 2007-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2008-2010 David Anderson. All rights reserved.

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



#include "config.h"
#include "dwarf_incl.h"
#include "dwarf_die_deliv.h"

int
dwarf_hasform(Dwarf_Attribute attr,
              Dwarf_Half form,
              Dwarf_Bool * return_bool, Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    *return_bool = (attr->ar_attribute_form == form);
    return DW_DLV_OK;
}

/* Not often called, we do not worry about efficiency here.
   The dwarf_whatform() call does the sanity checks for us.
*/
int
dwarf_whatform_direct(Dwarf_Attribute attr,
                      Dwarf_Half * return_form, Dwarf_Error * error)
{
    int res = dwarf_whatform(attr, return_form, error);

    if (res != DW_DLV_OK) {
        return res;
    }

    *return_form = attr->ar_attribute_form_direct;
    return (DW_DLV_OK);
}
void *
dwarf_uncompress_integer_block(
    Dwarf_Debug      dbg,
    Dwarf_Bool       unit_is_signed,
    Dwarf_Small      unit_length_in_bits,
    void*            input_block,
    Dwarf_Unsigned   input_length_in_bytes,
    Dwarf_Unsigned*  output_length_in_units_ptr,
    Dwarf_Error*     error
)
{
    Dwarf_Unsigned output_length_in_units = 0;
    void * output_block = 0;
    int i = 0;
    char * ptr = 0;
    int remain = 0;
    Dwarf_sfixed * array = 0;

    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_DBG_NULL);
        return((void *)DW_DLV_BADADDR);
    }
    
    if (unit_is_signed == false ||
        unit_length_in_bits != 32 ||
        input_block == NULL ||
        input_length_in_bytes == 0 ||
        output_length_in_units_ptr == NULL) {
        
        _dwarf_error(NULL, error, DW_DLE_BADBITC);
        return ((void *) DW_DLV_BADADDR);
    }

    /* At this point we assume the format is: signed 32 bit */

    /* first uncompress everything to find the total size. */

    output_length_in_units = 0;
    remain = input_length_in_bytes;
    ptr = input_block;
    while (remain > 0) {
        Dwarf_Signed num;
        Dwarf_Word len;
        num = _dwarf_decode_s_leb128((unsigned char *)ptr, &len);
        ptr += len;
        remain -= len;
        output_length_in_units++;
    }

    if (remain != 0) {
        _dwarf_error(NULL, error, DW_DLE_ALLOC_FAIL);
        return((void *)DW_DLV_BADADDR);
    }
    
    /* then alloc */

    output_block = (void *)
        _dwarf_get_alloc(dbg,
                         DW_DLA_STRING,
                         output_length_in_units * (unit_length_in_bits / 8));
    if (output_block == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return((void*)DW_DLV_BADADDR);
    }
    
    /* then uncompress again and copy into new buffer */

    array = (Dwarf_sfixed *) output_block;
    remain = input_length_in_bytes;
    ptr = input_block;
    for (i=0; i<output_length_in_units && remain>0; i++) {
        Dwarf_Signed num;
        Dwarf_Word len;
        num = _dwarf_decode_s_leb128((unsigned char *)ptr, &len);
        ptr += len;
        remain -= len;
        array[i] = num;
    }

    if (remain != 0) {
        dwarf_dealloc(dbg, (unsigned char *)output_block, DW_DLA_STRING);
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return((Dwarf_P_Attribute)DW_DLV_BADADDR);
    }

    *output_length_in_units_ptr = output_length_in_units;
    return output_block;
}

void
dwarf_dealloc_uncompressed_block(Dwarf_Debug dbg, void * space)
{
    dwarf_dealloc(dbg, space, DW_DLA_STRING);
}


int
dwarf_whatform(Dwarf_Attribute attr,
               Dwarf_Half * return_form, Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    *return_form = attr->ar_attribute_form;
    return (DW_DLV_OK);
}


/*
    This function is analogous to dwarf_whatform.
    It returns the attribute in attr instead of
    the form.
*/
int
dwarf_whatattr(Dwarf_Attribute attr,
               Dwarf_Half * return_attr, Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    *return_attr = (attr->ar_attribute);
    return DW_DLV_OK;
}


/* 
    A global offset cannot be returned by this interface:
    see dwarf_global_formref().

    DW_FORM_ref_addr is considered an incorrect form 
    for this call because DW_FORM_ref_addr is a global-offset into 
    the debug_info section.

    For the same reason DW_FORM_data4/data8 are not returned
    from this function.

    For the same reason DW_FORM_sec_offset is not returned
    from this function, DW_FORM_sec_offset is a global offset 
    (to various sections, not a CU relative offset.

    DW_FORM_ref_addr has a value which was documented in
    DWARF2 as address-size but which was always an offset
    so should have always been offset size (wording
    corrected in DWARF3). 

    
*/
int
dwarf_formref(Dwarf_Attribute attr,
              Dwarf_Off * ret_offset, Dwarf_Error * error)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_CU_Context cu_context = 0;


    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = cu_context->cc_dbg;

    switch (attr->ar_attribute_form) {

    case DW_FORM_ref1:
        offset = *(Dwarf_Small *) attr->ar_debug_info_ptr;
        break;

    case DW_FORM_ref2:
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_Half));
        break;

    case DW_FORM_ref4:
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_ufixed));
        break;

    case DW_FORM_ref8:
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_Unsigned));
        break;

    case DW_FORM_ref_udata:
        offset = _dwarf_decode_u_leb128(attr->ar_debug_info_ptr, NULL);
        break;

    default:
        _dwarf_error(dbg, error, DW_DLE_BAD_REF_FORM);
        return (DW_DLV_ERROR);
    }

    /* Check that offset is within current cu portion of .debug_info. */
    if (offset >= cu_context->cc_length +
        cu_context->cc_length_size + cu_context->cc_extension_size) {
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_OFFSET_BAD);
        return (DW_DLV_ERROR);
    }

    *ret_offset = (offset);
    return DW_DLV_OK;
}

/*  dwarf_formsig8 returns in the caller-provided 8 byte area
    the 8 bytes of a DW_FORM_ref_sig8 (copying the bytes
    directly to the caller).  Not a string, an 8 byte
    MD5 hash.  This function is new in DWARF4 libdwarf.
*/
int dwarf_formsig8(Dwarf_Attribute attr,
    Dwarf_Sig8 * returned_sig_bytes,
    Dwarf_Error*     error)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Unsigned field_end_offset = 0;
    Dwarf_CU_Context cu_context = 0;


    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = cu_context->cc_dbg;

    if(attr->ar_attribute_form != DW_FORM_ref_sig8 ) {
        _dwarf_error(dbg, error, DW_DLE_BAD_REF_SIG8_FORM);
        return (DW_DLV_ERROR);
    }

    field_end_offset = attr->ar_debug_info_ptr + sizeof(Dwarf_Sig8) -
        (dbg->de_debug_info.dss_data + cu_context->cc_debug_info_offset);
    /* Check that offset is within current cu portion of .debug_info. */
    if (field_end_offset > cu_context->cc_length +
        cu_context->cc_length_size + cu_context->cc_extension_size) {
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_OFFSET_BAD);
        return (DW_DLV_ERROR);
    }
  
    memcpy(returned_sig_bytes, attr->ar_debug_info_ptr, 
        sizeof(Dwarf_Sig8));
    return DW_DLV_OK;
}


/* 
    Since this returns section-relative debug_info offsets,
    this can represent all REFERENCE forms correctly
    and allows all applicable forms.

    DW_FORM_ref_addr has a value which was documented in
    DWARF2 as address-size but which was always an offset
    so should have always been offset size (wording
    corrected in DWARF3).

    See the DWARF4 document for the 3 cases fitting
    reference forms.  The caller must determine which section the
    reference 'points' to.  The function added in November 2009, 
    dwarf_get_form_class(), helps in this regard.
    
*/
int
dwarf_global_formref(Dwarf_Attribute attr,
                     Dwarf_Off * ret_offset, Dwarf_Error * error)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_Addr ref_addr = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Half context_version = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }
    context_version = cu_context->cc_version_stamp;

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = cu_context->cc_dbg;

    switch (attr->ar_attribute_form) {

    case DW_FORM_ref1:
        offset = *(Dwarf_Small *) attr->ar_debug_info_ptr;
        goto fixoffset;

    case DW_FORM_ref2:
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_Half));
        goto fixoffset;

    case DW_FORM_ref4:
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_ufixed));
        goto fixoffset;

    case DW_FORM_ref8:
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_Unsigned));
        goto fixoffset;

    case DW_FORM_ref_udata:
        offset = _dwarf_decode_u_leb128(attr->ar_debug_info_ptr, NULL);

      fixoffset:                /* we have a local offset, make it
                                   global */

        /* check legality of offset */
        if (offset >= cu_context->cc_length +
            cu_context->cc_length_size +
            cu_context->cc_extension_size) {
            _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_OFFSET_BAD);
            return (DW_DLV_ERROR);
        }

        /* globalize the offset */
        offset += cu_context->cc_debug_info_offset;
        break;
    /* The DWARF2 document did not make clear that
       DW_FORM_data4( and 8) were references with
       global offsets to some section.
       That was first clearly documented in DWARF3.
       In DWARF4 these two forms are no longer references. */
    case DW_FORM_data4:
        if(context_version == DW_CU_VERSION4) {
            _dwarf_error(dbg, error, DW_DLE_NOT_REF_FORM);
            return (DW_DLV_ERROR);
        }
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_ufixed));
        /* The offset is global. */
        break;
    case DW_FORM_data8:
        if(context_version == DW_CU_VERSION4) {
            _dwarf_error(dbg, error, DW_DLE_NOT_REF_FORM);
            return (DW_DLV_ERROR);
        }
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_Unsigned));
        /* The offset is global. */
        break;
    case DW_FORM_ref_addr:
    case DW_FORM_sec_offset:
        {
            /* DW_FORM_sec_offset first exists in DWARF4.*/
            /* It is up to the caller to know what the offset 
               of DW_FORM_sec_offset refers to,
               the offset is not going to refer to .debug_info! */
            unsigned length_size = cu_context->cc_length_size;
            if(length_size == 4) {
                READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_ufixed));
            } else if (length_size == 8) {
                READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_Unsigned));
            } else {
                _dwarf_error(dbg, error, DW_DLE_FORM_SEC_OFFSET_LENGTH_BAD);
                return (DW_DLV_ERROR);
            }
        }
        break;

    default:
        _dwarf_error(dbg, error, DW_DLE_BAD_REF_FORM);
        return (DW_DLV_ERROR);
    }

    /* We do not know what section the offset refers to, so
       we have no way to check it for correctness. */
    *ret_offset = offset;
    return DW_DLV_OK;
}


int
dwarf_formaddr(Dwarf_Attribute attr,
               Dwarf_Addr * return_addr, Dwarf_Error * error)
{
    Dwarf_Debug dbg = 0;
    Dwarf_Addr ret_addr = 0;
    Dwarf_CU_Context cu_context = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = cu_context->cc_dbg;

    if (attr->ar_attribute_form == DW_FORM_addr
        /* || attr->ar_attribute_form == DW_FORM_ref_addr Allowance of
           DW_FORM_ref_addr was a mistake. The value returned in that
           case is NOT an address it is a global debug_info offset (ie, 
           not CU-relative offset within the CU in debug_info). The
           Dwarf document refers to it as an address (misleadingly) in
           sec 6.5.4 where it describes the reference form. It is
           address-sized so that the linker can easily update it, but
           it is a reference inside the debug_info section. No longer
           allowed. */
        ) {

        READ_UNALIGNED(dbg, ret_addr, Dwarf_Addr,
                       attr->ar_debug_info_ptr, 
                       cu_context->cc_address_size);
        *return_addr = ret_addr;
        return (DW_DLV_OK);
    }

    _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_BAD);
    return (DW_DLV_ERROR);
}


int
dwarf_formflag(Dwarf_Attribute attr,
               Dwarf_Bool * ret_bool, Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    if (attr->ar_attribute_form == DW_FORM_flag_present) {
        /* Implicit means we don't read any data at all. Just
           the existence of the Form does it. DWARF4. */
        *ret_bool = 1;
        return (DW_DLV_OK);
    }

    if (attr->ar_attribute_form == DW_FORM_flag) {
        *ret_bool = (*(Dwarf_Small *) attr->ar_debug_info_ptr != 0);
        return (DW_DLV_OK);
    }
    _dwarf_error(cu_context->cc_dbg, error, DW_DLE_ATTR_FORM_BAD);
    return (DW_DLV_ERROR);
}


int
dwarf_formudata(Dwarf_Attribute attr,
                Dwarf_Unsigned * return_uval, Dwarf_Error * error)
{
    Dwarf_Unsigned ret_value = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }


    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    dbg = cu_context->cc_dbg;
    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    switch (attr->ar_attribute_form) {

    case DW_FORM_data1:
        READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_Small));
        *return_uval = ret_value;
        return DW_DLV_OK;

    /* READ_UNALIGNED does the right thing as it reads
       the right number bits and generates host order. 
       So we can just assign to *return_uval. */
    case DW_FORM_data2:{
            READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                           attr->ar_debug_info_ptr, sizeof(Dwarf_Half));
            *return_uval = ret_value;
            return DW_DLV_OK;
        }

    case DW_FORM_data4:{
            READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                           attr->ar_debug_info_ptr,
                           sizeof(Dwarf_ufixed));
            *return_uval = ret_value;
            return DW_DLV_OK;
        }

    case DW_FORM_data8:{
            READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                           attr->ar_debug_info_ptr,
                           sizeof(Dwarf_Unsigned));
            *return_uval = ret_value;
            return DW_DLV_OK;
        }
        break;
    case DW_FORM_udata:
        ret_value =
            (_dwarf_decode_u_leb128(attr->ar_debug_info_ptr, NULL));
        *return_uval = ret_value;
        return DW_DLV_OK;


        /* see bug 583450. We do not allow reading sdata from a udata
           value. Caller can retry, calling sdata */


    default:
        break;
    }
    _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_BAD);
    return (DW_DLV_ERROR);
}


int
dwarf_formsdata(Dwarf_Attribute attr,
                Dwarf_Signed * return_sval, Dwarf_Error * error)
{
    Dwarf_Signed ret_value = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    dbg = cu_context->cc_dbg;
    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    switch (attr->ar_attribute_form) {

    case DW_FORM_data1:
        *return_sval = (*(Dwarf_Sbyte *) attr->ar_debug_info_ptr);
        return DW_DLV_OK;

    /* READ_UNALIGNED does not sign extend. 
       So we have to use a cast to get the
       value sign extended in the right way for each case. */
    case DW_FORM_data2:{
            READ_UNALIGNED(dbg, ret_value, Dwarf_Signed,
                           attr->ar_debug_info_ptr,
                           sizeof(Dwarf_Shalf));
            *return_sval = (Dwarf_Shalf) ret_value;
            return DW_DLV_OK;

        }

    case DW_FORM_data4:{
            READ_UNALIGNED(dbg, ret_value, Dwarf_Signed,
                           attr->ar_debug_info_ptr,
                           sizeof(Dwarf_sfixed));
            *return_sval = (Dwarf_sfixed) ret_value;
            return DW_DLV_OK;
        }

    case DW_FORM_data8:{
            READ_UNALIGNED(dbg, ret_value, Dwarf_Signed,
                           attr->ar_debug_info_ptr,
                           sizeof(Dwarf_Signed));
            *return_sval = (Dwarf_Signed) ret_value;
            return DW_DLV_OK;
        }

    case DW_FORM_sdata:
        ret_value =
            (_dwarf_decode_s_leb128(attr->ar_debug_info_ptr, NULL));
        *return_sval = ret_value;
        return DW_DLV_OK;


        /* see bug 583450. We do not allow reading sdata from a udata
           value. Caller can retry, calling sdata */


    default:
        break;
    }
    _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_BAD);
    return (DW_DLV_ERROR);
}


int
dwarf_formblock(Dwarf_Attribute attr,
                Dwarf_Block ** return_block, Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Small *data = 0;
    Dwarf_Word leb128_length = 0;
    Dwarf_Block *ret_block = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = cu_context->cc_dbg;

    switch (attr->ar_attribute_form) {

    case DW_FORM_block1:
        length = *(Dwarf_Small *) attr->ar_debug_info_ptr;
        data = attr->ar_debug_info_ptr + sizeof(Dwarf_Small);
        break;

    case DW_FORM_block2:
        READ_UNALIGNED(dbg, length, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_Half));
        data = attr->ar_debug_info_ptr + sizeof(Dwarf_Half);
        break;

    case DW_FORM_block4:
        READ_UNALIGNED(dbg, length, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr, sizeof(Dwarf_ufixed));
        data = attr->ar_debug_info_ptr + sizeof(Dwarf_ufixed);
        break;

    case DW_FORM_block:
        length = _dwarf_decode_u_leb128(attr->ar_debug_info_ptr,
                                        &leb128_length);
        data = attr->ar_debug_info_ptr + leb128_length;
        break;

    default:
        _dwarf_error(cu_context->cc_dbg, error, DW_DLE_ATTR_FORM_BAD);
        return (DW_DLV_ERROR);
    }

    /* Check that block lies within current cu in .debug_info. */
    if (attr->ar_debug_info_ptr + length >=
        dbg->de_debug_info.dss_data + cu_context->cc_debug_info_offset +
        cu_context->cc_length + cu_context->cc_length_size +
        cu_context->cc_extension_size) {
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_SIZE_BAD);
        return (DW_DLV_ERROR);
    }

    ret_block = (Dwarf_Block *) _dwarf_get_alloc(dbg, DW_DLA_BLOCK, 1);
    if (ret_block == NULL) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return (DW_DLV_ERROR);
    }

    ret_block->bl_len = length;
    ret_block->bl_data = (Dwarf_Ptr) data;
    ret_block->bl_from_loclist = 0;
    ret_block->bl_section_offset = data - dbg->de_debug_info.dss_data;


    *return_block = ret_block;
    return (DW_DLV_OK);
}


/* Contrary to long standing documentation,
   The string pointer returned thru return_str must
   never have dwarf_dealloc() applied to it.
   Documentation fixed July 2005.
*/
int
dwarf_formstring(Dwarf_Attribute attr,
                 char **return_str, Dwarf_Error * error)
{
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Unsigned offset = 0;
    int res = DW_DLV_ERROR;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    if (cu_context->cc_dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }
    dbg = cu_context->cc_dbg;

    if (attr->ar_attribute_form == DW_FORM_string) {

        void *begin = attr->ar_debug_info_ptr;

        if (0 == dbg->de_assume_string_in_bounds) {
            /* Check that string lies within current cu in .debug_info. 
             */
            void *end = dbg->de_debug_info.dss_data +
                cu_context->cc_debug_info_offset +
                cu_context->cc_length + cu_context->cc_length_size +
                cu_context->cc_extension_size;
            if (0 == _dwarf_string_valid(begin, end)) {
                _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_SIZE_BAD);
                return (DW_DLV_ERROR);
            }
        }
        *return_str = (char *) (begin);
        return DW_DLV_OK;
    }

    if (attr->ar_attribute_form == DW_FORM_strp) {
        READ_UNALIGNED(dbg, offset, Dwarf_Unsigned,
                       attr->ar_debug_info_ptr,
                       cu_context->cc_length_size);

        res = _dwarf_load_section(dbg, &dbg->de_debug_str,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        if (0 == dbg->de_assume_string_in_bounds) {
            /* Check that string lies within current cu in .debug_info. 
             */
            void *end = dbg->de_debug_str.dss_data + 
                dbg->de_debug_str.dss_size;
            void*begin = dbg->de_debug_str.dss_data + offset;
            if (0 == _dwarf_string_valid(begin, end)) {
                _dwarf_error(dbg, error, DW_DLE_STRP_OFFSET_BAD);
                return (DW_DLV_ERROR);
            }
        }
        *return_str = (char *) (dbg->de_debug_str.dss_data + offset);
        return DW_DLV_OK;
    }

    _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_BAD);
    return (DW_DLV_ERROR);
}

int
dwarf_formexprloc(Dwarf_Attribute attr,
    Dwarf_Unsigned * return_exprlen, 
    Dwarf_Ptr  * block_ptr,
    Dwarf_Error * error)
{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;

    if (attr == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return (DW_DLV_ERROR);
    }

    cu_context = attr->ar_cu_context;
    if (cu_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return (DW_DLV_ERROR);
    }

    dbg = cu_context->cc_dbg;
    if (dbg == NULL) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_DBG_NULL);
        return (DW_DLV_ERROR);
    }

    if (attr->ar_attribute_form == DW_FORM_exprloc ) {
        Dwarf_Unsigned exprlen =
            (_dwarf_decode_u_leb128(attr->ar_debug_info_ptr, NULL));
        Dwarf_Small * addr = attr->ar_debug_info_ptr;
        *return_exprlen = exprlen;
        *block_ptr = addr + exprlen;
        return DW_DLV_OK;

    }
    _dwarf_error(dbg, error, DW_DLE_ATTR_EXPRLOC_FORM_BAD);
    return (DW_DLV_ERROR);
}
