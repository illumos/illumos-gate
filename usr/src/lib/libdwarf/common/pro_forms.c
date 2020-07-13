/*
  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2002-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2007-2013 David Anderson. All rights reserved.
  Portions Copyright 2012 SN Systems Ltd. All rights reserved.

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
#include "libdwarfdefs.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "pro_incl.h"
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_error.h"
#include "pro_encode_nm.h"
#include "pro_alloc.h"
#include "pro_die.h"
#include "pro_expr.h"

#ifndef R_MIPS_NONE
#define R_MIPS_NONE 0
#endif


/* Indicates no relocation needed. */
#define NO_ELF_SYM_INDEX        0


#ifdef WORDS_BIGENDIAN
#define ASNAR(t,s,l)                   \
    do {                                    \
        unsigned tbyte = sizeof(t) - l;     \
        t = 0;                              \
        dbg->de_copy_word(((char *)&t)+tbyte ,&s[0],l);\
    } while (0)
#else /* LITTLE ENDIAN */
#define ASNAR(t,s,l)                 \
    do {                                \
        t = 0;                          \
        dbg->de_copy_word(&t,&s[0],l);             \
    } while (0)
#endif /* end LITTLE- BIG-ENDIAN */


#ifdef WORDS_BIGENDIAN
#define ASNOUT(t,s,l)                       \
    do {                                    \
        unsigned sbyte = 0;                 \
        char *p = 0;                        \
        if (l > sizeof(s)) {                \
            _dwarf_p_error(dbg, error, DW_DLE_DEBUG_FRAME_LENGTH_BAD);\
            return DW_DLV_ERROR;            \
        }                                   \
        sbyte = sizeof(s) - l;              \
        p = (const char *)(&s);             \
        dbg->de_copy_word(t,(const void *)(p+sbyte),l);\
    } while (0)
#else /* LITTLEENDIAN */
#define ASNOUT(t,s,l)                       \
    do {                                    \
        const char *p = 0;                  \
        if (l > sizeof(s)) {                \
            _dwarf_p_error(dbg, error, DW_DLE_DEBUG_FRAME_LENGTH_BAD);\
            return DW_DLV_ERROR;            \
        }                                   \
        p = (const char *)(&s);             \
        memcpy(t,(const void *)p,l);        \
        dbg->de_copy_word(t,(const void *)p,l); \
    } while (0)
#endif /* ENDIANNESS */

#ifdef WORDS_BIGENDIAN
#define SIGN_EXTEND(dest, length)                                 \
    do {                                                          \
        if (*(Dwarf_Sbyte *)((char *)&dest +                      \
            sizeof(dest) - length) < 0) {                         \
            memcpy((char *)&dest, "\xff\xff\xff\xff\xff\xff\xff\xff",\
                sizeof(dest) - length);                           \
        }                                                         \
    } while (0)
#else /* LITTLE ENDIAN */
#define SIGN_EXTEND(dest, length)                               \
    do {                                                        \
        if (*(Dwarf_Sbyte *)((char *)&dest + (length-1)) < 0) { \
            memcpy((char *)&dest+length,                        \
                "\xff\xff\xff\xff\xff\xff\xff\xff",             \
                sizeof(dest) - length);                         \
        }                                                       \
    } while (0)

#endif /* ! LITTLE_ENDIAN */


/*  This function adds an attribute whose value is
    a target address to the given die.  The attribute
    is given the name provided by attr.  The address
    is given in pc_value.  */

static int
local_add_AT_address_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Signed form,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error);

/* old interface */
Dwarf_P_Attribute
dwarf_add_AT_targ_address(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Signed sym_index, Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    if (sym_index < 0) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    res =   dwarf_add_AT_targ_address_c(dbg,
        ownerdie, attr, pc_value,
        (Dwarf_Unsigned) sym_index,
        &a,
        error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;

}

/*  New interface, replacing dwarf_add_AT_targ_address.
    Essentially just makes sym_index a Dwarf_Unsigned
    so for symbolic relocations it can be a full address.  */
Dwarf_P_Attribute
dwarf_add_AT_targ_address_b(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_targ_address_c(dbg,
        ownerdie,attr,pc_value,sym_index,
        &a, error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;

}
int
dwarf_add_AT_targ_address_c(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    int res = 0;

    switch (attr) {
    case DW_AT_low_pc:
    case DW_AT_high_pc:

    /* added to support location lists */
    /* no way to check that this is a loclist-style address though */
    case DW_AT_location:
    case DW_AT_string_length:
    case DW_AT_return_addr:
    case DW_AT_frame_base:
    case DW_AT_segment:
    case DW_AT_static_link:
    case DW_AT_use_location:
    case DW_AT_vtable_elem_location:
    case DW_AT_const_value: /* Gcc can generate this as address. */
    case DW_AT_entry_pc:
        break;
    default:
        if (attr < DW_AT_lo_user || attr > DW_AT_hi_user ) {
            _dwarf_p_error(dbg, error, DW_DLE_INPUT_ATTR_BAD);
            return DW_DLV_ERROR;
        }
        break;
    }

    res = local_add_AT_address_a(dbg, ownerdie, attr, DW_FORM_addr,
        pc_value, sym_index,attr_out, error);
    return res;
}

Dwarf_P_Attribute
dwarf_add_AT_ref_address(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_ref_address_a(dbg,ownerdie,
        attr,pc_value,sym_index,&a,error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}

int
dwarf_add_AT_ref_address_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    int res = 0;

    switch (attr) {
    case DW_AT_type:
    case DW_AT_import:
        break;

    default:
        if (attr < DW_AT_lo_user || attr > DW_AT_hi_user ) {
            _dwarf_p_error(dbg, error, DW_DLE_INPUT_ATTR_BAD);
            return DW_DLV_ERROR;
        }
        break;
    }

    /*  FIXME: For DWARF3 and later this call is problematic as
        DW_FORM_ref_addr is really an offset in
        .debug_info , not an address.  */
    res = local_add_AT_address_a(dbg, ownerdie,
        attr, DW_FORM_ref_addr,
        pc_value, sym_index,attr_out, error);
    return res;
}


/* Make sure attribute types are checked before entering here. */
static int
local_add_AT_address_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Signed form,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int upointer_size = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    upointer_size = dbg->de_pointer_size;

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    /* attribute types have already been checked */
    /* switch (attr) { ... } */

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attr;
    new_attr->ar_attribute_form = form;
    new_attr->ar_nbytes = upointer_size;
    new_attr->ar_rel_symidx = sym_index;
    new_attr->ar_reloc_len = upointer_size;
    new_attr->ar_next = 0;
    if (sym_index != NO_ELF_SYM_INDEX) {
        new_attr->ar_rel_type = dbg->de_ptr_reloc;
    } else {
        new_attr->ar_rel_type = R_MIPS_NONE;
    }

    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, upointer_size);
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    WRITE_UNALIGNED(dbg, new_attr->ar_data,
        (const void *) &pc_value,
        sizeof(pc_value), upointer_size);

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}

/*  Pass in array (ie a pointer to) of Dwarf_Signed
    with input_array_length elements.

    A block of bytes is created
    with the sleb data in it.

    A pointer to the glob of bytes is returned
    through the output_block pointer and its length
    through output_block_len pointer. */
int
dwarf_compress_integer_block_a(
    Dwarf_P_Debug    dbg,
    Dwarf_Unsigned  input_array_length,
    Dwarf_Signed *  input_array,
    Dwarf_Unsigned *output_block_len,
    void         ** output_block_returned,
    Dwarf_Error*     error
)
{
    Dwarf_Unsigned output_length_in_bytes = 0;
    char * output_block = 0;
    char encode_buffer[ENCODE_SPACE_NEEDED];
    unsigned u = 0;
    char * ptr = 0;
    int remain = 0;
    int result = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    /* First compress everything to find the total size. */

    output_length_in_bytes = 0;
    for (u=0; u<input_array_length; u++) {
        int unit_encoded_size;
        Dwarf_Signed unit = 0;

        unit = input_array[u];
        result = _dwarf_pro_encode_signed_leb128_nm(
            unit, &unit_encoded_size,
            encode_buffer,sizeof(encode_buffer));
        if (result !=  DW_DLV_OK) {
            _dwarf_p_error(NULL, error, DW_DLE_LEB_IMPROPER);
            return DW_DLV_ERROR;
        }
        output_length_in_bytes += unit_encoded_size;
    }
    output_block = (void *)
        _dwarf_p_get_alloc(dbg, output_length_in_bytes);
    if (output_block == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    /* Then compress again and copy into new buffer */
    ptr = output_block;
    remain = output_length_in_bytes;
    for (u=0; u<input_array_length; u++) {
        int unit_encoded_size;
        Dwarf_Signed unit = 0;

        unit = input_array[u];
        result = _dwarf_pro_encode_signed_leb128_nm(unit,
            &unit_encoded_size,
            ptr, remain);
        if (result !=  DW_DLV_OK) {
            _dwarf_p_error(NULL, error, DW_DLE_LEB_IMPROPER);
            return DW_DLV_ERROR;
        }
        remain -= unit_encoded_size;
        ptr += unit_encoded_size;
    }

    *output_block_len = output_length_in_bytes;
    *output_block_returned = output_block;
    return DW_DLV_OK;
}
/*  Functions to compress and uncompress data from normal
    arrays of integral types into arrays of LEB128 numbers.
    Extend these functions as needed to handle wider input
    variety.  Return values should be freed with _dwarf_p_dealloc
    after they aren't needed any more.

    It is not clear there is any use to this function
    as it was contributed by SUN but may not have ever
    been needed in any released SUN compiler. */

/* return value points to an array of LEB numbers */

void *
dwarf_compress_integer_block(
    Dwarf_P_Debug    dbg,
    Dwarf_Bool       unit_is_signed,
    Dwarf_Small      unit_length_in_bits,
    void*            input_block,
    Dwarf_Unsigned   input_length_in_units,
    Dwarf_Unsigned*  output_length_in_bytes_ptr,
    Dwarf_Error*     error
)
{
    Dwarf_Unsigned output_length_in_bytes = 0;
    char * output_block = 0;
    char encode_buffer[ENCODE_SPACE_NEEDED];
    unsigned u = 0;
    char * ptr = 0;
    int remain = 0;
    int result = 0;
    char *inptr = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return((void *)DW_DLV_BADADDR);
    }

    if (unit_is_signed == false ||
        unit_length_in_bits != 32 ||
        input_block == NULL ||
        input_length_in_units == 0 ||
        output_length_in_bytes_ptr == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_BADBITC);
        return ((void *) DW_DLV_BADADDR);
    }

    /* At this point we assume the format is: signed 32 bit */

    /* First compress everything to find the total size. */

    output_length_in_bytes = 0;
    inptr = input_block;
    for (u=0; u<input_length_in_units; u++) {
        int unit_encoded_size;
        Dwarf_Signed unit = 0;

        ASNAR(unit,inptr,DWARF_32BIT_SIZE);
        SIGN_EXTEND(unit,DWARF_32BIT_SIZE);
        result = _dwarf_pro_encode_signed_leb128_nm(
            unit, &unit_encoded_size,
            encode_buffer,sizeof(encode_buffer));
        if (result !=  DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return((Dwarf_P_Attribute)DW_DLV_BADADDR);
        }
        output_length_in_bytes += unit_encoded_size;
        inptr += DWARF_32BIT_SIZE;
    }

    /* Then alloc */
    output_block = (void *)
        _dwarf_p_get_alloc(dbg, output_length_in_bytes);
    if (output_block == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return((void*)DW_DLV_BADADDR);
    }

    /* Then compress again and copy into new buffer */
    ptr = output_block;
    inptr = input_block;
    remain = output_length_in_bytes;
    for (u=0; u<input_length_in_units; u++) {
        int unit_encoded_size;
        Dwarf_Signed unit = 0;

        ASNAR(unit,inptr,DWARF_32BIT_SIZE);
        SIGN_EXTEND(unit,DWARF_32BIT_SIZE);
        result = _dwarf_pro_encode_signed_leb128_nm(unit,
            &unit_encoded_size,
            ptr, remain);
        if (result !=  DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return((Dwarf_P_Attribute)DW_DLV_BADADDR);
        }
        remain -= unit_encoded_size;
        ptr += unit_encoded_size;
        inptr += DWARF_32BIT_SIZE;
    }

    if (remain != 0) {
        _dwarf_p_dealloc(dbg, (unsigned char *)output_block);
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return((Dwarf_P_Attribute)DW_DLV_BADADDR);
    }

    *output_length_in_bytes_ptr = output_length_in_bytes;
    return (void*) output_block;
}

void
dwarf_dealloc_compressed_block(Dwarf_P_Debug dbg, void * space)
{
    _dwarf_p_dealloc(dbg, space);
}

/*  This is very similar to targ_address but results in a different FORM */
/*  dbg->de_ar_data_attribute_form is data4 or data8
    and dwarf4 changes the definition for such on DW_AT_high_pc.
    DWARF 3: the FORM here has no defined meaning for dwarf3.
    DWARF 4: the FORM here means that for DW_AT_high_pc the value
        is not a high address but is instead an offset
        from a (separate) DW_AT_low_pc.
    The intent for DWARF4 is that this is not a relocated
    address at all.  Instead a simple offset.
    But this should NOT be called for a simple non-relocated offset.
    So do not call this with an attr of DW_AT_high_pc.
    Use dwarf_add_AT_unsigned_const() (for example) instead of
    dwarf_add_AT_dataref when the value is a simple offset .  */

int
dwarf_add_AT_dataref_a(
    Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    int res = 0;

    /* TODO: Add checking here */
    res = local_add_AT_address_a(dbg, ownerdie, attr,
        dbg->de_ar_data_attribute_form,
        pc_value,
        sym_index,
        attr_out,
        error);
    return res;
}


Dwarf_P_Attribute
dwarf_add_AT_dataref(
    Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Unsigned pc_value,
    Dwarf_Unsigned sym_index,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    /* TODO: Add checking here */
    res = local_add_AT_address_a(dbg, ownerdie, attr,
        dbg->de_ar_data_attribute_form,
        pc_value,
        sym_index,
        &a,
        error);
    if (res != DW_DLV_OK) {
        return((Dwarf_P_Attribute)DW_DLV_BADADDR);
    }
    return a;
}

Dwarf_P_Attribute
dwarf_add_AT_block(
    Dwarf_P_Debug       dbg,
    Dwarf_P_Die         ownerdie,
    Dwarf_Half          attr,
    Dwarf_Small         *block_data,
    Dwarf_Unsigned      block_size,
    Dwarf_Error         *error)
{
    int res = 0;
    Dwarf_P_Attribute   new_attr = 0;

    res = dwarf_add_AT_block_a(dbg,ownerdie,attr,
        block_data,block_size,&new_attr,error);
    if (res != DW_DLV_OK) {
        return((Dwarf_P_Attribute)DW_DLV_BADADDR);
    }
    return new_attr;
}
int
dwarf_add_AT_block_a(
    Dwarf_P_Debug       dbg,
    Dwarf_P_Die         ownerdie,
    Dwarf_Half          attr,
    Dwarf_Small         *block_data,
    Dwarf_Unsigned      block_size,
    Dwarf_P_Attribute*  attr_out,
    Dwarf_Error         *error)
{
    Dwarf_P_Attribute   new_attr = 0;
    int result = 0;
    char encode_buffer[ENCODE_SPACE_NEEDED];
    int len_size = 0;
    char * attrdata = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    /* I don't mess with block1, block2, block4, not worth the effort */

    /* So, encode the length into LEB128 */
    result = _dwarf_pro_encode_leb128_nm(block_size, &len_size,
        encode_buffer,sizeof(encode_buffer));
    if (result !=  DW_DLV_OK) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    /* Allocate the new attribute */
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    /* Fill in the attribute */
    new_attr->ar_attribute = attr;
    new_attr->ar_attribute_form = DW_FORM_block;
    new_attr->ar_nbytes = len_size + block_size;
    new_attr->ar_next = 0;

    new_attr->ar_data = attrdata = (char *)
        _dwarf_p_get_alloc(dbg, len_size + block_size);
    if (new_attr->ar_data == NULL) {
        /* free the block we got earlier */
        _dwarf_p_dealloc(dbg, (unsigned char *) new_attr);
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    /* write length and data to attribute data buffer */
    memcpy(attrdata, encode_buffer, len_size);
    attrdata += len_size;
    memcpy(attrdata, block_data, block_size);

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}


/*
    This function adds attributes whose value
    is an unsigned constant.  It determines the
    size of the value field from the value of
    the constant.
*/
Dwarf_P_Attribute
dwarf_add_AT_unsigned_const(Dwarf_P_Debug dbg,
   Dwarf_P_Die ownerdie,
   Dwarf_Half attr,
   Dwarf_Unsigned value, Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_unsigned_const_a(dbg,
        ownerdie,attr,value,
        &a,error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}


int
dwarf_add_AT_unsigned_const_a(Dwarf_P_Debug dbg,
   Dwarf_P_Die ownerdie,
   Dwarf_Half attr,
   Dwarf_Unsigned value,
   Dwarf_P_Attribute *attr_out,
   Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Small size = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    switch (attr) {
    case DW_AT_ordering:
    case DW_AT_byte_size:
    case DW_AT_bit_offset:
    case DW_AT_bit_size:
    case DW_AT_inline:
    case DW_AT_language:
    case DW_AT_visibility:
    case DW_AT_virtuality:
    case DW_AT_accessibility:
    case DW_AT_address_class:
    case DW_AT_calling_convention:
    case DW_AT_encoding:
    case DW_AT_identifier_case:
    case DW_AT_MIPS_loop_unroll_factor:
    case DW_AT_MIPS_software_pipeline_depth:
        break;

    case DW_AT_decl_column:
    case DW_AT_decl_file:
    case DW_AT_decl_line:
    case DW_AT_const_value:
    case DW_AT_start_scope:
    case DW_AT_stride_size: /* DW_AT_bit_stride  is DWARF3 name */
    case DW_AT_count:
    case DW_AT_high_pc:     /* DWARF5: allowing const udata high_pc */
    case DW_AT_associated:
    case DW_AT_allocated:
    case DW_AT_upper_bound:
    case DW_AT_lower_bound:
    case DW_AT_call_file:
    case DW_AT_call_line:
    case DW_AT_data_member_location:
    case DW_AT_trampoline:
        break;

    default:
        if (attr < DW_AT_lo_user || attr > DW_AT_hi_user ) {
            _dwarf_p_error(dbg, error, DW_DLE_INPUT_ATTR_BAD);
            return DW_DLV_ERROR;
        }
        break;
    }

    /* Compute the number of bytes needed to hold constant. */
    if (value <= UCHAR_MAX) {
        attr_form = DW_FORM_data1;
        size = 1;
    } else if (value <= USHRT_MAX) {
        attr_form = DW_FORM_data2;
        size = 2;
    } else if (value <= UINT_MAX) {
        attr_form = DW_FORM_data4;
        size = 4;
    } else {
        attr_form = DW_FORM_data8;
        size = 8;
    }

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attr;
    new_attr->ar_attribute_form = attr_form;
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_reloc_len = 0; /* irrelevant: unused with R_MIPS_NONE */
    new_attr->ar_nbytes = size;
    new_attr->ar_next = 0;

    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, size);
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    WRITE_UNALIGNED(dbg, new_attr->ar_data,
        (const void *) &value, sizeof(value), size);

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}


/*  This function adds attributes whose value
    is an signed constant.  It determines the
    size of the value field from the value of
    the constant.  */
Dwarf_P_Attribute
dwarf_add_AT_signed_const(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Signed value,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_signed_const_a(dbg,
        ownerdie,attr,value,&a,error);
    if(res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}

int
dwarf_add_AT_signed_const_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Signed value,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    Dwarf_Half attr_form = 0;
    Dwarf_Small size = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    switch (attr) {
    case DW_AT_lower_bound:
    case DW_AT_upper_bound:
    case DW_AT_const_value:
    case DW_AT_bit_offset:
    case DW_AT_bit_size:
    case DW_AT_byte_size:
    case DW_AT_count:
    case DW_AT_byte_stride:
    case DW_AT_bit_stride:
    case DW_AT_allocated:
    case DW_AT_associated:
        break;

    default:
        if (attr < DW_AT_lo_user || attr > DW_AT_hi_user ) {
            _dwarf_p_error(dbg, error, DW_DLE_INPUT_ATTR_BAD);
            return DW_DLV_ERROR;
        }
        break;
    }

    /* Compute the number of bytes needed to hold constant. */
    if (value >= SCHAR_MIN && value <= SCHAR_MAX) {
        attr_form = DW_FORM_data1;
        size = 1;
    } else if (value >= SHRT_MIN && value <= SHRT_MAX) {
        attr_form = DW_FORM_data2;
        size = 2;
    } else if (value >= INT_MIN && value <= INT_MAX) {
        attr_form = DW_FORM_data4;
        size = 4;
    } else {
        attr_form = DW_FORM_data8;
        size = 8;
    }

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attr;
    new_attr->ar_attribute_form = attr_form;
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_reloc_len = 0; /* irrelevant: unused with R_MIPS_NONE */
    new_attr->ar_nbytes = size;
    new_attr->ar_next = 0;

    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, size);
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    WRITE_UNALIGNED(dbg, new_attr->ar_data,
        (const void *) &value, sizeof(value), size);

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}


/*  This function adds attributes whose value
    is a location expression.  */
Dwarf_P_Attribute
dwarf_add_AT_location_expr(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_P_Expr loc_expr, Dwarf_Error * error)
{
    int res = 0;
    Dwarf_P_Attribute a = 0;

    res = dwarf_add_AT_location_expr_a(dbg,ownerdie,attr,
        loc_expr,&a,error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}

/* Preferred interface as of December 2018 */
int
dwarf_add_AT_location_expr_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_P_Expr loc_expr,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    char encode_buffer[ENCODE_SPACE_NEEDED];
    int res = 0;
    Dwarf_P_Attribute new_attr = 0;
    Dwarf_Half attr_form = 0;
    char *len_str = 0;
    int len_size = 0;
    Dwarf_Unsigned block_size = 0;
    char *block_dest_ptr = 0;
    int do_len_as_int = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    if (loc_expr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_EXPR_NULL);
        return DW_DLV_ERROR;
    }

    if (loc_expr->ex_dbg != dbg) {
        _dwarf_p_error(dbg, error, DW_DLE_LOC_EXPR_BAD);
        return DW_DLV_ERROR;
    }
    block_size = loc_expr->ex_next_byte_offset;

    switch (attr) {
    case DW_AT_location:
    case DW_AT_string_length:
    case DW_AT_const_value:
    case DW_AT_use_location:
    case DW_AT_return_addr:
    case DW_AT_data_member_location:
    case DW_AT_frame_base:
    case DW_AT_static_link:
    case DW_AT_vtable_elem_location:
    case DW_AT_lower_bound:
    case DW_AT_upper_bound:
    case DW_AT_count:
    case DW_AT_associated:
    case DW_AT_allocated:
    case DW_AT_data_location:
    case DW_AT_byte_stride:
    case DW_AT_bit_stride:
    case DW_AT_byte_size:
    case DW_AT_bit_size:
    break;

    default:
        if (attr < DW_AT_lo_user || attr > DW_AT_hi_user ) {
            _dwarf_p_error(dbg, error, DW_DLE_INPUT_ATTR_BAD);
            return DW_DLV_ERROR;
        }
    break;
    }

    /*  Compute the number of bytes needed to hold constant.
        This is a bit fake in that the size will never
        be particularly large and always < UINT_MAX. */
    if (block_size <= UCHAR_MAX) {
        attr_form = DW_FORM_block1;
        len_size = 1;
        do_len_as_int = 1;
    } else if (block_size <= USHRT_MAX) {
        attr_form = DW_FORM_block2;
        len_size = 2;
        do_len_as_int = 1;
    } else if (block_size <= UINT_MAX) {
        attr_form = DW_FORM_block4;
        len_size = 4;
        do_len_as_int = 1;
    } else {
        attr_form = DW_FORM_block;
        res = _dwarf_pro_encode_leb128_nm(block_size, &len_size,
            encode_buffer,
            sizeof(encode_buffer));
        if (res != DW_DLV_OK) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        len_str = (char *) encode_buffer;
    }

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attr;
    new_attr->ar_attribute_form = attr_form;
    new_attr->ar_reloc_len = dbg->de_pointer_size;
    if (loc_expr->ex_reloc_sym_index != NO_ELF_SYM_INDEX) {
        new_attr->ar_rel_type = dbg->de_ptr_reloc;
    } else {
        new_attr->ar_rel_type = R_MIPS_NONE;
    }
    new_attr->ar_rel_symidx = loc_expr->ex_reloc_sym_index;
    new_attr->ar_rel_offset =
        loc_expr->ex_reloc_offset + len_size;

    new_attr->ar_nbytes = block_size + len_size;

    new_attr->ar_next = 0;
    new_attr->ar_data = block_dest_ptr =
        (char *) _dwarf_p_get_alloc(dbg, block_size + len_size);
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    if (do_len_as_int) {
        WRITE_UNALIGNED(dbg, block_dest_ptr, (const void *) &block_size,
            sizeof(block_size), len_size);
    } else {
        /* Is uleb number form, DW_FORM_block. See above. */
        memcpy(block_dest_ptr, len_str, len_size);
    }
    block_dest_ptr += len_size;
    if (block_size > sizeof(loc_expr->ex_byte_stream)) {
        /* ex_byte_stream has a fixed max value. */
        _dwarf_p_error(dbg, error, DW_DLE_EXPR_LENGTH_BAD);
        return DW_DLV_ERROR;
    }
    memcpy(block_dest_ptr, &(loc_expr->ex_byte_stream[0]), block_size);

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}


/*  This function adds attributes of reference class.
    The references here are local CU references,
    not DW_FORM_ref_addr.
    The offset field is 4 bytes for 32-bit objects,
    and 8-bytes for 64-bit objects.  Otherdie is the
    that is referenced by ownerdie.

    For reference attributes, the ar_data and ar_nbytes
    are not needed.  Instead, the ar_ref_die points to
    the other die, and its di_offset value is used as
    the reference value.  */

static int
_dwarf_add_AT_reference_internal_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_P_Die otherdie,
    int check_otherdie,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    if (check_otherdie && (otherdie == NULL)) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    switch (attr) {
    case DW_AT_count:
    case DW_AT_sibling:
    case DW_AT_byte_size:
    case DW_AT_bit_offset:
    case DW_AT_bit_size:
    case DW_AT_discr:
    case DW_AT_import:
    case DW_AT_common_reference:
    case DW_AT_containing_type:
    case DW_AT_default_value:
    case DW_AT_lower_bound:
    case DW_AT_bit_stride: /* Early name is DW_AT_stride_size */
    case DW_AT_upper_bound:
    case DW_AT_abstract_origin:
    case DW_AT_base_types:
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
        break;

    default:
        if (attr < DW_AT_lo_user || attr > DW_AT_hi_user ) {
            _dwarf_p_error(dbg, error, DW_DLE_INPUT_ATTR_BAD);
            return DW_DLV_ERROR;
        }
        break;
    }

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attr;
    new_attr->ar_attribute_form = dbg->de_ar_ref_attr_form;
    new_attr->ar_nbytes = dbg->de_dwarf_offset_size;
    new_attr->ar_reloc_len = dbg->de_dwarf_offset_size;
    new_attr->ar_ref_die = otherdie;
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_next = 0;

    /* Add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}

/*  Allowing the target die to be identified later.
    */
int
dwarf_add_AT_reference_c(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_P_Die otherdie,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    int res = 0;

    res = _dwarf_add_AT_reference_internal_a(dbg,
        ownerdie,
        attr,
        otherdie,
        /* check otherdie */ 0,
        attr_out,
        error);
    return res;
}



Dwarf_P_Attribute
dwarf_add_AT_reference(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_P_Die otherdie, Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = _dwarf_add_AT_reference_internal_a(dbg,
        ownerdie,
        attr,
        otherdie,
        /* check otherdie */ 1,
        &a,
        error);
    if (res != DW_DLV_OK) {
        return (Dwarf_P_Attribute)DW_DLV_BADADDR;
    }
    return a;
}

/*  Allowing the target die to be identified later.
    */
Dwarf_P_Attribute
dwarf_add_AT_reference_b(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_P_Die otherdie,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = _dwarf_add_AT_reference_internal_a(dbg,
        ownerdie,
        attr,
        otherdie,
        /* check otherdie */ 0,
        &a,
        error);
    if (res != DW_DLV_OK) {
        return (Dwarf_P_Attribute)DW_DLV_BADADDR;
    }
    return a;
}




int
dwarf_fixup_AT_reference_die(Dwarf_P_Debug dbg,
   Dwarf_Half attrnum,
   Dwarf_P_Die sourcedie,
   Dwarf_P_Die targetdie,
   Dwarf_Error *error)
{
    Dwarf_P_Attribute a = 0;
    Dwarf_P_Attribute cur = 0;
    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    for(cur = sourcedie->di_attrs; cur; cur = cur->ar_next) {
        if (attrnum == cur->ar_attribute) {
            a = cur;
            break;
        }
    }
    if(!a) {
        _dwarf_p_error(dbg, error, DW_DLE_AT_FIXUP_NULL);
        return DW_DLV_ERROR;
    }
    if(a->ar_ref_die) {
        _dwarf_p_error(dbg, error, DW_DLE_AT_FIXUP_DUP);
        return DW_DLV_ERROR;
    }
    a->ar_ref_die = targetdie;
    return DW_DLV_OK;
}


/* This function adds attributes of the flag class.  */
Dwarf_P_Attribute
dwarf_add_AT_flag(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Small flag,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_flag_a(dbg,ownerdie,attr,flag,
        &a,error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}
int
dwarf_add_AT_flag_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    Dwarf_Small flag,
    Dwarf_P_Attribute * attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }
    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attr;
    new_attr->ar_attribute_form = DW_FORM_flag;
    new_attr->ar_nbytes = 1;
    new_attr->ar_reloc_len = 0; /* not used */
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_next = 0;

    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, 1);
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    memcpy(new_attr->ar_data, &flag, 1);

    /* Add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}


/*  This function adds values of attributes
    belonging to the string class. */
Dwarf_P_Attribute
dwarf_add_AT_string(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr, char *string, Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_string_a(dbg,
        ownerdie,attr,string,&a,error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}

int
dwarf_add_AT_string_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die ownerdie,
    Dwarf_Half attr,
    char *string,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    int res = 0;

    if (dbg == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_DBG_NULL);
        return DW_DLV_ERROR;
    }

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    switch (attr) {
    /* See also: pro_section.c for same strings attribute list. */
    case DW_AT_comp_dir:
    case DW_AT_const_value:
    case DW_AT_linkage_name:/* DWARF5, but ok for any version really.*/
    case DW_AT_MIPS_abstract_name:
    case DW_AT_MIPS_linkage_name:
    case DW_AT_name:
    case DW_AT_producer:
        break;

        default:
            if (attr < DW_AT_lo_user || attr > DW_AT_hi_user ) {
            _dwarf_p_error(dbg, error, DW_DLE_INPUT_ATTR_BAD);
            return DW_DLV_ERROR;
        }
            break;
    }
    new_attr->ar_attribute = attr;
    res = _dwarf_pro_set_string_attr(new_attr,ownerdie->di_dbg,
        string,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}

Dwarf_P_Attribute
dwarf_add_AT_const_value_string(Dwarf_P_Die ownerdie,
    char *string_value, Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_const_value_string_a(ownerdie,
        string_value,&a,error);
    if (res != DW_DLV_OK) {
        return (Dwarf_P_Attribute) DW_DLV_BADADDR;
    }
    return a;
}

int
dwarf_add_AT_const_value_string_a(Dwarf_P_Die ownerdie,
    char *string_value,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    Dwarf_P_Debug dbg = 0;
    int res = 0;

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }
    dbg = ownerdie->di_dbg;

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = DW_AT_const_value;
    res = _dwarf_pro_set_string_attr(new_attr,dbg,
        string_value,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}

Dwarf_P_Attribute
dwarf_add_AT_with_ref_sig8(Dwarf_P_Die ownerdie,
    Dwarf_Half attrnum,
    const Dwarf_Sig8 *sig8_in,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_with_ref_sig8_a(ownerdie,
        attrnum,sig8_in,&a,error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}

int
dwarf_add_AT_with_ref_sig8_a(Dwarf_P_Die ownerdie,
    Dwarf_Half attrnum,
    const Dwarf_Sig8 *sig8_in,
    Dwarf_P_Attribute * attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    Dwarf_P_Debug dbg = 0;

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }
    dbg = ownerdie->di_dbg;

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    new_attr->ar_attribute = attrnum;
    new_attr->ar_attribute_form = DW_FORM_ref_sig8;
    new_attr->ar_nbytes = sizeof (Dwarf_Sig8);
    new_attr->ar_next = 0;

    new_attr->ar_data =
        (char *) _dwarf_p_get_alloc(dbg, sizeof(Dwarf_Sig8));
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    memcpy(new_attr->ar_data,sig8_in,sizeof(Dwarf_Sig8));
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_reloc_len = 0; /* unused for R_MIPS_NONE */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}



Dwarf_P_Attribute
dwarf_add_AT_producer(Dwarf_P_Die ownerdie,
    char *producer_string, Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_producer_a(ownerdie,
        producer_string,&a,error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute)DW_DLV_BADADDR);
    }
    return a;
}

int
dwarf_add_AT_producer_a(Dwarf_P_Die ownerdie,
    char *producer_string,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    Dwarf_P_Debug dbg = 0;
    int res = 0;

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }
    dbg = ownerdie->di_dbg;
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = DW_AT_producer;
    res = _dwarf_pro_set_string_attr(new_attr,dbg,
        producer_string,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}

int
dwarf_add_AT_const_value_signedint_a(Dwarf_P_Die ownerdie,
    Dwarf_Signed signed_value,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    int res = 0;

    res = dwarf_add_AT_any_value_sleb_a(
        ownerdie,DW_AT_const_value,
        signed_value,
        attr_out, error);
    return res;
}

Dwarf_P_Attribute
dwarf_add_AT_const_value_signedint(Dwarf_P_Die ownerdie,
    Dwarf_Signed signed_value,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_any_value_sleb_a(
        ownerdie,DW_AT_const_value,
        signed_value,
        &a, error);
    if (res != DW_DLV_OK) {
        return (Dwarf_P_Attribute)DW_DLV_BADADDR;
    }
    return a;
}

int
dwarf_add_AT_implicit_const(Dwarf_P_Die ownerdie,
    Dwarf_Half attrnum,
    Dwarf_Signed signed_value,
    Dwarf_P_Attribute *outattr,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    Dwarf_P_Debug dbg = 0;

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }
    dbg = ownerdie->di_dbg;

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attrnum;
    new_attr->ar_attribute_form = DW_FORM_implicit_const;
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_reloc_len = 0; /* unused for R_MIPS_NONE */
    new_attr->ar_next = 0;

    /*  The value will go in the abbrev section.
        Not the DIE. Encoding done with abbrev generation. */
    new_attr->ar_data = 0;
    new_attr->ar_nbytes = 0;
    new_attr->ar_implicit_const = signed_value;

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *outattr = new_attr;
    return DW_DLV_OK;
}

Dwarf_P_Attribute
dwarf_add_AT_any_value_sleb(Dwarf_P_Die ownerdie,
    Dwarf_Half attrnum,
    Dwarf_Signed signed_value,
    Dwarf_Error * error)
{
    int res = 0;
    Dwarf_P_Attribute a = 0;

    res = dwarf_add_AT_any_value_sleb_a(ownerdie,
        attrnum,
        signed_value,
        &a, error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}

int
dwarf_add_AT_any_value_sleb_a(Dwarf_P_Die ownerdie,
    Dwarf_Half attrnum,
    Dwarf_Signed signed_value,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    int leb_size = 0;
    Dwarf_P_Debug dbg = 0;
    char encode_buffer[ENCODE_SPACE_NEEDED];
    int res = 0;

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }
    dbg = ownerdie->di_dbg;

    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attrnum;
    new_attr->ar_attribute_form = DW_FORM_sdata;
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_reloc_len = 0; /* unused for R_MIPS_NONE */
    new_attr->ar_next = 0;

    res = _dwarf_pro_encode_signed_leb128_nm(signed_value, &leb_size,
        encode_buffer,
        sizeof(encode_buffer));
    if (res != DW_DLV_OK) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, leb_size);
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    memcpy(new_attr->ar_data, encode_buffer, leb_size);
    new_attr->ar_nbytes = leb_size;

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}

/* AT_const_value, uleb */
Dwarf_P_Attribute
dwarf_add_AT_const_value_unsignedint(Dwarf_P_Die ownerdie,
    Dwarf_Unsigned unsigned_value,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a =0;
    int res = 0;

    res = dwarf_add_AT_any_value_uleb_a(
        ownerdie,DW_AT_const_value,
        unsigned_value,
        &a,
        error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}

int
dwarf_add_AT_const_value_unsignedint_a(Dwarf_P_Die ownerdie,
    Dwarf_Unsigned unsigned_value,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{

    return dwarf_add_AT_any_value_uleb_a(
        ownerdie,DW_AT_const_value,
        unsigned_value,
        attr_out,
        error);
}

int
dwarf_add_AT_data16(Dwarf_P_Die ownerdie,
    Dwarf_Half attrnum,
    Dwarf_Form_Data16 * ptr_to_val,
    Dwarf_P_Attribute * attr_return,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int val_size = sizeof(Dwarf_Form_Data16);
    Dwarf_P_Debug dbg = 0;

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }
    dbg = ownerdie->di_dbg;
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    new_attr->ar_attribute = attrnum;
    new_attr->ar_attribute_form = DW_FORM_data16;
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_reloc_len = 0; /* unused for R_MIPS_NONE */
    new_attr->ar_next = 0;
    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, val_size);
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    memcpy(new_attr->ar_data, ptr_to_val->fd_data, val_size);
    new_attr->ar_nbytes = val_size;
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_return = new_attr;
    return DW_DLV_OK;
}

Dwarf_P_Attribute
dwarf_add_AT_any_value_uleb(Dwarf_P_Die ownerdie,
    Dwarf_Half attrnum,
    Dwarf_Unsigned unsigned_value,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_any_value_uleb_a(ownerdie,
        attrnum,unsigned_value,&a,error);
    if (res != DW_DLV_OK) {
        return ((Dwarf_P_Attribute) DW_DLV_BADADDR);
    }
    return a;
}
int
dwarf_add_AT_any_value_uleb_a(Dwarf_P_Die ownerdie,
    Dwarf_Half attrnum,
    Dwarf_Unsigned unsigned_value,
    Dwarf_P_Attribute * attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int leb_size;
    Dwarf_P_Debug dbg = 0;
    char encode_buffer[ENCODE_SPACE_NEEDED];
    int res;

    if (ownerdie == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_DIE_NULL);
        return DW_DLV_ERROR;
    }
    dbg = ownerdie->di_dbg;
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        _dwarf_p_error(NULL, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    new_attr->ar_attribute = attrnum;
    new_attr->ar_attribute_form = DW_FORM_udata;
    new_attr->ar_rel_type = R_MIPS_NONE;
    new_attr->ar_reloc_len = 0; /* unused for R_MIPS_NONE */
    new_attr->ar_next = 0;

    res = _dwarf_pro_encode_leb128_nm(unsigned_value, &leb_size,
        encode_buffer,
        sizeof(encode_buffer));
    if (res != DW_DLV_OK) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, leb_size);
    if (new_attr->ar_data == NULL) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    memcpy(new_attr->ar_data, encode_buffer, leb_size);
    new_attr->ar_nbytes = leb_size;

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}
