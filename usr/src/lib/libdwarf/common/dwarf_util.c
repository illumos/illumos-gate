/*
  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2007-2020 David Anderson. All Rights Reserved.
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
#include <stdio.h>
#include <stdarg.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h> /* For free() and emergency abort() */
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#elif defined(_WIN32) && defined(_MSC_VER)
#include <io.h>
#endif /* HAVE_UNISTD_H */
#include <sys/types.h> /* for open() */
#include <sys/stat.h> /* for open() */
#include <fcntl.h> /* for open() */
#include "dwarf_incl.h"
#include "dwarf_alloc.h"
#include "dwarf_error.h"
#include "dwarf_util.h"
#include "dwarf_abbrev.h"
#include "memcpy_swap.h"
#include "dwarf_die_deliv.h"
#include "dwarfstring.h"
#include "pro_encode_nm.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif /* O_BINARY */



#define MINBUFLEN 1000
#define TRUE  1
#define FALSE 0

#if _WIN32
#define NULL_DEVICE_NAME "NUL"
#else
#define NULL_DEVICE_NAME "/dev/null"
#endif /* _WIN32 */

/*  The function returned allows dwarfdump and other callers to
    do an endian-sensitive copy-word with a chosen
    source-length.  */
typedef void (*endian_funcp_type)(void *, const void *,unsigned long);

const char *
dwarf_package_version(void)
{
    return PACKAGE_VERSION;
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

endian_funcp_type
dwarf_get_endian_copy_function(Dwarf_Debug dbg)
{
    if (dbg) {
        return dbg->de_copy_word;
    }
    return 0;
}


Dwarf_Bool
_dwarf_file_has_debug_fission_cu_index(Dwarf_Debug dbg)
{
    if(!dbg) {
        return FALSE;
    }
    if (dbg->de_cu_hashindex_data) {
        return TRUE;
    }
    return FALSE;
}
Dwarf_Bool
_dwarf_file_has_debug_fission_tu_index(Dwarf_Debug dbg)
{
    if(!dbg) {
        return FALSE;
    }
    if (dbg->de_tu_hashindex_data ) {
        return TRUE;
    }
    return FALSE;
}


Dwarf_Bool
_dwarf_file_has_debug_fission_index(Dwarf_Debug dbg)
{
    if(!dbg) {
        return FALSE;
    }
    if (dbg->de_cu_hashindex_data ||
        dbg->de_tu_hashindex_data) {
        return 1;
    }
    return FALSE;
}

int
_dwarf_internal_get_die_comp_dir(Dwarf_Die die, const char **compdir_out,
    const char **compname_out,
    Dwarf_Error *error)
{
    Dwarf_Attribute comp_dir_attr = 0;
    Dwarf_Attribute comp_name_attr = 0;
    int resattr = 0;
    Dwarf_Debug dbg = 0;

    dbg = die->di_cu_context->cc_dbg;
    resattr = dwarf_attr(die, DW_AT_name, &comp_name_attr, error);
    if (resattr == DW_DLV_ERROR) {
        return resattr;
    }
    if (resattr == DW_DLV_OK) {
        int cres = DW_DLV_ERROR;
        char *name = 0;

        cres = dwarf_formstring(comp_name_attr, &name, error);
        if (cres == DW_DLV_ERROR) {
            dwarf_dealloc(dbg, comp_name_attr, DW_DLA_ATTR);
            return cres;
        } else if (cres == DW_DLV_OK) {
            *compname_out = (const char *)name;
        } else {
            /* FALL thru */
        }
    }
    if (resattr == DW_DLV_OK) {
        dwarf_dealloc(dbg, comp_name_attr, DW_DLA_ATTR);
    }
    resattr = dwarf_attr(die, DW_AT_comp_dir, &comp_dir_attr, error);
    if (resattr == DW_DLV_ERROR) {
        return resattr;
    }
    if (resattr == DW_DLV_OK) {
        int cres = DW_DLV_ERROR;
        char *cdir = 0;

        cres = dwarf_formstring(comp_dir_attr, &cdir, error);
        if (cres == DW_DLV_ERROR) {
            dwarf_dealloc(dbg, comp_dir_attr, DW_DLA_ATTR);
            return cres;
        } else if (cres == DW_DLV_OK) {
            *compdir_out = (const char *) cdir;
        } else {
            /* FALL thru */
        }
    }
    if (resattr == DW_DLV_OK) {
        dwarf_dealloc(dbg, comp_dir_attr, DW_DLA_ATTR);
    }
    return resattr;
}


/*  Given a form, and a pointer to the bytes encoding
    a value of that form, val_ptr, this function returns
    the length, in bytes, of a value of that form.
    When using this function, check for a return of 0
    a recursive DW_FORM_INDIRECT value.  */
int
_dwarf_get_size_of_val(Dwarf_Debug dbg,
    Dwarf_Unsigned form,
    Dwarf_Half cu_version,
    Dwarf_Half address_size,
    Dwarf_Small * val_ptr,
    int v_length_size,
    Dwarf_Unsigned *size_out,
    Dwarf_Small *section_end_ptr,
    Dwarf_Error*error)
{
    Dwarf_Unsigned length = 0;
    Dwarf_Unsigned leb128_length = 0;
    Dwarf_Unsigned form_indirect = 0;
    Dwarf_Unsigned ret_value = 0;

    switch (form) {

    /*  When we encounter a FORM here that
        we know about but forgot to enter here,
        we had better not just continue.
        Usually means we forgot to update this function
        when implementing form handling of a new FORM.
        Disaster results from using a bogus value,
        so generate error. */
    default:
        _dwarf_error(dbg,error,DW_DLE_DEBUG_FORM_HANDLING_INCOMPLETE);
        return DW_DLV_ERROR;


    case 0:  return DW_DLV_OK;

    case DW_FORM_GNU_ref_alt:
    case DW_FORM_GNU_strp_alt:
    case DW_FORM_strp_sup:
        *size_out = v_length_size;
        return DW_DLV_OK;

    case DW_FORM_addr:
        if (address_size) {
            *size_out = address_size;
        } else {
            /* This should never happen, address_size should be set. */
            *size_out = dbg->de_pointer_size;
        }
        return DW_DLV_OK;
    case DW_FORM_ref_sig8:
        *size_out = 8;
        /* sizeof Dwarf_Sig8 */
        return DW_DLV_OK;

    /*  DWARF2 was wrong on the size of the attribute for
        DW_FORM_ref_addr.  We assume compilers are using the
        corrected DWARF3 text (for 32bit pointer target objects pointer and
        offsets are the same size anyway).
        It is clear (as of 2014) that for 64bit folks used
        the V2 spec in the way V2 was
        written, so the ref_addr has to account for that.*/
    case DW_FORM_ref_addr:
        if (cu_version == DW_CU_VERSION2) {
            *size_out = address_size;
        } else {
            *size_out = v_length_size;
        }
        return DW_DLV_OK;

    case DW_FORM_block1: {
        ptrdiff_t sizeasptrdiff = 0;

        if (val_ptr >= section_end_ptr) {
            _dwarf_error_string(dbg,error,
                DW_DLE_FORM_BLOCK_LENGTH_ERROR,
                "DW_DLE_FORM_BLOCK_LENGTH_ERROR: DW_FORM_block1"
                " itself is off the end of the section."
                " Corrupt Dwarf.");
            return DW_DLV_ERROR;
        }
        ret_value =  *(Dwarf_Small *) val_ptr;
        sizeasptrdiff = (ptrdiff_t)ret_value;
        if (sizeasptrdiff > (section_end_ptr - val_ptr) ||
            sizeasptrdiff < 0) {
            _dwarf_error_string(dbg,error,
                DW_DLE_FORM_BLOCK_LENGTH_ERROR,
                "DW_DLE_FORM_BLOCK_LENGTH_ERROR: DW_FORM_block1"
                " runs off the end of the section."
                " Corrupt Dwarf.");
            return DW_DLV_ERROR;
        }
        *size_out = ret_value +1;
        }
        return DW_DLV_OK;

    case DW_FORM_block2: {
        ptrdiff_t sizeasptrdiff = 0;

        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned,
            val_ptr, DWARF_HALF_SIZE,error,section_end_ptr);
        sizeasptrdiff = (ptrdiff_t)ret_value;
        if (sizeasptrdiff > (section_end_ptr - val_ptr) ||
            sizeasptrdiff < 0) {
            _dwarf_error_string(dbg,error,
                DW_DLE_FORM_BLOCK_LENGTH_ERROR,
                "DW_DLE_FORM_BLOCK_LENGTH_ERROR: DW_FORM_block2"
                " runs off the end of the section."
                " Corrupt Dwarf.");
            return DW_DLV_ERROR;
        }
        *size_out = ret_value + DWARF_HALF_SIZE;
        }
        return DW_DLV_OK;

    case DW_FORM_block4: {
        ptrdiff_t sizeasptrdiff = 0;

        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned,
            val_ptr, DWARF_32BIT_SIZE,
            error,section_end_ptr);
        sizeasptrdiff = (ptrdiff_t)ret_value;
        if (sizeasptrdiff > (section_end_ptr - val_ptr) ||
            sizeasptrdiff < 0) {
            _dwarf_error_string(dbg,error,
                DW_DLE_FORM_BLOCK_LENGTH_ERROR,
                "DW_DLE_FORM_BLOCK_LENGTH_ERROR: DW_FORM_block4"
                " runs off the end of the section."
                " Corrupt Dwarf.");
            return DW_DLV_ERROR;
        }
        *size_out = ret_value + DWARF_32BIT_SIZE;
        }
        return DW_DLV_OK;

    case DW_FORM_data1:
        *size_out = 1;
        return DW_DLV_OK;

    case DW_FORM_data2:
        *size_out = 2;
        return DW_DLV_OK;

    case DW_FORM_data4:
        *size_out = 4;
        return DW_DLV_OK;

    case DW_FORM_data8:
        *size_out = 8;
        return DW_DLV_OK;

    case DW_FORM_data16:
        *size_out = 16;
        return DW_DLV_OK;

    case DW_FORM_string: {
        int res = 0;
        res = _dwarf_check_string_valid(dbg,val_ptr,
            val_ptr,
            section_end_ptr,
            DW_DLE_FORM_STRING_BAD_STRING,
            error);
        if ( res != DW_DLV_OK) {
            return res;
        }
        }
        *size_out = strlen((char *) val_ptr) + 1;
        return DW_DLV_OK;

    case DW_FORM_block:
    case DW_FORM_exprloc: {
        DECODE_LEB128_UWORD_LEN_CK(val_ptr,length,leb128_length,
            dbg,error,section_end_ptr);
        *size_out = length + leb128_length;
        return DW_DLV_OK;;
    }

    case DW_FORM_flag_present:
        *size_out = 0;
        return DW_DLV_OK;

    case DW_FORM_flag:
        *size_out = 1;
        return DW_DLV_OK;

    case DW_FORM_sec_offset:
        /* If 32bit dwarf, is 4. Else is 64bit dwarf and is 8. */
        *size_out = v_length_size;
        return DW_DLV_OK;

    case DW_FORM_ref_udata: {
        UNUSEDARG Dwarf_Unsigned v = 0;

        /*  Discard the decoded value, we just want the length
            of the value. */
        DECODE_LEB128_UWORD_LEN_CK(val_ptr,v,leb128_length,
            dbg,error,section_end_ptr);
        *size_out = leb128_length;
        return DW_DLV_OK;;
    }

    case DW_FORM_indirect:
        {
            Dwarf_Unsigned indir_len = 0;
            int res = 0;
            Dwarf_Unsigned info_data_len = 0;

            DECODE_LEB128_UWORD_LEN_CK(val_ptr,form_indirect,indir_len,
                dbg,error,section_end_ptr);
            if (form_indirect == DW_FORM_indirect) {
                /* We are in big trouble: The true form
                    of DW_FORM_indirect is
                    DW_FORM_indirect? Nonsense. Should
                    never happen. */
                _dwarf_error(dbg,error,DW_DLE_NESTED_FORM_INDIRECT_ERROR);
                return DW_DLV_ERROR;
            }
            /*  If form_indirect  is DW_FORM_implicit_const then
                the following call will set info_data_len 0 */
            res = _dwarf_get_size_of_val(dbg,
                form_indirect,
                cu_version,
                address_size,
                val_ptr + indir_len,
                v_length_size,
                &info_data_len,
                section_end_ptr,
                error);
            if(res != DW_DLV_OK) {
                return res;
            }
            *size_out = indir_len + info_data_len;
            return DW_DLV_OK;
        }

    case DW_FORM_ref1:
        *size_out = 1;
        return DW_DLV_OK;

    case DW_FORM_ref2:
        *size_out = 2;
        return DW_DLV_OK;

    case DW_FORM_ref4:
        *size_out = 4;
        return DW_DLV_OK;

    case DW_FORM_ref8:
        *size_out = 8;
        return DW_DLV_OK;

    /*  DW_FORM_implicit_const  is a value in the
        abbreviations, not in the DIEs and this
        functions measures DIE size. */
    case DW_FORM_implicit_const:
        *size_out = 0;
        return DW_DLV_OK;

    case DW_FORM_sdata: {
        /*  Discard the decoded value, we just want the length
            of the value. */
        UNUSEDARG Dwarf_Signed v = 0;

        /*  Discard the decoded value, we just want the length
            of the value. */
        DECODE_LEB128_SWORD_LEN_CK(val_ptr,v,leb128_length,
            dbg,error,section_end_ptr);
        *size_out = leb128_length;
        return DW_DLV_OK;
    }
    case DW_FORM_ref_sup4:
        *size_out = 4;
        return DW_DLV_OK;
    case DW_FORM_ref_sup8:
        *size_out = 8;
        return DW_DLV_OK;
    case DW_FORM_addrx1:
        *size_out = 1;
        return DW_DLV_OK;
    case DW_FORM_addrx2:
        *size_out = 2;
        return DW_DLV_OK;
    case DW_FORM_addrx3:
        *size_out = 4;
        return DW_DLV_OK;
    case DW_FORM_addrx4:
        *size_out = 4;
        return DW_DLV_OK;
    case DW_FORM_strx1:
        *size_out = 1;
        return DW_DLV_OK;
    case DW_FORM_strx2:
        *size_out = 2;
        return DW_DLV_OK;
    case DW_FORM_strx3:
        *size_out = 4;
        return DW_DLV_OK;
    case DW_FORM_strx4:
        *size_out = 4;
        return DW_DLV_OK;

    case DW_FORM_loclistx:
    case DW_FORM_rnglistx:
    case DW_FORM_addrx:
    case DW_FORM_GNU_addr_index:
    case DW_FORM_strx:
    case DW_FORM_GNU_str_index: {
        UNUSEDARG Dwarf_Unsigned v = 0;

        DECODE_LEB128_UWORD_LEN_CK(val_ptr,v,leb128_length,
            dbg,error,section_end_ptr);
        *size_out = leb128_length;
        return DW_DLV_OK;
    }

    case DW_FORM_line_strp:
    case DW_FORM_strp:
        *size_out = v_length_size;
        return DW_DLV_OK;

    case DW_FORM_udata: {
        /*  Discard the decoded value, we just want the length
            of the value. */
        UNUSEDARG Dwarf_Unsigned v = 0;

        DECODE_LEB128_UWORD_LEN_CK(val_ptr,v,leb128_length,
            dbg,error,section_end_ptr);
        *size_out = leb128_length;
        return DW_DLV_OK;
    }
    }
}

/*  We allow an arbitrary number of HT_MULTIPLE entries
    before resizing.  It seems up to 20 or 30
    would work nearly as well.
    We could have a different resize multiple than 'resize now'
    test multiple, but for now we don't do that.  */
#define HT_MULTIPLE 8

/*  Copy the old entries, updating each to be in
    a new list.  Don't delete anything. Leave the
    htin with stale data. */
static void
copy_abbrev_table_to_new_table(Dwarf_Hash_Table htin,
  Dwarf_Hash_Table htout)
{
    Dwarf_Hash_Table_Entry entry_in = htin->tb_entries;
    unsigned entry_in_count = htin->tb_table_entry_count;
    Dwarf_Hash_Table_Entry entry_out = htout->tb_entries;
    unsigned entry_out_count = htout->tb_table_entry_count;
    unsigned k = 0;
    for (; k < entry_in_count; ++k,++entry_in) {
        Dwarf_Abbrev_List listent = entry_in->at_head;
        Dwarf_Abbrev_List nextlistent = 0;

        for (; listent ; listent = nextlistent) {
            unsigned newtmp = listent->abl_code;
            unsigned newhash = newtmp%entry_out_count;
            Dwarf_Hash_Table_Entry e;
            nextlistent = listent->abl_next;
            e = entry_out+newhash;
            /*  Move_entry_to_new_hash. This reverses the
                order of the entries, effectively, but
                that does not seem significant. */
            listent->abl_next = e->at_head;
            e->at_head = listent;

            htout->tb_total_abbrev_count++;
        }
    }
}

/*  We allow zero form here, end of list. */
int
_dwarf_valid_form_we_know(Dwarf_Unsigned at_form,
    Dwarf_Unsigned at_name)
{
    if(at_form == 0 && at_name == 0) {
        return TRUE;
    }
    if (at_name == 0) {
        return FALSE;
    }
    if (at_form <= DW_FORM_addrx4 ) {
        return TRUE;
    }
    if (at_form == DW_FORM_GNU_addr_index ||
        at_form == DW_FORM_GNU_str_index  ||
        at_form == DW_FORM_GNU_ref_alt ||
        at_form == DW_FORM_GNU_strp_alt) {
        return TRUE;
    }
    return FALSE;
}

int
_dwarf_format_TAG_err_msg(Dwarf_Debug dbg,
    Dwarf_Unsigned tag,
    const char *m,
    Dwarf_Error *errp)
{
    dwarfstring v;

    dwarfstring_constructor(&v);
    dwarfstring_append(&v,(char *)m);
    dwarfstring_append(&v," The value ");
    dwarfstring_append_printf_u(&v,"0x%" DW_PR_DUx
        " is outside the valid TAG range.",tag);
    dwarfstring_append(&v," Corrupt DWARF.");
    _dwarf_error_string(dbg, errp,DW_DLE_TAG_CORRUPT,
        dwarfstring_string(&v));
    dwarfstring_destructor(&v);
    return DW_DLV_ERROR;
}

/*  This function returns a pointer to a Dwarf_Abbrev_List_s
    struct for the abbrev with the given code.  It puts the
    struct on the appropriate hash table.  It also adds all
    the abbrev between the last abbrev added and this one to
    the hash table.  In other words, the .debug_abbrev section
    is scanned sequentially from the top for an abbrev with
    the given code.  All intervening abbrevs are also put
    into the hash table.

    This function hashes the given code, and checks the chain
    at that hash table entry to see if a Dwarf_Abbrev_List_s
    with the given code exists.  If yes, it returns a pointer
    to that struct.  Otherwise, it scans the .debug_abbrev
    section from the last byte scanned for that CU till either
    an abbrev with the given code is found, or an abbrev code
    of 0 is read.  It puts Dwarf_Abbrev_List_s entries for all
    abbrev's read till that point into the hash table.  The
    hash table contains both a head pointer and a tail pointer
    for each entry.

    While the lists can move and entries can be moved between
    lists on reallocation, any given Dwarf_Abbrev_list entry
    never moves once allocated, so the pointer is safe to return.

    See also dwarf_get_abbrev() in dwarf_abbrev.c.

    Returns DW_DLV_ERROR on error.  */
int
_dwarf_get_abbrev_for_code(Dwarf_CU_Context cu_context,
    Dwarf_Unsigned code,
    Dwarf_Abbrev_List *list_out,
    Dwarf_Error *error)
{
    Dwarf_Debug dbg = cu_context->cc_dbg;
    Dwarf_Hash_Table hash_table_base =
        cu_context->cc_abbrev_hash_table;
    Dwarf_Hash_Table_Entry entry_base = 0;
    Dwarf_Hash_Table_Entry entry_cur = 0;
    Dwarf_Unsigned hash_num = 0;
    Dwarf_Unsigned abbrev_code = 0;
    Dwarf_Unsigned abbrev_tag  = 0;
    Dwarf_Abbrev_List hash_abbrev_entry = 0;
    Dwarf_Abbrev_List inner_list_entry = 0;
    Dwarf_Hash_Table_Entry inner_hash_entry = 0;

    Dwarf_Byte_Ptr abbrev_ptr = 0;
    Dwarf_Byte_Ptr end_abbrev_ptr = 0;
    unsigned hashable_val = 0;

    if (!hash_table_base->tb_entries) {
        hash_table_base->tb_table_entry_count =  HT_MULTIPLE;
        hash_table_base->tb_total_abbrev_count= 0;
        hash_table_base->tb_entries =
            (struct  Dwarf_Hash_Table_Entry_s *)_dwarf_get_alloc(dbg,
            DW_DLA_HASH_TABLE_ENTRY,
            hash_table_base->tb_table_entry_count);
        if (!hash_table_base->tb_entries) {
            return DW_DLV_NO_ENTRY;
        }
    } else if (hash_table_base->tb_total_abbrev_count >
        (hash_table_base->tb_table_entry_count * HT_MULTIPLE)) {
        struct Dwarf_Hash_Table_s newht;

        memset(&newht,0,sizeof(newht));
        /* Effectively multiplies by >= HT_MULTIPLE */
        newht.tb_table_entry_count =
            hash_table_base->tb_total_abbrev_count;
        newht.tb_total_abbrev_count = 0;
        newht.tb_entries =
            (struct  Dwarf_Hash_Table_Entry_s *)
            _dwarf_get_alloc(dbg, DW_DLA_HASH_TABLE_ENTRY,
            newht.tb_table_entry_count);
        if (!newht.tb_entries) {
            return DW_DLV_NO_ENTRY;
        }
        /*  Copy the existing entries to the new table,
            rehashing each.  */
        copy_abbrev_table_to_new_table(hash_table_base, &newht);
        /*  Dealloc only the entries hash table array, not the lists
            of things pointed to by a hash table entry array. */
        dwarf_dealloc(dbg, hash_table_base->tb_entries,
            DW_DLA_HASH_TABLE_ENTRY);
        hash_table_base->tb_entries = 0;
        /*  Now overwrite the existing table descriptor with
            the new, newly valid, contents. */
        *hash_table_base = newht;
    } /* Else is ok as is, add entry */

    hashable_val = code;
    hash_num = hashable_val %
        hash_table_base->tb_table_entry_count;
    entry_base = hash_table_base->tb_entries;
    entry_cur  = entry_base + hash_num;

    /* Determine if the 'code' is the list of synonyms already. */
    for (hash_abbrev_entry = entry_cur->at_head;
        hash_abbrev_entry != NULL && hash_abbrev_entry->abl_code != code;
        hash_abbrev_entry = hash_abbrev_entry->abl_next);
    if (hash_abbrev_entry) {
        /*  This returns a pointer to an abbrev
            list entry, not the list itself. */
        *list_out = hash_abbrev_entry;
        return DW_DLV_OK;
    }

    if (cu_context->cc_last_abbrev_ptr) {
        abbrev_ptr = cu_context->cc_last_abbrev_ptr;
        end_abbrev_ptr = cu_context->cc_last_abbrev_endptr;
    } else {
        /*  This is ok because cc_abbrev_offset includes DWP
            offset if appropriate. */
        abbrev_ptr = dbg->de_debug_abbrev.dss_data +
            cu_context->cc_abbrev_offset;

        if (cu_context->cc_dwp_offsets.pcu_type)  {
            /*  In a DWP the abbrevs
                for this context are known quite precisely. */
            Dwarf_Unsigned size = 0;

            /*  Ignore the offset returned.
                Already in cc_abbrev_offset. */
            _dwarf_get_dwp_extra_offset(
                &cu_context->cc_dwp_offsets,
                DW_SECT_ABBREV,&size);
            /*  ASSERT: size != 0 */
            end_abbrev_ptr = abbrev_ptr + size;
        } else {
            end_abbrev_ptr = dbg->de_debug_abbrev.dss_data +
                dbg->de_debug_abbrev.dss_size;
        }
    }

    /*  End of abbrev's as we are past the end entirely.
        This can happen,though it seems wrong.
        Or we are at the end of the data block,
        which we also take as
        meaning done with abbrevs for this CU.
        An abbreviations table
        is supposed to end with a zero byte.
        Not ended by end of data block.
        But we are allowing what is possibly a bit
        more flexible end policy here. */
    if (abbrev_ptr >= end_abbrev_ptr) {
        return DW_DLV_NO_ENTRY;
    }
    /*  End of abbrev's for this cu, since abbrev code
        is 0. */
    if (*abbrev_ptr == 0) {
        return DW_DLV_NO_ENTRY;
    }

    do {
        unsigned new_hashable_val = 0;
        Dwarf_Off  abb_goff = 0;
        Dwarf_Unsigned atcount = 0;
        Dwarf_Byte_Ptr abbrev_ptr2 = 0;
        int res = 0;

        abb_goff = abbrev_ptr - dbg->de_debug_abbrev.dss_data;
        DECODE_LEB128_UWORD_CK(abbrev_ptr, abbrev_code,
            dbg,error,end_abbrev_ptr);
        DECODE_LEB128_UWORD_CK(abbrev_ptr, abbrev_tag,
            dbg,error,end_abbrev_ptr);
        if (abbrev_tag > DW_TAG_hi_user) {
            return _dwarf_format_TAG_err_msg(dbg,
                abbrev_tag,"DW_DLE_TAG_CORRUPT",
                error);
        }
        if (abbrev_ptr >= end_abbrev_ptr) {
            _dwarf_error(dbg, error, DW_DLE_ABBREV_OFF_END);
            return DW_DLV_ERROR;
        }
        inner_list_entry = (Dwarf_Abbrev_List)
            _dwarf_get_alloc(cu_context->cc_dbg,
                DW_DLA_ABBREV_LIST, 1);
        if (inner_list_entry == NULL) {
            _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }

        new_hashable_val = abbrev_code;
        hash_num = new_hashable_val %
            hash_table_base->tb_table_entry_count;
        inner_hash_entry = entry_base + hash_num;
        /* Move_entry_to_new_hash */
        inner_list_entry->abl_next = inner_hash_entry->at_head;
        inner_hash_entry->at_head = inner_list_entry;

        hash_table_base->tb_total_abbrev_count++;

        inner_list_entry->abl_code = abbrev_code;
        inner_list_entry->abl_tag = abbrev_tag;
        inner_list_entry->abl_has_child = *(abbrev_ptr++);
        inner_list_entry->abl_abbrev_ptr = abbrev_ptr;
        inner_list_entry->abl_goffset =  abb_goff;
        hash_table_base->tb_total_abbrev_count++;

        /*  Cycle thru the abbrev content,
            ignoring the content except
            to find the end of the content. */
        res = _dwarf_count_abbrev_entries(dbg,abbrev_ptr,
            end_abbrev_ptr,&atcount,&abbrev_ptr2,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        abbrev_ptr = abbrev_ptr2;
        inner_list_entry->abl_count = atcount;
    } while ((abbrev_ptr < end_abbrev_ptr) &&
        *abbrev_ptr != 0 && abbrev_code != code);

    cu_context->cc_last_abbrev_ptr = abbrev_ptr;
    cu_context->cc_last_abbrev_endptr = end_abbrev_ptr;
    if(abbrev_code == code) {
        *list_out = inner_list_entry;
        return DW_DLV_OK;
    }
    /*  We cannot find an abbrev_code  matching code.
        ERROR will be declared eventually.
        Might be better to declare
        specific errors here? */
    return DW_DLV_NO_ENTRY;
}


/*
    We check that:
        areaptr <= strptr.
        a NUL byte (*p) exists at p < end.
    and return DW_DLV_ERROR if a check fails.

    de_assume_string_in_bounds
*/
int
_dwarf_check_string_valid(Dwarf_Debug dbg,void *areaptr,
    void *strptr, void *areaendptr,
    int suggested_error,
    Dwarf_Error*error)
{
    Dwarf_Small *start = areaptr;
    Dwarf_Small *p = strptr;
    Dwarf_Small *end = areaendptr;

    if (p < start) {
        _dwarf_error(dbg,error,suggested_error);
        return DW_DLV_ERROR;
    }
    if (p >= end) {
        _dwarf_error(dbg,error,suggested_error);
        return DW_DLV_ERROR;
    }
    if (dbg->de_assume_string_in_bounds) {
        /* This NOT the default. But folks can choose
            to live dangerously and just assume strings ok. */
        return DW_DLV_OK;
    }
    while (p < end) {
        if (*p == 0) {
            return DW_DLV_OK;
        }
        ++p;
    }
    _dwarf_error(dbg,error,DW_DLE_STRING_NOT_TERMINATED);
    return DW_DLV_ERROR;
}


/*  Return non-zero if the start/end are not valid for the
    die's section.
    If pastend matches the dss_data+dss_size then
    pastend is a pointer that cannot be dereferenced.
    But we allow it as valid here, it is normal for
    a pointer to point one-past-end in
    various circumstances (one must
    avoid dereferencing it, of course).
    Return 0 if valid. Return 1 if invalid. */
int
_dwarf_reference_outside_section(Dwarf_Die die,
    Dwarf_Small * startaddr,
    Dwarf_Small * pastend)
{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context contxt = 0;
    struct Dwarf_Section_s *sec = 0;

    contxt = die->di_cu_context;
    dbg = contxt->cc_dbg;
    if (die->di_is_info) {
        sec = &dbg->de_debug_info;
    } else {
        sec = &dbg->de_debug_types;
    }
    if (startaddr < sec->dss_data) {
        return 1;
    }
    if (pastend > (sec->dss_data + sec->dss_size)) {
        return 1;
    }
    return 0;
}


/*
  A byte-swapping version of memcpy
  for cross-endian use.
  Only 2,4,8 should be lengths passed in.
*/
void
_dwarf_memcpy_noswap_bytes(void *s1, const void *s2, unsigned long len)
{
    memcpy(s1,s2,(size_t)len);
    return;
}
void
_dwarf_memcpy_swap_bytes(void *s1, const void *s2, unsigned long len)
{
    unsigned char *targ = (unsigned char *) s1;
    const unsigned char *src = (const unsigned char *) s2;

    if (len == 4) {
        targ[3] = src[0];
        targ[2] = src[1];
        targ[1] = src[2];
        targ[0] = src[3];
    } else if (len == 8) {
        targ[7] = src[0];
        targ[6] = src[1];
        targ[5] = src[2];
        targ[4] = src[3];
        targ[3] = src[4];
        targ[2] = src[5];
        targ[1] = src[6];
        targ[0] = src[7];
    } else if (len == 2) {
        targ[1] = src[0];
        targ[0] = src[1];
    }
/* should NOT get below here: is not the intended use */
    else if (len == 1) {
        targ[0] = src[0];
    } else {
        memcpy(s1, s2, (size_t)len);
    }
    return;
}


/*  This calculation used to be sprinkled all over.
    Now brought to one place.

    We try to accurately compute the size of a cu header
    given a known cu header location ( an offset in .debug_info
    or debug_types).  */
/* ARGSUSED */

int
_dwarf_length_of_cu_header(Dwarf_Debug dbg,
    Dwarf_Unsigned offset,
    Dwarf_Bool is_info,
    Dwarf_Unsigned *area_length_out,
    Dwarf_Error *error)
{
    int local_length_size = 0;
    int local_extension_size = 0;
    Dwarf_Half version = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Unsigned final_size = 0;
    Dwarf_Small *section_start =
        is_info? dbg->de_debug_info.dss_data:
            dbg->de_debug_types.dss_data;
    Dwarf_Small *cuptr = section_start + offset;
    Dwarf_Unsigned section_length =
        is_info? dbg->de_debug_info.dss_size:
            dbg->de_debug_types.dss_size;
    Dwarf_Small * section_end_ptr =
        section_start + section_length;

    READ_AREA_LENGTH_CK(dbg, length, Dwarf_Unsigned,
        cuptr, local_length_size, local_extension_size,
        error,section_length,section_end_ptr);

    READ_UNALIGNED_CK(dbg, version, Dwarf_Half,
        cuptr, DWARF_HALF_SIZE,error,section_end_ptr);
    cuptr += DWARF_HALF_SIZE;
    if (version == 5) {
        Dwarf_Ubyte unit_type = 0;

        READ_UNALIGNED_CK(dbg, unit_type, Dwarf_Ubyte,
            cuptr, sizeof(Dwarf_Ubyte),error,section_end_ptr);
        switch (unit_type) {
        case DW_UT_compile:
            final_size = local_extension_size +
                local_length_size  + /* Size of cu length field. */
                DWARF_HALF_SIZE + /* Size of version stamp field. */
                sizeof(Dwarf_Small)+ /* Size of  unit type field. */
                sizeof(Dwarf_Small)+ /* Size of address size field. */
                local_length_size ;  /* Size of abbrev offset field. */
            break;
        case DW_UT_type:
        case DW_UT_partial:
        case DW_UT_skeleton:
        case DW_UT_split_compile:
        case DW_UT_split_type:
        default:
            _dwarf_error(dbg,error,DW_DLE_UNIT_TYPE_NOT_HANDLED);
            return DW_DLV_ERROR;
        }
    } else if (version == 4) {
        final_size = local_extension_size +
            local_length_size  +  /* Size of cu length field. */
            DWARF_HALF_SIZE +  /* Size of version stamp field. */
            local_length_size  +  /* Size of abbrev offset field. */
            sizeof(Dwarf_Small);  /* Size of address size field. */
        if (!is_info) {
            final_size +=
            /* type signature size */
            sizeof (Dwarf_Sig8) +
            /* type offset size */
            local_length_size;
        }
    } else if (version < 4) {
        final_size = local_extension_size +
            local_length_size  +
            DWARF_HALF_SIZE +
            local_length_size  +
            sizeof(Dwarf_Small);  /* Size of address size field. */
    }

    *area_length_out = final_size;
    return DW_DLV_OK;
}

/*  Pretend we know nothing about the CU
    and just roughly compute the result.  */
Dwarf_Unsigned
_dwarf_length_of_cu_header_simple(Dwarf_Debug dbg,
    Dwarf_Bool dinfo)
{
    Dwarf_Unsigned finalsize = 0;
    finalsize =  dbg->de_length_size + /* Size of cu length field. */
        DWARF_HALF_SIZE +    /* Size of version stamp field. */
        dbg->de_length_size +   /* Size of abbrev offset field. */
        sizeof(Dwarf_Small);    /* Size of address size field. */
    if (!dinfo) {
        finalsize +=
            /* type signature size */
            sizeof (Dwarf_Sig8) +
            /* type offset size */
            dbg->de_length_size;
    }
    return finalsize;
}

/*  Now that we delay loading .debug_info, we need to do the
    load in more places. So putting the load
    code in one place now instead of replicating it in multiple
    places.  */
int
_dwarf_load_debug_info(Dwarf_Debug dbg, Dwarf_Error * error)
{
    int res = DW_DLV_ERROR;
    if (dbg->de_debug_info.dss_data) {
        return DW_DLV_OK;
    }
    res = _dwarf_load_section(dbg, &dbg->de_debug_abbrev,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = _dwarf_load_section(dbg, &dbg->de_debug_info, error);
    if (res != DW_DLV_OK) {
        return res;
    }
    /*  debug_info won't be meaningful without
        .debug_rnglists and .debug_rnglists if there
        is one or both such sections. */
    res = dwarf_load_rnglists(dbg,0,error);
    if (res == DW_DLV_ERROR) {
        return res;
    }
    res = dwarf_load_loclists(dbg,0,error);
    if (res == DW_DLV_ERROR) {
        return res;
    }
    return DW_DLV_OK;
}
int
_dwarf_load_debug_types(Dwarf_Debug dbg, Dwarf_Error * error)
{
    int res = DW_DLV_ERROR;
    if (dbg->de_debug_types.dss_data) {
        return DW_DLV_OK;
    }
    res = _dwarf_load_section(dbg, &dbg->de_debug_abbrev,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = _dwarf_load_section(dbg, &dbg->de_debug_types, error);
    return res;
}
void
_dwarf_free_abbrev_hash_table_contents(Dwarf_Debug dbg,
    Dwarf_Hash_Table hash_table)
{
    /*  A Hash Table is an array with tb_table_entry_count struct
        Dwarf_Hash_Table_s entries in the array. */
    unsigned hashnum = 0;
    if(!hash_table) {
        /*  Not fully set up yet. There is nothing to do. */
        return;
    }
    if (!hash_table->tb_entries) {
        /*  Not fully set up yet. There is nothing to do. */
        return;
    }
    for (; hashnum < hash_table->tb_table_entry_count; ++hashnum) {
        struct Dwarf_Abbrev_List_s *abbrev = 0;
        struct Dwarf_Abbrev_List_s *nextabbrev = 0;
        struct  Dwarf_Hash_Table_Entry_s *tb =
            &hash_table->tb_entries[hashnum];

        abbrev = tb->at_head;
        for (; abbrev; abbrev = nextabbrev) {
            nextabbrev = abbrev->abl_next;
            abbrev->abl_next = 0;
            dwarf_dealloc(dbg, abbrev, DW_DLA_ABBREV_LIST);
        }
        tb->at_head = 0;
    }
    /* Frees all the entries at once: an array. */
    dwarf_dealloc(dbg,hash_table->tb_entries,DW_DLA_HASH_TABLE_ENTRY);
    hash_table->tb_entries = 0;
}

/*
    If no die provided the size value returned might be wrong.
    If different compilation units have different address sizes
    this may not give the correct value in all contexts if the die
    pointer is NULL.
    If the Elf offset size != address_size
    (for example if address_size = 4 but recorded in elf64 object)
    this may not give the correct value in all contexts if the die
    pointer is NULL.
    If the die pointer is non-NULL (in which case it must point to
    a valid DIE) this will return the correct size.
*/
int
_dwarf_get_address_size(Dwarf_Debug dbg, Dwarf_Die die)
{
    Dwarf_CU_Context context = 0;
    Dwarf_Half addrsize = 0;
    if (!die) {
        return dbg->de_pointer_size;
    }
    context = die->di_cu_context;
    addrsize = context->cc_address_size;
    return addrsize;
}

/* Encode val as an unsigned LEB128. */
int dwarf_encode_leb128(Dwarf_Unsigned val, int *nbytes,
    char *space, int splen)
{
    /* Encode val as an unsigned LEB128. */
    return _dwarf_pro_encode_leb128_nm(val,nbytes,space,splen);
}

/* Encode val as a signed LEB128. */
int dwarf_encode_signed_leb128(Dwarf_Signed val, int *nbytes,
    char *space, int splen)
{
    /* Encode val as a signed LEB128. */
    return _dwarf_pro_encode_signed_leb128_nm(val,nbytes,space,splen);
}


struct  Dwarf_Printf_Callback_Info_s
dwarf_register_printf_callback( Dwarf_Debug dbg,
    struct  Dwarf_Printf_Callback_Info_s * newvalues)
{
    struct  Dwarf_Printf_Callback_Info_s oldval = dbg->de_printf_callback;
    if (!newvalues) {
        return oldval;
    }
    if( newvalues->dp_buffer_user_provided) {
        if( oldval.dp_buffer_user_provided) {
            /* User continues to control the buffer. */
            dbg->de_printf_callback = *newvalues;
        }else {
            /*  Switch from our control of buffer to user
                control.  */
            free(oldval.dp_buffer);
            oldval.dp_buffer = 0;
            dbg->de_printf_callback = *newvalues;
        }
    } else if (oldval.dp_buffer_user_provided){
        /* Switch from user control to our control */
        dbg->de_printf_callback = *newvalues;
        dbg->de_printf_callback.dp_buffer_len = 0;
        dbg->de_printf_callback.dp_buffer= 0;
    } else {
        /* User does not control the buffer. */
        dbg->de_printf_callback = *newvalues;
        dbg->de_printf_callback.dp_buffer_len =
            oldval.dp_buffer_len;
        dbg->de_printf_callback.dp_buffer =
            oldval.dp_buffer;
    }
    return oldval;
}



/* No varargs required */
int
_dwarf_printf(Dwarf_Debug dbg,
    const char * data)
{
    int nlen = 0;
    struct Dwarf_Printf_Callback_Info_s *bufdata =
        &dbg->de_printf_callback;

    dwarf_printf_callback_function_type func = bufdata->dp_fptr;
    if (!func) {
        return 0;
    }
    nlen =  strlen(data);
    func(bufdata->dp_user_pointer,data);
    return nlen;
}

/*  Often errs and errt point to the same Dwarf_Error,
    So exercise care.
    All the arguments MUST be non-null.*/
void
_dwarf_error_mv_s_to_t(Dwarf_Debug dbgs,Dwarf_Error *errs,
    Dwarf_Debug dbgt,Dwarf_Error *errt)
{
    if (!errt || !errs) {
        return;
    }
    if (!dbgs || !dbgt) {
        return;
    }
    if(dbgs == dbgt) {
        if(errs != errt) {
            Dwarf_Error ers = *errs;
            *errs = 0;
            *errt = ers;
        }
    } else {
        /*  Do not stomp on the system errno
            variable if there is one! */
        int mydw_errno = dwarf_errno(*errs);

        dwarf_dealloc(dbgs,*errs, DW_DLA_ERROR);
        *errs = 0;
        _dwarf_error(dbgt,errt, mydw_errno);
    }
}

static int
inthissection(struct Dwarf_Section_s *sec,Dwarf_Small *ptr)
{
    if (!sec->dss_data) {
        return FALSE;
    }
    if (ptr < sec->dss_data ) {
        return FALSE;
    }
    if (ptr >= (sec->dss_data + sec->dss_size) ) {
        return FALSE;
    }
    return TRUE;
}

#define FINDSEC(m_s,m_p,n,st,l,e)    \
do {                                 \
    if (inthissection((m_s),(m_p))) { \
        *(n) = (m_s)->dss_name;      \
        *(st)= (m_s)->dss_data;      \
        *(l) = (m_s)->dss_size;      \
        *(e) = (m_s)->dss_data + (m_s)->dss_size; \
        return DW_DLV_OK;            \
    }                                \
} while (0)


/* So we can know a section end even when we do not
    have the section info apriori  It's only
    needed for a subset of sections. */
int
_dwarf_what_section_are_we(Dwarf_Debug dbg,
    Dwarf_Small    *  our_pointer,
    const char     ** section_name_out,
    Dwarf_Small    ** sec_start_ptr_out,
    Dwarf_Unsigned *  sec_len_out,
    Dwarf_Small    ** sec_end_ptr_out,
    UNUSEDARG Dwarf_Error    *  error)
{
    FINDSEC(&dbg->de_debug_info,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_loc,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_loclists,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_rnglists,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_addr,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_line,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_aranges,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_macro,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_ranges,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_str_offsets,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_addr,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_pubtypes,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_gdbindex,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_abbrev,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_cu_index,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_tu_index,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_line_str,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_types,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_sup,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_frame,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    FINDSEC(&dbg->de_debug_frame_eh_gnu,
        our_pointer, section_name_out,
        sec_start_ptr_out, sec_len_out, sec_end_ptr_out);
    return DW_DLV_NO_ENTRY;
}

/* New September 2019. */
int  dwarf_add_file_path(
    Dwarf_Debug dbg,
    const char *          file_name,
    Dwarf_Error* error)
{
    if(!dbg || !file_name) {
        /*  Pretty much a disaster. Caller error. */
        _dwarf_error(dbg,error,DW_DLE_NULL_ARGS_DWARF_ADD_PATH);
        return DW_DLV_ERROR;
    }
    if (!dbg->de_path) {
        dbg->de_path = strdup(file_name);
    }
    return DW_DLV_OK;
}

/*  New late April 2020.
    All the crucial macros will surely
    need  to use wrapper code to ensure we do not leak
    memory at certain points.  */
int
_dwarf_read_unaligned_ck_wrapper(Dwarf_Debug dbg,
    Dwarf_Unsigned *out_value,
    Dwarf_Small *readfrom,
    int          readlength,
    Dwarf_Small *end_arange,
    Dwarf_Error *err)
{
    Dwarf_Unsigned val = 0;

    READ_UNALIGNED_CK(dbg,val,Dwarf_Unsigned,
        readfrom,readlength,err,end_arange);
    *out_value = val;
    return DW_DLV_OK;
}

int
_dwarf_read_area_length_ck_wrapper(Dwarf_Debug dbg,
    Dwarf_Unsigned *out_value,
    Dwarf_Small **readfrom,
    int    *  length_size_out,
    int    *  exten_size_out,
    Dwarf_Unsigned sectionlength,
    Dwarf_Small *endsection,
    Dwarf_Error *err)
{
    Dwarf_Small *ptr = *readfrom;
    Dwarf_Unsigned val = 0;
    int length_size = 0;
    int exten_size = 0;

    READ_AREA_LENGTH_CK(dbg,val,Dwarf_Unsigned,
        ptr,length_size,exten_size,
        err,
        sectionlength,endsection);
    *readfrom = ptr;
    *out_value = val;
    *length_size_out = length_size;
    *exten_size_out = exten_size;
    return DW_DLV_OK;
}
/*  New March 2020 */
/*  We need to increment startptr for the caller
    in these wrappers so the caller passes in
    wrappers return either DW_DLV_OK or DW_DLV_ERROR.
    Never DW_DLV_NO_ENTRY. */
int
_dwarf_leb128_uword_wrapper(Dwarf_Debug dbg,
    Dwarf_Small ** startptr,
    Dwarf_Small * endptr,
    Dwarf_Unsigned *out_value,
    Dwarf_Error * error)
{
    Dwarf_Unsigned utmp2 = 0;
    Dwarf_Small * start = *startptr;
    DECODE_LEB128_UWORD_CK(start, utmp2,
        dbg,error,endptr);
    *out_value = utmp2;
    *startptr = start;
    return DW_DLV_OK;
}
int
_dwarf_leb128_sword_wrapper(Dwarf_Debug dbg,
    Dwarf_Small ** startptr,
    Dwarf_Small * endptr,
    Dwarf_Signed *out_value,
    Dwarf_Error * error)
{
    Dwarf_Small * start = *startptr;
    Dwarf_Signed stmp2 = 0;
    DECODE_LEB128_SWORD_CK(start, stmp2,
        dbg,error,endptr);
    *out_value = stmp2;
    *startptr = start;
    return DW_DLV_OK;
}
