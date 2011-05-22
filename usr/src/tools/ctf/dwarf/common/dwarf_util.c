/*
  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
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



/*
    Given a form, and a pointer to the bytes encoding 
    a value of that form, val_ptr, this function returns
    the length, in bytes, of a value of that form.
    When using this function, check for a return of 0
    a recursive DW_FORM_INDIRECT value.
*/
Dwarf_Unsigned
_dwarf_get_size_of_val(Dwarf_Debug dbg,
    Dwarf_Unsigned form,
    Dwarf_Half address_size,
    Dwarf_Small * val_ptr, int v_length_size)
{
    Dwarf_Unsigned length = 0;
    Dwarf_Word leb128_length = 0;
    Dwarf_Unsigned form_indirect = 0;
    Dwarf_Unsigned ret_value = 0;

    switch (form) {

    default:                    /* Handles form = 0. */
        return (form);

    case DW_FORM_addr:
        if(address_size) {
            return address_size;
        }
        /* This should never happen, address_size should be set. */
        return (dbg->de_pointer_size);

    /* DWARF2 was wrong on the size of the attribute for
       DW_FORM_ref_addr.  We assume compilers are using the 
       corrected DWARF3 text (for 32bit pointer target objects pointer and
       offsets are the same size anyway). */
    case DW_FORM_ref_addr:
        return (v_length_size);

    case DW_FORM_block1:
        return (*(Dwarf_Small *) val_ptr + 1);

    case DW_FORM_block2:
        READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                       val_ptr, sizeof(Dwarf_Half));
        return (ret_value + sizeof(Dwarf_Half));

    case DW_FORM_block4:
        READ_UNALIGNED(dbg, ret_value, Dwarf_Unsigned,
                       val_ptr, sizeof(Dwarf_ufixed));
        return (ret_value + sizeof(Dwarf_ufixed));


    case DW_FORM_data1:
        return (1);

    case DW_FORM_data2:
        return (2);

    case DW_FORM_data4:
        return (4);

    case DW_FORM_data8:
        return (8);

    case DW_FORM_string:
        return (strlen((char *) val_ptr) + 1);

    case DW_FORM_block:
    case DW_FORM_exprloc:
        length = _dwarf_decode_u_leb128(val_ptr, &leb128_length);
        return (length + leb128_length);

    case DW_FORM_flag_present:
        return (0);
    case DW_FORM_flag:
        return (1);

    case DW_FORM_sec_offset:
        /* If 32bit dwarf, is 4. Else is 64bit dwarf and is 8. */
        return (v_length_size);

    case DW_FORM_ref_udata:
        length = _dwarf_decode_u_leb128(val_ptr, &leb128_length);
        return (leb128_length);

    case DW_FORM_indirect:
        {
            Dwarf_Word indir_len = 0;

            form_indirect = _dwarf_decode_u_leb128(val_ptr, &indir_len);
            if (form_indirect == DW_FORM_indirect) {
                return (0);     /* We are in big trouble: The true form 
                                   of DW_FORM_indirect is
                                   DW_FORM_indirect? Nonsense. Should
                                   never happen. */
            }
            return (indir_len + _dwarf_get_size_of_val(dbg,
                   form_indirect,
                   address_size,
                   val_ptr + indir_len,
                   v_length_size));
        }

    case DW_FORM_ref1:
        return (1);

    case DW_FORM_ref2:
        return (2);

    case DW_FORM_ref4:
        return (4);

    case DW_FORM_ref8:
        return (8);

    case DW_FORM_sdata:
        _dwarf_decode_s_leb128(val_ptr, &leb128_length);
        return (leb128_length);

    case DW_FORM_strp:
        return (v_length_size);

    case DW_FORM_udata:
        _dwarf_decode_u_leb128(val_ptr, &leb128_length);
        return (leb128_length);
    }
}

/* We allow an arbitrary number of HT_MULTIPLE entries
   before resizing.  It seems up to 20 or 30
   would work nearly as well.
   We could have a different resize multiple than 'resize now'
   test multiple, but for now we don't do that.
*/
#define HT_MULTIPLE 8

/* Copy the old entries, updating each to be in
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
    for ( ;  k < entry_in_count; ++k,++entry_in) {
        Dwarf_Abbrev_List listent = entry_in->at_head;
        Dwarf_Abbrev_List nextlistent = 0;

        for (  ; listent ; listent = nextlistent) {
             unsigned newtmp = listent->ab_code;
             unsigned newhash = newtmp%entry_out_count;
             Dwarf_Hash_Table_Entry e;
             nextlistent = listent->ab_next;
             e = entry_out+newhash; 
             /* Move_entry_to_new_hash. This reverses the
                order of the entries, effectively, but
                that does not seem significant. */
             listent->ab_next = e->at_head;
             e->at_head = listent;

             htout->tb_total_abbrev_count++;
        } 
    }
}

/*
    This function returns a pointer to a Dwarf_Abbrev_List_s
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

    Returns NULL on error.
*/
Dwarf_Abbrev_List
_dwarf_get_abbrev_for_code(Dwarf_CU_Context cu_context, Dwarf_Unsigned code)
{
    Dwarf_Debug dbg = cu_context->cc_dbg;
    Dwarf_Hash_Table hash_table_base = cu_context->cc_abbrev_hash_table;
    Dwarf_Hash_Table_Entry entry_base = 0; 
    Dwarf_Hash_Table_Entry entry_cur = 0; 
    Dwarf_Word hash_num = 0;
    Dwarf_Unsigned abbrev_code = 0; 
    Dwarf_Unsigned abbrev_tag  = 0;
    Dwarf_Unsigned attr_name = 0;
    Dwarf_Unsigned attr_form = 0;

    Dwarf_Abbrev_List hash_abbrev_entry = 0;

    Dwarf_Abbrev_List inner_list_entry = 0; 
    Dwarf_Hash_Table_Entry inner_hash_entry = 0; 

    Dwarf_Byte_Ptr abbrev_ptr = 0;
    unsigned hashable_val;

    if ( !hash_table_base->tb_entries ) {
         hash_table_base->tb_table_entry_count =  HT_MULTIPLE;
         hash_table_base->tb_total_abbrev_count= 0;
         hash_table_base->tb_entries =  _dwarf_get_alloc(dbg,
            DW_DLA_HASH_TABLE_ENTRY, 
            hash_table_base->tb_table_entry_count);
         if(! hash_table_base->tb_entries) {
             return NULL;
         }

    } else if (hash_table_base->tb_total_abbrev_count >
          ( hash_table_base->tb_table_entry_count * HT_MULTIPLE) ) {
        struct Dwarf_Hash_Table_s newht;
        /* Effectively multiplies by >= HT_MULTIPLE */
        newht.tb_table_entry_count =  hash_table_base->tb_total_abbrev_count;
        newht.tb_total_abbrev_count = 0;
        newht.tb_entries =  _dwarf_get_alloc(dbg,
            DW_DLA_HASH_TABLE_ENTRY, 
            newht.tb_table_entry_count);

        if(! newht.tb_entries) {
             return NULL;
        }
        /* Copy the existing entries to the new table,
           rehashing each. 
        */
        copy_abbrev_table_to_new_table(hash_table_base, &newht);
        /* Dealloc only the entries hash table array, not the lists
           of things pointed to by a hash table entry array. */
        dwarf_dealloc(dbg, hash_table_base->tb_entries,DW_DLA_HASH_TABLE_ENTRY);
        hash_table_base->tb_entries = 0;
        /* Now overwrite the existing table descriptor with
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
         hash_abbrev_entry != NULL && hash_abbrev_entry->ab_code != code;
         hash_abbrev_entry = hash_abbrev_entry->ab_next);
    if (hash_abbrev_entry != NULL) {
        /* This returns a pointer to an abbrev list entry, not 
           the list itself. */
        return (hash_abbrev_entry);
    }

    abbrev_ptr = cu_context->cc_last_abbrev_ptr != NULL ?
        cu_context->cc_last_abbrev_ptr :
        dbg->de_debug_abbrev.dss_data + cu_context->cc_abbrev_offset;

    /* End of abbrev's for this cu, since abbrev code is 0. */
    if (*abbrev_ptr == 0) {
        return (NULL);
    }

    do {
        unsigned new_hashable_val;
        DECODE_LEB128_UWORD(abbrev_ptr, abbrev_code);
        DECODE_LEB128_UWORD(abbrev_ptr, abbrev_tag);

        inner_list_entry = (Dwarf_Abbrev_List)
            _dwarf_get_alloc(cu_context->cc_dbg, DW_DLA_ABBREV_LIST, 1);
        if (inner_list_entry == NULL)
            return (NULL);

        new_hashable_val = abbrev_code;
        hash_num = new_hashable_val % 
            hash_table_base->tb_table_entry_count;
        inner_hash_entry = entry_base + hash_num;
        /* Move_entry_to_new_hash */
        inner_list_entry->ab_next = inner_hash_entry->at_head;
        inner_hash_entry->at_head = inner_list_entry;

        hash_table_base->tb_total_abbrev_count++;

        inner_list_entry->ab_code = abbrev_code;
        inner_list_entry->ab_tag = abbrev_tag;
        inner_list_entry->ab_has_child = *(abbrev_ptr++);
        inner_list_entry->ab_abbrev_ptr = abbrev_ptr;

        /* Cycle thru the abbrev content, ignoring the content except
           to find the end of the content. */
        do {
            DECODE_LEB128_UWORD(abbrev_ptr, attr_name);
            DECODE_LEB128_UWORD(abbrev_ptr, attr_form);
        } while (attr_name != 0 && attr_form != 0);

    } while (*abbrev_ptr != 0 && abbrev_code != code);

    cu_context->cc_last_abbrev_ptr = abbrev_ptr;
    return (abbrev_code == code ? inner_list_entry : NULL);
}


/* return 1 if string ends before 'endptr' else
** return 0 meaning string is not properly terminated.
** Presumption is the 'endptr' pts to end of some dwarf section data.
*/
int
_dwarf_string_valid(void *startptr, void *endptr)
{

    char *start = startptr;
    char *end = endptr;

    while (start < end) {
        if (*start == 0) {
            return 1;           /* OK! */
        }
        ++start;
        ++end;
    }
    return 0;                   /* FAIL! bad string! */
}

/*
  A byte-swapping version of memcpy
  for cross-endian use.
  Only 2,4,8 should be lengths passed in.
*/
void *
_dwarf_memcpy_swap_bytes(void *s1, const void *s2, size_t len)
{
    void *orig_s1 = s1;
    unsigned char *targ = (unsigned char *) s1;
    unsigned char *src = (unsigned char *) s2;

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
        memcpy(s1, s2, len);
    }

    return orig_s1;
}


/*
  This calculation used to be sprinkled all over.
  Now brought to one place.

  We try to accurately compute the size of a cu header
  given a known cu header location ( an offset in .debug_info).

*/
/* ARGSUSED */
Dwarf_Unsigned
_dwarf_length_of_cu_header(Dwarf_Debug dbg, Dwarf_Unsigned offset)
{
    int local_length_size = 0;
    int local_extension_size = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Small *cuptr = dbg->de_debug_info.dss_data + offset;

    READ_AREA_LENGTH(dbg, length, Dwarf_Unsigned,
                     cuptr, local_length_size, local_extension_size);

    return local_extension_size +       /* initial extesion, if present 
                                         */
        local_length_size +     /* Size of cu length field. */
        sizeof(Dwarf_Half) +    /* Size of version stamp field. */
        local_length_size +     /* Size of abbrev offset field. */
        sizeof(Dwarf_Small);    /* Size of address size field. */

}

/*
        Pretend we know nothing about the CU
        and just roughly compute the result. 
*/
Dwarf_Unsigned
_dwarf_length_of_cu_header_simple(Dwarf_Debug dbg)
{
    return dbg->de_length_size +        /* Size of cu length field. */
        sizeof(Dwarf_Half) +    /* Size of version stamp field. */
        dbg->de_length_size +   /* Size of abbrev offset field. */
        sizeof(Dwarf_Small);    /* Size of address size field. */
}

/* Now that we delay loading .debug_info, we need to do the
   load in more places. So putting the load
   code in one place now instead of replicating it in multiple
   places.

*/
int
_dwarf_load_debug_info(Dwarf_Debug dbg, Dwarf_Error * error)
{
    int res = DW_DLV_ERROR;

    /* Testing de_debug_info.dss_data allows us to avoid testing
       de_debug_abbrev.dss_data. 
       One test instead of 2. .debug_info is useless
       without .debug_abbrev. */
    if (dbg->de_debug_info.dss_data) {
        return DW_DLV_OK;
    }

    res = _dwarf_load_section(dbg, &dbg->de_debug_abbrev,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = _dwarf_load_section(dbg, &dbg->de_debug_info, error);
    return res;

}
void
_dwarf_free_abbrev_hash_table_contents(Dwarf_Debug dbg,Dwarf_Hash_Table hash_table)
{
    /* A Hash Table is an array with tb_table_entry_count struct
       Dwarf_Hash_Table_s entries in the array. */
    int hashnum = 0;
    for (; hashnum < hash_table->tb_table_entry_count; ++hashnum) {
        struct Dwarf_Abbrev_List_s *abbrev = 0;
        struct Dwarf_Abbrev_List_s *nextabbrev = 0;
        struct  Dwarf_Hash_Table_Entry_s *tb =  &hash_table->tb_entries[hashnum];

        abbrev = tb->at_head;
        for (; abbrev; abbrev = nextabbrev) {
            nextabbrev = abbrev->ab_next;
            dwarf_dealloc(dbg, abbrev, DW_DLA_ABBREV_LIST);
        }
    }
    /* Frees all the entries at once: an array. */
    dwarf_dealloc(dbg,hash_table->tb_entries,DW_DLA_HASH_TABLE_ENTRY);
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
    if(!die) {
        return dbg->de_pointer_size;
    }
    context = die->di_cu_context;
    addrsize = context->cc_address_size;
    return addrsize;
}



