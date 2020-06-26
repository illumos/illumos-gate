/*

  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2002-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2011-2017 David Anderson.  All Rights Reserved.

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
#include "libdwarfdefs.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h> /* for exit(), C89 malloc */
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#ifdef HAVE_STDINT_H
#include <stdint.h> /* For uintptr_t */
#endif /* HAVE_STDINT_H */
#include <string.h>
#include <stddef.h>
#include "pro_incl.h"
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_error.h"
#include "pro_util.h"
#include "pro_alloc.h"
#include "pro_die.h"
#include "pro_section.h"
#include "dwarf_tsearch.h"

#ifndef R_MIPS_NONE
#define R_MIPS_NONE 0
#endif

#define TRUE 1
#define FALSE 0

/*  This function creates a new die.
    tag: tag of the new die to be created
    parent,child,left,right: specify neighbors of the new die. Only
    one of these may be non-null */
Dwarf_P_Die
dwarf_new_die(Dwarf_P_Debug dbg,
    Dwarf_Tag tag,
    Dwarf_P_Die parent,
    Dwarf_P_Die child,
    Dwarf_P_Die left, Dwarf_P_Die right,
    Dwarf_Error * error)
{
    Dwarf_P_Die created = 0;
    int res = 0;

    res = dwarf_new_die_a(dbg,tag,parent,child,
        left,right,&created,error);
    if (res != DW_DLV_OK) {
        return (Dwarf_P_Die)DW_DLV_BADADDR;
    }
    return created;
}

/* New September 2016. Preferred as error checking
   is easier, no need for ugly cast. */
int
dwarf_new_die_a(Dwarf_P_Debug dbg,
    Dwarf_Tag tag,
    Dwarf_P_Die parent,
    Dwarf_P_Die child,
    Dwarf_P_Die left, Dwarf_P_Die right,
    Dwarf_P_Die *die_out,
    Dwarf_Error *error)
{
    Dwarf_P_Die ret_die = 0;
    int res = 0;

    ret_die = (Dwarf_P_Die)
        _dwarf_p_get_alloc(dbg, sizeof(struct Dwarf_P_Die_s));
    if (ret_die == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_DIE_ALLOC,
            DW_DLV_ERROR);
    }
    ret_die->di_parent = NULL;
    ret_die->di_left = NULL;
    ret_die->di_right = NULL;
    ret_die->di_child = NULL;
    ret_die->di_last_child = NULL;
    ret_die->di_tag = tag;
    ret_die->di_dbg = dbg;
    ret_die->di_marker = 0;
    res = dwarf_die_link_a(ret_die, parent, child, left, right,
        error);
    if (res != DW_DLV_OK) {
        _dwarf_p_dealloc(dbg,(Dwarf_Small *)ret_die);
        ret_die = 0;
    } else {
        *die_out = ret_die;
    }
    return res;
}

/*  This function links up a die to specified neighbors
    parent,child,left,right: specify neighbors of the new die. Only
    one of these may be non-null
    This is the original version. Use dwarf_die_link_a()
    instead as that function is easier to use (in checking for error).
    */
Dwarf_P_Die
dwarf_die_link(Dwarf_P_Die new_die,
    Dwarf_P_Die parent,
    Dwarf_P_Die child,
    Dwarf_P_Die left, Dwarf_P_Die right, Dwarf_Error * error)
{
    int res = 0;

    res = dwarf_die_link_a(new_die,parent,child,left,right,error);
    if (res != DW_DLV_OK) {
        return (Dwarf_P_Die)DW_DLV_BADADDR;
    }
    return new_die;
}

/*  New September 2016.
    Error return easier to deal with
    than dwarf_die_link(). */
int
dwarf_die_link_a(Dwarf_P_Die new_die,
    Dwarf_P_Die parent,
    Dwarf_P_Die child,
    Dwarf_P_Die left, Dwarf_P_Die right, Dwarf_Error * error)
{
    /* Count the # of non null neighbors. */
    int n_nulls = 0;

    if (parent != NULL) {
        n_nulls++;
        if (new_die->di_parent != NULL) {
            DWARF_P_DBG_ERROR(NULL, DW_DLE_LINK_LOOP,
                DW_DLV_ERROR);
        }
        new_die->di_parent = parent;
        if (parent->di_child) {

            /*  di_last_child identifies the last sibling, the
                die we want to attach new_die to. */
            /*  ASSERT: if di_child is set so is di_last_child. */
            Dwarf_P_Die former_lastchild = parent->di_last_child;
            parent->di_last_child = new_die;
            /* Attach to  the new die to end of the sibling list. */
            former_lastchild->di_right = new_die;
            new_die->di_left = former_lastchild;
        } else {
            parent->di_child = new_die;
            parent->di_last_child = new_die;
        }
    }
    if (child != NULL) {
        n_nulls++;
        new_die->di_child = child;
        new_die->di_last_child = child;
        if (child->di_parent) {
            DWARF_P_DBG_ERROR(NULL, DW_DLE_PARENT_EXISTS,
                DW_DLV_ERROR);
        } else {
            child->di_parent = new_die;
        }
    }
    if (left != NULL) {
        n_nulls++;
        new_die->di_left = left;
        if (left->di_right) {
            /*  There's already a right sibling of left,
                insert the new die in the list. */
            new_die->di_right = left->di_right;
            left->di_right->di_left = new_die;
        }
        left->di_right = new_die;
        if (new_die->di_parent) {
            DWARF_P_DBG_ERROR(NULL, DW_DLE_PARENT_EXISTS,
                DW_DLV_ERROR);
        } else {
            new_die->di_parent = left->di_parent;
        }
    }
    if (right != NULL) {
        n_nulls++;
        new_die->di_right = right;
        if (right->di_left) {
            /*  There is already a left sibling of the right die,
                insert the new die in the list.  */
            new_die->di_left = right->di_left;
            right->di_left->di_right = new_die;
        }
        right->di_left = new_die;
        if (new_die->di_parent) {
            DWARF_P_DBG_ERROR(NULL, DW_DLE_PARENT_EXISTS,
                DW_DLV_ERROR);
        } else {
            new_die->di_parent = right->di_parent;
        }
    }
    if (n_nulls > 1) {
        /* Multiple neighbors! error! */
        DWARF_P_DBG_ERROR(NULL, DW_DLE_EXTRA_NEIGHBORS,
            DW_DLV_ERROR);
    }
    return DW_DLV_OK;
}

Dwarf_Unsigned
dwarf_add_die_marker(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    Dwarf_Unsigned marker,
    Dwarf_Error * error) {
    if (die == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_DIE_NULL, DW_DLV_NOCOUNT);
    }
    die->di_marker = marker;
    return 0;
}
int
dwarf_add_die_marker_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    Dwarf_Unsigned marker,
    Dwarf_Error * error)
{
    if (die == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_DIE_NULL,
            DW_DLV_ERROR);
    }
    die->di_marker = marker;
    return DW_DLV_OK;
}


Dwarf_Unsigned
dwarf_get_die_marker(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    Dwarf_Unsigned * marker,
    Dwarf_Error * error)
{
    if (die == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_DIE_NULL,
            DW_DLV_NOCOUNT);
    }
    *marker = die->di_marker;
    return 0;
}
int
dwarf_get_die_marker_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    Dwarf_Unsigned * marker,
    Dwarf_Error * error)
{
    if (die == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_DIE_NULL,
            DW_DLV_ERROR);
    }
    *marker = die->di_marker;
    return DW_DLV_ERROR;
}


/*---------------------------------------------------------
    This function adds a die to dbg struct. It should
    be called using the root of all the dies.
---------------------------------------------------------*/
/*  Original form of this call..
    dwarf_add_die_to_debug_a() is preferred now. */
Dwarf_Unsigned
dwarf_add_die_to_debug(Dwarf_P_Debug dbg,
    Dwarf_P_Die first_die, Dwarf_Error * error)
{
    int res = dwarf_add_die_to_debug_a(dbg,first_die,error);
    if (res == DW_DLV_ERROR) {
        return DW_DLV_NOCOUNT;
    }
    return 0;
}

/*  New September 2016. The new and preferred form. */
int
dwarf_add_die_to_debug_a(Dwarf_P_Debug dbg,
    Dwarf_P_Die first_die, Dwarf_Error * error)
{
    if (first_die == NULL) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_DIE_NULL,
            DW_DLV_ERROR);
    }
    if (first_die->di_tag != DW_TAG_compile_unit) {
        DWARF_P_DBG_ERROR(dbg, DW_DLE_WRONG_TAG,
            DW_DLV_ERROR);
    }
    dbg->de_dies = first_die;
    return DW_DLV_OK;
}

int
_dwarf_pro_add_AT_stmt_list(Dwarf_P_Debug dbg,
    Dwarf_P_Die first_die, Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int uwordb_size = dbg->de_dwarf_offset_size;

    /* Add AT_stmt_list attribute */
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg,
            sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC,
            DW_DLV_ERROR);
    }

    new_attr->ar_attribute = DW_AT_stmt_list;
    new_attr->ar_attribute_form =
        dbg->de_ar_data_attribute_form;
    new_attr->ar_rel_type = dbg->de_offset_reloc;

    new_attr->ar_nbytes = uwordb_size;
    new_attr->ar_next = NULL;
    new_attr->ar_reloc_len = uwordb_size;
    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, uwordb_size);
    if (new_attr->ar_data == NULL) {
        DWARF_P_DBG_ERROR(NULL,DW_DLE_ADDR_ALLOC,
            DW_DLV_ERROR);
    }
    {
        Dwarf_Unsigned du = 0;

        WRITE_UNALIGNED(dbg, (void *) new_attr->ar_data,
            (const void *) &du, sizeof(du), uwordb_size);
    }

    _dwarf_pro_add_at_to_die(first_die, new_attr);
    return DW_DLV_OK;
}

static int
_dwarf_debug_str_compare_func(const void *l,const void *r)
{
    const struct Dwarf_P_debug_str_entry_s*el = l;
    const struct Dwarf_P_debug_str_entry_s*er = r;
    char *lname =  0;
    char *rname =  0;
    int ir = 0;

    if (el->dse_has_table_offset) {
        /*  When set the name is in the debug_str table. */
        /*  ASSERT: dse_dbg->de_debug_str->ds_data
            is non-zero.
            ASSERT: dse_name NULL. */
        lname = el->dse_dbg->de_debug_str->ds_data +
            el->dse_table_offset;
    } else {
        /*  ASSERT: dse_name non-null */
        lname = el->dse_name;
    }
    if (er->dse_has_table_offset) {
        /*  When set the name is in the debug_str table. */
        /*  ASSERT: dse_dbg->de_debug_str->ds_data
            is non-zero.
            ASSERT: dse_name NULL. */
        rname = er->dse_dbg->de_debug_str->ds_data +
            er->dse_table_offset;
    } else {
        /*  ASSERT: dse_name non-null */
        rname = er->dse_name;
    }
    ir = strcmp(lname,rname);
    return ir;
}

static  void
debug_str_entry_free_func(void *m)
{
    free(m);
}

static int
make_debug_str_entry(Dwarf_P_Debug dbg,
    struct Dwarf_P_debug_str_entry_s **mt_out,
    char *name,
    unsigned slen,
    unsigned char has_offset,
    Dwarf_Unsigned offset_in_table,
    Dwarf_Error *error)
{
    struct Dwarf_P_debug_str_entry_s *mt =
        (struct  Dwarf_P_debug_str_entry_s *)calloc(
        sizeof(struct Dwarf_P_debug_str_entry_s),1);
    if (!mt) {
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    mt->dse_slen = slen;
    mt->dse_table_offset = 0;
    mt->dse_dbg = dbg;
    if (has_offset) {
        mt->dse_has_table_offset = TRUE;
        mt->dse_table_offset = offset_in_table;
        mt->dse_name = 0;
    } else {
        /* ASSERT: name != NULL */
        mt->dse_has_table_offset = FALSE;
        /* We just set dse_table_offset so it has
            a known value, though nothing should refer
            to dse_table_offset because
            dse_has_table_offset is FALSE.*/
        mt->dse_table_offset = 0;
        mt->dse_name = name;
    }
    *mt_out = mt;
    return DW_DLV_OK;
}
#define STRTAB_BASE_ALLOC_SIZE 2048
static int
insert_debug_str_data_string(Dwarf_P_Debug dbg,
    char *name,
    unsigned slen,
    Dwarf_P_Section_Data sd,
    Dwarf_Unsigned*adding_at_offset,
    Dwarf_Error *  error)
{
    Dwarf_Unsigned current_offset = 0;

    if (!sd->ds_data) {
        Dwarf_Unsigned initial_alloc = STRTAB_BASE_ALLOC_SIZE;
        Dwarf_Unsigned base_insert_offset = 0;

        /*  Inserting our first string.
            The GNU linker refuses to commonize strings
            if the section starts with a NUL byte,
            so start with real string, using a
            base_insert_offset of 0. */
        if ( (slen + base_insert_offset) >= STRTAB_BASE_ALLOC_SIZE) {
            initial_alloc = slen *2+ base_insert_offset;
        }
        if (initial_alloc < slen) {
            _dwarf_p_error(dbg, error, DW_DLE_SIZE_WRAPAROUND);
            return DW_DLV_ERROR;
        }
        sd->ds_data = calloc(1,initial_alloc);
        if (!sd->ds_data) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        sd->ds_orig_alloc = initial_alloc;
        *adding_at_offset = base_insert_offset;
        sd->ds_nbytes = slen + base_insert_offset;
        strcpy(sd->ds_data+base_insert_offset,name);
        return DW_DLV_OK;
    }
    current_offset = sd->ds_nbytes;
    if ( (current_offset + slen) >= sd->ds_orig_alloc) {
        unsigned updated_length = sd->ds_orig_alloc;
        char *newbuf = 0;
        if (slen > updated_length) {
            /*  Very long string passed in. */
            updated_length = slen *2;
        } else {
            updated_length = updated_length *2;
        }
        if (updated_length < sd->ds_orig_alloc) {
            _dwarf_p_error(dbg, error, DW_DLE_SIZE_WRAPAROUND);
            return DW_DLV_ERROR;
        }
        newbuf = calloc(1,updated_length);
        if (!newbuf) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        memcpy(newbuf,sd->ds_data,sd->ds_nbytes);
        free(sd->ds_data);
        sd->ds_data = newbuf;
        sd->ds_orig_alloc = updated_length;
        newbuf = 0;
    }
    strcpy(sd->ds_data + current_offset,name);
    sd->ds_nbytes += slen;
    *adding_at_offset = current_offset;
    return DW_DLV_OK;
}

/*  Find the string offset using the hash table,
    and if not known, insert the new string. */
int
_dwarf_insert_or_find_in_debug_str(Dwarf_P_Debug dbg,
    char *name,
    enum dwarf_which_hash whash,
    unsigned slen, /* includes space for trailing NUL */
    Dwarf_Unsigned *offset_in_debug_str,
    Dwarf_Error *error)
{
    struct Dwarf_P_debug_str_entry_s *mt = 0;
    struct Dwarf_P_debug_str_entry_s *mt2 = 0;
    struct Dwarf_P_debug_str_entry_s *retval = 0;
    struct Dwarf_P_debug_str_entry_s *re = 0;
    int res = 0;
    Dwarf_Unsigned adding_at_offset = 0;
    void **hashtab = 0;
    Dwarf_P_Section_Data sd = 0;
    struct Dwarf_P_Str_stats_s * stats =  0;

    switch (whash) {
    case _dwarf_hash_debug_str:
        hashtab =  &dbg->de_debug_str_hashtab;
        sd =  dbg->de_debug_str;
        stats = &dbg->de_stats.ps_strp;
        break;
    case _dwarf_hash_debug_line_str:
        hashtab =  &dbg->de_debug_line_str_hashtab;
        sd =  dbg->de_debug_line_str;
        stats = &dbg->de_stats.ps_line_strp;
        break;
    case _dwarf_hash_debug_str_sup:
    default:
        /* Not supported or unknown. */
        _dwarf_p_error(dbg, error, DW_DLE_STRING_HASHTAB_IDENTITY_ERROR);
        return DW_DLV_ERROR;
    }
    res = make_debug_str_entry(dbg,&mt,name,
        slen,FALSE, 0, error);
    if (res != DW_DLV_OK) {
        return res;
    }
    /*  We do a find as we do not want the string pointer passed in
        to be in the hash table, we want a pointer into the
        debug_str table in the hash table. */
    retval = dwarf_tfind(mt,(void *const*)hashtab,
        _dwarf_debug_str_compare_func);
    if (retval) {

        stats->ps_strp_reused_count++;
        stats->ps_strp_reused_len += slen;

        re = *(struct Dwarf_P_debug_str_entry_s **)retval;
        *offset_in_debug_str = re->dse_table_offset;
        debug_str_entry_free_func(mt);
        return DW_DLV_OK;
    }

    /*  We know the string is not in .debug_str data yet.
        Insert it into the big string table and get that
        offset. */

    debug_str_entry_free_func(mt);
    mt = 0;
    res = insert_debug_str_data_string(dbg,name,slen,sd,
        &adding_at_offset, error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /*  The name is in the string table itself, so use that pointer
        and offset for the string. */
    res = make_debug_str_entry(dbg,&mt2, 0,
        slen,TRUE,adding_at_offset,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    retval = dwarf_tsearch(mt2,
        (void *)hashtab,
        _dwarf_debug_str_compare_func);
    if (!retval) {
        debug_str_entry_free_func(mt2);
        _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    /* This indirection is one of the surprises in using tsearch... */
    re = *(struct Dwarf_P_debug_str_entry_s **)retval;
    if (re != mt2) {
        debug_str_entry_free_func(mt2);
        /*  Found it in hash tab: illogical as the tsearch_find should
            have found it. */
        _dwarf_p_error(dbg, error, DW_DLE_ILLOGICAL_TSEARCH);
        return DW_DLV_ERROR;
    }
    stats->ps_strp_count_debug_str++;
    stats->ps_strp_len_debug_str += slen;
    /* we added it to hash, do not free mt2 (which == re). */
    *offset_in_debug_str = re->dse_table_offset;
    return DW_DLV_OK;
}

/*  Returns DW_DLV_OK or DW_DLV_ERROR. */
int _dwarf_pro_set_string_attr(Dwarf_P_Attribute new_attr,
    Dwarf_P_Debug dbg,
    char *name,
    Dwarf_Error *error)
{
    int form = dbg->de_debug_default_str_form;
    unsigned slen = strlen(name)+1;

    if (form == DW_FORM_string ||
        slen <= dbg->de_dwarf_offset_size) {
        new_attr->ar_nbytes = slen;
        new_attr->ar_next = 0;

        new_attr->ar_data =
            (char *) _dwarf_p_get_alloc(dbg, slen);
        if (new_attr->ar_data == NULL) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        dbg->de_stats.ps_str_count++;
        dbg->de_stats.ps_str_total_length += slen;

        strcpy(new_attr->ar_data, name);
        new_attr->ar_attribute_form = DW_FORM_string;
        new_attr->ar_rel_type = R_MIPS_NONE;
        new_attr->ar_reloc_len = 0; /* unused for R_MIPS_NONE */
        return DW_DLV_OK;
    }
    if (form == DW_FORM_strp) {
        int uwordb_size = dbg->de_dwarf_offset_size;
        Dwarf_Unsigned offset_in_debug_str = 0;
        int res = 0;

        res = _dwarf_insert_or_find_in_debug_str(dbg,name,
            _dwarf_hash_debug_str,slen,
            &offset_in_debug_str,error);
        if(res != DW_DLV_OK) {
            return res;
        }
        new_attr->ar_attribute_form = form;
        new_attr->ar_rel_type = dbg->de_offset_reloc;
        new_attr->ar_nbytes = uwordb_size;
        new_attr->ar_next = NULL;
        new_attr->ar_reloc_len = uwordb_size;
        /*  During transform to disk
            a symbol index will be applied. */
        new_attr->ar_data = (char *)
            _dwarf_p_get_alloc(dbg, uwordb_size);
        if (new_attr->ar_data == NULL) {
            _dwarf_p_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        {
            Dwarf_Unsigned du = offset_in_debug_str;

            WRITE_UNALIGNED(dbg, (void *) new_attr->ar_data,
                (const void *) &du, sizeof(du), uwordb_size);
        }

        return DW_DLV_OK;
    }
    _dwarf_p_error(dbg, error, DW_DLE_BAD_STRING_FORM);
    return DW_DLV_ERROR;

}


/*-------------------------------------------------------------------
    Add AT_name attribute to die
---------------------------------------------------------------------*/
/*  Original function. dwarf_add_AT_name_a() is the
    suggested alternative. */
Dwarf_P_Attribute
dwarf_add_AT_name(Dwarf_P_Die die,
    char *name,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_name_a(die, name,
        &a, error);
    if (res == DW_DLV_ERROR) {
        return (Dwarf_P_Attribute)(DW_DLV_BADADDR);
    }
    return a;
}

/*   New December 2018.  */
int
dwarf_add_AT_name_a(Dwarf_P_Die die, char *name,
    Dwarf_P_Attribute *newattr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    int res = 0;

    if (die == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_DIE_NULL,
            DW_DLV_ERROR);
    }
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(die->di_dbg,
            sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC,
            DW_DLV_ERROR);
    }

    /* fill in the information */
    new_attr->ar_attribute = DW_AT_name;
    res = _dwarf_pro_set_string_attr(new_attr,die->di_dbg,name,error);
    if (res != DW_DLV_OK) {
        return DW_DLV_ERROR;
    }

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(die, new_attr);
    *newattr_out = new_attr;
    return DW_DLV_OK;
}


/*--------------------------------------------------------------------
    Add AT_comp_dir attribute to die
--------------------------------------------------------------------*/
Dwarf_P_Attribute
dwarf_add_AT_comp_dir(Dwarf_P_Die ownerdie,
    char *current_working_directory,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute a = 0;
    int res = 0;

    res = dwarf_add_AT_comp_dir_a(ownerdie,
        current_working_directory,
        &a, error);
    if (res != DW_DLV_OK) {
        return (Dwarf_P_Attribute)(DW_DLV_BADADDR);
    }
    return a;
}

int
dwarf_add_AT_comp_dir_a(Dwarf_P_Die ownerdie,
    char *current_working_directory,
    Dwarf_P_Attribute *attr_out,
    Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr = 0;
    int res = 0;

    if (ownerdie == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_DIE_NULL,
            DW_DLV_ERROR);
    }
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(ownerdie->di_dbg,
        sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC,
            DW_DLV_ERROR);
    }

    /* fill in the information */
    new_attr->ar_attribute = DW_AT_comp_dir;
    res = _dwarf_pro_set_string_attr(new_attr,ownerdie->di_dbg,
        current_working_directory,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    /* add attribute to the die */
    _dwarf_pro_add_at_to_die(ownerdie, new_attr);
    *attr_out = new_attr;
    return DW_DLV_OK;
}


int
_dwarf_pro_add_AT_fde(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    Dwarf_Unsigned offset, Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int uwordb_size = dbg->de_dwarf_offset_size;

    if (die == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_DIE_NULL, DW_DLV_ERROR);
    }
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg,sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC, DW_DLV_ERROR);
    }

    /* fill in the information */
    new_attr->ar_attribute = DW_AT_MIPS_fde;
    new_attr->ar_attribute_form = dbg->de_ar_data_attribute_form;
    new_attr->ar_rel_type = dbg->de_offset_reloc;
    new_attr->ar_nbytes = uwordb_size;
    new_attr->ar_next = NULL;
    new_attr->ar_reloc_len = uwordb_size;
    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, uwordb_size);
    if (new_attr->ar_data == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_ADDR_ALLOC, DW_DLV_ERROR);
    }
    {
        Dwarf_Unsigned du = offset;

        WRITE_UNALIGNED(dbg, (void *) new_attr->ar_data,
            (const void *) &du, sizeof(du), uwordb_size);
    }
    _dwarf_pro_add_at_to_die(die, new_attr);
    return DW_DLV_OK;
}

/* Sept 2016: returns DW_DLV_OK or DW_DLV_ERROR */
int
_dwarf_pro_add_AT_macro_info(Dwarf_P_Debug dbg,
    Dwarf_P_Die die,
    Dwarf_Unsigned offset, Dwarf_Error * error)
{
    Dwarf_P_Attribute new_attr;
    int uwordb_size = dbg->de_dwarf_offset_size;

    if (die == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_DIE_NULL, DW_DLV_ERROR);
    }
    new_attr = (Dwarf_P_Attribute)
        _dwarf_p_get_alloc(dbg,sizeof(struct Dwarf_P_Attribute_s));
    if (new_attr == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_ATTR_ALLOC, DW_DLV_ERROR);
    }

    /* fill in the information */
    new_attr->ar_attribute = DW_AT_macro_info;
    new_attr->ar_attribute_form = dbg->de_ar_data_attribute_form;
    new_attr->ar_rel_type = dbg->de_offset_reloc;

    new_attr->ar_nbytes = uwordb_size;
    new_attr->ar_next = NULL;
    new_attr->ar_reloc_len = uwordb_size;
    new_attr->ar_data = (char *)
        _dwarf_p_get_alloc(dbg, uwordb_size);
    if (new_attr->ar_data == NULL) {
        DWARF_P_DBG_ERROR(NULL, DW_DLE_ADDR_ALLOC, DW_DLV_ERROR);
    }
    {
        Dwarf_Unsigned du = offset;

        WRITE_UNALIGNED(dbg, (void *) new_attr->ar_data,
            (const void *) &du, sizeof(du), uwordb_size);
    }

    _dwarf_pro_add_at_to_die(die, new_attr);

    return DW_DLV_OK;
}


/*  Updates the list of attributes on this Dwarf_P_Die
*/
void
_dwarf_pro_add_at_to_die(Dwarf_P_Die die, Dwarf_P_Attribute attr)
{
    if (die->di_last_attr) {
        /* Inserts new attr at the end */
        die->di_last_attr->ar_next = attr;
        die->di_last_attr = attr;
        die->di_n_attr++;
    } else {
        die->di_n_attr = 1;
        die->di_attrs = die->di_last_attr = attr;
    }
}
