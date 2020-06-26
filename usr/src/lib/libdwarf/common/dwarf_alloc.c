/*
  Copyright (C) 2000-2005 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright (C) 2007-2020  David Anderson. All Rights Reserved.

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
/*  To see the full set of DW_DLA types and nothing
    else  try:
    grep DW_DLA dwarf_alloc.c | grep 0x
*/

#include "config.h"
#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h> /* For uintptr_t */
#endif /* HAVE_STDINT_H */
#include "dwarf_incl.h"
#include "dwarf_error.h"
#include "dwarf_alloc.h"
/*  These files are included to get the sizes
    of structs for malloc.
*/
#include "dwarf_util.h"
#include "dwarf_line.h"
#include "dwarf_global.h"
#include "dwarf_arange.h"
#include "dwarf_abbrev.h"
#include "dwarf_die_deliv.h"
#include "dwarf_frame.h"
#include "dwarf_loc.h"
#include "dwarf_funcs.h"
#include "dwarf_types.h"
#include "dwarf_vars.h"
#include "dwarf_weaks.h"
#include "dwarf_harmless.h"
#include "dwarf_tsearch.h"
#include "dwarf_gdbindex.h"
#include "dwarf_xu_index.h"
#include "dwarf_macro5.h"
#include "dwarf_dnames.h"
#include "dwarf_rnglists.h"
#include "dwarf_dsc.h"
#include "dwarfstring.h"
#include "dwarf_str_offsets.h"

#define TRUE 1
#define FALSE 0
/*  Some allocations are simple some not. These reduce
    the issue of determining which sort of thing to a simple
    test. See ia_multiply_count
    Usually when MULTIPLY_NO is set the count
    is 1, so MULTIPY_CT would work as well.  */
#define MULTIPLY_NO 0
#define MULTIPLY_CT 1
#define MULTIPLY_SP 2
/*  This translates into de_alloc_hdr into a per-instance size
    and allows room for a constructor/destructor pointer.
    Rearranging the DW_DLA values would break binary compatibility
    so that is not an option.
*/
struct ial_s {
    /*  In bytes, one struct instance.  */
    short ia_struct_size;

    /*  Not a count, but a MULTIPLY{_NO,_CT,_SP} value. */
    short ia_multiply_count;

    /*  When we really need a constructor/destructor
        these make applying such quite simple. */
    int (*specialconstructor) (Dwarf_Debug, void *);
    void (*specialdestructor) (void *);
};

/*  Used as a way to return meaningful errors when
    the malloc arena is exhausted (when malloc returns NULL).
    Not normally used.
    New in December 2014.*/
struct Dwarf_Error_s _dwarf_failsafe_error = {
    DW_DLE_FAILSAFE_ERRVAL,
    0,
    1
};

/*  If non-zero (the default) de_alloc_tree (see dwarf_alloc.c)
    is used normally.  If zero then dwarf allocations
    are not tracked by libdwarf and dwarf_finish() cannot
    clean up any per-Dwarf_Debug allocations the
    caller forgot to dealloc. */
static signed char global_de_alloc_tree_on = 1;
#ifdef HAVE_GLOBAL_ALLOC_SUMS
static Dwarf_Unsigned global_allocation_count;
static Dwarf_Unsigned global_allocation_total;
static Dwarf_Unsigned global_de_alloc_tree_count;
static Dwarf_Unsigned global_de_alloc_tree_total;
static Dwarf_Unsigned global_de_alloc_tree_early_dealloc_count;
static Dwarf_Unsigned global_de_alloc_tree_early_dealloc_size;
#endif /* HAVE_GLOBAL_ALLOC_SUMS */

void _dwarf_alloc_tree_counts( UNUSEDARG Dwarf_Unsigned *allocount,
    UNUSEDARG Dwarf_Unsigned *allosum,
    UNUSEDARG Dwarf_Unsigned *treecount,
    UNUSEDARG Dwarf_Unsigned *treesum,
    UNUSEDARG Dwarf_Unsigned *earlydealloccount,
    UNUSEDARG Dwarf_Unsigned *earlydeallocsize,
    UNUSEDARG Dwarf_Unsigned *unused1,
    UNUSEDARG Dwarf_Unsigned *unused2,
    UNUSEDARG Dwarf_Unsigned *unused3)
{
#ifdef HAVE_GLOBAL_ALLOC_SUMS
    *allocount = global_allocation_count;
    *allosum =   global_allocation_total;
    *treecount = global_de_alloc_tree_count;
    *treesum =   global_de_alloc_tree_total;
    *earlydealloccount =
        global_de_alloc_tree_early_dealloc_count;
    *earlydeallocsize =
        global_de_alloc_tree_early_dealloc_size;
    if (unused1) {
        *unused1 = 0;
    }
    if (unused2) {
        *unused2 = 0;
    }
    if (unused3) {
        *unused3 = 0;
    }
#endif /* HAVE_GLOBAL_ALLOC_SUMS */
}

/*  Defined March 7 2020. Allows a caller to
    avoid most tracking by the de_alloc_tree hash
    table if called with v of zero.
    Returns the value the flag was before this call. */
int dwarf_set_de_alloc_flag(int v)
{
    int ov = global_de_alloc_tree_on;
    global_de_alloc_tree_on = v;
    return ov;
}



void
_dwarf_error_destructor(void *m)
{
    Dwarf_Error er = (Dwarf_Error)m;
    dwarfstring *erm = (dwarfstring *)er->er_msg;
    if (! erm) {
        return;
    }
#if DEBUG
    printf("libdwarfdetector DEALLOC Now destruct error string %s\n",dwarfstring_string(erm));
#endif
    dwarfstring_destructor(erm);
    free(erm);
    er->er_msg = 0;
    return;
}

/*  To do destructors we need some extra data in every
    _dwarf_get_alloc situation. */
/* Here is the extra we malloc for a prefix. */
struct reserve_size_s {
   void *dummy_rsv1;
   void *dummy_rsv2;
};
/* Here is how we use the extra prefix area. */
struct reserve_data_s {
   void *rd_dbg;
   unsigned short rd_length;
   unsigned short rd_type;
};
#define DW_RESERVE sizeof(struct reserve_size_s)


static const
struct ial_s alloc_instance_basics[ALLOC_AREA_INDEX_TABLE_MAX] = {
    /* 0  none */
    { 1,MULTIPLY_NO, 0, 0},

    /* 0x1 x1 DW_DLA_STRING */
    { 1,MULTIPLY_CT, 0, 0},

    /* 0x2 DW_DLA_LOC */
    { sizeof(Dwarf_Loc),MULTIPLY_NO, 0, 0} ,

    /* x3 DW_DLA_LOCDESC */
    { sizeof(Dwarf_Locdesc),MULTIPLY_NO, 0, 0},

    /* 0x4 DW_DLA_ELLIST */ /* not used */
    { 1,MULTIPLY_NO, 0, 0},

    /* 0x5 DW_DLA_BOUNDS */ /* not used */
    { 1,MULTIPLY_NO, 0, 0},

    /* 0x6 DW_DLA_BLOCK */
    { sizeof(Dwarf_Block),MULTIPLY_NO,  0, 0},

    /* x7 DW_DLA_DEBUG */
    /* the actual dwarf_debug structure */
    { 1,MULTIPLY_NO, 0, 0} ,

    /* x8 DW_DLA_DIE */
    {sizeof(struct Dwarf_Die_s),MULTIPLY_NO, 0, 0},

    /* x9 DW_DLA_LINE */
    {sizeof(struct Dwarf_Line_s),MULTIPLY_NO, 0, 0},

    /* 0xa  10 DW_DLA_ATTR */
    {sizeof(struct Dwarf_Attribute_s),MULTIPLY_NO,  0, 0},

    /* 0xb DW_DLA_TYPE *//* not used */
    {1,MULTIPLY_NO,  0, 0},

    /* 0xc DW_DLA_SUBSCR *//* not used */
    {1,MULTIPLY_NO,  0, 0},

    /* 0xd 13 DW_DLA_GLOBAL */
    {sizeof(struct Dwarf_Global_s),MULTIPLY_NO,  0, 0},

    /* 0xe 14 DW_DLA_ERROR */
    {sizeof(struct Dwarf_Error_s),MULTIPLY_NO,  0,
        _dwarf_error_destructor},

    /* 0xf DW_DLA_LIST */
    {sizeof(Dwarf_Ptr),MULTIPLY_CT, 0, 0},

    /* 0x10 DW_DLA_LINEBUF */ /* not used */
    {1,MULTIPLY_NO, 0, 0},

    /* 0x11 17 DW_DLA_ARANGE */
    {sizeof(struct Dwarf_Arange_s),MULTIPLY_NO,  0, 0},

    /* 0x12 18 DW_DLA_ABBREV */
    {sizeof(struct Dwarf_Abbrev_s),MULTIPLY_NO,  0, 0},

    /* 0x13 19 DW_DLA_FRAME_OP */
    {sizeof(Dwarf_Frame_Op),MULTIPLY_NO,  0, 0} ,

    /* 0x14  20 DW_DLA_CIE */
    {sizeof(struct Dwarf_Cie_s),MULTIPLY_NO,  0, 0},

    /* 0x15 DW_DLA_FDE */
    {sizeof(struct Dwarf_Fde_s),MULTIPLY_NO,  0,
        _dwarf_fde_destructor},

    /* 0x16 DW_DLA_LOC_BLOCK */
    {sizeof(Dwarf_Loc),MULTIPLY_CT, 0, 0},

    /* 0x17 DW_DLA_FRAME_BLOCK */
    {sizeof(Dwarf_Frame_Op),MULTIPLY_CT, 0, 0},

    /* 0x18 DW_DLA_FUNC UNUSED */
    {sizeof(struct Dwarf_Global_s),MULTIPLY_NO,  0, 0},

    /* 0x19 DW_DLA_TYPENAME UNUSED */
    {sizeof(struct Dwarf_Global_s),MULTIPLY_NO,  0, 0},

    /* 0x1a DW_DLA_VAR UNUSED  */
    {sizeof(struct Dwarf_Global_s),MULTIPLY_NO,  0, 0},

    /* 0x1b DW_DLA_WEAK UNUSED */
    {sizeof(struct Dwarf_Global_s),MULTIPLY_NO,  0, 0},

    /* 0x1c DW_DLA_ADDR */
    {1,MULTIPLY_SP, 0, 0},

    /* 0x1d DW_DLA_RANGES */
    {sizeof(Dwarf_Ranges),MULTIPLY_CT, 0,0 },

    /*  The following DW_DLA data types
        are known only inside libdwarf.  */

    /* 0x1e DW_DLA_ABBREV_LIST */
    { sizeof(struct Dwarf_Abbrev_List_s),MULTIPLY_NO, 0, 0},

    /* 0x1f DW_DLA_CHAIN */
    {sizeof(struct Dwarf_Chain_s),MULTIPLY_NO, 0, 0},

    /* 0x20 DW_DLA_CU_CONTEXT */
    {sizeof(struct Dwarf_CU_Context_s),MULTIPLY_NO,  0, 0},

    /* 0x21 DW_DLA_FRAME */
    {sizeof(struct Dwarf_Frame_s),MULTIPLY_NO,
        _dwarf_frame_constructor,
        _dwarf_frame_destructor},

    /* 0x22 DW_DLA_GLOBAL_CONTEXT */
    {sizeof(struct Dwarf_Global_Context_s),MULTIPLY_NO,  0, 0},

    /* 0x23 DW_DLA_FILE_ENTRY */
    {sizeof(struct Dwarf_File_Entry_s),MULTIPLY_NO,  0, 0},

    /* 0x24 DW_DLA_LINE_CONTEXT */
    {sizeof(struct Dwarf_Line_Context_s),MULTIPLY_NO,
        _dwarf_line_context_constructor,
        _dwarf_line_context_destructor},

    /* 0x25 DW_DLA_LOC_CHAIN */
    {sizeof(struct Dwarf_Loc_Chain_s),MULTIPLY_NO,  0, 0},

    /* 0x26 0x26 DW_DLA_HASH_TABLE */
    {sizeof(struct Dwarf_Hash_Table_s),MULTIPLY_NO, 0, 0},

    /*  The following really use Global struct: used to be unique struct
    per type, but now merged (11/99).  The opaque types
    are visible in the interface. The types  for
    DW_DLA_FUNC, DW_DLA_TYPENAME, DW_DLA_VAR, DW_DLA_WEAK also use
    the global types.  */

    /* 0x27 DW_DLA_FUNC_CONTEXT */
    {sizeof(struct Dwarf_Global_Context_s),MULTIPLY_NO,  0, 0},

    /* 0x28 40 DW_DLA_TYPENAME_CONTEXT */
    {sizeof(struct Dwarf_Global_Context_s),MULTIPLY_NO,  0, 0},

    /* 0x29 41 DW_DLA_VAR_CONTEXT */
    {sizeof(struct Dwarf_Global_Context_s),MULTIPLY_NO,  0, 0},

    /* 0x2a 42 DW_DLA_WEAK_CONTEXT */
    {sizeof(struct Dwarf_Global_Context_s),MULTIPLY_NO,  0, 0},

    /* 0x2b 43 DW_DLA_PUBTYPES_CONTEXT DWARF3 */
    {sizeof(struct Dwarf_Global_Context_s),MULTIPLY_NO,  0, 0},

    /* 0x2c 44 DW_DLA_HASH_TABLE_ENTRY */
    {sizeof(struct Dwarf_Hash_Table_Entry_s),MULTIPLY_CT,0,0 },

    /* 0x2d -0x34 reserved */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x2e 46 reserved for future use  */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x2f 47  reserved for future use  */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x30 reserved for future internal use */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x31 reserved for future internal use */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x32 50 reserved for future internal use */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x33 51 reserved for future internal use */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x34 52 reserved for future internal use */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x35 53 reserved for future use. */
    {sizeof(int),MULTIPLY_NO,  0, 0},

    /* 0x36 54 Used starting May 2020  DW_DLA_RNGLISTS_HEAD */
    {sizeof(struct Dwarf_Rnglists_Head_s),MULTIPLY_NO,  0,
        _dwarf_rnglists_head_destructor},

    /*  now,  we have types that are public. */
    /* 0x37 55.  New in June 2014. Gdb. */
    {sizeof(struct Dwarf_Gdbindex_s),MULTIPLY_NO,  0, 0},

    /* 0x38 56.  New in July 2014. */
    /* DWARF5 DebugFission dwp file sections
        .debug_cu_index and .debug_tu_index . */
    {sizeof(struct Dwarf_Xu_Index_Header_s),MULTIPLY_NO,  0, 0},

    /*  These required by new features in DWARF5. Also usable
        for DWARF2,3,4. */
    /* 0x39 57 DW_DLA_LOC_BLOCK_C DWARF5 */
    {sizeof(struct Dwarf_Loc_Expr_Op_s),MULTIPLY_CT, 0, 0},

    /* 0x3a 58  DW_DLA_LOCDESC_C */
    {sizeof(struct Dwarf_Locdesc_c_s),MULTIPLY_CT, 0, 0},

    /* 0x3b 59 DW_DLA_LOC_HEAD_C */
    {sizeof(struct Dwarf_Loc_Head_c_s),MULTIPLY_NO, 0, 0},

    /* 0x3c 60 DW_DLA_MACRO_CONTEXT */
    {sizeof(struct Dwarf_Macro_Context_s),MULTIPLY_NO,
        _dwarf_macro_constructor,
        _dwarf_macro_destructor},

    /* 0x3d 61 DW_DLA_CHAIN_2 */
    {sizeof(struct Dwarf_Chain_o),MULTIPLY_NO, 0, 0},

    /* 0x3e 62 DW_DLA_DSC_HEAD */
    {sizeof(struct Dwarf_Dsc_Head_s),MULTIPLY_NO, 0,
        _dwarf_dsc_destructor},

    /* 0x3f 63 DW_DLA_DNAMES_HEAD */
    {sizeof(struct Dwarf_Dnames_Head_s),MULTIPLY_NO, 0,
        _dwarf_debugnames_destructor},

    /* 0x40 64 DW_DLA_STR_OFFSETS */
    {sizeof(struct Dwarf_Str_Offsets_Table_s),MULTIPLY_NO, 0,0},
};

/*  We are simply using the incoming pointer as the key-pointer.
*/

static DW_TSHASHTYPE
simple_value_hashfunc(const void *keyp)
{
    DW_TSHASHTYPE up = (DW_TSHASHTYPE)(uintptr_t)keyp;
    return up;
}
/*  We did alloc something but not a fixed-length thing.
    Instead, it starts with some special data we noted.
    The incoming pointer is to the caller data, we
    destruct based on caller, but find the special
    extra data in a prefix area. */
static void
tdestroy_free_node(void *nodep)
{
    char * m = (char *)nodep;
    char * malloc_addr = m - DW_RESERVE;
    struct reserve_data_s * reserve =(struct reserve_data_s *)malloc_addr;
    unsigned type = reserve->rd_type;
    if (type >= ALLOC_AREA_INDEX_TABLE_MAX) {
        /* Internal error, corrupted data. */
        return;
    }
    if(!reserve->rd_dbg) {
        /*  Unused (corrupted?) node in the tree.
            Should never happen. */
        return;
    }
    if(!reserve->rd_type) {
        /*  Unused (corrupted?) node in the tree.
            Should never happen. */
        return;
    }
    if (alloc_instance_basics[type].specialdestructor) {
        alloc_instance_basics[type].specialdestructor(m);
    }
    free(malloc_addr);
}

/* The sort of hash table entries result in very simple helper functions. */
static int
simple_compare_function(const void *l, const void *r)
{
    DW_TSHASHTYPE lp = (DW_TSHASHTYPE)(uintptr_t)l;
    DW_TSHASHTYPE rp = (DW_TSHASHTYPE)(uintptr_t)r;
    if(lp < rp) {
        return -1;
    }
    if(lp > rp) {
        return 1;
    }
    return 0;
}

/*  This function returns a pointer to a region
    of memory.  For alloc_types that are not
    strings or lists of pointers, only 1 struct
    can be requested at a time.  This is indicated
    by an input count of 1.  For strings, count
    equals the length of the string it will
    contain, i.e it the length of the string
    plus 1 for the terminating null.  For lists
    of pointers, count is equal to the number of
    pointers.  For DW_DLA_FRAME_BLOCK, DW_DLA_RANGES, and
    DW_DLA_LOC_BLOCK allocation types also, count
    is the count of the number of structs needed.

    This function cannot be used to allocate a
    Dwarf_Debug_s struct.  */

char *
_dwarf_get_alloc(Dwarf_Debug dbg,
    Dwarf_Small alloc_type, Dwarf_Unsigned count)
{
    char * alloc_mem = 0;
    Dwarf_Signed basesize = 0;
    Dwarf_Signed size = 0;
    unsigned int type = alloc_type;
    short action = 0;

    if (dbg == NULL) {
        return NULL;
    }
    if (type >= ALLOC_AREA_INDEX_TABLE_MAX) {
        /* internal error */
        return NULL;
    }
    basesize = alloc_instance_basics[alloc_type].ia_struct_size;
    action = alloc_instance_basics[alloc_type].ia_multiply_count;
    if(action == MULTIPLY_NO) {
        /* Usually count is 1, but do not assume it. */
        size = basesize;
    } else if (action == MULTIPLY_CT) {
        size = basesize * count;
    }  else {
        /* MULTIPLY_SP */
        /* DW_DLA_ADDR.. count * largest size */
        size = count *
            (sizeof(Dwarf_Addr) > sizeof(Dwarf_Off) ?
            sizeof(Dwarf_Addr) : sizeof(Dwarf_Off));
    }
    size += DW_RESERVE;
    alloc_mem = malloc(size);
    if (!alloc_mem) {
        return NULL;
    }
    {
        char * ret_mem = alloc_mem + DW_RESERVE;
        void *key = ret_mem;
        struct reserve_data_s *r = (struct reserve_data_s*)alloc_mem;
        void *result = 0;

        memset(alloc_mem, 0, size);
        /* We are not actually using rd_dbg, we are using rd_type. */
        r->rd_dbg = dbg;
        r->rd_type = alloc_type;
        r->rd_length = size;
        if (alloc_instance_basics[type].specialconstructor) {
            int res = alloc_instance_basics[type].
                specialconstructor(dbg, ret_mem);
            if (res != DW_DLV_OK) {
                /*  We leak what we allocated in
                    _dwarf_find_memory when
                    constructor fails. */
                return NULL;
            }
        }
        /*  See global flag.
            If zero then caller choses not
            to track allocations, so dwarf_finish()
            is unable to free anything the caller
            omitted to dealloc. Normally
            the global flag is non-zero */
#ifdef HAVE_GLOBAL_ALLOC_SUMS
        global_allocation_count++;
        global_allocation_total += size;
#endif /* HAVE_GLOBAL_ALLOC_SUMS */

        /*  As of March 14, 2020 it's
            not necessary to test for alloc type, but instead
            only call tsearch if de_alloc_tree_on. */
        if (global_de_alloc_tree_on) {
#ifdef HAVE_GLOBAL_ALLOC_SUMS
            global_de_alloc_tree_total += size;
            global_de_alloc_tree_count++;
#endif /* HAVE_GLOBAL_ALLOC_SUMS */
            result = dwarf_tsearch((void *)key,
                &dbg->de_alloc_tree,simple_compare_function);
            if(!result) {
                /*  Something badly wrong. Out of memory.
                    pretend all is well. */
            }
        }
#if DEBUG
    printf("libdwarfdetector ALLOC ret 0x%lx type 0x%x size %lu line %d %s\n",(unsigned long)ret_mem,(unsigned)alloc_type,(unsigned long)size,__LINE__,__FILE__);
#endif
        return (ret_mem);
    }
}

/*  This was once a long list of tests using dss_data
    and dss_size to see if 'space' was inside a debug section.
    This tfind approach removes that maintenance headache. */
static int
string_is_in_debug_section(Dwarf_Debug dbg,void * space)
{
    /*  See dwarf_line.c dwarf_srcfiles()
        for one way we can wind up with
        a DW_DLA_STRING string that may or may not be malloc-ed
        by _dwarf_get_alloc().

        dwarf_formstring(), for example, returns strings
        which point into .debug_info or .debug_types but
        dwarf_dealloc is never supposed to be applied
        to strings dwarf_formstring() returns!

        Lots of calls returning strings
        have always been documented as requiring
        dwarf_dealloc(...DW_DLA_STRING) when the code
        just returns a pointer to a portion of a loaded section!
        It is too late to change the documentation. */

    void *result = 0;
    result = dwarf_tfind((void *)space,
        &dbg->de_alloc_tree,simple_compare_function);
    if(!result) {
        /*  Not in the tree, so not malloc-ed
            Nothing to delete. */
        return TRUE;
    }
    /*  We found the address in the tree, so it is NOT
        part of .debug_info or any other dwarf section,
        but is space malloc-d in _dwarf_get_alloc(). */
    return FALSE;
}


/*  These wrappers for dwarf_dealloc enable type-checking
    at call points. */
void
dwarf_dealloc_error(Dwarf_Debug dbg, Dwarf_Error err)
{
    dwarf_dealloc(dbg,err,DW_DLA_ERROR);
}
void
dwarf_dealloc_die( Dwarf_Die die)
{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context context = 0;

    if (!die) {
#ifdef DEBUG
        printf("DEALLOC does nothing, die NULL line %d %s\n",
            __LINE__,__FILE__);
        fflush(stdout);
#endif
        return;
    }
    context = die->di_cu_context;
    if (!context) {
#ifdef DEBUG
        printf("DEALLOC does nothing, context NULL line %d %s\n",
            __LINE__,__FILE__);
        fflush(stdout);
#endif
        return;
    }
    dbg = context->cc_dbg;
    dwarf_dealloc(dbg,die,DW_DLA_DIE);
}


void
dwarf_dealloc_attribute(Dwarf_Attribute attr)
{
    Dwarf_Debug dbg = 0;

    if (!attr) {
#ifdef DEBUG
        printf("DEALLOC does nothing, attr is NULL line %d %s\n",
            __LINE__,__FILE__);
        fflush(stdout);
#endif
        return;
    }
    dbg = attr->ar_dbg;
    dwarf_dealloc(dbg,attr,DW_DLA_ATTR);
}
/*
    This function is used to deallocate a region of memory
    that was obtained by a call to _dwarf_get_alloc.  Note
    that though dwarf_dealloc() is a public function,
    _dwarf_get_alloc() isn't.

    For lists, typically arrays of pointers, it is assumed
    that the space was allocated by a direct call to malloc,
    and so a straight free() is done.  This is also the case
    for variable length blocks such as DW_DLA_FRAME_BLOCK
    and DW_DLA_LOC_BLOCK and DW_DLA_RANGES.

    For strings, the pointer might point to a string in
    .debug_info or .debug_string.  After this is checked,
    and if found not to be the case, a free() is done,
    again on the assumption that a malloc was used to
    obtain the space.

    This function does not return anything.
    The _dwarf_error_destructor() will be called
    to free the er_msg string
    (if this is a Dwarf_Error) just before the
    Dwarf_Error is freed here. See...specialdestructor()
    below.

*/
void
dwarf_dealloc(Dwarf_Debug dbg,
    Dwarf_Ptr space, Dwarf_Unsigned alloc_type)
{
    unsigned int type = 0;
    char * malloc_addr = 0;
    struct reserve_data_s * r = 0;

    if (!space) {
#ifdef DEBUG
        printf("DEALLOC does nothing, space NULL line %d %s\n",
            __LINE__,__FILE__);
        fflush(stdout);
abort();
#endif /* DEBUG*/
        return;
    }
    if (!dbg) {
        /*  App error, or an app that failed to succeed in a
            dwarf_init() call. */
#ifdef DEBUG
        printf( "DEALLOC does nothing, dbg NULL line %d %s\n",
            __LINE__,__FILE__);
        fflush(stdout);
#endif /* DEBUG*/
        return;
    }
    if (dbg->de_alloc_tree) {
        /*  If it's a string in debug_info etc doing
            (char *)space - DW_RESERVE is totally bogus. */
        if (alloc_type == DW_DLA_STRING &&
            string_is_in_debug_section(dbg,space)) {
            /*  A string pointer may point into .debug_info or
                .debug_string etc.
                So must not be freed.  And strings have
                no need of a specialdestructor().
                Mostly a historical mistake here.
                Corrected in libdwarf March 14,2020. */
            return;
        }
    }
    /*  Otherwise it might be allocated string so it is ok
        do the (char *)space - DW_RESERVE  */

    /*  If it's a DW_DLA_STRING case and erroneous
        the following pointer operations might
        result in a coredump if the pointer
        is to the beginning of a string section.
        If not DW_DLA_STRING
        no correctly written caller could coredump
        here.  */
    malloc_addr = (char *)space - DW_RESERVE;
    r =(struct reserve_data_s *)malloc_addr;
    if(dbg != r->rd_dbg) {
        /*  Something is mixed up. */
#ifdef DEBUG
        printf("DEALLOC does nothing, dbg 0x%lx rd_dbg 0x%lx space 0x%lx line %d %s\n",
            (unsigned long)dbg,
            (unsigned long)r->rd_dbg,
            (unsigned long)space,
            __LINE__,__FILE__);
        fflush(stdout);
#endif /* DEBUG*/
        return;
    }
    if(alloc_type != r->rd_type) {
        /*  Something is mixed up. */
#ifdef DEBUG
        printf("DEALLOC does nothing, type 0x%lx rd_type 0x%lx space 0x%lx line %d %s\n",
            (unsigned long)alloc_type,
            (unsigned long)r->rd_type,
            (unsigned long)space,
            __LINE__,__FILE__);
        fflush(stdout);
#endif /* DEBUG*/
        return;
    }
    if (alloc_type == DW_DLA_ERROR) {
        Dwarf_Error ep = (Dwarf_Error)space;

        if (ep->er_static_alloc == DE_STATIC) {
            /*  This is special, malloc arena
                was exhausted or a NULL dbg
                was used for the error because the real
                dbg was unavailable.
                There is nothing to delete, really.
                Set er_errval to signal that the
                space was dealloc'd.
                Not dealing with destructor here. */
            _dwarf_failsafe_error.er_errval =
                DW_DLE_FAILSAFE_ERRVAL;
#ifdef DEBUG
            printf("DEALLOC does nothing, DE_STATIC line %d %s\n",
                __LINE__,__FILE__);
            fflush(stdout);
#endif /* DEBUG*/
            return;
        }
        if (ep->er_static_alloc == DE_MALLOC) {
            /*  This is special, we had no arena
                so just malloc'd a Dwarf_Error_s.
                Not dealing with destructor here. */
            free(space);
            return;
        }
        /* Was normal alloc, use normal dealloc. */
        /* DW_DLA_ERROR has a specialdestructor */
    }
    type = alloc_type;
#if DEBUG
    if(dbg != r->rd_dbg) {
        /*  Something is badly wrong. Better to leak than
            to crash. */
        return;
    }
#endif
#if DEBUG
    printf("libdwarfdetector DEALLOC ret 0x%lx type 0x%x size %lu line %d %s\n",(unsigned long)space,(unsigned)type,(unsigned long)r->rd_length,__LINE__,__FILE__);
#endif
    if (type >= ALLOC_AREA_INDEX_TABLE_MAX) {
        /* internal or user app error */
#ifdef DEBUG
        printf("DEALLOC does nothing, type too big %lu line %d %s\n",
            (unsigned long)type,
            __LINE__,__FILE__);
#endif /* DEBUG*/
        return;
    }
#ifdef HAVE_GLOBAL_ALLOC_SUMS
    global_de_alloc_tree_early_dealloc_count++;
    global_de_alloc_tree_early_dealloc_size += r->rd_length;
#endif /* HAVE_GLOBAL_ALLOC_SUMS */
    if (alloc_instance_basics[type].specialdestructor) {
        alloc_instance_basics[type].specialdestructor(space);
    }
    if (dbg->de_alloc_tree) {
        /*  The 'space' pointer we get points after the
            reserve space.  The key is 'space'
            and address to free
            is just a few bytes before 'space'. */
        void *key = space;

        dwarf_tdelete(key,&dbg->de_alloc_tree,
            simple_compare_function);
        /*  If dwarf_tdelete returns NULL it might mean
            a) tree is empty.
            b) If hashsearch, then a single chain might
                now be empty,
                so we do not know of a 'parent node'.
            c) We did not find that key, we did nothing.

            In any case, we simply don't worry about it.
            Not Supposed To Happen. */
    }
    r->rd_dbg  = (void *)0xfeadbeef;
    r->rd_length = 0;
    r->rd_type = 0;
    free(malloc_addr);
    return;
}

/*
    Allocates space for a Dwarf_Debug_s struct,
    since one does not exist.
*/
Dwarf_Debug
_dwarf_get_debug(void)
{
    Dwarf_Debug dbg;

    dbg = (Dwarf_Debug) malloc(sizeof(struct Dwarf_Debug_s));
    if (dbg == NULL) {
        return (NULL);
    }
    memset(dbg, 0, sizeof(struct Dwarf_Debug_s));
    /* Set up for a dwarf_tsearch hash table */

    /* Leaving initialization on so we can track
        DW_DLA_STRING even when global_de_alloc_tree_on
        is zero. */
    if (global_de_alloc_tree_on) {
        dwarf_initialize_search_hash(&dbg->de_alloc_tree,
            simple_value_hashfunc,0);
    }
    return (dbg);
}

/*
    This function prints out the statistics
    collected on allocation of memory chunks.
    No longer used.
*/
void
dwarf_print_memory_stats(UNUSEDARG Dwarf_Debug dbg)
{
}



/* In the 'rela' relocation case we might have malloc'd
   space to ensure it is read-write. In that case, free the space.  */
static void
rela_free(struct Dwarf_Section_s * sec)
{
    if (sec->dss_data_was_malloc) {
        free(sec->dss_data);
    }
    sec->dss_data = 0;
    sec->dss_data_was_malloc = 0;
}

static void
freecontextlist(Dwarf_Debug dbg, Dwarf_Debug_InfoTypes dis)
{
    Dwarf_CU_Context context = 0;
    Dwarf_CU_Context nextcontext = 0;
    for (context = dis->de_cu_context_list;
        context; context = nextcontext) {
        Dwarf_Hash_Table hash_table = context->cc_abbrev_hash_table;
        _dwarf_free_abbrev_hash_table_contents(dbg,hash_table);
        hash_table->tb_entries = 0;
        nextcontext = context->cc_next;
        context->cc_next = 0;
        /*  See also  local_dealloc_cu_context() in
            dwarf_die_deliv.c */
        dwarf_dealloc(dbg, hash_table, DW_DLA_HASH_TABLE);
        context->cc_abbrev_hash_table = 0;
        dwarf_dealloc(dbg, context, DW_DLA_CU_CONTEXT);
    }
    dis->de_cu_context_list = 0;
}

/*
    Used to free all space allocated for this Dwarf_Debug.
    The caller should assume that the Dwarf_Debug pointer
    itself is no longer valid upon return from this function.

    In case of difficulty, this function simply returns quietly.
*/
int
_dwarf_free_all_of_one_debug(Dwarf_Debug dbg)
{
    unsigned g = 0;

    if (dbg == NULL) {
        return (DW_DLV_ERROR);
    }
    /*  To do complete validation that we have no surprising
        missing or erroneous deallocs it is advisable to do
        the dwarf_deallocs here
        that are not things the user can otherwise request.
        Housecleaning.  */
    if (dbg->de_cu_hashindex_data) {
        dwarf_xu_header_free(dbg->de_cu_hashindex_data);
        dbg->de_cu_hashindex_data = 0;
    }
    if (dbg->de_tu_hashindex_data) {
        dwarf_xu_header_free(dbg->de_tu_hashindex_data);
        dbg->de_tu_hashindex_data = 0;
    }
    if( dbg->de_printf_callback_null_device_handle) {
        fclose(dbg->de_printf_callback_null_device_handle);
        dbg->de_printf_callback_null_device_handle = 0;
    }
    freecontextlist(dbg,&dbg->de_info_reading);
    freecontextlist(dbg,&dbg->de_types_reading);

    /* Housecleaning done. Now really free all the space. */
    rela_free(&dbg->de_debug_info);
    rela_free(&dbg->de_debug_types);
    rela_free(&dbg->de_debug_abbrev);
    rela_free(&dbg->de_debug_line);
    rela_free(&dbg->de_debug_line_str);
    rela_free(&dbg->de_debug_loc);
    rela_free(&dbg->de_debug_aranges);
    rela_free(&dbg->de_debug_macinfo);
    rela_free(&dbg->de_debug_macro);
    rela_free(&dbg->de_debug_names);
    rela_free(&dbg->de_debug_pubnames);
    rela_free(&dbg->de_debug_str);
    rela_free(&dbg->de_debug_sup);
    rela_free(&dbg->de_debug_frame);
    rela_free(&dbg->de_debug_frame_eh_gnu);
    rela_free(&dbg->de_debug_pubtypes);
    rela_free(&dbg->de_debug_funcnames);
    rela_free(&dbg->de_debug_typenames);
    rela_free(&dbg->de_debug_varnames);
    rela_free(&dbg->de_debug_weaknames);
    rela_free(&dbg->de_debug_ranges);
    rela_free(&dbg->de_debug_str_offsets);
    rela_free(&dbg->de_debug_addr);
    rela_free(&dbg->de_debug_gdbindex);
    rela_free(&dbg->de_debug_cu_index);
    rela_free(&dbg->de_debug_tu_index);
    dwarf_harmless_cleanout(&dbg->de_harmless_errors);

    _dwarf_dealloc_rnglists_context(dbg);
    _dwarf_dealloc_loclists_context(dbg);
    if (dbg->de_printf_callback.dp_buffer &&
        !dbg->de_printf_callback.dp_buffer_user_provided ) {
        free(dbg->de_printf_callback.dp_buffer);
    }

    _dwarf_destroy_group_map(dbg);
    /*  de_alloc_tree might be NULL if
        global_de_alloc_tree_on is zero. */
    if (dbg->de_alloc_tree) {
        dwarf_tdestroy(dbg->de_alloc_tree,tdestroy_free_node);
        dbg->de_alloc_tree = 0;
    }
    if (dbg->de_tied_data.td_tied_search) {
        dwarf_tdestroy(dbg->de_tied_data.td_tied_search,
            _dwarf_tied_destroy_free_node);
        dbg->de_tied_data.td_tied_search = 0;
    }
    free((void *)dbg->de_path);
    dbg->de_path = 0;
    for (g = 0; g < dbg->de_gnu_global_path_count; ++g) {
        free((char *)dbg->de_gnu_global_paths[g]);
        dbg->de_gnu_global_paths[g] = 0;
    }
    free((void*)dbg->de_gnu_global_paths);
    dbg->de_gnu_global_paths = 0;
    dbg->de_gnu_global_path_count = 0;
    memset(dbg, 0, sizeof(*dbg)); /* Prevent accidental use later. */
    free(dbg);
    return (DW_DLV_OK);
}
/*  A special case: we have no dbg, no alloc header etc.
    So create something out of thin air that we can recognize
    in dwarf_dealloc.
    Something with the prefix (prefix space hidden from caller).

    Only applies to DW_DLA_ERROR, and  making up an error record.
    The allocated space simply leaks.
*/
struct Dwarf_Error_s *
_dwarf_special_no_dbg_error_malloc(void)
{
    Dwarf_Error e = 0;
    Dwarf_Unsigned len = sizeof(struct Dwarf_Error_s);
    char *mem = (char *)malloc(len);

    if (mem == 0) {
        return 0;
    }
    memset(mem, 0, len);
    e = (Dwarf_Error)mem;
    e->er_static_alloc = DE_MALLOC;
    return e;
}
