/*
  Copyright (C) 2000,2004 Silicon Graphics, Inc.  All Rights Reserved.
  Portions Copyright 2002-2010 Sun Microsystems, Inc. All rights reserved.
  Portions Copyright 2011-2019. David Anderson.  All Rights Reserved.

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
#include "pro_incl.h"
#include <stddef.h>
#include "dwarf.h"
#include "libdwarf.h"
#include "pro_opaque.h"
#include "pro_alloc.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#ifdef HAVE_MALLOC_H
/* Useful include for some Windows compilers. */
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STDINT_H
#include <stdint.h> /* For uintptr_t */
#endif /* HAVE_STDINT_H */
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif /* HAVE_INTTYPES_H */
#include "dwarf_tsearch.h"

/*  When each block is allocated, there is a two-word structure
    allocated at the beginning so the block can go on a list.
    The address returned is the address *after* the two pointers
    at the start.  But this allows us to be given a pointer to
    a generic block, and go backwards to find the list-node.  Then
    we can remove this block from it's list without the need to search
    through a linked list in order to remove the node.  It also allows
    us to 'delete' a memory block without needing the dbg structure.
    We still need the dbg structure on allocation so that we know which
    linked list to add the block to.

    Only the allocation of the dbg structure itself cannot use
    _dwarf_p_get_alloc.
    That structure should be set up by hand, and the two list pointers
    should be initialized to point at the node itself.  That initializes
    the doubly linked list.  */

#define LIST_TO_BLOCK(lst) ((void*) (((char *)lst) + sizeof(memory_list_t)))
#define BLOCK_TO_LIST(blk) ((memory_list_t*) (((char*)blk) - sizeof(memory_list_t)))


/*
  dbg should be NULL only when allocating dbg itself.  In that
  case we initialize it to an empty circular doubly-linked list.
*/

Dwarf_Ptr
_dwarf_p_get_alloc(Dwarf_P_Debug dbg, Dwarf_Unsigned size)
{
    void *sp;
    memory_list_t *lp = NULL;
    memory_list_t *dbglp = NULL;
    memory_list_t *nextblock = NULL;

    /* alloc control struct and data block together for performance reasons */
    lp = (memory_list_t *) malloc(size + sizeof(memory_list_t));
    if (lp == NULL) {
        /* should throw an error */
        return NULL;
    }

    /* point to 'size' bytes just beyond lp struct */
    sp = LIST_TO_BLOCK(lp);
    memset(sp, 0, size);

    if (dbg == NULL) {
        lp->next = lp->prev = lp;
    } else {
        /* I always have to draw a picture to understand this part. */

        dbglp = BLOCK_TO_LIST(dbg);
        nextblock = dbglp->next;

        /* Insert between dbglp and nextblock */
        dbglp->next = lp;
        lp->prev = dbglp;
        lp->next = nextblock;
        nextblock->prev = lp;
    }

    return sp;
}

/*
  This routine is only here in case a caller of an older version of the
  library is calling this for some reason.
  This does nothing!
  No need to remove this block.  In theory the user might be
  depending on the fact that we used to just 'free' this.
  In theory they might also be
  passing a block that they got from libdwarf.  So we don't know if we
  should try to remove this block from our global list.  Safest just to
  do nothing at this point.

  !!!
  This function is deprecated!  Don't call it inside libdwarf or outside of it.
  Does nothing!
  !!!
*/

void
dwarf_p_dealloc(UNUSEDARG Dwarf_Small * ptr)
{
    return;
}

/*
  The dbg structure is not needed here anymore.
*/

void
_dwarf_p_dealloc(UNUSEDARG Dwarf_P_Debug dbg,
    Dwarf_Small * ptr) /* ARGSUSED */
{
    memory_list_t *lp;
    lp = BLOCK_TO_LIST(ptr);

    /*  Remove from a doubly linked, circular list.
        Read carefully, use a white board if necessary.
        If this is an empty list, the following statements are no-ops, and
        will write to the same memory location they read from.
        This should only happen when we deallocate the dbg structure itself.
    */
    if (lp == lp->next) {
        /*  The list has a single item, itself. */
        lp->prev = 0;
        lp->next = 0;
    } else if (lp->next == lp->prev) {
        /*  List had exactly two entries. Reduce it to one,
            cutting lp out. */
        memory_list_t * remaining = lp->next;
        remaining->next = remaining;
        remaining->prev = remaining;
    } else  {
        /*  Multi=entry. Just cut lp out. */
        lp->prev->next = lp->next;
        lp->next->prev = lp->prev;
        lp->prev = lp->next = 0;
    }
    free((void*)lp);
}


static void
_dwarf_str_hashtab_freenode(void * nodep)
{
    free(nodep);
}


/*
  This routine deallocates all the nodes on the dbg list,
  and then deallocates the dbg structure itself.
*/

void
_dwarf_p_dealloc_all(Dwarf_P_Debug dbg)
{
    memory_list_t *dbglp;
    memory_list_t *base_dbglp;

    if (dbg == NULL) {
        /* should throw an error */
        return;
    }

    base_dbglp = BLOCK_TO_LIST(dbg);
    dbglp = base_dbglp->next;

    while (dbglp != base_dbglp) {
        memory_list_t*next = dbglp->next;

        _dwarf_p_dealloc(dbg, LIST_TO_BLOCK(dbglp));
        dbglp = next;
    }
    dwarf_tdestroy(dbg->de_debug_str_hashtab,
        _dwarf_str_hashtab_freenode);
    dwarf_tdestroy(dbg->de_debug_line_str_hashtab,
        _dwarf_str_hashtab_freenode);
    free((void *)base_dbglp);
}
