/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004 by Martin C. Shepherd.
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "strngmem.h"
#include "freelist.h"

struct StringMem {
  unsigned long nmalloc;  /* The number of strings allocated with malloc */
  FreeList *fl;           /* The free-list */
};

/*.......................................................................
 * Create a string free-list container and the first block of its free-list.
 *
 * Input:
 *  blocking_factor   int    The blocking_factor argument specifies how
 *                           many strings of length SM_STRLEN
 *                           bytes (see stringmem.h) are allocated in each
 *                           free-list block.
 *                           For example if blocking_factor=64 and
 *                           SM_STRLEN=16, then each new
 *                           free-list block will take 1K of memory.
 * Output:
 *  return      StringMem *  The new free-list container, or NULL on
 *                           error.
 */
StringMem *_new_StringMem(unsigned blocking_factor)
{
  StringMem *sm;    /* The container to be returned. */
/*
 * Check arguments.
 */
  if(blocking_factor < 1) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Allocate the container.
 */
  sm = (StringMem *) malloc(sizeof(StringMem));
  if(!sm) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize
 * the container at least up to the point at which it can safely
 * be passed to _del_StringMem().
 */
  sm->nmalloc = 0;
  sm->fl = NULL;
/*
 * Allocate the free-list.
 */
  sm->fl = _new_FreeList(SM_STRLEN, blocking_factor);
  if(!sm->fl)
    return _del_StringMem(sm, 1);
/*
 * Return the free-list container.
 */
  return sm;
}

/*.......................................................................
 * Delete a string free-list.
 *
 * Input:
 *  sm       StringMem *  The string free-list to be deleted, or NULL.
 *  force          int    If force==0 then _del_StringMem() will complain
 *                         and refuse to delete the free-list if any
 *                         of nodes have not been returned to the free-list.
 *                        If force!=0 then _del_StringMem() will not check
 *                         whether any nodes are still in use and will
 *                         always delete the list.
 * Output:
 *  return   StringMem *  Always NULL (even if the list couldn't be
 *                        deleted).
 */
StringMem *_del_StringMem(StringMem *sm, int force)
{
  if(sm) {
/*
 * Check whether any strings have not been returned to the free-list.
 */
    if(!force && (sm->nmalloc > 0 || _busy_FreeListNodes(sm->fl) > 0)) {
      errno = EBUSY;
      return NULL;
    };
/*
 * Delete the free-list.
 */
    sm->fl = _del_FreeList(sm->fl, force);
/*
 * Delete the container.
 */
    free(sm);
  };
  return NULL;
}

/*.......................................................................
 * Allocate an array of 'length' chars.
 *
 * Input:
 *  sm      StringMem *  The string free-list to allocate from.
 *  length     size_t    The length of the new string (including '\0').
 * Output:
 *  return       char *  The new string or NULL on error.
 */
char *_new_StringMemString(StringMem *sm, size_t length)
{
  char *string;   /* The string to be returned */
  int was_malloc; /* True if malloc was used to allocate the string */
/*
 * Check arguments.
 */
  if(!sm)
    return NULL;
  if(length < 1)
    length = 1;
/*
 * Allocate the new node from the free list if possible.
 */
  if(length < SM_STRLEN) {
    string = (char *)_new_FreeListNode(sm->fl);
    if(!string)
      return NULL;
    was_malloc = 0;
  } else {
    string = (char *) malloc(length+1); /* Leave room for the flag byte */
    if(!string)
      return NULL;
/*
 * Count malloc allocations.
 */
    was_malloc = 1;
    sm->nmalloc++;
  };
/*
 * Use the first byte of the string to record whether the string was
 * allocated with malloc or from the free-list. Then return the rest
 * of the string for use by the user.
 */
  string[0] = (char) was_malloc;
  return string + 1;
}

/*.......................................................................
 * Free a string that was previously returned by _new_StringMemString().
 *
 * Input:
 *  sm      StringMem *  The free-list from which the string was originally
 *                       allocated.
 *  s            char *  The string to be returned to the free-list, or NULL.
 * Output:
 *  return       char *  Always NULL.
 */
char *_del_StringMemString(StringMem *sm, char *s)
{
  int was_malloc;  /* True if the string originally came from malloc() */
/*
 * Is there anything to be deleted?
 */
  if(s && sm) {
/*
 * Retrieve the true string pointer. This is one less than the one
 * returned by _new_StringMemString() because the first byte of the
 * allocated memory is reserved by _new_StringMemString as a flag byte
 * to say whether the memory was allocated from the free-list or directly
 * from malloc().
 */
    s--;
/*
 * Get the origination flag.
 */
    was_malloc = s[0];
    if(was_malloc) {
      free(s);
      s = NULL;
      sm->nmalloc--;
    } else {
      s = (char *) _del_FreeListNode(sm->fl, s);
    };
  };
  return NULL;
}
