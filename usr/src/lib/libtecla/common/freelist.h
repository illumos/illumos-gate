#ifndef freelist_h
#define freelist_h

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

/*
 * This module provides a memory allocation scheme that helps to
 * prevent memory fragmentation by allocating large blocks of
 * fixed sized objects and forming them into a free-list for
 * subsequent allocations. The free-list is expanded as needed.
 */
typedef struct FreeList FreeList;

/*
 * Allocate a new free-list from blocks of 'blocking_factor' objects of size
 * node_size. The node_size argument should be determined by applying
 * the sizeof() operator to the object type that you intend to allocate from
 * the freelist.
 */
FreeList *_new_FreeList(size_t node_size, unsigned blocking_factor);

/*
 * If it is known that none of the nodes currently allocated from
 * a freelist are still in use, the following function can be called
 * to return all nodes to the freelist without the overhead of
 * having to call del_FreeListNode() for every allocated node. The
 * nodes of the freelist can then be reused by future callers to
 * new_FreeListNode().
 */
void _rst_FreeList(FreeList *fl);

/*
 * Delete a free-list.
 */
FreeList *_del_FreeList(FreeList *fl, int force);

/*
 * Determine the number of nodes that are currently in use.
 */
long _busy_FreeListNodes(FreeList *fl);

/*
 * Query the number of allocated nodes in the freelist which are
 * currently unused.
 */
long _idle_FreeListNodes(FreeList *fl);

/*
 * Allocate a new object from a free-list.
 */
void *_new_FreeListNode(FreeList *fl);

/*
 * Return an object to the free-list that it was allocated from.
 */
void *_del_FreeListNode(FreeList *fl, void *object);

#endif
