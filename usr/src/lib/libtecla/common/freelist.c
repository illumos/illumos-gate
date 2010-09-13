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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "freelist.h"

typedef struct FreeListBlock FreeListBlock;
struct FreeListBlock {
  FreeListBlock *next;   /* The next block in the list */
  char *nodes;           /* The array of free-list nodes */
};

struct FreeList {
  size_t node_size;         /* The size of a free-list node */
  unsigned blocking_factor; /* The number of nodes per block */
  long nbusy;               /* The number of nodes that are in use */
  long ntotal;              /* The total number of nodes in the free list */
  FreeListBlock *block;     /* The head of the list of free-list blocks */
  void *free_list;          /* The free-list of nodes */
};

static FreeListBlock *_new_FreeListBlock(FreeList *fl);
static FreeListBlock *_del_FreeListBlock(FreeListBlock *fl);
static void _thread_FreeListBlock(FreeList *fl, FreeListBlock *block);

/*.......................................................................
 * Allocate a new free-list from blocks of 'blocking_factor' objects of size
 * node_size.
 *
 * Input:
 *  node_size         size_t    The size of the free-list nodes to be returned
 *                              by _new_FreeListNode(). Use sizeof() to
 *                              determine this.
 *  blocking_factor unsigned    The number of objects of size 'object_size'
 *                              to allocate per block.
 * Output:
 *  return          FreeList *  The new freelist, or NULL on error.
 */
FreeList *_new_FreeList(size_t node_size, unsigned blocking_factor)
{
  FreeList *fl;  /* The new free-list container */
/*
 * When a free-list node is on the free-list, it is used as a (void *)
 * link field. Roundup node_size to a mulitple of the size of a void
 * pointer. This, plus the fact that the array of nodes is obtained via
 * malloc, which returns memory suitably aligned for any object, will
 * ensure that the first sizeof(void *) bytes of each node will be
 * suitably aligned to use as a (void *) link pointer.
 */
  node_size = sizeof(void *) *
    ((node_size + sizeof(void *) - 1) / sizeof(void *));
/*
 * Enfore a minimum block size.
 */
  if(blocking_factor < 1)
    blocking_factor = 1;
/*
 * Allocate the container of the free list.
 */
  fl = (FreeList *) malloc(sizeof(FreeList));
  if(!fl) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to _del_FreeList().
 */
  fl->node_size = node_size;
  fl->blocking_factor = blocking_factor;
  fl->nbusy = 0;
  fl->ntotal = 0;
  fl->block = NULL;
  fl->free_list = NULL;
/*
 * Allocate the first block of memory.
 */
  fl->block = _new_FreeListBlock(fl);
  if(!fl->block) {
    errno = ENOMEM;
    return _del_FreeList(fl, 1);
  };
/*
 * Add the new list of nodes to the free-list.
 */
  fl->free_list = fl->block->nodes;
/*
 * Return the free-list for use.
 */
  return fl;
}

/*.......................................................................
 * Re-thread a freelist to reclaim all allocated nodes.
 * This function should not be called unless if it is known that none
 * of the currently allocated nodes are still being used.
 *
 * Input:
 *  fl          FreeList *  The free-list to be reset, or NULL.
 */
void _rst_FreeList(FreeList *fl)
{
  if(fl) {
    FreeListBlock *block;
/*
 * Re-thread the nodes of each block into individual free-lists.
 */
    for(block=fl->block; block; block=block->next)
      _thread_FreeListBlock(fl, block);
/*
 * Link all of the block freelists into one large freelist.
 */
    fl->free_list = NULL;
    for(block=fl->block; block; block=block->next) {
/*
 * Locate the last node of the current block.
 */
      char *last_node = block->nodes + fl->node_size *
	(fl->blocking_factor - 1);
/*
 * Make the link-field of the last node point to the first
 * node of the current freelist, then make the first node of the
 * new block the start of the freelist. 
 */
      *(void **)last_node = fl->free_list;
      fl->free_list = block->nodes;
    };
/*
 * All allocated nodes have now been returned to the freelist.
 */
    fl->nbusy = 0;
  };
}

/*.......................................................................
 * Delete a free-list.
 *
 * Input:
 *  fl          FreeList *  The free-list to be deleted, or NULL.
 *  force            int    If force==0 then _del_FreeList() will complain
 *                           and refuse to delete the free-list if any
 *                           of nodes have not been returned to the free-list.
 *                          If force!=0 then _del_FreeList() will not check
 *                           whether any nodes are still in use and will
 *                           always delete the list.
 * Output:
 *  return      FreeList *  Always NULL (even if the list couldn't be
 *                          deleted).
 */
FreeList *_del_FreeList(FreeList *fl, int force)
{
  if(fl) {
/*
 * Check whether any nodes are in use.
 */
    if(!force && _busy_FreeListNodes(fl) != 0) {
      errno = EBUSY;
      return NULL;
    };
/*
 * Delete the list blocks.
 */
    {
      FreeListBlock *next = fl->block;
      while(next) {
	FreeListBlock *block = next;
	next = block->next;
	block = _del_FreeListBlock(block);
      };
    };
    fl->block = NULL;
    fl->free_list = NULL;
/*
 * Discard the container.
 */
    free(fl);
  };
  return NULL;
}

/*.......................................................................
 * Allocate a new object from a free-list.
 *
 * Input:
 *  fl        FreeList *  The free-list to return an object from.
 * Output:
 *  return        void *  A new object of the size that was specified via
 *                        the node_size argument of _new_FreeList() when
 *                        the free-list was created, or NULL if there
 *                        is insufficient memory, or 'fl' is NULL.
 */
void *_new_FreeListNode(FreeList *fl)
{
  void *node;  /* The node to be returned */
/*
 * Check arguments.
 */
  if(!fl)
    return NULL;
/*
 * If the free-list has been exhausted extend it by allocating
 * another block of nodes.
 */
  if(!fl->free_list) {
    FreeListBlock *block = _new_FreeListBlock(fl);
    if(!block)
      return NULL;
/*
 * Prepend the new block to the list of free-list blocks.
 */
    block->next = fl->block;
    fl->block = block;
/*
 * Add the new list of nodes to the free-list.
 */
    fl->free_list = fl->block->nodes;
  };
/*
 * Remove and return a node from the front of the free list.
 */
  node = fl->free_list;
  fl->free_list = *(void **)node;
/*
 * Record the loss of a node from the free-list.
 */
  fl->nbusy++;
/*
 * Return the node.
 */
  return node;
}

/*.......................................................................
 * Return an object to the free-list that it was allocated from.
 *
 * Input:
 *  fl        FreeList *  The free-list from which the object was taken.
 *  object        void *  The node to be returned.
 * Output:
 *  return        void *  Always NULL.
 */
void *_del_FreeListNode(FreeList *fl, void *object)
{
/*
 * Check arguments.
 */
  if(!fl)
    return NULL;
/*
 * Return the node to the head of the free list.
 */
  if(object) {
    *(void **)object = fl->free_list;
    fl->free_list = object;
/*
 * Record the return of the node to the free-list.
 */
    fl->nbusy--;
  };
  return NULL;
}

/*.......................................................................
 * Return a count of the number of nodes that are currently allocated.
 *
 * Input:
 *  fl      FreeList *  The list to count wrt, or NULL.
 * Output:
 *  return      long    The number of nodes (or 0 if fl==NULL).
 */
long _busy_FreeListNodes(FreeList *fl)
{
  return fl ? fl->nbusy : 0;
}

/*.......................................................................
 * Query the number of allocated nodes in the freelist which are
 * currently unused.
 *
 * Input:
 *  fl      FreeList *  The list to count wrt, or NULL.
 * Output:
 *  return      long    The number of unused nodes (or 0 if fl==NULL).
 */
long _idle_FreeListNodes(FreeList *fl)
{
  return fl ? (fl->ntotal - fl->nbusy) : 0;
}

/*.......................................................................
 * Allocate a new list of free-list nodes. On return the nodes will
 * be linked together as a list starting with the node at the lowest
 * address and ending with a NULL next pointer.
 *
 * Input:
 *  fl          FreeList *  The free-list to allocate the list for.
 * Output:
 *  return FreeListBlock *  The new linked block of free-list nodes,
 *                          or NULL on error.
 */
static FreeListBlock *_new_FreeListBlock(FreeList *fl)
{
  FreeListBlock *block;  /* The new block to be returned */
/*
 * Allocate the container.
 */
  block = (FreeListBlock *) malloc(sizeof(FreeListBlock));
  if(!block)
    return NULL;
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to _del_FreeListBlock().
 */
  block->next = NULL;
  block->nodes = NULL;
/*
 * Allocate the block of nodes.
 */
  block->nodes = (char *) malloc(fl->node_size * fl->blocking_factor);
  if(!block->nodes)
    return _del_FreeListBlock(block);
/*
 * Initialize the block as a linked list of FreeListNode's.
 */
  _thread_FreeListBlock(fl, block);
/*
 * Update the record of the number of nodes in the freelist.
 */
  fl->ntotal += fl->blocking_factor;
  return block;
}

/*.......................................................................
 * Link each node of a freelist block to the node that follows it.
 *
 * Input:
 *  fl         FreeList *   The freelist that contains the block.
 *  block FreeListBlock *   The block to be threaded.
 */
static void _thread_FreeListBlock(FreeList *fl, FreeListBlock *block)
{
  char *mem = block->nodes;
  int i;
  for(i=0; i<fl->blocking_factor - 1; i++, mem += fl->node_size)
    *(void **)mem = mem + fl->node_size;  /* Link to the next node */
  *(void **)mem = NULL;                   /* Terminate the list */
}

/*.......................................................................
 * Delete a free-list block.
 *
 * Input:
 *  fl      FreeListBlock *  The block to be deleted, or NULL.
 * Output:
 *  return  FreeListBlock *  Always NULL.
 */
static FreeListBlock *_del_FreeListBlock(FreeListBlock *fl)
{
  if(fl) {
    fl->next = NULL;
    if(fl->nodes)
      free(fl->nodes);
    fl->nodes = NULL;
    free(fl);
  };
  return NULL;
}
