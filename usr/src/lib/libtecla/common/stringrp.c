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

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "freelist.h"
#include "stringrp.h"

/*
 * StringSegment objects store lots of small strings in larger
 * character arrays. Since the total length of all of the strings can't
 * be known in advance, an extensible list of large character arrays,
 * called string-segments are used.
 */
typedef struct StringSegment StringSegment;
struct StringSegment {
  StringSegment *next; /* A pointer to the next segment in the list */
  char *block;         /* An array of characters to be shared between strings */
  int unused;          /* The amount of unused space at the end of block[] */
};

/*
 * StringGroup is typedef'd in stringrp.h.
 */
struct StringGroup {
  FreeList *node_mem;  /* The StringSegment free-list */
  int block_size;      /* The dimension of each character array block */
  StringSegment *head; /* The list of character arrays */
};

/*
 * Specify how many StringSegment's to allocate at a time.
 */
#define STR_SEG_BLK 20

/*.......................................................................
 * Create a new StringGroup object.
 *
 * Input:
 *  segment_size    int    The length of each of the large character
 *                         arrays in which multiple strings will be
 *                         stored. This sets the length of longest
 *                         string that can be stored, and for efficiency
 *                         should be at least 10 times as large as
 *                         the average string that will be stored.
 * Output:
 *  return  StringGroup *  The new object, or NULL on error.
 */
StringGroup *_new_StringGroup(int segment_size)
{
  StringGroup *sg;    /* The object to be returned */
/*
 * Check the arguments.
 */
  if(segment_size < 1) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Allocate the container.
 */
  sg = (StringGroup *) malloc(sizeof(StringGroup));
  if(!sg) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to _del_StringGroup().
 */
  sg->node_mem = NULL;
  sg->head = NULL;
  sg->block_size = segment_size;
/*
 * Allocate the free list that is used to allocate list nodes.
 */
  sg->node_mem = _new_FreeList(sizeof(StringSegment), STR_SEG_BLK);
  if(!sg->node_mem)
    return _del_StringGroup(sg);
  return sg;
}

/*.......................................................................
 * Delete a StringGroup object.
 *
 * Input:
 *  sg     StringGroup *  The object to be deleted.
 * Output:
 *  return StringGroup *  The deleted object (always NULL).
 */
StringGroup *_del_StringGroup(StringGroup *sg)
{
  if(sg) {
    StringSegment *node;
/*
 * Delete the character arrays.
 */
    for(node=sg->head; node; node=node->next) {
      if(node->block)
	free(node->block);
      node->block = NULL;
    };
/*
 * Delete the list nodes that contained the string segments.
 */
    sg->node_mem = _del_FreeList(sg->node_mem, 1);
    sg->head = NULL; /* Already deleted by deleting sg->node_mem */
/*
 * Delete the container.
 */
    free(sg);
  };
  return NULL;
}

/*.......................................................................
 * Make a copy of a string in the specified string group, and return
 * a pointer to the copy. 
 *
 * Input:
 *  sg      StringGroup *  The group to store the string in.
 *  string   const char *  The string to be recorded.
 *  remove_escapes  int    If true, omit backslashes which escape
 *                         other characters when making the copy.
 * Output:
 *  return         char *  The pointer to the copy of the string,
 *                         or NULL if there was insufficient memory.
 */
char *_sg_store_string(StringGroup *sg, const char *string, int remove_escapes)
{
  char *copy;           /* The recorded copy of string[] */
  size_t len;
/*
 * Check the arguments.
 */
  if(!sg || !string)
    return NULL;
/*
 * Get memory for the string.
 */
  len = strlen(string);
  copy = _sg_alloc_string(sg, len);
  if(copy) {
/*
 * If needed, remove backslash escapes while copying the input string
 * into the cache string.
 */
    if(remove_escapes) {
      int escaped = 0;             /* True if the next character should be */
                                   /*  escaped. */
      const char *src = string;    /* A pointer into the input string */
      char *dst = copy;            /* A pointer into the cached copy of the */
                                   /*  string. */
      while(*src) {
	if(!escaped && *src == '\\') {
	  escaped = 1;
	  src++;
	} else {
	  escaped = 0;
	  *dst++ = *src++;
	};
      };
      *dst = '\0';
/*
 * If escapes have already been removed, copy the input string directly
 * into the cache.
 */
    } else {
      strlcpy(copy, string, len + 1);
    };
  };
/*
 * Return a pointer to the copy of the string (or NULL if the allocation
 * failed).
 */
  return copy;
}

/*.......................................................................
 * Allocate memory for a string of a given length.
 *
 * Input:
 *  sg      StringGroup *  The group to store the string in.
 *  length          int    The required length of the string.
 * Output:
 *  return         char *  The pointer to the copy of the string,
 *                         or NULL if there was insufficient memory.
 */
char *_sg_alloc_string(StringGroup *sg, int length)
{
  StringSegment *node;  /* A node of the list of string segments */
  char *copy;           /* The allocated string */
/*
 * If the string is longer than block_size, then we can't record it.
 */
  if(length > sg->block_size || length < 0)
    return NULL;
/*
 * See if there is room to record the string in one of the existing
 * string segments. Do this by advancing the node pointer until we find
 * a node with length+1 bytes unused, or we get to the end of the list.
 */
  for(node=sg->head; node && node->unused <= length; node=node->next)
    ;
/*
 * If there wasn't room, allocate a new string segment.
 */
  if(!node) {
    node = (StringSegment *) _new_FreeListNode(sg->node_mem);
    if(!node)
      return NULL;
/*
 * Initialize the segment.
 */
    node->next = NULL;
    node->block = NULL;
    node->unused = sg->block_size;
/*
 * Attempt to allocate the string segment character array.
 */
    node->block = (char *) malloc(sg->block_size);
    if(!node->block)
      return NULL;
/*
 * Prepend the node to the list.
 */
    node->next = sg->head;
    sg->head = node;
  };
/*
 * Get memory for the string.
 */
  copy = node->block + sg->block_size - node->unused;
  node->unused -= length + 1;
/*
 * Return a pointer to the string memory.
 */
  return copy;
}

/*.......................................................................
 * Delete all of the strings that are currently stored by a specified
 * StringGroup object.
 *
 * Input:
 *  sg   StringGroup *   The group of strings to clear.
 */
void _clr_StringGroup(StringGroup *sg)
{
  StringSegment *node;   /* A node in the list of string segments */
/*
 * Mark all of the string segments as unoccupied.
 */
  for(node=sg->head; node; node=node->next)
    node->unused = sg->block_size;
  return;
}
