#ifndef stringmem_h
#define stringmem_h
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

typedef struct StringMem StringMem;

/*
 * Applications that dynamically allocate lots of small strings
 * run the risk of significantly fragmenting the heap. This module
 * aims to reduce this risk by allocating large arrays of small fixed
 * length strings, arranging them as a free-list and allowing
 * callers to allocate from the list. Strings that are too long
 * to be allocated from the free-list are allocated from the heap.
 * Since typical implementations of malloc() eat up a minimum of
 * 16 bytes per call to malloc() [because of alignment and space
 * management constraints] it makes sense to set the free-list
 * string size to 16 bytes. Note that unlike malloc() which typically
 * keeps 8 bytes per allocation for its own use, our allocator will
 * return all but one of the 16 bytes for use. One hidden byte of overhead
 * is reserved for flagging whether the string was allocated directly
 * from malloc or from the free-list.
 */

/*
 * Set the length of each free-list string. The longest string that
 * will be returned without calling malloc() will be one less than
 * this number.
 */
#define SM_STRLEN 16

/*
 * Create a string free-list container and the first block of its free-list.
 */
StringMem *_new_StringMem(unsigned blocking_factor);

/*
 * Delete a string free-list.
 */
StringMem *_del_StringMem(StringMem *sm, int force);

/*
 * Allocate an array of 'length' chars.
 */
char *_new_StringMemString(StringMem *sm, size_t size);

/*
 * Free a string that was previously returned by _new_StringMemString().
 */
char *_del_StringMemString(StringMem *sm, char *s);

#endif
