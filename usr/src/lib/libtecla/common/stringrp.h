#ifndef stringrp_h
#define stringrp_h
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
 * StringGroup objects provide memory for modules that need to
 * allocate lots of small strings without needing to free any of them
 * individually, but rather is happy to free them all at the same
 * time. Taking advantage of these properties, StringGroup objects
 * avoid the heap fragmentation that tends to occur when lots of small
 * strings are allocated directly from the heap and later free'd. They
 * do this by allocating a list of large character arrays in each of
 * which multiple strings are stored. Thus instead of allocating lots
 * of small strings, a few large character arrays are allocated. When
 * the strings are free'd on mass, this list of character arrays is
 * maintained, ready for subsequent use in recording another set of
 * strings.
 */
typedef struct StringGroup StringGroup;

/*
 * The following constructor allocates a string-allocation object.
 * The segment_size argument specifies how long each string segment
 * array should be. This should be at least 10 times the length of
 * the average string to be recorded in the string group, and
 * sets the length of the longest string that can be stored.
 */
StringGroup *_new_StringGroup(int segment_size);

/*
 * Delete all of the strings that are currently stored by a specified
 * StringGroup object.
 */
void _clr_StringGroup(StringGroup *sg);

/*
 * Make a copy of the specified string, returning a pointer to
 * the copy, or NULL if there was insufficient memory. If the
 * remove_escapes argument is non-zero, backslashes that escape
 * other characters will be removed.
 */
char *_sg_store_string(StringGroup *sg, const char *string, int remove_escapes);

/*
 * Allocate memory for a string of a given length.
 */
char *_sg_alloc_string(StringGroup *sg, int length);

/*
 * Delete a StringGroup object (and all of the strings that it
 * contains).
 */
StringGroup *_del_StringGroup(StringGroup *sg);

#endif
