#ifndef ioutil_h
#define ioutil_h

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

/*.......................................................................
 * Callback functions of the following type can be registered to write
 * to a terminal, when the default blocking writes to a local terminal
 * aren't appropriate. In particular, if you don't want gl_get_line()
 * to block, then this function should return before writing the
 * specified number of characters if doing otherwise would involve
 * waiting.
 *
 * Input:
 *  data     void *  The anonymous data pointer that was registered with
 *                   this callback function.
 *  s  const char *  The string to be written. Beware that this string
 *                   may not have a terminating '\0' character.
 *  n         int    The length of the prefix of s[] to attempt to
 *                   write.
 * Output:
 *  return    int    The number of characters written from s[]. This
 *                   should normally be a number in the range 0 to n.
 *                   To signal that an I/O error occurred, return -1.
 */
#define GL_WRITE_FN(fn) int (fn)(void *data, const char *s, int n)
typedef GL_WRITE_FN(GlWriteFn);

/*
 * The following output callback function requires a (FILE *) callback
 * data argument, and writes to this stream using the fwrite stdio
 * function.
 */
GL_WRITE_FN(_io_write_stdio);

/*
 * Left justify text within the bounds of the terminal adding optional
 * indentation, prefixes and suffixes to each line if requested.
 */
int _io_display_text(GlWriteFn *write_fn, void *data, int indentation,
		     const char *prefix, const char *suffix, int fill_char,
		     int term_width, int start, const char *string);

#endif
