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
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "ioutil.h"

static int _io_pad_line(GlWriteFn *write_fn, void *data, int c, int n);

/*.......................................................................
 * Display a left-justified string over multiple terminal lines,
 * taking account of the specified width of the terminal. Optional
 * indentation and an option prefix string can be specified to be
 * displayed at the start of each new terminal line used, and if
 * needed, a single paragraph can be broken across multiple calls.
 * Note that literal newlines in the input string can be used to force
 * a newline at any point, and that in order to allow individual
 * paragraphs to be written using multiple calls to this function,
 * unless an explicit newline character is specified at the end of the
 * string, a newline will not be started at the end of the last word
 * in the string. Note that when a new line is started between two
 * words that are separated by spaces, those spaces are not output,
 * whereas when a new line is started because a newline character was
 * found in the string, only the spaces before the newline character
 * are discarded.
 *
 * Input:
 *  write_fn  GlWriteFn *  The callback function to use to write the
 *                         output.
 *  data           void *  A pointer to arbitrary data to be passed to
 *                         write_fn() whenever it is called.
 *  fp             FILE *  The stdio stream to write to.
 *  indentation     int    The number of fill characters to use to
 *                        indent the start of each new terminal line.
 *  prefix   const char *  An optional prefix string to write after the
 *                         indentation margin at the start of each new
 *                         terminal line. You can specify NULL if no
 *                         prefix is required.
 *  suffix   const char *  An optional suffix string to draw at the end
 *                         of the terminal line. The line will be padded
 *                         where necessary to ensure that the suffix ends
 *                         in the last column of the terminal line. If
 *                         no suffix is desired, specify NULL.
 *  fill_char       int    The padding character to use when indenting
 *                         and filling up to the suffix.
 *  term_width      int    The width of the terminal being written to.
 *  start           int    The number of characters already written to
 *                         the start of the current terminal line. This
 *                         is primarily used to allow individual
 *                         paragraphs to be written over multiple calls
 *                         to this function, but can also be used to
 *                         allow you to start the first line of a
 *                         paragraph with a different prefix or
 *                         indentation than those specified above.
 *  string   const char *  The string to be written.
 * Output:
 *  return          int    On error -1 is returned. Otherwise the
 *                         return value is the terminal column index at
 *                         which the cursor was left after writing the
 *                         final word in the string. Successful return
 *                         values can thus be passed verbatim to the
 *                         'start' arguments of subsequent calls to
 *                         _io_display_text() to allow the printing of a
 *                         paragraph to be broken across multiple calls
 *                         to _io_display_text().
 */
int _io_display_text(GlWriteFn *write_fn, void *data, int indentation,
		     const char *prefix, const char *suffix, int fill_char,
		     int term_width, int start, const char *string)
{
  int ndone;        /* The number of characters written from string[] */
  int nnew;         /* The number of characters to be displayed next */
  int was_space;    /* True if the previous character was a space or tab */
  int last = start; /* The column number of the last character written */
  int prefix_len;   /* The length of the optional line prefix string */
  int suffix_len;   /* The length of the optional line prefix string */
  int margin_width; /* The total number of columns used by the indentation */
                    /*  margin and the prefix string. */
  int i;
/*
 * Check the arguments?
 */
  if(!string || !write_fn) {
    errno = EINVAL;
    return -1;
  };
/*
 * Enforce sensible values on the arguments.
 */
  if(term_width < 0)
    term_width = 0;
  if(indentation > term_width)
    indentation = term_width;
  else if(indentation < 0)
    indentation = 0;
  if(start > term_width)
    start = term_width;
  else if(start < 0)
    start = 0;
/*
 * Get the length of the prefix string.
 */
  prefix_len = prefix ? strlen(prefix) : 0;
/*
 * Get the length of the suffix string.
 */
  suffix_len = suffix ? strlen(suffix) : 0;
/*
 * How many characters are devoted to indenting and prefixing each line?
 */
  margin_width = indentation + prefix_len;
/*
 * Write as many terminal lines as are needed to display the whole string.
 */
  for(ndone=0; string[ndone]; start=0) {
    last = start;
/*
 * Write spaces from the current position in the terminal line to the
 * width of the requested indentation margin.
 */
    if(indentation > 0 && last < indentation) {
      if(_io_pad_line(write_fn, data, fill_char, indentation - last))
	return -1;
      last = indentation;
    };
/*
 * If a prefix string has been specified, display it unless we have
 * passed where it should end in the terminal output line.
 */
    if(prefix_len > 0 && last < margin_width) {
      int pstart = last - indentation;
      int plen = prefix_len - pstart;
      if(write_fn(data, prefix+pstart, plen) != plen)
	return -1;
      last = margin_width;
    };
/*
 * Locate the end of the last complete word in the string before
 * (term_width - start) characters have been seen. To handle the case
 * where a single word is wider than the available space after the
 * indentation and prefix margins, always make sure that at least one
 * word is printed after the margin, regardless of whether it won't
 * fit on the line. The two exceptions to this rule are if an embedded
 * newline is found in the string or the end of the string is reached
 * before any word has been seen.
 */
    nnew = 0;
    was_space = 0;
    for(i=ndone; string[i] && (last+i-ndone < term_width - suffix_len ||
			   (nnew==0 && last==margin_width)); i++) {
      if(string[i] == '\n') {
	if(!was_space)
	  nnew = i-ndone;
	break;
      } else if(isspace((int) string[i])) {
	if(!was_space) {
	  nnew = i-ndone+1;
	  was_space = 1;
	};
      } else {
	was_space = 0;
      };
    };
/*
 * Does the end of the string delimit the last word that will fit on the
 * output line?
 */
    if(nnew==0 && string[i] == '\0')
      nnew = i-ndone;
/*
 * Write the new line.
 */
    if(write_fn(data, string+ndone, nnew) != nnew)
      return -1;
    ndone += nnew;
    last += nnew;
/*
 * Start a newline unless we have reached the end of the input string.
 * In the latter case, in order to give the caller the chance to
 * concatenate multiple calls to _io_display_text(), omit the newline,
 * leaving it up to the caller to write this.
 */
    if(string[ndone] != '\0') {
/*
 * If a suffix has been provided, pad out the end of the line with spaces
 * such that the suffix will end in the right-most terminal column.
 */
      if(suffix_len > 0) {
	int npad = term_width - suffix_len - last;
	if(npad > 0 && _io_pad_line(write_fn, data, fill_char, npad))
	  return -1;
	last += npad;
	if(write_fn(data, suffix, suffix_len) != suffix_len)
	  return -1;
	last += suffix_len;
      };
/*
 * Start a new line.
 */
      if(write_fn(data, "\n",  1) != 1)
	return -1;
/*
 * Skip any spaces and tabs that follow the last word that was written.
 */
      while(string[ndone] && isspace((int)string[ndone]) &&
	    string[ndone] != '\n')
	ndone++;
/*
 * If the terminating character was a literal newline character,
 * skip it in the input string, since we just wrote it.
 */
      if(string[ndone] == '\n')
	ndone++;
      last = 0;
    };
  };
/*
 * Return the column number of the last character printed.
 */
  return last;
}

/*.......................................................................
 * Write a given number of spaces to the specified stdio output string.
 *
 * Input:
 *  write_fn  GlWriteFn *  The callback function to use to write the
 *                         output.
 *  data           void *  A pointer to arbitrary data to be passed to
 *                         write_fn() whenever it is called.
 *  c               int    The padding character.
 *  n               int    The number of spaces to be written.
 * Output:
 *  return          int    0 - OK.
 *                         1 - Error.
 */
static int _io_pad_line(GlWriteFn *write_fn, void *data, int c, int n)
{
  enum {FILL_SIZE=20};
  char fill[FILL_SIZE+1];
/*
 * Fill the buffer with the specified padding character.
 */
  memset(fill, c, FILL_SIZE);
  fill[FILL_SIZE] = '\0';
/*
 * Write the spaces using the above literal string of spaces as
 * many times as needed to output the requested number of spaces.
 */
  while(n > 0) {
    int nnew = n <= FILL_SIZE ? n : FILL_SIZE;
    if(write_fn(data, fill, nnew) != nnew)
      return 1;
    n -= nnew;
  };
  return 0;
}

/*.......................................................................
 * The following is an output callback function which uses fwrite()
 * to write to the stdio stream specified via its callback data argument.
 *
 * Input:
 *  data     void *  The stdio stream to write to, specified via a
 *                   (FILE *) pointer cast to (void *).
 *  s  const char *  The string to be written.
 *  n         int    The length of the prefix of s[] to attempt to
 *                   write.
 * Output:
 *  return    int    The number of characters written from s[]. This
 *                   should normally be a number in the range 0 to n.
 *                   To signal that an I/O error occurred, return -1.
 */
GL_WRITE_FN(_io_write_stdio)
{
  int ndone;   /* The total number of characters written */
  int nnew;    /* The number of characters written in the latest write */
/*
 * The callback data is the stdio stream to write to.
 */
  FILE *fp = (FILE *) data;
/*
 * Because of signals we may need to do more than one write to output
 * the whole string.
 */
  for(ndone=0; ndone<n; ndone += nnew) {
    int nmore = n - ndone;
    nnew = fwrite(s, sizeof(char), nmore, fp);
    if(nnew < nmore) {
      if(errno == EINTR)
	clearerr(fp);
      else
	return ferror(fp) ? -1 : ndone + nnew;
    };
  };
  return ndone;
}

