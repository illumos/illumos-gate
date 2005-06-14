#ifndef cplfile_h
#define cplfile_h

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

typedef struct CompleteFile CompleteFile;

/*
 * Create a file-completion resource object.
 */
CompleteFile *_new_CompleteFile(void);
/*
 * Delete a file-completion resource object.
 */
CompleteFile *_del_CompleteFile(CompleteFile *cf);

/*.......................................................................
 * Complete the string between path[0] and path[len-1] as a pathname,
 * leaving the last component uncompleted if it is potentially ambiguous,
 * and returning an array of possible completions. Note that the returned
 * container belongs to the 'cf' object and its contents will change on
 * subsequent calls to this function.
 *
 * Input:
 *  cpl   WordCompletion *  The object in which to record the completions.
 *  cf      CompleteFile *  The filename-completion resource object.
 *  line      const char *  The string containing the incomplete filename.
 *  word_start       int    The index of the first character in line[]
 *                          of the incomplete filename.
 *  word_end         int    The index of the character in line[] that
 *                          follows the last character of the incomplete
 *                          filename.
 *  escaped          int    If true, backslashes in path[] are
 *                          interpreted as escaping the characters
 *                          that follow them, and any spaces, tabs,
 *                          backslashes, or wildcard characters in the
 *                          returned suffixes will be similarly be escaped.
 *                          If false, backslashes will be interpreted as
 *                          literal parts of the file name, and no
 *                          backslashes will be added to the returned
 *                          suffixes.
 *  check_fn  CplCheckFn *  If not zero, this argument specifies a
 *                          function to call to ask whether a given
 *                          file should be included in the list
 *                          of completions.
 *  check_data      void *  Anonymous data to be passed to check_fn().
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error. A description of the error can be
 *                                     acquired by calling cf_last_error(cf).
 */
int _cf_complete_file(WordCompletion *cpl, CompleteFile *cf,
		     const char *line, int word_start, int word_end,
		     int escaped, CplCheckFn *check_fn, void *check_data);

/*.......................................................................
 * Return a description of the error that occurred on the last call to
 * cf_complete_file().
 *
 * Input:
 *  cf    CompleteFile *  The path-completion resource object.
 * Output:
 *  return        char *  The description of the last error.
 */
const char *_cf_last_error(CompleteFile *cf);

#endif
