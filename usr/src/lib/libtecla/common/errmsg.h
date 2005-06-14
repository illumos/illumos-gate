#ifndef errmsg_h
#define errmsg_h

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
 * Set the longest expected length of an error message (excluding its
 * '\0' terminator. Since any message over a nominal terminal width of
 * 80 characters is going to look a mess, it makes no sense to support
 * huge lengths. Note that many uses of strings declared with this
 * macro assume that it will be at least 81, so don't reduce it below
 * this limit.
 */
#define ERR_MSG_LEN 128

/*
 * Provide an opaque typedef to the error-message object.
 */
typedef struct ErrMsg ErrMsg;

/*
 * The following token is used to terminate the argument lists of calls
 * to _err_record_msg().
 */
#define END_ERR_MSG ((const char *)0)

/*
 * Allocate a new error-message buffer.
 */
ErrMsg *_new_ErrMsg(void);

/*
 * Delete an error message buffer.
 */
ErrMsg *_del_ErrMsg(ErrMsg *err);

/*
 * Concatenate a list of string arguments into the specified buffer, buff[],
 * which has an allocated size of buffdim characters.
 * The last argument must be END_ERR_MSG to terminate the argument list.
 */
void _err_record_msg(ErrMsg *err, ...);

/*
 * Replace the current error message with an empty string.
 */
void _err_clear_msg(ErrMsg *err);

/*
 * Return a pointer to the error message buffer. This is
 * a '\0' terminated character array containing ERR_MSG_LEN+1
 * elements.
 */
char *_err_get_msg(ErrMsg *err);

#endif
