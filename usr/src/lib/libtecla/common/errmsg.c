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
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include "errmsg.h"

/*
 * Encapsulate the error reporting buffer in an opaque object.
 */
struct ErrMsg {
  char msg[ERR_MSG_LEN+1];  /* An error message */
};

/*.......................................................................
 * Create a new error-message object.
 *
 * Output:
 *  return  ErrMsg *  The new object, or NULL on error.
 */
ErrMsg *_new_ErrMsg(void)
{
  ErrMsg *err;  /* The object to be returned */
/*
 * Allocate the container.
 */
  err = malloc(sizeof(ErrMsg));
  if(!err) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_ErrMsg().
 */
  err->msg[0] = '\0';
  return err;
}

/*.......................................................................
 * Delete an error-message object.
 *
 * Input:
 *  err     ErrMsg *  The object to be deleted.
 * Output:
 *  return  ErrMsg *  The deleted object (always NULL).
 */
ErrMsg *_del_ErrMsg(ErrMsg *err)
{
  if(err) {
    free(err);
  };
  return NULL;
}

/*.......................................................................
 * Record the concatenation of a list of string arguments in an error
 * message object. The last argument must be END_ERR_MSG to terminate
 * the argument list.
 *
 * Input:
 *  err      ErrMsg *   The error-message container.
 *  ...  const char *   Zero or more strings to be concatenated in buff[].
 *  ...  const char *   The last argument must always be END_ERR_MSG to
 *                      terminate the argument list.
 */
void _err_record_msg(ErrMsg *err, ...)
{
  va_list ap;         /* The variable argument list */
  const char *s;      /* The string being printed */
  size_t msglen = 0;  /* The total length of the message */
/*
 * Nowhere to record the result?
 */
  if(!err) {
    errno = EINVAL;
    return;
  };
/*
 * Concatenate the list of argument strings in err->msg[].
 */
  va_start(ap, err);
  while((s = va_arg(ap, const char *)) != END_ERR_MSG) {
/*
 * How much room is left in the output buffer (note that the output
 * buffer has ERR_MSG_LEN+1 elements).
 */
    int nleft = ERR_MSG_LEN - msglen;
/*
 * How long is the next string to be appended?
 */
    size_t slen = strlen(s);
/*
 * If there is any room left, append as much of the string
 * as will fit.
 */
    if(nleft > 0) {
      int nnew = slen < nleft ? slen : nleft;
      strncpy(err->msg + msglen, s, nnew);
      msglen += nnew;
    };
  };
  va_end(ap);
/*
 * Terminate the message.
 */
  err->msg[msglen] = '\0';
  return;
}

/*.......................................................................
 * Return a pointer to the error message buffer.
 *
 * Input:
 *  err     ErrMsg *  The container of the error message buffer.
 * Output:
 *  return    char *  The current error message, or NULL if err==NULL.
 */
char *_err_get_msg(ErrMsg *err)
{
  return err ? err->msg : NULL;
}

/*.......................................................................
 * Replace the current error message with an empty string.
 *
 * Input:
 *  err     ErrMsg *  The container of the error message buffer.
 */
void _err_clear_msg(ErrMsg *err)
{
  if(err)
    err->msg[0] = '\0';
}

