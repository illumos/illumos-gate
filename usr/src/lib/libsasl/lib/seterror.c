/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* seterror.c - sasl_seterror split out because glue libraries
 *              can't pass varargs lists
 * Rob Siemborski
 * Tim Martin
 * split from common.c by Rolf Braun
 * $Id: seterror.c,v 1.7 2003/02/13 19:55:55 rjs3 Exp $
 */

/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#ifdef HAVE_SYSLOG
#include <syslog.h>
#endif
#include <stdarg.h>
#include <ctype.h>

#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>
#include "saslint.h"

#ifdef WIN32
/* need to handle the fact that errno has been defined as a function
   in a dll, not an extern int */
# ifdef errno
#  undef errno
# endif /* errno */
#endif /* WIN32 */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _SUN_SDK_
#include "plugin_common.h"
#include <wchar.h>
#endif /* _SUN_SDK_ */

/* this is apparently no longer a user function */
static int _sasl_seterror_usererr(int saslerr)
{
    /* Hide the difference in a username failure and a password failure */
    if (saslerr == SASL_NOUSER)
	return SASL_BADAUTH;

    /* otherwise return the error given; no transform necessary */
    return saslerr;
}

/* set the error string which will be returned by sasl_errdetail() using  
 *  syslog()-style formatting (e.g. printf-style with %m as the string form
 *  of an errno error)
 * 
 *  primarily for use by server callbacks such as the sasl_authorize_t
 *  callback and internally to plug-ins
 *
 * This will also trigger a call to the SASL logging callback (if any)
 * with a level of SASL_LOG_FAIL unless the SASL_NOLOG flag is set.
 *
 * Messages should be sensitive to the current language setting.  If there
 * is no SASL_CB_LANGUAGE callback messages MUST be US-ASCII otherwise UTF-8
 * is used and use of RFC 2482 for mixed-language text is encouraged.
 * 
 * if conn is NULL, function does nothing
 */
void sasl_seterror(sasl_conn_t *conn,
		   unsigned flags,
		   const char *fmt, ...) 
{
  size_t outlen=0; /* current length of output buffer */
  int pos=0; /* current position in format string */
  int formatlen;
  int result;
  sasl_log_t *log_cb;
  void *log_ctx;
  int ival;
  char *cval;
  va_list ap; /* varargs thing */
  char **error_buf;
  size_t *error_buf_len;
#ifdef _SUN_SDK_
  _sasl_global_context_t *gctx;
#endif /* _SUN_SDK_ */
#ifdef _INTEGRATED_SOLARIS_
  sasl_getsimple_t *simple_cb;
  void *simple_context;
  const char *lang = NULL;
  int ret;
  const sasl_utils_t *utils;
  int char_len;
  char *utf8_buf;
  const char *orig_fmt = fmt;
  int is_client;
#endif /* _INTEGRATED_SOLARIS_ */

  if(!conn) {
#ifndef SASL_OSX_CFMGLUE
      if(!(flags & SASL_NOLOG)) {
	  /* See if we have a logging callback... */
	  result = _sasl_getcallback(NULL, SASL_CB_LOG, &log_cb, &log_ctx);
	  if (result == SASL_OK && ! log_cb)
	      result = SASL_FAIL;
	  if (result != SASL_OK)
	      return;
	  
	  log_cb(log_ctx, SASL_LOG_FAIL,
		 "No sasl_conn_t passed to sasl_seterror");
      }  
#endif /* SASL_OSX_CFMGLUE */
      return;
  } else if(!fmt) return;    

#ifdef _SUN_SDK_
  gctx = conn->gctx;
#endif /* _SUN_SDK_ */

#ifdef _INTEGRATED_SOLARIS_
  if (conn->type == SASL_CONN_SERVER) {
    utils = ((sasl_server_conn_t *)conn)->sparams->utils;
    is_client = 0;
  } else if (conn->type == SASL_CONN_CLIENT) {
    utils = ((sasl_client_conn_t *)conn)->cparams->utils;
    is_client = 1;
  } else
    utils = NULL;

  if (utils != NULL) {
    ret = utils->getcallback(conn, SASL_CB_LANGUAGE, &simple_cb,
	&simple_context);

    if (ret == SASL_OK && simple_cb)
	(void) simple_cb(simple_context, SASL_CB_LANGUAGE, &lang, NULL);

    if (use_locale(lang, is_client))
	fmt = dgettext(TEXT_DOMAIN, fmt);
  }
#endif /* _INTEGRATED_SOLARIS_ */

/* we need to use a back end function to get the buffer because the
   cfm glue can't be rooting around in the internal structs */
  _sasl_get_errorbuf(conn, &error_buf, &error_buf_len);

  formatlen = strlen(fmt);

  va_start(ap, fmt); /* start varargs */

  while(pos<formatlen)
  {
    if (fmt[pos]!='%') /* regular character */
    {
#ifdef _INTEGRATED_SOLARIS_
      char_len =  mbrlen(fmt + pos, formatlen - pos, NULL);
      result = _buf_alloc(error_buf, error_buf_len, outlen + char_len);
      if (result != SASL_OK)
	return;
      while (char_len-- > 0) {
	(*error_buf)[outlen]=fmt[pos];
	outlen++;
	pos++;
      }
#else
      result = _buf_alloc(error_buf, error_buf_len, outlen+1);
      if (result != SASL_OK)
	return;
      (*error_buf)[outlen]=fmt[pos];
      outlen++;
      pos++;
#endif /* _INTEGRATED_SOLARIS_ */
    } else { /* formating thing */
      int done=0;
      char frmt[10];
      int frmtpos=1;
      char tempbuf[21];
      frmt[0]='%';
      pos++;

      while (done==0)
      {
	switch(fmt[pos])
	  {
	  case 's': /* need to handle this */
	    cval = va_arg(ap, char *); /* get the next arg */
	    result = _sasl_add_string(error_buf, error_buf_len,
				      &outlen, cval);
	      
	    if (result != SASL_OK) /* add the string */
	      return;

	    done=1;
	    break;

	  case '%': /* double % output the '%' character */
	    result = _buf_alloc(error_buf, error_buf_len, outlen+1);
	    if (result != SASL_OK)
	      return;
	    (*error_buf)[outlen]='%';
	    outlen++;
	    done=1;
	    break;

	  case 'm': /* insert the errno string */
	    result = _sasl_add_string(error_buf, error_buf_len,
				      &outlen,
				      strerror(va_arg(ap, int)));
	    if (result != SASL_OK)
	      return;
	    done=1;
	    break;

	  case 'z': /* insert the sasl error string */
#ifdef _INTEGRATED_SOLARIS_
	    result = _sasl_add_string(error_buf, error_buf_len,	&outlen,
			 (char *)sasl_errstring(_sasl_seterror_usererr(
					        va_arg(ap, int)), lang, NULL));
#else
	    result = _sasl_add_string(error_buf, error_buf_len,	&outlen,
			 (char *)sasl_errstring(_sasl_seterror_usererr(
					        va_arg(ap, int)),NULL,NULL));
#endif /* _INTEGRATED_SOLARIS_ */
	    if (result != SASL_OK)
	      return;
	    done=1;
	    break;

	  case 'c':
#ifndef _SUN_SDK_
	    frmt[frmtpos++]=fmt[pos];
	    frmt[frmtpos]=0;
#endif /* _SUN_SDK_ */
	    tempbuf[0] = (char) va_arg(ap, int); /* get the next arg */
	    tempbuf[1]='\0';
	    
	    /* now add the character */
	    result = _sasl_add_string(error_buf, error_buf_len,
				      &outlen, tempbuf);
	    if (result != SASL_OK)
	      return;
	    done=1;
	    break;

	  case 'd':
	  case 'i':
	    frmt[frmtpos++]=fmt[pos];
	    frmt[frmtpos]=0;
	    ival = va_arg(ap, int); /* get the next arg */

	    snprintf(tempbuf,20,frmt,ival); /* have snprintf do the work */
	    /* now add the string */
	    result = _sasl_add_string(error_buf, error_buf_len,
				      &outlen, tempbuf);
	    if (result != SASL_OK)
	      return;
	    done=1;

	    break;
	  default: 
	    frmt[frmtpos++]=fmt[pos]; /* add to the formating */
	    frmt[frmtpos]=0;	    
#ifdef _SUN_SDK_
	    if (frmtpos > sizeof (frmt) - 2) 
#else
	    if (frmtpos>9) 
#endif	/* _SUN_SDK_ */
	      done=1;
	  }
	pos++;
	if (pos>formatlen)
	  done=1;
      }

    }
  }

  (*error_buf)[outlen]='\0'; /* put 0 at end */

  va_end(ap);  

#ifdef _INTEGRATED_SOLARIS_
  if (orig_fmt != fmt) {
    utf8_buf = local_to_utf(utils, *error_buf);
    if (utf8_buf != NULL) {
      outlen = strlen(utf8_buf);
      result = SASL_OK;
      if (outlen >= *error_buf_len)
      result = _buf_alloc(error_buf, error_buf_len, outlen+1);
      if (result != SASL_OK) {
	utils->free(utf8_buf);
	return;
      }
      strcpy(*error_buf, utf8_buf);
      utils->free(utf8_buf);
    }
  }
#endif /* _INTEGRATED_SOLARIS_ */

#ifndef SASL_OSX_CFMGLUE
  if(!(flags & SASL_NOLOG)) {
      /* See if we have a logging callback... */
      result = _sasl_getcallback(conn, SASL_CB_LOG, &log_cb, &log_ctx);
      if (result == SASL_OK && ! log_cb)
	  result = SASL_FAIL;
      if (result != SASL_OK)
	  return;
      
      result = log_cb(log_ctx, SASL_LOG_FAIL, conn->error_buf);
  }
#endif /* SASL_OSX_CFMGLUE */
}
