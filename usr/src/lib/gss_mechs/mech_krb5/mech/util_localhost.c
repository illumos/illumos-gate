/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * $Id: util_localhost.c 7797 1996-04-12 00:40:24Z marc $
 */

/* This file could be OS specific */

#include <sys/param.h>

#include "gssapiP_generic.h"
#include <strings.h> /* SUNW15resync */
#include <unistd.h>  /* SUNW15resync */

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

char *g_local_host_name()
{
     char buf[MAXHOSTNAMELEN+1], *ptr;

     if (gethostname(buf, sizeof(buf)) < 0)
	  return 0;

     buf[sizeof(buf)-1] = '\0';

     if (! (ptr = xmalloc(strlen(buf) + 1)))
	  return 0;

     return strcpy(ptr, buf);
}
