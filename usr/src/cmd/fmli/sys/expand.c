/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	<ctype.h>
#include	"wish.h"
#include	"moremacros.h"
#include	"terror.h"
#include	"sizes.h"
#include 	"sizes.h"

/*
 * Globals to maintain dynamic expansion buffer
 * (destination buffer for "variable expanded" text)
 */
static char *Destbuf;
static int  Bufsize;
static int  Bufcnt;

/*
 * These macros check that the expansion buffer is BIG enough
 * before text is copies into it.
 */
#define CHKbuf(p, q)		if (++Bufcnt >= Bufsize) { \
					growbuf(q, BUFSIZ); \
					p = Destbuf + Bufcnt - 1; \
				}

#define CHKnbuf(p, q, num)	if ((Bufcnt += num) >= Bufsize) { \
					growbuf(q, num); \
					p = Destbuf + Bufcnt - num; \
				}
static char *pexpand(char *buf, char *name, char eos);

/*
 * GROWBUF will allocate/grow Destbuf by BUFSIZ
 */
static void 
growbuf(buf, num)
char *buf;
int num;
{

	Bufsize += num;
	if (Destbuf == NULL) {
		if ((Destbuf = malloc(Bufsize)) == NULL)
			fatal(NOMEM, nil);
		strcpy(Destbuf, buf);
	}
 	else if ((Destbuf = realloc(Destbuf, Bufsize)) == NULL)
		fatal(NOMEM, nil);
}

/*
 * EXPAND will "expand" all environment variables in the
 * string pointed to by "src" and return a pointer to
 * the expanded text.
 */ 
char *
expand(src)
char *src;
{
	char	buf[BUFSIZ];
	char	*ret;

	/*
	 * Use a static 1K buffer by default ....
	 * pexpand() will create a dynamic buffer
	 * if necessary and set "Destbuf" to it.
	 */ 
	Destbuf = NULL;
	Bufsize = BUFSIZ;
	Bufcnt = 0;

	(void) pexpand(buf, src, '\0');
	if (Destbuf)		
		ret = Destbuf;		/* return malloc'd buffer */
	else
		ret = strsave(buf);	/* strsave text from static buffer */
	return(ret);
}

static char *
pexpand(char *buf, char *name, char eos)
{
    register char	delim;
    register char	*src;
    register char	*dst;
    register char	*file;
    char	fbuf[PATHSIZ];
    char	*anyenv();
    char	*getepenv();
    char	*savebuf;
    int	savesize;
    int	savecnt;

    dst = buf;
    src = name;
    while (*src && *src != eos) {
	if (*src == '\\') {
	    ++src;
	    CHKbuf(dst, buf);
	    *dst++ = *src++;
	}
	else if (*src == '$') {
	    register char	*start;

	    if ((delim = (*++src == '{') ? '}' : '\0'))
		start = ++src;
	    else
		start = src;
	    file = NULL;
	    if (*src == '(') {
		/*
		 * Save dynamic buffer before calling
		 * pexpand() recursively
		 */
		savebuf = Destbuf;
		savesize = Bufsize;
		savecnt = Bufcnt;

		/*
		 * Initialize globals
		 */
		Destbuf = NULL;
		Bufsize = PATHSIZ;
		Bufcnt = 0;

		src = pexpand(fbuf, ++src, ')');
		if (*src) {
		    start = ++src;
		    if (Destbuf)
			file = Destbuf;
		    else
			file = fbuf;
		}

		/*
		 * Restore previous values for 
		 * dynamic buffer and continue
		 * as usual ....
		 */
		Destbuf = savebuf;
		Bufsize = savesize;
		Bufcnt = savecnt;
	    }
	    if (isalpha(*src)) {
		register char	*p;
		register char	savechar;

		while (isalpha(*src) || isdigit(*src) || *src == '_')
		    src++;
		savechar = *src;
		*src = '\0';
		if ((p = (file ? anyenv(file, start) : getepenv(start))) == NULL) {
		    if (delim) {
			if ((*src = savechar) == ':' && *++src == '-')
			    while (*++src && *src != delim) {
				CHKbuf(dst, buf);
				*dst++ = *src;
			    }
		    }
		    else
			*src = savechar;
		}
		else {
		    *src = savechar;
		    CHKnbuf(dst, buf, (int)strlen(p)); /* EFT k16 */
		    strcpy(dst, p);
		    dst += strlen(p);
		    free(p);
		}
		if (delim)
		    while (*src && *src++ != delim)
			;
	    }
	}
	else {
	    CHKbuf(dst, buf);
	    *dst++ = *src++;
	}
    }
    CHKbuf(dst, buf);
    *dst = '\0';
    return src;
}
