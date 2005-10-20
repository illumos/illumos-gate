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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*LINTLIBRARY*/
/*
 * This version writes directly to the buffer rather than looping on putc.
 * Ptr args aren't checked for NULL because the program would be a
 * catastrophic mess anyway.  Better to abort than just to return NULL.
 */
#include <stdio.h>
#include "stdiom.h"
#include <errno.h>
#include <memory.h>

static char	*memnulccpy(char *, char *, int, int);

int
fputs(char *ptr, FILE *iop)
{
	int ndone = 0, n;
	unsigned char *cptr, *bufend;
	char *p;
	char c;

	if (_WRTCHK(iop)) {
		iop->_flag |= _IOERR;
#ifdef POSIX
		errno = EBADF;
#endif	/* POSIX */
		return (EOF);
	}
	bufend = iop->_base + iop->_bufsiz;

	if ((iop->_flag & _IONBF) == 0)  {
		if (iop->_flag & _IOLBF) {
			for ( ; ; ptr += n) {
				while ((n = bufend - (cptr = iop->_ptr)) <= 0)  
					/* full buf */
					if (_xflsbuf(iop) == EOF)
						return(EOF);
				if ((p = memnulccpy((char *) cptr, ptr, '\n', n)) != NULL) {
					/*
					 * Copy terminated either because we
					 * saw a newline or we saw a NUL (end
					 * of string).
					 */
					c = *(p - 1);	/* last character moved */
					if (c == '\0')
						p--;	/* didn't write '\0' */
					n = p - (char *) cptr;
				}
				iop->_cnt -= n;
				iop->_ptr += n;
				_BUFSYNC(iop);
				ndone += n;
				if (p != NULL) {
					/*
					 * We found either a newline or a NUL.
					 * If we found a newline, flush the
					 * buffer.
					 * If we found a NUL, we're done.
					 */
					if (c == '\n') {
						if (_xflsbuf(iop) == EOF)
							return(EOF);
					} else {
						/* done */
						return(ndone);
					}
		       		}
			}
		} else {
			for ( ; ; ptr += n) {
				while ((n = bufend - (cptr = iop->_ptr)) <= 0)  
					/* full buf */
					if (_xflsbuf(iop) == EOF)
						return(EOF);
				if ((p = memccpy((char *) cptr, ptr, '\0', n)) != NULL)
					n = (p - (char *) cptr) - 1;
				iop->_cnt -= n;
				iop->_ptr += n;
				_BUFSYNC(iop);
				ndone += n;
				if (p != NULL)  { 
					/* done */
		       			return(ndone);
		       		}
			}
		}
	}  else  {
		/* write out to an unbuffered file */
		return (write(iop->_file, ptr, strlen(ptr)));
	}
}

/*
 * Copy s2 to s1, stopping if character c or a NUL is copied.
 * Copy no more than n bytes.
 * Return a pointer to the byte after character c or NUL in the copy,
 * or NULL if c or NUL is not found in the first n bytes.
 */
static char *
memnulccpy(char *s1, char *s2, int c, int n)
{
	int cmoved;

	while (--n >= 0) {
		cmoved = *s2++;
		if ((*s1++ = cmoved) == '\0' || cmoved == c)
			return (s1);
	}
	return (0);
}
