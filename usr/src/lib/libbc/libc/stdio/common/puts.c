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
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 3.3 */

/*LINTLIBRARY*/
/*
 * This version writes directly to the buffer rather than looping on putc.
 * Ptr args aren't checked for NULL because the program would be a
 * catastrophic mess anyway.  Better to abort than just to return NULL.
 */
#include <stdio.h>
#include "stdiom.h"

extern char *memccpy();

int
puts(ptr)
char *ptr;
{
	char *p;
	register int ndone = 0, n;
	register unsigned char *cptr, *bufend;

	if (_WRTCHK(stdout))
		return (EOF);

	bufend = stdout->_base + stdout->_bufsiz;

	for ( ; ; ptr += n) {
		while ((n = bufend - (cptr = stdout->_ptr)) <= 0) /* full buf */
			if (_xflsbuf(stdout) == EOF)
				return(EOF);
		if ((p = memccpy((char *) cptr, ptr, '\0', n)) != NULL)
			n = p - (char *) cptr;
		stdout->_cnt -= n;
		stdout->_ptr += n;
		_BUFSYNC(stdout);
		ndone += n;
		if (p != NULL) {
			stdout->_ptr[-1] = '\n'; /* overwrite '\0' with '\n' */
			if (stdout->_flag & (_IONBF | _IOLBF)) /* flush line */
				if (_xflsbuf(stdout) == EOF)
					return(EOF);
			return(ndone);
		}
	}
}
