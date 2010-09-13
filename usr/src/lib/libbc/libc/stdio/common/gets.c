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
/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
/*
 * This version reads directly from the buffer rather than looping on getc.
 * Ptr args aren't checked for NULL because the program would be a
 * catastrophic mess anyway.  Better to abort than just to return NULL.
 */
#include <stdio.h>
#include "stdiom.h"
#include <memory.h>

extern int _filbuf();

char *
gets(char *ptr)
{
	char *p, *ptr0 = ptr;
	int n;

	for ( ; ; ) {
		if (stdin->_cnt <= 0) { /* empty buffer */
			if (_filbuf(stdin) == EOF) {
				if (ptr0 == ptr)
					return (NULL);
				break; /* no more data */
			}
			stdin->_ptr--;
			stdin->_cnt++;
		}
		n = stdin->_cnt;
		if ((p = memccpy(ptr, (char *) stdin->_ptr, '\n', n)) != NULL)
			n = p - ptr;
		ptr += n;
		stdin->_cnt -= n;
		stdin->_ptr += n;
		_BUFSYNC(stdin);
		if (p != NULL) { /* found '\n' in buffer */
			ptr--; /* step back over '\n' */
			break;
		}
	}
	*ptr = '\0';
	return (ptr0);
}
