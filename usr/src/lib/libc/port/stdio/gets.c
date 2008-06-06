/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <memory.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include "stdiom.h"
#include "mse.h"

/* read a single line from stdin, replace the '\n' with '\0' */
char *
gets(char *buf)
{
	char *ptr = buf;
	ssize_t n;
	char *p;
	Uchar *bufend;
	rmutex_t *lk;

	FLOCKFILE(lk, stdin);

	_SET_ORIENTATION_BYTE(stdin);

	if (!(stdin->_flag & (_IOREAD | _IORW))) {
		errno = EBADF;
		FUNLOCKFILE(lk);
		return (0);
	}

	if (stdin->_base == NULL) {
		if ((bufend = _findbuf(stdin)) == 0) {
			FUNLOCKFILE(lk);
			return (0);
		}
	}
	else
		bufend = _bufend(stdin);

	for (;;)	/* until get a '\n' */
	{
		if (stdin->_cnt <= 0)	/* empty buffer */
		{
			if (__filbuf(stdin) != EOF) {
				stdin->_ptr--;	/* put back the character */
				stdin->_cnt++;
			} else if (ptr == buf) {  /* never read anything */
				FUNLOCKFILE(lk);
				return (0);
			} else
				break;		/* nothing left to read */
		}
		n = stdin->_cnt;
		if ((p = (char *)memccpy(ptr, (char *)stdin->_ptr, '\n',
		    (size_t)n)) != 0)
			n = p - ptr;
		ptr += n;
		stdin->_cnt -= n;
		stdin->_ptr += n;
		if (_needsync(stdin, bufend))
			_bufsync(stdin, bufend);
		if (p != 0) /* found a '\n' */
		{
			ptr--;	/* step back over the '\n' */
			break;
		}
	}
	*ptr = '\0';
	FUNLOCKFILE(lk);
	return (buf);
}
