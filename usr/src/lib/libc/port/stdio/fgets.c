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
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <sys/types.h>
#include "stdiom.h"
#include "mse.h"

/* read size-max line from stream, including '\n' */
char *
fgets(char *buf, int size, FILE *iop)
{
	char *ptr = buf;
	int n;
	Uchar *bufend;
	char *p;
	rmutex_t *lk;

	FLOCKFILE(lk, iop);

	_SET_ORIENTATION_BYTE(iop);

	if (!(iop->_flag & (_IOREAD | _IORW))) {
		errno = EBADF;
		FUNLOCKFILE(lk);
		return (NULL);
	}

	if (iop->_base == NULL) {
		if ((bufend = _findbuf(iop)) == NULL) {
			FUNLOCKFILE(lk);
			return (NULL);
		}
	}
	else
		bufend = _bufend(iop);

	size--;		/* room for '\0' */
	while (size > 0) {
		/* empty buffer */
		if (iop->_cnt <= 0) {
			if (__filbuf(iop) != EOF) {
				iop->_ptr--;	/* put back the character */
				iop->_cnt++;
			} else if (ptr == buf) {  /* never read anything */
				FUNLOCKFILE(lk);
				return (NULL);
			} else
				break;		/* nothing left to read */
		}
		n = (int)(size < iop->_cnt ? size : iop->_cnt);
		if ((p = memccpy(ptr, (char *)iop->_ptr, '\n',
		    (size_t)n)) != NULL)
			n = (int)(p - ptr);
		ptr += n;
		iop->_cnt -= n;
		iop->_ptr += n;
		if (_needsync(iop, bufend))
			_bufsync(iop, bufend);
		if (p != NULL)
			break; /* newline found */
		size -= n;
	}
	FUNLOCKFILE(lk);
	*ptr = '\0';
	return (buf);
}
