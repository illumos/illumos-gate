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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <stdio.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <unistd.h>
#include <limits.h>
#include <malloc.h>
#include <sys/types.h>
#include "stdiom.h"

#define	LINESZ	128	/* initial guess for a NULL *lineptr */

ssize_t
getdelim(char **_RESTRICT_KYWD lineptr, size_t *_RESTRICT_KYWD n,
    int delimiter, FILE *_RESTRICT_KYWD iop)
{
	rmutex_t *lk;
	char *ptr;
	size_t size;
	int c;
	size_t cnt;

	if (lineptr == NULL || n == NULL ||
	    delimiter < 0 || delimiter > UCHAR_MAX) {
		errno = EINVAL;
		return (-1);
	}

	if (*lineptr == NULL || *n < LINESZ) {	/* initial allocation */
		if ((*lineptr = realloc(*lineptr, LINESZ)) == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		*n = LINESZ;
	}
	ptr = *lineptr;
	size = *n;
	cnt = 0;

	FLOCKFILE(lk, iop);

	_SET_ORIENTATION_BYTE(iop);

	do {
		c = (--iop->_cnt < 0) ? __filbuf(iop) : *iop->_ptr++;
		if (c == EOF)
			break;
		*ptr++ = c;
		if (++cnt == size) {	/* must reallocate */
			if ((ptr = realloc(*lineptr, 2 * size)) == NULL) {
				FUNLOCKFILE(lk);
				ptr = *lineptr + size - 1;
				*ptr = '\0';
				errno = ENOMEM;
				return (-1);
			}
			*lineptr = ptr;
			ptr += size;
			*n = size = 2 * size;
		}
	} while (c != delimiter);

	*ptr = '\0';

	FUNLOCKFILE(lk);
	if (cnt > SSIZE_MAX) {
		errno = EOVERFLOW;
		return (-1);
	}
	return (cnt ? cnt : -1);
}

ssize_t
getline(char **_RESTRICT_KYWD lineptr, size_t *_RESTRICT_KYWD n,
    FILE *_RESTRICT_KYWD iop)
{
	return (getdelim(lineptr, n, '\n', iop));
}
