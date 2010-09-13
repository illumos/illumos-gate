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

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Putws transforms process codes in wchar_t array pointed to by
 * "ptr" into a byte string, and writes the string followed
 * by a new-line character to stdout.
 */

#include "lint.h"
#include "file64.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <limits.h>
#include "stdiom.h"
#include "libc.h"

int
putws(const wchar_t *ptr)
{
	wchar_t *ptr0 = (wchar_t *)ptr;
	ptrdiff_t diff;
	rmutex_t	*lk;

	FLOCKFILE(lk, stdout);
	for (; *ptr; ptr++) {		/* putwc till NULL */
		if (fputwc(*ptr, stdout) == EOF) {
			FUNLOCKFILE(lk);
			return (EOF);
		}
	}
	(void) fputwc('\n', stdout); /* append a new line */
	FUNLOCKFILE(lk);

	if (fflush(stdout))  /* flush line */
		return (EOF);
	diff = ptr - ptr0;
	if (diff <= INT_MAX)
		return ((int)diff);
	else
		return (EOF);
}
