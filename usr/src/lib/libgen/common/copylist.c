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

/*
 * copylist copies a file into a block of memory, replacing newlines
 * with null characters, and returns a pointer to the copy.
 */

#include <sys/types.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>

static char *
common_copylist(const char *filenm, off64_t size)
{
	FILE	*strm;
	int	c;
	char	*ptr, *p;

	if (size > SSIZE_MAX) {
		errno = EOVERFLOW;
		return (NULL);
	}

	/* get block of memory */
	if ((ptr = malloc(size)) == NULL) {
		return (NULL);
	}

	/* copy contents of file into memory block, replacing newlines */
	/* with null characters */
	if ((strm = fopen(filenm, "rF")) == NULL) {
		return (NULL);
	}
	for (p = ptr; p < ptr + size && (c = getc(strm)) != EOF; p++) {
		if (c == '\n')
			*p = '\0';
		else
			*p = (char)c;
	}
	(void) fclose(strm);

	return (ptr);
}


#ifndef _LP64
char *
copylist64(const char *filenm, off64_t *szptr)
{
	struct	stat64	stbuf;

	/* get size of file */
	if (stat64(filenm, &stbuf) == -1) {
		return (NULL);
	}
	*szptr = stbuf.st_size;

	return (common_copylist(filenm, stbuf.st_size));
}
#endif


char *
copylist(const char *filenm, off_t *szptr)
{
	struct	stat64	stbuf;

	/* get size of file */
	if (stat64(filenm, &stbuf) == -1) {
		return (NULL);
	}

	if (stbuf.st_size > LONG_MAX) {
		errno = EOVERFLOW;
		return (NULL);
	}

	*szptr = (off_t)stbuf.st_size;

	return (common_copylist(filenm, stbuf.st_size));
}
