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

/* Copyright (c) 2013 OmniTI Computer Consulting, Inc. All rights reserved. */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 *
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the regents of the University of
 * California.
 */

#include <sys/feature_tests.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#define	mkstemp		mkstemp64
#define	mkstemps	mkstemps64
#define	mkostemp	mkostemp64
#define	mkostemps	mkostemps64
#define	libc_mkstemps	libc_mkstemps64		/* prefer unique statics */
#pragma weak _mkstemp64 = mkstemp64
#else
#pragma weak _mkstemp = mkstemp
#endif

#include "lint.h"
#include <sys/fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

extern char *libc_mktemps(char *, int);

static int
libc_mkstemps(char *as, int slen, int flags)
{
	int	fd;
	int	len;
	char	*tstr, *str, *mkret;

	if (as == NULL || *as == NULL)
		return (-1);

	len = (int)strlen(as);
	tstr = alloca(len + 1);
	(void) strcpy(tstr, as);

	if (slen < 0 || slen >= len)
		return (-1);

	str = tstr + (len - 1 - slen);

	/*
	 * The following for() loop is doing work.  mktemp() will generate
	 * a different name each time through the loop.  So if the first
	 * name is used then keep trying until you find a free filename.
	 */

	for (;;) {
		if (*str == 'X') { /* If no trailing X's don't call mktemp. */
			mkret = libc_mktemps(as, slen);
			if (*mkret == '\0') {
				return (-1);
			}
		}
#if _FILE_OFFSET_BITS == 64
		if ((fd = open64(as, O_CREAT|O_EXCL|O_RDWR|flags,
		    0600)) != -1) {
			return (fd);
		}
#else
		if ((fd = open(as, O_CREAT|O_EXCL|O_RDWR|flags,
		    0600)) != -1) {
			return (fd);
		}
#endif  /* _FILE_OFFSET_BITS == 64 */

		/*
		 * If the error condition is other than EEXIST or if the
		 * file exists and there are no X's in the string
		 * return -1.
		 */

		if ((errno != EEXIST) || (*str != 'X')) {
			return (-1);
		}
		(void) strcpy(as, tstr);
	}
}

int
mkstemp(char *as)
{
	return (libc_mkstemps(as, 0, 0));
}

int
mkstemps(char *as, int slen)
{
	return (libc_mkstemps(as, slen, 0));
}

int
mkostemp(char *as, int flags)
{
	return (libc_mkstemps(as, 0, flags));
}

int
mkostemps(char *as, int slen, int flags)
{
	return (libc_mkstemps(as, slen, flags));
}
