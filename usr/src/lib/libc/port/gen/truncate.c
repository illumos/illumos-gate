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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * ftruncate() and truncate() set a file to a specified
 * length using fcntl(F_FREESP) system call. If the file
 * was previously longer than length, the bytes past the
 * length will no longer be accessible. If it was shorter,
 * bytes not written will be zero filled.
 */

#include <sys/feature_tests.h>

#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#pragma weak ftruncate64 = _ftruncate64
#pragma weak truncate64 = _truncate64
#define	_ftruncate	_ftruncate64
#define	_truncate	_truncate64
#else /* !_LP64 && _FILE_OFFSET_BITS == 64 */
#pragma weak ftruncate = _ftruncate
#pragma weak truncate = _truncate
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */

#include "synonyms.h"
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>

int
_ftruncate(int fildes, off_t len)
{
	struct flock lck;

	lck.l_whence = 0;	/* offset l_start from beginning of file */
	lck.l_start = len;
	lck.l_type = F_WRLCK;	/* setting a write lock */
	lck.l_len = (off_t)0;	/* until the end of the file address space */

	if (fcntl(fildes, F_FREESP, &lck) == -1) {
		return (-1);
	}
	return (0);
}

int
_truncate(const char *path, off_t len)
{

	int rval = 0;
	int cancel_state;
	int fd;

	/*
	 * truncate() is not a cancellation point,
	 * even though it calls open() and close().
	 */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	if ((fd = open(path, O_WRONLY)) == -1 || ftruncate(fd, len) == -1)
		rval = -1;
	if (fd >= 0)
		(void) close(fd);
	(void) pthread_setcancelstate(cancel_state, NULL);
	return (rval);
}
