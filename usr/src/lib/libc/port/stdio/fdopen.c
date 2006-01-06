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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Unix routine to do an "fopen" on file descriptor
 * The mode has to be repeated because you can't query its
 * status
 */

#define	_LARGEFILE64_SOURCE 1

#pragma weak fdopen = _fdopen

#include "synonyms.h"
#include <mtlib.h>
#include "file64.h"
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"
#include <errno.h>
#include <fcntl.h>

FILE *
fdopen(int fd, const char *type) /* associate file desc. with stream */
{
	/* iop doesn't need locking since this function is creating it */
	FILE *iop;
	char plus;
	unsigned char flag;


	/* Sets EBADF for bad fds */
	if (fcntl(fd, F_GETFD) == -1)
		return (NULL);

#ifdef	_LP64
	if ((iop = _findiop()) == 0) {
		errno = ENOMEM;
		return (NULL);
	}
	iop->_file = fd;
#else
	if (fd > UCHAR_MAX) {
		errno = EMFILE;
		return (NULL);
	}
	if ((iop = _findiop()) == 0) {
		errno = ENOMEM;
		return (NULL);
	}
	iop->_file = (unsigned char)fd;
#endif	/*	_LP64	*/

	switch (type[0]) {
	default:
		iop->_flag = 0; /* release iop */
		errno = EINVAL;
		return (NULL);
	case 'r':
		flag = _IOREAD;
		break;
	case 'a':
		(void) lseek64(fd, (off64_t)0, SEEK_END);
		/*FALLTHROUGH*/
	case 'w':
		flag = _IOWRT;
		break;
	}
	if ((plus = type[1]) == 'b')	/* Unix ignores 'b' ANSI std */
		plus = type[2];
	if (plus == '+')
		flag = _IORW;
	iop->_flag = flag;

	return (iop);
}
