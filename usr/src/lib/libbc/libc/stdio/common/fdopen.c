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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.4 */

/*LINTLIBRARY*/
/*
 * Unix routine to do an "fopen" on file descriptor
 * The mode has to be repeated because you can't query its
 * status
 */

#include <stdio.h>
#include <sys/errno.h>

extern int  errno;
extern long lseek();
extern FILE *_findiop();

FILE *
fdopen(fd, mode)
int	fd;
register char *mode;
{
	static int nofile = -1;
	register FILE *iop;

	if(nofile < 0)
		nofile = getdtablesize();

	if(fd < 0 || fd >= nofile) {
		errno = EINVAL;
		return(NULL);
	}

	if((iop = _findiop()) == NULL)
		return(NULL);

	iop->_cnt = 0;
	iop->_file = fd;
	iop->_base = iop->_ptr = NULL;
	iop->_bufsiz = 0;
	switch(*mode) {

		case 'r':
			iop->_flag = _IOREAD;
			break;
		case 'a':
			(void) lseek(fd, 0L, 2);
			/* No break */
		case 'w':
			iop->_flag = _IOWRT;
			break;
		default:
			errno = EINVAL;
			return(NULL);
	}

	if(mode[1] == '+')
		iop->_flag = _IORW;

	return(iop);
}
