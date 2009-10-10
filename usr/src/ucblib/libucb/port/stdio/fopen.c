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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include "file64.h"
#include <stdio.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include "stdiom.h"

/* Final argument to _endopen depends on build environment */
#define	ALWAYS_LARGE_OPEN	1
#define	LARGE_OPEN	(_FILE_OFFSET_BITS == 64)

static FILE *
_endopen(const char *file, const char *mode, FILE *iop, int largefile)
{
	int	plus, oflag, fd;

	if (iop == NULL || file == NULL || file[0] == '\0')
		return (NULL);
	plus = (mode[1] == '+');
	switch (mode[0]) {
	case 'w':
		oflag = (plus ? O_RDWR : O_WRONLY) | O_TRUNC | O_CREAT;
		break;
	case 'a':
		oflag = (plus ? O_RDWR : O_WRONLY) | O_CREAT;
		break;
	case 'r':
		oflag = plus ? O_RDWR : O_RDONLY;
		break;
	default:
		return (NULL);
	}

	if (largefile) {
		fd = open64(file, oflag, 0666);	/* mapped to open() for V9 */
	} else {
		fd = open(file, oflag, 0666);
	}
	if (fd < 0)
		return (NULL);
	iop->_cnt = 0;
#ifdef _LP64
	iop->_file = fd;
#else
	if (fd <= _FILE_FD_MAX) {
		SET_FILE(iop, fd);
	} else if (_file_set(iop, fd, mode) != 0) {
		/* errno set in _file_set() */
		(void) close(fd);
		return (NULL);
	}
#endif
	iop->_flag = plus ? _IORW : (mode[0] == 'r') ? _IOREAD : _IOWRT;
	if (mode[0] == 'a')   {
		if ((lseek64(fd, 0L, SEEK_END)) < 0)  {
			(void) close(fd);
			return (NULL);
		}
	}
	iop->_base = iop->_ptr = NULL;
	/*
	 * Sys5 does not support _bufsiz
	 *
	 * iop->_bufsiz = 0;
	 */
	return (iop);
}

FILE *
fopen(const char *file, const char *mode)
{
	FILE	*iop;
	FILE	*rc;

	iop = _findiop();
	rc = _endopen(file, mode, iop, LARGE_OPEN);
	if (rc == NULL && iop != NULL)
		iop->_flag = 0;	/* release iop */
	return (rc);
}

/*
 * For _LP64, all fopen() calls are 64-bit calls, i.e., open64() system call.
 * There should not be fopen64() calls.
 * Similar for freopen64().
 */
#if !defined(_LP64)
FILE *
fopen64(const char *file, const char *mode)
{
	FILE	*iop;
	FILE	*rc;

	iop = _findiop();
	rc = _endopen(file, mode, iop, ALWAYS_LARGE_OPEN);
	if (rc == NULL && iop != NULL)
		iop->_flag = 0;	/* release iop */
	return (rc);
}
#endif

FILE *
freopen(const char *file, const char *mode, FILE *iop)
{
	(void) fclose(iop); /* doesn't matter if this fails */
	return (_endopen(file, mode, iop, LARGE_OPEN));
}

#if !defined(_LP64)
FILE *
freopen64(const char *file, const char *mode, FILE *iop)
{
	(void) fclose(iop); /* doesn't matter if this fails */
	return (_endopen(file, mode, iop, ALWAYS_LARGE_OPEN));
}
#endif
