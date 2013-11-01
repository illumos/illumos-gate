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

/* Copyright (c) 2013 OmniTI Computer Consulting, Inc. All rights reserved. */

/*
 *	This routine is a special case, in that it is aware of
 *	both small and large file interfaces. It must be built
 *	in the small compilation environment.
 */

#include "lint.h"
#include "file64.h"
#include <mtlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"
#include <errno.h>

/*
 * open UNIX file name, associate with iop
 */

FILE *
_endopen(const char *name, const char *type, FILE *iop, int largefile)
{
	int oflag, fd, fflag, eflag, plusflag, xflag;
	const char *echr;

	if (iop == NULL)
		return (NULL);
	switch (type[0]) {
	default:
		errno = EINVAL;
		return (NULL);
	case 'r':
		oflag = O_RDONLY;
		fflag = _IOREAD;
		break;
	case 'w':
		oflag = O_WRONLY | O_TRUNC | O_CREAT;
		fflag = _IOWRT;
		break;
	case 'a':
		oflag = O_WRONLY | O_APPEND | O_CREAT;
		fflag = _IOWRT;
		break;
	}

	plusflag = 0;
	eflag = 0;
	xflag = 0;
	for (echr = type + 1; *echr != '\0'; echr++) {
		switch (*echr) {
		/* UNIX ignores 'b' and treats text and binary the same */
		default:
			break;
		case '+':
			plusflag = 1;
			break;
		case 'e':
			eflag = 1;
			break;
		case 'x':
			xflag = 1;
			break;
		}
	}
	if (eflag) {
		/* Subsequent to a mode flag, 'e' indicates O_CLOEXEC */
		oflag = oflag | O_CLOEXEC;
	}
	if (plusflag) {
		oflag = (oflag & ~(O_RDONLY | O_WRONLY)) | O_RDWR;
		fflag = _IORW;
	}
	if (xflag) {
		oflag |= O_EXCL;
	}

	/* select small or large file open based on flag */
	if (largefile) {
		fd = open64(name, oflag, 0666);
	} else {
		fd = open(name, oflag, 0666);
	}
	if (fd < 0)
		return (NULL);

	/* As long as we make sure _flag stays != 0, we don't need to lock */
#ifdef	_LP64
	iop->_file = fd;
	iop->_flag = (iop->_flag & ~0377) | fflag;
#else
	if (fd <= _FILE_FD_MAX) {
		SET_FILE(iop, fd);
	} else if (_file_set(iop, fd, type) != 0) {
		/* errno set in _file_set() */
		(void) close(fd);
		return (NULL);
	}
	iop->_flag = fflag;
#endif	/*	_LP64	*/

	if (oflag == (O_WRONLY | O_APPEND | O_CREAT)) {	/* type == "a" */
		if (lseek64(fd, (off64_t)0, SEEK_END) < (off64_t)0) {
			(void) close(fd);
			return (NULL);
		}
	}

	return (iop);
}
