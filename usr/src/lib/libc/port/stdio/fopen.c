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
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Copyright 2020 Robert Mustacchi
 */

#include "lint.h"
#include "file64.h"
#include <sys/types.h>
#include <stdio.h>
#include <mtlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <thread.h>
#include <synch.h>
#include <stdlib.h>
#include <errno.h>
#include "stdiom.h"
#include "xpg6.h"

/* Final argument to _endopen depends on build environment */
#define	LARGE_OPEN		(_FILE_OFFSET_BITS == 64)

FILE *
fopen(const char *name, const char *type) /* open name, return new stream */
{
	FILE *iop;
	FILE  *rc;

	iop = _findiop();
	/*
	 * Note that iop is not locked here, since no other thread could
	 * possibly call _endopen with the same iop at this point.
	 */
	rc = _endopen(name, type, iop, LARGE_OPEN);

	if (rc == NULL && iop != NULL)
		iop->_flag = 0; /* release iop */

	return (rc);
}

static FILE *
_freopen_null(const char *type, FILE *iop)
{
	char	plus, mode;
	int	oflag, nflag, fd, accmode;
	mbstate_t	*mb;

	if (iop == NULL || iop->_flag == 0) {
		errno = EBADF;
		return (NULL);
	}

	/*
	 * If this is not a file-based stream (as in we have no file
	 * descriptor), then we need to close this, but still actually return an
	 * error.
	 */
	if (_get_fd(iop) == -1) {
		(void) close_fd(iop);
		errno = EBADF;
		return (NULL);
	}

	if (!(iop->_flag & _IONBF) && (iop->_flag & (_IOWRT | _IOREAD | _IORW)))
		(void) _fflush_u(iop);

	if (iop->_flag & _IOMYBUF) {
		free((char *)iop->_base - PUSHBACK);
	}
	iop->_base = NULL;
	iop->_ptr = NULL;
	/*
	 * Clear stream orientation, clear stream encoding rule, and set
	 * stream's mbstate_t object to describe an initial conversion state.
	 */
	mb = _getmbstate(iop);
	if (mb != NULL)
		(void) memset(mb, 0, sizeof (mbstate_t));
	iop->_cnt = 0;
	_setorientation(iop, _NO_MODE);

	fd = FILENO(iop);
	mode = type[0];
	if (mode != 'r' && mode != 'w' && mode != 'a') {
		errno = EINVAL;
		goto errret;
	}

	if ((oflag = fcntl(fd, F_GETFL)) == -1)
		goto errret;

	if ((plus = type[1]) == 'b')
		plus = type[2];

	/*
	 * Because the filename has not been specified, the underlying file
	 * will not be closed and reopened.  The access modes of an open
	 * file descriptor can't be changed via fcntl().  When '+' is
	 * specified, the old access mode needs to be O_RDWR.  When 'r' is
	 * specified, the old access mode needs to be O_RDONLY or O_RDWR.
	 * When 'a' or 'w' is specified, the old access mode needs to be
	 * O_WRONLY or O_RDWR.  Otherwise, fail with EBADF, indicating that
	 * the underlying file descriptor was not opened with a mode that
	 * would allow the stream to do successful I/O with the requested mode.
	 */

	accmode = oflag & O_ACCMODE;
	if ((accmode == O_RDONLY && (mode != 'r' || plus == '+')) ||
	    (accmode == O_WRONLY && (mode == 'r' || plus == '+'))) {
		(void) close(fd);
		errno = EBADF;
		goto errret_noclose;
	}

#ifdef	_LP64
	iop->_flag &= ~_DEF_FLAG_MASK;	/* clear lower 8-bits */
	if (mode == 'r') {
		iop->_flag |= _IOREAD;
		nflag = oflag & ~O_APPEND;
	} else if (mode == 'w') {
		iop->_flag |= _IOWRT;
		nflag = oflag & ~O_APPEND;
	} else {
		iop->_flag |= _IOWRT;
		nflag = oflag | O_APPEND;
	}
	if (plus == '+') {
		iop->_flag = (iop->_flag & ~(_IOREAD | _IOWRT)) | _IORW;
	}
#else
	if (mode == 'r') {
		iop->_flag = _IOREAD;
		nflag = oflag & ~O_APPEND;
	} else if (mode == 'w') {
		iop->_flag = _IOWRT;
		nflag = oflag & ~O_APPEND;
	} else {
		iop->_flag = _IOWRT;
		nflag = oflag | O_APPEND;
	}
	if (plus == '+') {
		iop->_flag = _IORW;
	}
#endif
	/*
	 * Change mode of underlying fd as much as possible without closing
	 * and reopening it.  Ignore truncate failures, eg. with stdout.
	 */
	if (mode == 'w')
		(void) ftruncate64(fd, (off64_t)0);

	if (fcntl(fd, F_SETFL, nflag) == -1)
		goto errret;

	/* ignore seek failures, eg. with pipes */
	(void) lseek64(fd, (off64_t)0, SEEK_SET);

	return (iop);

errret:
	if (errno != EBADF)
		(void) close(fd);

errret_noclose:
	iop->_flag = 0;		/* release iop */
	return (NULL);
}

FILE *
freopen(const char *name, const char *type, FILE *iop)
{
	FILE *rc;
	rmutex_t *lk;

	if (name == NULL && __xpg6 & _C99SUSv3_freopen_NULL_filename) {
		/*
		 * XPG6:  If name is a null pointer, freopen will attempt to
		 * change the mode of the stream to that specified by type.
		 */
		FLOCKFILE(lk, iop);
		rc = _freopen_null(type, iop);
		FUNLOCKFILE(lk);
		return (rc);
	}
	/*
	 * there may be concurrent calls to reopen the same stream - need
	 * to make freopen() atomic
	 */
	FLOCKFILE(lk, iop);
	/*
	 * new function to do everything that fclose() does, except
	 * to release the iop - this cannot yet be released since
	 * _endopen() is yet to be called on this iop
	 */

	(void) close_fd(iop);

	rc = _endopen(name, type, iop, LARGE_OPEN);

	if (rc == NULL)
		iop->_flag = 0; /* release iop */

	FUNLOCKFILE(lk);
	return (rc);
}
