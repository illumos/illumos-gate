/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Robert Mustacchi
 */

/*
 * Implements fmemopen(3C).
 */

#include "mtlib.h"
#include "file64.h"
#include <stdio.h>
#include "stdiom.h"
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <limits.h>

typedef enum fmemopen_flags {
	/*
	 * Indicates that the user gave us the buffer and so we shouldn't free
	 * it.
	 */
	FMO_F_USER_BUFFER	= 1 << 0,
	/*
	 * When the stream is open for update (a, a+) then we have to have
	 * slightly different behavior on write and zeroing the buffer.
	 */
	FMO_F_APPEND		= 1 << 1
} fmemopen_flags_t;

typedef struct fmemopen {
	/*
	 * Pointer to the underlying memory stream.
	 */
	char	*fmo_buf;
	/*
	 * Allocated length of the buffer.
	 */
	size_t	fmo_alloc;
	/*
	 * Current position of the buffer.
	 */
	size_t	fmo_pos;
	/*
	 * Current 'size' of the buffer. POSIX describes a size that the buffer
	 * has which is separate from the allocated size, but cannot exceed it.
	 */
	size_t	fmo_lsize;
	fmemopen_flags_t fmo_flags;
} fmemopen_t;

static ssize_t
fmemopen_read(FILE *iop, char *buf, size_t nbytes)
{
	fmemopen_t *fmp = _xdata(iop);

	nbytes = MIN(nbytes, fmp->fmo_lsize - fmp->fmo_pos);
	if (nbytes == 0) {
		return (0);
	}

	(void) memcpy(buf, fmp->fmo_buf, nbytes);
	fmp->fmo_pos += nbytes;

	return (nbytes);
}

static ssize_t
fmemopen_write(FILE *iop, const char *buf, size_t nbytes)
{
	size_t npos;
	fmemopen_t *fmp = _xdata(iop);

	if ((fmp->fmo_flags & FMO_F_APPEND) != 0) {
		/*
		 * POSIX says that if append mode is in effect, we must always
		 * seek to the logical size. This effectively is mimicking the
		 * O_APPEND behavior.
		 */
		fmp->fmo_pos = fmp->fmo_lsize;
	}

	if (nbytes == 0) {
		return (0);
	} else if (nbytes >= SSIZE_MAX) {
		errno = EINVAL;
		return (-1);
	}

	npos = fmp->fmo_pos + nbytes;
	if (npos < nbytes) {
		errno = EOVERFLOW;
		return (-1);
	} else if (npos > fmp->fmo_alloc) {
		nbytes = fmp->fmo_alloc - fmp->fmo_pos;
	}

	(void) memcpy(&fmp->fmo_buf[fmp->fmo_pos], buf, nbytes);
	fmp->fmo_pos += nbytes;

	if (fmp->fmo_pos > fmp->fmo_lsize) {
		fmp->fmo_lsize = fmp->fmo_pos;

		/*
		 * POSIX distinguishes behavior for writing a NUL in these
		 * streams. Basically if we are open for update and we are at
		 * the end of the buffer, we don't place a NUL. Otherwise, we
		 * always place one at the current position (or the end if we
		 * were over the edge).
		 */
		if (fmp->fmo_lsize < fmp->fmo_alloc) {
			fmp->fmo_buf[fmp->fmo_lsize] = '\0';
		} else if ((fmp->fmo_flags & FMO_F_APPEND) == 0) {
			fmp->fmo_buf[fmp->fmo_alloc - 1] = '\0';
		}
	}

	return (nbytes);
}

static off_t
fmemopen_seek(FILE *iop, off_t off, int whence)
{
	fmemopen_t *fmp = _xdata(iop);
	size_t base, npos;

	switch (whence) {
	case SEEK_SET:
		base = 0;
		break;
	case SEEK_CUR:
		base = fmp->fmo_pos;
		break;
	case SEEK_END:
		base = fmp->fmo_lsize;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	if (!memstream_seek(base, off, fmp->fmo_alloc, &npos)) {
		errno = EINVAL;
		return (-1);
	}
	fmp->fmo_pos = npos;

	return ((off_t)fmp->fmo_pos);
}

static void
fmemopen_free(fmemopen_t *fmp)
{
	if (fmp->fmo_buf != NULL &&
	    (fmp->fmo_flags & FMO_F_USER_BUFFER) == 0) {
		free(fmp->fmo_buf);
	}

	free(fmp);
}

static int
fmemopen_close(FILE *iop)
{
	fmemopen_t *fmp = _xdata(iop);
	fmemopen_free(fmp);
	_xunassoc(iop);
	return (0);
}

FILE *
fmemopen(void *_RESTRICT_KYWD buf, size_t size,
    const char *_RESTRICT_KYWD mode)
{
	int oflags, fflags, err;
	fmemopen_t *fmp;
	FILE *iop;

	if (size == 0 || mode == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if (_stdio_flags(mode, &oflags, &fflags) != 0) {
		/* errno set for us */
		return (NULL);
	}

	/*
	 * buf is only allowed to be NULL if the '+' is specified.  If the '+'
	 * mode was specified, then we'll have fflags set to _IORW.
	 */
	if (buf == NULL && fflags != _IORW) {
		errno = EINVAL;
		return (NULL);
	}

	if ((fmp = calloc(1, sizeof (fmemopen_t))) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	if (buf == NULL) {
		fmp->fmo_buf = calloc(size, sizeof (uint8_t));
		if (fmp->fmo_buf == NULL) {
			errno = ENOMEM;
			goto cleanup;
		}
	} else {
		fmp->fmo_buf = buf;
		fmp->fmo_flags |= FMO_F_USER_BUFFER;
	}

	fmp->fmo_alloc = size;

	/*
	 * Set the initial logical size and position depending on whether we're
	 * using r(+), w(+), and a(+). The latter two are identified by O_TRUNC
	 * and O_APPEND in oflags.
	 */
	if ((oflags & O_APPEND) != 0) {
		fmp->fmo_pos = strnlen(fmp->fmo_buf, fmp->fmo_alloc);
		fmp->fmo_lsize = fmp->fmo_pos;
		fmp->fmo_flags |= FMO_F_APPEND;
	} else if ((oflags & O_TRUNC) != 0) {
		fmp->fmo_buf[0] = '\0';
		fmp->fmo_pos = 0;
		fmp->fmo_lsize = 0;
	} else {
		fmp->fmo_pos = 0;
		fmp->fmo_lsize = size;
	}

	iop = _findiop();
	if (iop == NULL) {
		goto cleanup;
	}

#ifdef	_LP64
	iop->_flag = (iop->_flag & ~_DEF_FLAG_MASK) | fflags;
#else
	iop->_flag = fflags;
#endif
	if (_xassoc(iop, fmemopen_read, fmemopen_write, fmemopen_seek,
	    fmemopen_close, fmp) != 0) {
		goto cleanup;
	}

	SET_SEEKABLE(iop);

	return (iop);

cleanup:
	err = errno;
	fmemopen_free(fmp);
	errno = err;
	return (NULL);
}
