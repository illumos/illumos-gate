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
 * Implements open_wmemstream(3C).
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
#include "libc.h"

typedef struct wmemstream {
	wchar_t *wmstr_buf;
	size_t wmstr_alloc;
	size_t wmstr_pos;
	size_t wmstr_lsize;
	mbstate_t wmstr_mbs;
	wchar_t **wmstr_ubufp;
	size_t *wmstr_usizep;
} wmemstream_t;

#define	WMEMSTREAM_MAX	(SSIZE_MAX / sizeof (wchar_t))

/*
 * The SUSv4 spec says that this should not support reads.
 */
static ssize_t
open_wmemstream_read(FILE *iop, char *buf, size_t nbytes)
{
	errno = EBADF;
	return (-1);
}

static ssize_t
open_wmemstream_write(FILE *iop, const char *buf, size_t nbytes)
{
	wmemstream_t *wmemp = _xdata(iop);
	size_t newsize, mbscount;
	ssize_t nwritten = 0;
	int ret;

	/*
	 * nbytes is in bytes not wide characters. However, the most
	 * pathological case from a writing perspective is using ASCII
	 * characters. Thus if we size things assuming that nbytes will all
	 * possibly be valid wchar_t values on their own, then we'll always have
	 * enough buffer space.
	 */
	nbytes = MIN(nbytes, WMEMSTREAM_MAX);
	ret = memstream_newsize(wmemp->wmstr_pos, wmemp->wmstr_alloc, nbytes,
	    &newsize);
	if (ret < 0) {
		return (-1);
	} else if (ret > 0) {
		void *temp;
		temp = recallocarray(wmemp->wmstr_buf, wmemp->wmstr_alloc,
		    newsize, sizeof (wchar_t));
		if (temp == NULL) {
			return (-1);
		}
		wmemp->wmstr_buf = temp;
		wmemp->wmstr_alloc = newsize;
		*wmemp->wmstr_ubufp = temp;

	}

	while (nbytes > 0) {
		size_t nchars;

		nchars = mbrtowc_nz(&wmemp->wmstr_buf[wmemp->wmstr_pos],
		    &buf[nwritten], nbytes, &wmemp->wmstr_mbs);
		if (nchars == (size_t)-1) {
			if (nwritten > 0) {
				errno = 0;
				break;
			} else {
				/*
				 * Overwrite errno in this case to be EIO. Most
				 * callers of stdio routines don't expect
				 * EILSEQ and it's not documented in POSIX, so
				 * we use this instead.
				 */
				errno = EIO;
				return (-1);
			}
		} else if (nchars == (size_t)-2) {
			nwritten += nbytes;
			nbytes = 0;
		} else {
			nwritten += nchars;
			nbytes -= nchars;
			wmemp->wmstr_pos++;
		}
	}

	if (wmemp->wmstr_pos > wmemp->wmstr_lsize) {
		wmemp->wmstr_lsize = wmemp->wmstr_pos;
		wmemp->wmstr_buf[wmemp->wmstr_pos] = L'\0';
	}
	*wmemp->wmstr_usizep = MIN(wmemp->wmstr_pos, wmemp->wmstr_lsize);
	return (nwritten);
}

static off_t
open_wmemstream_seek(FILE *iop, off_t off, int whence)
{
	wmemstream_t *wmemp = _xdata(iop);
	size_t base, npos;

	switch (whence) {
	case SEEK_SET:
		base = 0;
		break;
	case SEEK_CUR:
		base = wmemp->wmstr_pos;
		break;
	case SEEK_END:
		base = wmemp->wmstr_lsize;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	if (!memstream_seek(base, off, WMEMSTREAM_MAX, &npos)) {
		errno = EINVAL;
		return (-1);
	}

	wmemp->wmstr_pos = npos;
	*wmemp->wmstr_usizep = MIN(wmemp->wmstr_pos, wmemp->wmstr_lsize);

	return ((off_t)wmemp->wmstr_pos);
}

static int
open_wmemstream_close(FILE *iop)
{
	wmemstream_t *wmemp = _xdata(iop);
	free(wmemp);
	_xunassoc(iop);
	return (0);
}


FILE *
open_wmemstream(wchar_t **bufp, size_t *sizep)
{
	int err;
	FILE *iop;
	wmemstream_t *wmemp;

	if (bufp == NULL || sizep == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	wmemp = calloc(1, sizeof (wmemstream_t));
	if (wmemp == NULL) {
		return (NULL);
	}

	wmemp->wmstr_alloc = BUFSIZ;
	wmemp->wmstr_buf = calloc(wmemp->wmstr_alloc, sizeof (wchar_t));
	if (wmemp->wmstr_buf == NULL) {
		goto cleanup;
	}
	wmemp->wmstr_buf[0] = L'\0';
	wmemp->wmstr_pos = 0;
	wmemp->wmstr_lsize = 0;
	wmemp->wmstr_ubufp = bufp;
	wmemp->wmstr_usizep = sizep;

	iop = _findiop();
	if (iop == NULL) {
		goto cleanup;
	}

#ifdef	_LP64
	iop->_flag = (iop->_flag & ~_DEF_FLAG_MASK) | _IOWRT;
#else
	iop->_flag = _IOWRT;
#endif

	/*
	 * Update the user pointers now, in case a call to fflush() happens
	 * immediately.
	 */

	if (_xassoc(iop, open_wmemstream_read, open_wmemstream_write,
	    open_wmemstream_seek, open_wmemstream_close, wmemp) != 0) {
		goto cleanup;
	}
	_setorientation(iop, _WC_MODE);
	SET_SEEKABLE(iop);

	*wmemp->wmstr_ubufp = wmemp->wmstr_buf;
	*wmemp->wmstr_usizep = MIN(wmemp->wmstr_pos, wmemp->wmstr_lsize);

	return (iop);

cleanup:
	free(wmemp->wmstr_buf);
	free(wmemp);
	return (NULL);
}
