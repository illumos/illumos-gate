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
 * Implements open_memstream(3C).
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

typedef struct memstream {
	char *mstr_buf;
	size_t mstr_alloc;
	size_t mstr_pos;
	size_t mstr_lsize;
	char **mstr_ubufp;
	size_t *mstr_usizep;
} memstream_t;

/*
 * Common seek and overflow detection logic for the memory stream family of
 * functions (open_memstream, open_wmemstream, etc.). We need to validate
 * several things:
 *
 *  - That the offset when applied to base doesn't cause an over or underflow.
 *  - That the resulting offset is positive (done implicitly with the above)
 *  - That the resulting offset does not exceed an off_t's maximum size.
 *    Unfortunately the kernel doesn't export an OFF_MAX value to userland, so
 *    we have to know that it will always be equivalent to the environment's
 *    long. This is designed with the assumption that in an ILP32 environment we
 *    care about an off_t and not an off64_t. In cases where an off64_t is
 *    valid, we still have to fit inside of the size_t constraints.
 *
 * We check for each of the cases and only perform unsigned arithmetic to verify
 * that we have defined behavior.
 */
boolean_t
memstream_seek(size_t base, off_t off, size_t max, size_t *nposp)
{
	size_t npos;

	npos = base + (size_t)off;
	if (off >= 0 && npos < base) {
		return (B_FALSE);
	}

	if (off >= 0 && npos > LONG_MAX) {
		return (B_FALSE);
	}

	if (off < 0 && npos >= base) {
		return (B_FALSE);
	}

	if (npos > max) {
		return (B_FALSE);
	}

	*nposp = npos;
	return (B_TRUE);
}

int
memstream_newsize(size_t pos, size_t alloc, size_t nbytes, size_t *nallocp)
{
	size_t npos = pos + nbytes + 1;
	if (npos < pos) {
		/*
		 * We've been asked to write a number of bytes that would result
		 * in an overflow in the position. This means the stream would
		 * need to allocate all of memory, that's impractical.
		 */
		errno = EOVERFLOW;
		return (-1);
	}

	/*
	 * If the new position is beyond the allocated amount, grow the array to
	 * a practical amount.
	 */
	if (npos > alloc) {
		size_t newalloc = P2ROUNDUP(npos, BUFSIZ);
		if (newalloc < npos) {
			errno = EOVERFLOW;
			return (-1);
		}
		*nallocp = newalloc;
		return (1);
	}

	return (0);
}

/*
 * The SUSv4 spec says that this should not support reads.
 */
static ssize_t
open_memstream_read(FILE *iop, char *buf, size_t nbytes)
{
	errno = EBADF;
	return (-1);
}

static ssize_t
open_memstream_write(FILE *iop, const char *buf, size_t nbytes)
{
	memstream_t *memp = _xdata(iop);
	size_t newsize;
	int ret;

	/*
	 * We need to fit inside of an ssize_t, so we need to first constrain
	 * nbytes to a reasonable value.
	 */
	nbytes = MIN(nbytes, SSIZE_MAX);
	ret = memstream_newsize(memp->mstr_pos, memp->mstr_alloc, nbytes,
	    &newsize);
	if (ret < 0) {
		return (-1);
	} else if (ret > 0) {
		void *temp;
		temp = recallocarray(memp->mstr_buf, memp->mstr_alloc,
		    newsize, sizeof (char));
		if (temp == NULL) {
			return (-1);
		}
		memp->mstr_buf = temp;
		memp->mstr_alloc = newsize;
		*memp->mstr_ubufp = temp;
	}

	(void) memcpy(&memp->mstr_buf[memp->mstr_pos], buf, nbytes);
	memp->mstr_pos += nbytes;

	if (memp->mstr_pos > memp->mstr_lsize) {
		memp->mstr_lsize = memp->mstr_pos;
		memp->mstr_buf[memp->mstr_pos] = '\0';
	}
	*memp->mstr_usizep = MIN(memp->mstr_pos, memp->mstr_lsize);

	return (nbytes);
}

static off_t
open_memstream_seek(FILE *iop, off_t off, int whence)
{
	memstream_t *memp = _xdata(iop);
	size_t base, npos;

	switch (whence) {
	case SEEK_SET:
		base = 0;
		break;
	case SEEK_CUR:
		base = memp->mstr_pos;
		break;
	case SEEK_END:
		base = memp->mstr_lsize;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	if (!memstream_seek(base, off, SSIZE_MAX, &npos)) {
		errno = EINVAL;
		return (-1);
	}
	memp->mstr_pos = npos;
	*memp->mstr_usizep = MIN(memp->mstr_pos, memp->mstr_lsize);

	return ((off_t)memp->mstr_pos);
}

static int
open_memstream_close(FILE *iop)
{
	memstream_t *memp = _xdata(iop);
	free(memp);
	_xunassoc(iop);
	return (0);
}

FILE *
open_memstream(char **bufp, size_t *sizep)
{
	int err;
	FILE *iop;
	memstream_t *memp;

	if (bufp == NULL || sizep == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	memp = calloc(1, sizeof (memstream_t));
	if (memp == NULL) {
		return (NULL);
	}

	memp->mstr_alloc = BUFSIZ;
	memp->mstr_buf = calloc(memp->mstr_alloc, sizeof (char));
	if (memp->mstr_buf == NULL) {
		goto cleanup;
	}
	memp->mstr_buf[0] = '\0';
	memp->mstr_pos = 0;
	memp->mstr_lsize = 0;
	memp->mstr_ubufp = bufp;
	memp->mstr_usizep = sizep;

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

	if (_xassoc(iop, open_memstream_read, open_memstream_write,
	    open_memstream_seek, open_memstream_close, memp) != 0) {
		goto cleanup;
	}
	_setorientation(iop, _BYTE_MODE);
	SET_SEEKABLE(iop);

	*memp->mstr_ubufp = memp->mstr_buf;
	*memp->mstr_usizep = MIN(memp->mstr_pos, memp->mstr_lsize);

	return (iop);

cleanup:
	free(memp->mstr_buf);
	free(memp);
	return (NULL);
}
