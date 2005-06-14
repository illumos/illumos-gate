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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/errno.h>

/*
 * Move "n" bytes at byte address "p"; "rw" indicates the direction
 * of the move, and the I/O parameters are provided in "uio", which is
 * update to reflect the data which was moved.  Returns 0 on success or
 * a non-zero errno on failure.
 */
int
uiomove(void *p, size_t n, enum uio_rw rw, struct uio *uio)
{
	struct iovec *iov;
	ulong_t cnt;
	int error;

	while (n && uio->uio_resid) {
		iov = uio->uio_iov;
		cnt = MIN(iov->iov_len, n);
		if (cnt == 0l) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		switch (uio->uio_segflg) {

		case UIO_USERSPACE:
		case UIO_USERISPACE:
			if (rw == UIO_READ) {
				error = xcopyout_nta(p, iov->iov_base, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			} else {
				error = xcopyin_nta(iov->iov_base, p, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			}

			if (error)
				return (error);
			break;

		case UIO_SYSSPACE:
			if (rw == UIO_READ)
				error = kcopy_nta(p, iov->iov_base, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			else
				error = kcopy_nta(iov->iov_base, p, cnt,
				    (uio->uio_extflg & UIO_COPY_CACHED));
			if (error)
				return (error);
			break;
		}
		iov->iov_base += cnt;
		iov->iov_len -= cnt;
		uio->uio_resid -= cnt;
		uio->uio_loffset += cnt;
		p = (caddr_t)p + cnt;
		n -= cnt;
	}
	return (0);
}

/*
 * transfer a character value into the address space
 * delineated by a uio and update fields within the
 * uio for next character. Return 0 for success, EFAULT
 * for error.
 */
int
ureadc(int val, struct uio *uiop)
{
	struct iovec *iovp;
	unsigned char c;

	/*
	 * first determine if uio is valid.  uiop should be
	 * non-NULL and the resid count > 0.
	 */
	if (!(uiop && uiop->uio_resid > 0))
		return (EFAULT);

	/*
	 * scan through iovecs until one is found that is non-empty.
	 * Return EFAULT if none found.
	 */
	while (uiop->uio_iovcnt > 0) {
		iovp = uiop->uio_iov;
		if (iovp->iov_len <= 0) {
			uiop->uio_iovcnt--;
			uiop->uio_iov++;
		} else
			break;
	}

	if (uiop->uio_iovcnt <= 0)
		return (EFAULT);

	/*
	 * Transfer character to uio space.
	 */

	c = (unsigned char) (val & 0xFF);

	switch (uiop->uio_segflg) {

	case UIO_USERISPACE:
	case UIO_USERSPACE:
		if (copyout(&c, iovp->iov_base, sizeof (unsigned char)))
			return (EFAULT);
		break;

	case UIO_SYSSPACE: /* can do direct copy since kernel-kernel */
		*iovp->iov_base = c;
		break;

	default:
		return (EFAULT); /* invalid segflg value */
	}

	/*
	 * bump up/down iovec and uio members to reflect transfer.
	 */
	iovp->iov_base++;
	iovp->iov_len--;
	uiop->uio_resid--;
	uiop->uio_loffset++;
	return (0); /* success */
}

/*
 * return a character value from the address space
 * delineated by a uio and update fields within the
 * uio for next character. Return the character for success,
 * -1 for error.
 */
int
uwritec(struct uio *uiop)
{
	struct iovec *iovp;
	unsigned char c;

	/*
	 * verify we were passed a valid uio structure.
	 * (1) non-NULL uiop, (2) positive resid count
	 * (3) there is an iovec with positive length
	 */

	if (!(uiop && uiop->uio_resid > 0))
		return (-1);

	while (uiop->uio_iovcnt > 0) {
		iovp = uiop->uio_iov;
		if (iovp->iov_len <= 0) {
			uiop->uio_iovcnt--;
			uiop->uio_iov++;
		} else
			break;
	}

	if (uiop->uio_iovcnt <= 0)
		return (-1);

	/*
	 * Get the character from the uio address space.
	 */
	switch (uiop->uio_segflg) {

	case UIO_USERISPACE:
	case UIO_USERSPACE:
		if (copyin(iovp->iov_base, &c, sizeof (unsigned char)))
			return (-1);
		break;

	case UIO_SYSSPACE:
		c = *iovp->iov_base;
		break;

	default:
		return (-1); /* invalid segflg */
	}

	/*
	 * Adjust fields of iovec and uio appropriately.
	 */
	iovp->iov_base++;
	iovp->iov_len--;
	uiop->uio_resid--;
	uiop->uio_loffset++;
	return ((int)c & 0xFF); /* success */
}

/*
 * Drop the next n chars out of *uiop.
 */
void
uioskip(uio_t *uiop, size_t n)
{
	if (n > uiop->uio_resid)
		return;
	while (n != 0) {
		register iovec_t	*iovp = uiop->uio_iov;
		register size_t		niovb = MIN(iovp->iov_len, n);

		if (niovb == 0) {
			uiop->uio_iov++;
			uiop->uio_iovcnt--;
			continue;
		}
		iovp->iov_base += niovb;
		uiop->uio_loffset += niovb;
		iovp->iov_len -= niovb;
		uiop->uio_resid -= niovb;
		n -= niovb;
	}
}

/*
 * Dup the suio into the duio and diovec of size diov_cnt. If diov
 * is too small to dup suio then an error will be returned, else 0.
 */
int
uiodup(uio_t *suio, uio_t *duio, iovec_t *diov, int diov_cnt)
{
	int ix;
	iovec_t *siov = suio->uio_iov;

	*duio = *suio;
	for (ix = 0; ix < suio->uio_iovcnt; ix++) {
		diov[ix] = siov[ix];
		if (ix >= diov_cnt)
			return (1);
	}
	duio->uio_iov = diov;
	return (0);
}
