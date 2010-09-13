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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/cmn_err.h>

#if defined(__sparc)
#include <sys/stack.h>
#endif

#define	STACK_BUF_SIZE	64	/* power of 2 */

int
prusrio(proc_t *p, enum uio_rw rw, struct uio *uiop, int old)
{
	/* longlong-aligned short buffer */
	longlong_t buffer[STACK_BUF_SIZE / sizeof (longlong_t)];
	int error = 0;
	void *bp;
	int allocated;
	ssize_t total = uiop->uio_resid;
	uintptr_t addr;
	size_t len;

	/* for short reads/writes, use the on-stack buffer */
	if (uiop->uio_resid <= STACK_BUF_SIZE) {
		bp = buffer;
		allocated = 0;
	} else {
		bp = kmem_alloc(PAGESIZE, KM_SLEEP);
		allocated = 1;
	}

#if defined(__sparc)
	if (p == curproc)
		(void) flush_user_windows_to_stack(NULL);
#endif

	switch (rw) {
	case UIO_READ:
		while (uiop->uio_resid != 0) {
			addr = uiop->uio_offset;
			len = MIN(uiop->uio_resid,
			    PAGESIZE - (addr & PAGEOFFSET));

			if ((error = uread(p, bp, len, addr)) != 0 ||
			    (error = uiomove(bp, len, UIO_READ, uiop)) != 0)
				break;
		}

		/*
		 * ENXIO indicates that a page didn't exist. If the I/O was
		 * truncated, return success; otherwise convert the error into
		 * EIO. When obeying new /proc semantics, we don't return an
		 * error for a read that begins at an invalid address.
		 */
		if (error == ENXIO) {
			if (total != uiop->uio_resid || !old)
				error = 0;
			else
				error = EIO;
		}
		break;
	case UIO_WRITE:
		while (uiop->uio_resid != 0) {
			addr = uiop->uio_offset;
			len = MIN(uiop->uio_resid,
			    PAGESIZE - (addr & PAGEOFFSET));

			if ((error = uiomove(bp, len, UIO_WRITE, uiop)) != 0)
				break;
			if ((error = uwrite(p, bp, len, addr)) != 0) {
				uiop->uio_resid += len;
				uiop->uio_loffset -= len;
				break;
			}
		}

		/*
		 * ENXIO indicates that a page didn't exist. If the I/O was
		 * truncated, return success; otherwise convert the error
		 * into EIO.
		 */
		if (error == ENXIO) {
			if (total != uiop->uio_resid)
				error = 0;
			else
				error = EIO;
		}
		break;
	default:
		panic("prusrio: rw=%d neither UIO_READ not UIO_WRITE", rw);
		/*NOTREACHED*/
	}

	if (allocated)
		kmem_free(bp, PAGESIZE);

	return (error);
}
