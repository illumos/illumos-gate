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
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/copyops.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/pathname.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>

int
getcwd(char *buf, size_t buflen)
{
	int err;
	char *kbuf;
	size_t kbuflen;

	/*
	 * If the buffer cannot accommodate one character and nul terminator,
	 * it is too small.
	 */
	if (buflen < 2)
		return (set_errno(ERANGE));

	/*
	 * The user should be able to specify any size buffer, but we don't want
	 * to arbitrarily allocate huge kernel buffers just because the user
	 * requests it.  So we'll start with MAXPATHLEN (which should hold any
	 * normal path), and only increase it if we fail with
	 * ERANGE / ENAMETOOLONG.
	 *
	 * To protect against unbounded memory usage, cap to kmem_max_cached.
	 * This is far bigger than the length of any practical path on the
	 * system, and avoids allocating memory from the kmem_oversized arena.
	 */
	kbuflen = MIN(buflen, MAXPATHLEN);

	while (kbuflen <= kmem_max_cached) {
		kbuf = kmem_alloc(kbuflen, KM_SLEEP);

		if (((err = dogetcwd(kbuf, kbuflen)) == 0) &&
		    (copyout(kbuf, buf, strlen(kbuf) + 1) != 0)) {
			err = EFAULT;
		}

		kmem_free(kbuf, kbuflen);

		/*
		 * dogetcwd() inconsistently returns ERANGE or ENAMETOOLONG
		 * depending on whether it calls dirtopath() and then whether
		 * the subsequent operations run out of space whilst
		 * evaluating a cached vnode path or otherwise.
		 */
		if (err == ENAMETOOLONG || err == ERANGE) {
			/* For some reason, getcwd() uses ERANGE. */
			err = ERANGE;
			/*
			 * If the user's buffer really was too small, give up.
			 */
			if (kbuflen == buflen)
				break;
			kbuflen = MIN(kbuflen * 2, buflen);
		} else {
			break;
		}
	}

	return ((err != 0) ? set_errno(err) : 0);
}
