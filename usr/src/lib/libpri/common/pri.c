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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/param.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "sys/ds_pri.h"
#include "pri.h"

static int pri_fd = -1;



/*
 * Library init function
 * Returns: Success (0), Failure (-1)
 */
int
pri_init(void)
{
	int fd;

	if (pri_fd != -1)
		return (-1);

	fd = open(DS_PRI_DRIVER, O_RDONLY);
	if (fd < 0)
		return (-1);

	pri_fd = fd;

	return (0);
}

/*
 * Library fini function
 * Returns: N/A
 */
void
pri_fini(void)
{
	if (pri_fd < 0)
		return;

	(void) close(pri_fd);
	pri_fd = -1;
}

/*
 * PRI retrieval function.
 * Description:
 *	- Library routine to retrieve the Physical Resource Inventory (PRI)
 *	- Utilized by sun4v platforms which support Logical Domains
 *	- Interacts with the ds_pri pseudo driver to retrieve the
 *	  PRI. ds_pri driver in turn gets the PRI from the
 *	  Domain Services kernel module. Domain Services gets the
 *	  PRI from the Service Processor via LDC (Logical Domain
 *	  Channel).
 *	- Consumers of this api include FMA, Zeus, and picld
 *	- MT-Safe, Stateless
 *
 * Imports:
 *	- ds_pri driver interfaces
 *
 * Arguments:
 *	- wait: specifies whether caller wants to wait for a new PRI,
 *		PRI_GET is no-wait, PRI_WAITGET is wait-forever
 *	- token: opaque PRI token, accepted from and/or returned to caller,
 *		see write-only or read-write semantics below
 *	- buf: PRI buffer received from ds_pri driver, returned to caller
 *	- allocp: caller provided pointer to memory allocator function
 *	- freep: caller provided pointer to memory free function
 *
 * Calling Semantics:
 *	- PRI_GET call ignores the token passed in, and returns
 *	  immediately with current PRI and its token (if any)
 *	- PRI_WAITGET call returns only upon the receipt of a new PRI
 *	  whose token differs from the token passed in by the caller;
 *	  the passed in token should come from a previous pri_get()
 *	  call with return value >= 0; the new PRI buffer and its token
 *	  are returned to the caller
 *	- If wait time must be bounded, the caller can spawn a thread
 *	  which makes a PRI_WAITGET call; caller can choose to kill the
 *	  spawned thread after a finite time
 *
 * Usage Semantics:
 *	- Caller can use the returned PRI buffer as an argument to
 *	  to md_init_intern() to process it into a machine
 *	  descriptor (md_t) format
 *	- Caller can choose to supply the same allocator and free
 *	  functions to the md_init_intern() call
 *	- Once the caller is done using these data structures,
 *	  the following actions need to be performed by the caller:
 *		- md_fini(mdp) if called md_init_intern()
 *		- freep(bufp, size)
 *
 * Returns:
 *	>0 if PRI is returned successfully (size of PRI buffer)
 *	0 if no PRI is available
 *	-1 if there is an error (errno contains the error code
 *	provided)
 *
 */
ssize_t
pri_get(uint8_t wait, uint64_t *token, uint64_t **buf,
		void *(*allocp)(size_t), void (*freep)(void *, size_t))
{
	uint64_t		*bufp;		/* buf holding PRI */
	size_t			size;		/* sizeof PRI */
	struct dspri_info	pri_info;	/* info about PRI */
	struct dspri_info	pri_info2;	/* for PRI delta check */

	if (pri_fd < 0) {
		errno = EBADF;
		return (-1);
	}

	if (wait == PRI_WAITGET) {
		/* wait until have new PRI with different token */
		if (ioctl(pri_fd, DSPRI_WAIT, token) < 0) {
			return (-1);
		}
	}

	do {
		/* get info on current PRI */
		if (ioctl(pri_fd, DSPRI_GETINFO, &pri_info) < 0) {
			return (-1);
		}

		size = (size_t)pri_info.size;

		/* check to see if no PRI available yet */
		if (size == 0) {
			*token = pri_info.token;
			return (0);
		}

		/* allocate a buffer and read the PRI into it */
		if ((bufp = (uint64_t *)allocp(size)) == NULL) {
			if (errno == 0)
				errno = ENOMEM;
			return (-1);
		}
		if (read(pri_fd, bufp, size) < 0) {
			freep(bufp, size);
			return (-1);
		}

		/*
		 * Check whether PRI token changed between the time
		 * we did the DSPRI_GETINFO ioctl() and the actual
		 * read() from the ds_pri driver. The token delta check
		 * tries to catch the above race condition; be sure
		 * to not leak memory on retries.
		 */
		if (ioctl(pri_fd, DSPRI_GETINFO, &pri_info2) < 0) {
			freep(bufp, size);
			return (-1);
		}
		if (pri_info2.token != pri_info.token)
			freep(bufp, size);

	} while (pri_info2.token != pri_info.token);

	/* return the PRI, its token, and its size to the caller */
	*buf = bufp;
	*token = pri_info.token;
	return ((ssize_t)size);
}
