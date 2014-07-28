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

#include "lint.h"
#include "thr_uberdata.h"
#include <libc.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <mtlib.h>
#include <thread.h>
#include <synch.h>
#include <atomic.h>
#include <limits.h>

static mutex_t auxlock = DEFAULTMUTEX;

/*
 * Get auxiliary entry.
 * Returns pointer to entry, or 0 if entry does not exist.
 */
static auxv_t *
_getaux(int type)
{
	static auxv_t *auxb = NULL;
	static size_t nauxv = 0;
	ssize_t i;

	/*
	 * The first time through, read the initial aux vector that was
	 * passed to the process at exec(2).  Only do this once.
	 */
	if (auxb == NULL) {
		lmutex_lock(&auxlock);
		if (auxb == NULL) {
			uberdata_t *udp = curthread->ul_uberdata;
			struct stat statb;
			auxv_t *buf = NULL;
			char *path = "/proc/self/auxv";
			char pbuf[PATH_MAX];
			int fd;

			if (udp->ub_broot != NULL) {
				(void) snprintf(pbuf, sizeof (pbuf),
				    "%s/proc/self/auxv", udp->ub_broot);
				path = pbuf;
			}

			if ((fd = open(path, O_RDONLY)) != -1 &&
			    fstat(fd, &statb) != -1)
				buf = libc_malloc(
				    statb.st_size + sizeof (auxv_t));

			if (buf != NULL) {
				i = read(fd, buf, statb.st_size);
				if (i != -1) {
					nauxv = i / sizeof (auxv_t);
					buf[nauxv].a_type = AT_NULL;
				} else {
					libc_free(buf);
					buf = NULL;
				}
			}

			if (fd != -1)
				(void) close(fd);

			membar_producer();
			auxb = buf;
		}
		lmutex_unlock(&auxlock);
	}
	membar_consumer();

	/*
	 * Scan the auxiliary entries looking for the required type.
	 */
	for (i = 0; i < nauxv; i++)
		if (auxb[i].a_type == type)
			return (&auxb[i]);

	/*
	 * No auxiliary array (static executable) or entry not found.
	 */
	return ((auxv_t *)0);
}

/*
 * These two routines are utilities exported to the rest of libc.
 */

long
___getauxval(int type)
{
	auxv_t *auxp;

	if ((auxp = _getaux(type)) != (auxv_t *)0)
		return (auxp->a_un.a_val);
	return (0);
}

void *
___getauxptr(int type)
{
	auxv_t *auxp;

	if ((auxp = _getaux(type)) != (auxv_t *)0)
		return (auxp->a_un.a_ptr);
	return (0);
}
