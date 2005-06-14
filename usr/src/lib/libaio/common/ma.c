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
 * Copyright 1992-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include "libaio.h"

/*
 * Allocate a worker control block.
 * We just use malloc(), like everywhere else in libaio.
 * A more sophisticated allocator could be used, but oh well...
 */
aio_worker_t *
_aio_alloc_worker()
{
	aio_worker_t *aiowp;

	aiowp = malloc(sizeof (aio_worker_t));
	if (aiowp != NULL) {
		(void) memset(aiowp, 0, sizeof (aio_worker_t));
		(void) mutex_init(&aiowp->work_qlock1, USYNC_THREAD, NULL);
		(void) mutex_init(&aiowp->work_lock, USYNC_THREAD, NULL);
		(void) cond_init(&aiowp->work_idle_cv, USYNC_THREAD, NULL);
	}
	return (aiowp);
}

/*
 * Free a worker control block.
 * Declared with void *arg so it can be a thr_keycreate() destructor.
 */
void
_aio_free_worker(void *arg)
{
	free(arg);
}
