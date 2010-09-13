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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "thr_uberdata.h"
#include "mtlib.h"

/*
 * fork handlers are run in LIFO order.
 * The libc fork handler is expected to be the first handler installed,
 * hence would be the last fork handler run in preparation for fork1().
 * It is essential that this be so, for other libraries depend on libc
 * and may grab their own locks before calling into libc.  By special
 * arrangement, the loader runs libc's init section (libc_init()) first.
 */

/*
 * pthread_atfork(): installs handlers to be called during fork1().
 * There is no POSIX API that provides for deletion of atfork handlers.
 * Collaboration between the loader and libc ensures that atfork
 * handlers installed by a library are deleted when that library
 * is unloaded (see _preexec_atfork_unload() in atexit.c).
 */
int
pthread_atfork(void (*prepare)(void),
	void (*parent)(void), void (*child)(void))
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	atfork_t *atfp;
	atfork_t *head;
	int error = 0;

	(void) mutex_lock(&udp->atfork_lock);
	if (self->ul_fork) {
		/*
		 * Cannot call pthread_atfork() from a fork handler.
		 */
		error = EDEADLK;
	} else if ((atfp = lmalloc(sizeof (atfork_t))) == NULL) {
		error = ENOMEM;
	} else {
		atfp->prepare = prepare;
		atfp->parent = parent;
		atfp->child = child;
		if ((head = udp->atforklist) == NULL) {
			udp->atforklist = atfp;
			atfp->forw = atfp->back = atfp;
		} else {
			head->back->forw = atfp;
			atfp->forw = head;
			atfp->back = head->back;
			head->back = atfp;
		}
	}

	(void) mutex_unlock(&udp->atfork_lock);
	return (error);
}

/*
 * _prefork_handler() is called by fork1() before it starts processing.
 * It executes the user installed "prepare" routines in LIFO order (POSIX)
 */
void
_prefork_handler(void)
{
	uberdata_t *udp = curthread->ul_uberdata;
	atfork_t *atfork_q;
	atfork_t *atfp;

	ASSERT(MUTEX_OWNED(&udp->atfork_lock, curthread));
	if ((atfork_q = udp->atforklist) != NULL) {
		atfp = atfork_q = atfork_q->back;
		do {
			if (atfp->prepare)
				(*atfp->prepare)();
		} while ((atfp = atfp->back) != atfork_q);
	}
}

/*
 * _postfork_parent_handler() is called by fork1() after it retuns as parent.
 * It executes the user installed "parent" routines in FIFO order (POSIX).
 */
void
_postfork_parent_handler(void)
{
	uberdata_t *udp = curthread->ul_uberdata;
	atfork_t *atfork_q;
	atfork_t *atfp;

	ASSERT(MUTEX_OWNED(&udp->atfork_lock, curthread));
	if ((atfork_q = udp->atforklist) != NULL) {
		atfp = atfork_q;
		do {
			if (atfp->parent)
				(*atfp->parent)();
		} while ((atfp = atfp->forw) != atfork_q);
	}
}

/*
 * _postfork_child_handler() is called by fork1() after it returns as child.
 * It executes the user installed "child" routines in FIFO order (POSIX).
 */
void
_postfork_child_handler(void)
{
	uberdata_t *udp = curthread->ul_uberdata;
	atfork_t *atfork_q;
	atfork_t *atfp;

	ASSERT(MUTEX_OWNED(&udp->atfork_lock, curthread));
	if ((atfork_q = udp->atforklist) != NULL) {
		atfp = atfork_q;
		do {
			if (atfp->child)
				(*atfp->child)();
		} while ((atfp = atfp->forw) != atfork_q);
	}
}
