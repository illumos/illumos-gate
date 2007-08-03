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

#include <sys/zfs_context.h>
#include <sys/refcount.h>
#include <sys/rprwlock.h>

void
rprw_init(rprwlock_t *rwl)
{
	mutex_init(&rwl->rw_lock, NULL, MUTEX_DEFAULT, NULL);
	rwl->rw_writer = NULL;
	cv_init(&rwl->rw_cv, NULL, CV_DEFAULT, NULL);
	refcount_create(&rwl->rw_count);
}

void
rprw_destroy(rprwlock_t *rwl)
{
	mutex_destroy(&rwl->rw_lock);
	ASSERT(rwl->rw_writer == NULL);
	cv_destroy(&rwl->rw_cv);
	refcount_destroy(&rwl->rw_count);
}

void
rprw_enter_read(rprwlock_t *rwl, void *tag)
{
	mutex_enter(&rwl->rw_lock);

	if (rwl->rw_writer != curthread) {
		while (rwl->rw_writer != NULL)
			cv_wait(&rwl->rw_cv, &rwl->rw_lock);
	}

	(void) refcount_add(&rwl->rw_count, tag);

	mutex_exit(&rwl->rw_lock);
}

void
rprw_enter_write(rprwlock_t *rwl, void *tag)
{
	mutex_enter(&rwl->rw_lock);

	if (rwl->rw_writer != curthread) {
		while (!refcount_is_zero(&rwl->rw_count))
			cv_wait(&rwl->rw_cv, &rwl->rw_lock);
		rwl->rw_writer = curthread;
	}

	(void) refcount_add(&rwl->rw_count, tag);

	mutex_exit(&rwl->rw_lock);
}

void
rprw_enter(rprwlock_t *rwl, krw_t rw, void *tag)
{
	if (rw == RW_READER)
		rprw_enter_read(rwl, tag);
	else
		rprw_enter_write(rwl, tag);
}

void
rprw_exit(rprwlock_t *rwl, void *tag)
{
	mutex_enter(&rwl->rw_lock);

	ASSERT(!refcount_is_zero(&rwl->rw_count));
	ASSERT(rwl->rw_writer == NULL || curthread == rwl->rw_writer);
	if (refcount_remove(&rwl->rw_count, tag) == 0) {
		cv_broadcast(&rwl->rw_cv);
		rwl->rw_writer = NULL;  /* OK in either case */
	}

	mutex_exit(&rwl->rw_lock);
}

boolean_t
rprw_held(rprwlock_t *rwl, krw_t rw)
{
	boolean_t held;

	mutex_enter(&rwl->rw_lock);
	if (rw == RW_WRITER)
		held = (rwl->rw_writer == curthread);
	else
		held = !rwl->rw_writer && !refcount_is_zero(&rwl->rw_count);
	mutex_exit(&rwl->rw_lock);

	return (held);
}
