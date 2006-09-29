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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * routines to wait and wake up a client waiting on a list for a
 * name service request
 */
#include "cache.h"

int
nscd_wait(waiter_t *wchan,  mutex_t *lock, uint8_t *key)
{
	waiter_t mywait;
	(void) cond_init(&(mywait.w_waitcv), USYNC_THREAD, 0);
	mywait.w_key = key;
	mywait.w_next = wchan->w_next;
	mywait.w_prev = wchan;
	if (mywait.w_next)
		mywait.w_next->w_prev = &mywait;
	wchan->w_next = &mywait;

	while (*key & ST_PENDING)
		(void) cond_wait(&(mywait.w_waitcv), lock);
	if (mywait.w_prev)
		mywait.w_prev->w_next = mywait.w_next;
	if (mywait.w_next)
		mywait.w_next->w_prev = mywait.w_prev;
	return (0);
}

int
nscd_signal(waiter_t *wchan, uint8_t *key)
{
	int c = 0;
	waiter_t *tmp = wchan->w_next;

	while (tmp) {
		if (tmp->w_key == key) {
			(void) cond_signal(&(tmp->w_waitcv));
			c++;
		}
		tmp = tmp->w_next;
	}

	return (c);
}
