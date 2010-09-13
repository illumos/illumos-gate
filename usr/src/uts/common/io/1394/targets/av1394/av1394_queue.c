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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * av1394 queue
 *    Based on av1394 list, plus locking, works only with mblk's,
 *    counts and limits amount of data on the queue.
 */
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/1394/targets/av1394/av1394_impl.h>

typedef void (*putfunc_t)(av1394_list_t *, void *);

static mblk_t	*av1394_getq_locked(av1394_queue_t *);
static int	av1394_put_common(av1394_queue_t *, mblk_t *, putfunc_t);

void
av1394_initq(av1394_queue_t *q, ddi_iblock_cookie_t ibc, int max)
{
	bzero(q, sizeof (av1394_queue_t));

	mutex_init(&q->q_mutex, NULL, MUTEX_DRIVER, ibc);
	cv_init(&q->q_cv, NULL, CV_DRIVER, NULL);

	AV1394_ENTERQ(q);
	av1394_list_init(&q->q_list);
	q->q_max = max;
	AV1394_LEAVEQ(q);
}

void
av1394_destroyq(av1394_queue_t *q)
{
	av1394_flushq(q);
	mutex_destroy(&q->q_mutex);
	cv_destroy(&q->q_cv);
}

void
av1394_setmaxq(av1394_queue_t *q, int max)
{
	AV1394_ENTERQ(q);
	q->q_max = max;
	AV1394_LEAVEQ(q);
}

int
av1394_getmaxq(av1394_queue_t *q)
{
	int	max;

	AV1394_ENTERQ(q);
	max = q->q_max;
	AV1394_LEAVEQ(q);
	return (max);
}

void
av1394_flushq(av1394_queue_t *q)
{
	mblk_t	*bp;

	AV1394_ENTERQ(q);
	while ((bp = av1394_getq_locked(q)) != NULL) {
		freemsg(bp);
	}
	ASSERT(q->q_size == 0);
	AV1394_LEAVEQ(q);
}

int
av1394_putq(av1394_queue_t *q, mblk_t *bp)
{
	return (av1394_put_common(q, bp, av1394_list_put_tail));
}

int
av1394_putbq(av1394_queue_t *q, mblk_t *bp)
{
	return (av1394_put_common(q, bp, av1394_list_put_head));
}

mblk_t *
av1394_getq(av1394_queue_t *q)
{
	mblk_t	*bp;

	AV1394_ENTERQ(q);
	bp = av1394_getq_locked(q);
	AV1394_LEAVEQ(q);

	return (bp);
}

mblk_t *
av1394_peekq(av1394_queue_t *q)
{
	mblk_t	*mp;

	AV1394_ENTERQ(q);
	mp = av1394_peekq_locked(q);
	AV1394_LEAVEQ(q);
	return (mp);
}

mblk_t *
av1394_peekq_locked(av1394_queue_t *q)
{
	ASSERT(mutex_owned(&q->q_mutex));
	return (av1394_list_head(&q->q_list));
}

/*
 * wait until queue is not empty or a signal arrives
 */
int
av1394_qwait_sig(av1394_queue_t *q)
{
	int	ret = 1;

	AV1394_ENTERQ(q);
	while (av1394_peekq_locked(q) == NULL) {
		if ((ret = cv_wait_sig(&q->q_cv, &q->q_mutex)) <= 0) {
			break;
		}
	}
	AV1394_LEAVEQ(q);

	return (ret);
}

static int
av1394_put_common(av1394_queue_t *q, mblk_t *bp, putfunc_t put)
{
	int	ret;
	int	len = MBLKL(bp);

	AV1394_ENTERQ(q);
	if (q->q_size + len > q->q_max) {
		ret = 0;
	} else {
		put(&q->q_list, bp);
		q->q_size += len;
		cv_broadcast(&q->q_cv);
		ret = 1;
	}
	AV1394_LEAVEQ(q);

	return (ret);
}

static mblk_t *
av1394_getq_locked(av1394_queue_t *q)
{
	mblk_t	*bp;

	if ((bp = av1394_list_get_head(&q->q_list)) != NULL) {
		q->q_size -= MBLKL(bp);
		ASSERT(q->q_size >= 0);
	}
	return (bp);
}
