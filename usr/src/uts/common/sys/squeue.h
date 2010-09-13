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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SQUEUE_H
#define	_SYS_SQUEUE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/processor.h>
#include <sys/stream.h>

struct squeue_s;
typedef struct squeue_s squeue_t;

#define	SET_SQUEUE(mp, proc, arg) {				\
	ASSERT((mp)->b_prev == NULL);				\
	ASSERT((mp)->b_next == NULL);				\
	(mp)->b_queue = (queue_t *)(proc);			\
	(mp)->b_prev = (mblk_t *)(arg);				\
}

#define	SQ_FILL		0x0001
#define	SQ_NODRAIN	0x0002
#define	SQ_PROCESS	0x0004

#define	SQUEUE_ENTER(sqp, head, tail, cnt, ira, flag, tag) {	\
	sqp->sq_enter(sqp, head, tail, cnt, ira, flag, tag);	\
}

#define	SQUEUE_ENTER_ONE(sqp, mp, proc, arg, ira, flag, tag) {	\
	ASSERT(mp->b_next == NULL);				\
	ASSERT(mp->b_prev == NULL);				\
	SET_SQUEUE(mp, proc, arg);				\
	SQUEUE_ENTER(sqp, mp, mp, 1, ira, flag, tag);		\
}

/*
 * May be called only by a thread executing in the squeue. The thread must
 * not continue to execute any code needing squeue protection after calling
 * this macro. Please see the comments in squeue.c for more details.
 */
#define	SQUEUE_SWITCH(connp, new_sqp)				\
	(connp)->conn_sqp = new_sqp;

/*
 * Facility-special private data in squeues.
 */
typedef enum {
	SQPRIVATE_TCP,
	SQPRIVATE_MAX
} sqprivate_t;

struct ip_recv_attr_s;
extern void squeue_init(void);
extern squeue_t *squeue_create(clock_t, pri_t);
extern void squeue_bind(squeue_t *, processorid_t);
extern void squeue_unbind(squeue_t *);
extern void squeue_enter(squeue_t *, mblk_t *, mblk_t *,
    uint32_t, struct ip_recv_attr_s *, int, uint8_t);
extern uintptr_t *squeue_getprivate(squeue_t *, sqprivate_t);

struct conn_s;
extern int squeue_synch_enter(struct conn_s *, mblk_t *);
extern void squeue_synch_exit(struct conn_s *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SQUEUE_H */
