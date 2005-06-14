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

#ifndef	_SYS_SQUEUE_H
#define	_SYS_SQUEUE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#define	GET_SQUEUE(mp)		((conn_t *)((mp)->b_prev))->conn_sqp

/*
 * Facility-special private data in squeues.
 */
typedef enum {
	SQPRIVATE_TCP,
	SQPRIVATE_MAX
} sqprivate_t;

typedef void (*sqproc_t)(void *, mblk_t *, void *);

extern void squeue_init(void);
extern squeue_t *squeue_create(char *, processorid_t, clock_t, pri_t);
extern void squeue_bind(squeue_t *, processorid_t);
extern void squeue_unbind(squeue_t *);
extern void squeue_enter_chain(squeue_t *, mblk_t *, mblk_t *,
    uint32_t, uint8_t);
extern void squeue_enter(squeue_t *, mblk_t *, sqproc_t, void *, uint8_t);
extern void squeue_enter_nodrain(squeue_t *, mblk_t *, sqproc_t, void *,
    uint8_t);
extern void squeue_fill(squeue_t *, mblk_t *, sqproc_t, void *, uint8_t);
extern uintptr_t *squeue_getprivate(squeue_t *, sqprivate_t);
extern processorid_t squeue_binding(squeue_t *);

extern void squeue_profile_reset(squeue_t *);
extern void squeue_profile_enable(squeue_t *);
extern void squeue_profile_disable(squeue_t *);
extern void squeue_profile_stop(void);
extern void squeue_profile_start(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SQUEUE_H */
