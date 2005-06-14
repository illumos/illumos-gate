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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_EVENTQ_H
#define	_FMD_EVENTQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_event.h>
#include <fmd_list.h>

typedef struct fmd_eventqelem {
	fmd_list_t eqe_list;		/* linked-list prev/next pointers */
	fmd_event_t *eqe_event;		/* pointer to event */
} fmd_eventqelem_t;

struct fmd_module;			/* see <fmd_module.h> */

typedef struct fmd_eventq {
	pthread_mutex_t eq_lock;	/* lock protecting queue contents */
	pthread_cond_t eq_cv;		/* condition variable for waiters */
	fmd_list_t eq_list;		/* list head/tail pointers for queue */
	struct fmd_module *eq_mod;	/* module associated with this queue */
	uint_t eq_limit;		/* limit on number of queue elements */
	uint_t eq_size;			/* number of elements on queue */
	uint_t eq_abort;		/* flag for fmd_eventq_abort() */
} fmd_eventq_t;

extern fmd_eventq_t *fmd_eventq_create(struct fmd_module *, uint_t);
extern void fmd_eventq_destroy(fmd_eventq_t *);
extern void fmd_eventq_insert_at_head(fmd_eventq_t *, fmd_event_t *);
extern void fmd_eventq_insert_at_time(fmd_eventq_t *, fmd_event_t *);
extern fmd_event_t *fmd_eventq_delete(fmd_eventq_t *);
extern void fmd_eventq_cancel(fmd_eventq_t *, uint_t, void *);
extern void fmd_eventq_abort(fmd_eventq_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_EVENTQ_H */
