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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SYS_TASKQ_IMPL_H
#define	_SYS_TASKQ_IMPL_H

#include <sys/taskq.h>
#include <sys/inttypes.h>
#include <sys/vmem.h>
#include <sys/list.h>
#include <sys/kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct taskq_ent {
	struct taskq_ent	*tqent_next;
	struct taskq_ent	*tqent_prev;
	task_func_t		*tqent_func;
	void			*tqent_arg;
	uintptr_t		tqent_flags;
} taskq_ent_t;

#define	TQENT_FLAG_PREALLOC	0x1	/* taskq_dispatch_ent used */

/* Special form of taskq dispatch that uses preallocated entries. */
void taskq_dispatch_ent(taskq_t *, task_func_t, void *, uint_t, taskq_ent_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TASKQ_IMPL_H */
