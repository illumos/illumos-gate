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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_FMD_THREAD_H
#define	_FMD_THREAD_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_list.h>
#include <fmd_trace.h>

struct fmd_module;			/* see <fmd_module.h> */

typedef void fmd_thread_f(void *);	/* signature of thread startup func */

typedef struct fmd_thread {
	fmd_list_t thr_list;		/* linked-list next/prev pointers */
	struct fmd_module *thr_mod;	/* module associated with this thread */
	pthread_t thr_tid;		/* thread identifier */
	fmd_thread_f *thr_func;		/* thread startup function */
	void *thr_arg;			/* argument for startup function */
	fmd_tracebuf_t *thr_trdata;	/* thread trace buffer */
	fmd_tracebuf_f *thr_trfunc;	/* thread trace function */
	uint_t thr_errdepth;		/* fmd_verror() nesting depth */
	int thr_isdoor;			/* a private door server thread */
} fmd_thread_t;

extern fmd_thread_t *fmd_thread_xcreate(struct fmd_module *, pthread_t);
extern fmd_thread_t *fmd_thread_create(struct fmd_module *,
    fmd_thread_f *, void *);
extern fmd_thread_t *fmd_doorthread_create(struct fmd_module *,
    fmd_thread_f *, void *);

#define	FMD_THREAD_NOJOIN	0	/* do not attempt to join with thread */
#define	FMD_THREAD_JOIN		1	/* wait for and join with thread */

extern void fmd_thread_destroy(fmd_thread_t *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_THREAD_H */
