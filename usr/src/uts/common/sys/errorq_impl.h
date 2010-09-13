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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ERRORQ_IMPL_H
#define	_ERRORQ_IMPL_H

#include <sys/errorq.h>
#include <sys/dditypes.h>
#include <sys/kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct errorq_nvelem {
	void *eqn_buf;			/* data buf for this nv element */
	nvlist_t *eqn_nvl;		/* nvlist */
	nv_alloc_t *eqn_nva;		/* fixed nv allocator */
} errorq_nvelem_t;

struct errorq_elem {
	struct errorq_elem *eqe_next;		/* next on processing list */
	struct errorq_elem *eqe_prev;		/* prev on free or pend list */
	struct errorq_elem *eqe_dump;		/* next on crash dump list */
	void *eqe_data;				/* data for this element */
};

typedef struct errorq_kstat {
	kstat_named_t eqk_dispatched;		/* total errors dispatched */
	kstat_named_t eqk_dropped;		/* total errors dropped */
	kstat_named_t eqk_logged;		/* total errors logged */
	kstat_named_t eqk_reserved;		/* total errors reserved */
	kstat_named_t eqk_reserve_fail;		/* total reservation failures */
	kstat_named_t eqk_committed;		/* total errors committed */
	kstat_named_t eqk_commit_fail;		/* total commit failures */
	kstat_named_t eqk_cancelled;		/* total reserves cancelled */
} errorq_kstat_t;

/*
 * errorq implementation flags: bit range 16-31
 */
#define	ERRORQ_ACTIVE	0x00010000		/* queue is enabled */
#define	ERRORQ_NVLIST	0x00020000		/* nvlist queue */

#define	ERRORQ_NAMELEN	31			/* length of queue name */

struct errorq {
	char eq_name[ERRORQ_NAMELEN + 1];	/* string name for debugging */
	errorq_kstat_t eq_kstat;		/* kstat data (see above) */
	kstat_t *eq_ksp;			/* pointer to installed kstat */
	errorq_func_t eq_func;			/* drain callback */
	void *eq_private;			/* drain callback data */
	void *eq_data;				/* buffer of queue data */
	ulong_t eq_qlen;			/* maximum queue length */
	size_t eq_size;				/* size of element data */
	uint_t eq_ipl;				/* soft interrupt priority */
	uint_t eq_flags;			/* flags (see above) */
	ddi_softintr_t eq_id;			/* soft interrupt identifier */
	kmutex_t eq_lock;			/* consumer lock */
	errorq_elem_t *eq_elems;		/* array of all elements */
	errorq_elem_t *eq_phead;		/* head of processing list */
	errorq_elem_t *eq_ptail;		/* tail of processing list */
	errorq_elem_t *eq_pend;			/* list of pending errors */
	ulong_t *eq_bitmap;			/* bitmap of free elements */
	errorq_elem_t *eq_dump;			/* list of crash dump elem's */
	struct errorq *eq_next;			/* next errorq on global list */
	index_t eq_rotor;			/* best efforts bitmap rotor */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _ERRORQ_IMPL_H */
