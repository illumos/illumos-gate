/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#ifndef	_SYS_DDI_PERIODIC_H
#define	_SYS_DDI_PERIODIC_H

#include <sys/list.h>
#include <sys/taskq_impl.h>
#include <sys/cyclic.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Opaque handle type for i_timeout() and i_untimeout().
 */
typedef struct __timeout *timeout_t;

typedef enum ddi_periodic_flags {
	DPF_DISPATCHED = 0x01,
	DPF_EXECUTING = 0x02,
	DPF_CANCELLED = 0x04
} ddi_periodic_flags_t;

/*
 * Each instance of this structure represents a single periodic handler
 * registered through ddi_periodic_add(9F).
 */
typedef struct ddi_periodic_impl {
	struct list_node dpr_link; /* protected by periodics_lock */
	struct list_node dpr_softint_link; /* only used when DPF_DISPATCHED */
	id_t dpr_id;
	hrtime_t dpr_interval;

	kmutex_t dpr_lock;
	kcondvar_t dpr_cv;
	ddi_periodic_flags_t dpr_flags;
	uint_t dpr_level; /* 0 <= dpr_level <= 10 */
	taskq_ent_t dpr_taskq_ent; /* only used for level of 0 */
	uint64_t dpr_fire_count;
	kthread_t *dpr_thread;

	cyclic_id_t dpr_cyclic_id;

	void (*dpr_handler)(void *);
	void *dpr_arg;
} ddi_periodic_impl_t;

/*
 * Internal implementation functions for the DDI periodic interface.
 */
void ddi_periodic_init(void);
void ddi_periodic_fini(void);
void ddi_periodic_softintr(int level);
timeout_t i_timeout(void (*)(void *), void *, hrtime_t, int);
void i_untimeout(timeout_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_PERIODIC_H */
