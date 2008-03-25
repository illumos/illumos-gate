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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_KCPC_H
#define	_SYS_KCPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cpc_impl.h>
#include <sys/ksynch.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Kernel clients need this file in order to know what a request is and how to
 * program one.
 */

typedef struct _kcpc_set kcpc_set_t;

#ifdef _KERNEL

/*
 * Forward declarations.
 */
struct _kthread;
struct cpu;
typedef struct _kcpc_request kcpc_request_t;
struct __pcbe_ops;

#define	KCPC_SET_BOUND		0x0001		/* Used in ks_state */

struct _kcpc_set {
	int			ks_flags;
	int			ks_nreqs;	/* Number of reqs */
	kcpc_request_t		*ks_req;	/* Pointer to reqs */
	uint64_t		*ks_data;	/* Data store for this set */
	kcpc_ctx_t		*ks_ctx;	/* ctx this set belongs to */
	ushort_t		ks_state;	/* Set is bound or unbound */
	kmutex_t		ks_lock;	/* Protects ks_state */
	kcondvar_t		ks_condv;	/* Wait for bind to complete */
};

struct _kcpc_request {
	void			*kr_config;
	int			kr_index;	/* indx of data for this req */
	int			kr_picnum;	/* Number of phys pic */
	kcpc_pic_t		*kr_picp;	/* Ptr to PIC in context */
	uint64_t		*kr_data;	/* Ptr to virtual 64-bit pic */
	char			kr_event[CPC_MAX_EVENT_LEN];
	uint64_t		kr_preset;
	uint_t			kr_flags;
	uint_t			kr_nattrs;
	kcpc_attr_t		*kr_attr;
};

/*
 * Bind the set to the indicated thread.
 * Returns 0 on success, or an errno in case of error. If EINVAL is returned,
 * a specific error code will be returned in the subcode parameter.
 */
extern int kcpc_bind_thread(kcpc_set_t *set, struct _kthread *t, int *subcode);

/*
 * Bind the set to the indicated CPU.
 * Same return convention as kcpc_bind_thread().
 */
extern int kcpc_bind_cpu(kcpc_set_t *set, int cpuid, int *subcode);

/*
 * Request the system to sample the current state of the set into users buf.
 */
extern int kcpc_sample(kcpc_set_t *set, uint64_t *buf, hrtime_t *hrtime,
    uint64_t *tick);

/*
 * Unbind a request and release the associated resources.
 */
extern int kcpc_unbind(kcpc_set_t *set);

/*
 * Preset the indicated request's counter and underlying PCBE config to the
 * given value.
 */
extern int kcpc_preset(kcpc_set_t *set, int index, uint64_t preset);

/*
 * Unfreeze the set and get it counting again.
 */
extern int kcpc_restart(kcpc_set_t *set);

extern int kcpc_enable(struct _kthread *t, int cmd, int enable);

/*
 * Mark a thread's CPC context, if it exists, INVALID.
 */
extern void kcpc_invalidate(struct _kthread *t);

extern int kcpc_overflow_ast(void);
extern uint_t kcpc_hw_overflow_intr(caddr_t, caddr_t);
extern int kcpc_hw_cpu_hook(int cpuid, ulong_t *kcpc_cpumap);
extern int kcpc_hw_lwp_hook(void);
extern void kcpc_idle_save(struct cpu *cp);
extern void kcpc_idle_restore(struct cpu *cp);

extern krwlock_t	kcpc_cpuctx_lock;  /* lock for 'kcpc_cpuctx' below */
extern int		kcpc_cpuctx;	   /* number of cpu-specific contexts */

extern void kcpc_free_set(kcpc_set_t *set);

extern void *kcpc_next_config(void *token, void *current,
    uint64_t **data);
extern void kcpc_invalidate_config(void *token);

/*
 * Called by a PCBE to determine if nonprivileged access to counters should be
 * allowed. Returns non-zero if non-privileged access is allowed, 0 if not.
 */
extern int kcpc_allow_nonpriv(void *token);

extern void kcpc_register_pcbe(struct __pcbe_ops *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_KCPC_H */
