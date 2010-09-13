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

#ifndef _SYS_KCPC_H
#define	_SYS_KCPC_H

#include <sys/cpc_impl.h>
#include <sys/ksynch.h>
#include <sys/types.h>

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
	void			*kr_ptr;	/* Ptr assigned by requester */
};

typedef struct _kcpc_request_list {
	kcpc_request_t		*krl_list;	/* counter event requests */
	int			krl_cnt;	/* how many requests */
	int			krl_max;	/* max request entries */
} kcpc_request_list_t;

/*
 * Type of update function to be called when reading counters on current CPU in
 * kcpc_read()
 */
typedef int (*kcpc_update_func_t)(void *, uint64_t);

/*
 * Type of read function to be called when reading counters on current CPU
 * (ie. should be same type signature as kcpc_read())
 */
typedef int (*kcpc_read_func_t)(kcpc_update_func_t);


/*
 * Initialize the kcpc framework
 */
extern int kcpc_init(void);

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
 * Create CPC context containing specified list of requested counter events
 */
extern int kcpc_cpu_ctx_create(struct cpu *cp, kcpc_request_list_t *req_list,
    int kmem_flags, kcpc_ctx_t ***ctx_ptr_array, size_t *ctx_ptr_array_sz);

/*
 * Returns whether specified counter event is supported
 */
extern boolean_t kcpc_event_supported(char *event);

/*
 * Initialize list of CPC event requests
 */
extern kcpc_request_list_t *kcpc_reqs_init(int nreqs, int kmem_flags);

/*
 * Add counter event request to given list of counter event requests
 */
extern int kcpc_reqs_add(kcpc_request_list_t *req_list, char *event,
    uint64_t preset, uint_t flags, uint_t nattrs, kcpc_attr_t *attr, void *ptr,
    int kmem_flags);

/*
 * Reset list of CPC event requests so its space can be used for another set
 * of requests
 */
extern int kcpc_reqs_reset(kcpc_request_list_t *req_list);

/*
 * Free given list of counter event requests
 */
extern int kcpc_reqs_fini(kcpc_request_list_t *req_list);

/*
 * Read CPC data for given event on current CPU
 */
extern int kcpc_read(kcpc_update_func_t);

/*
 * Program current CPU with given CPC context
 */
extern void kcpc_program(kcpc_ctx_t *ctx, boolean_t for_thread,
    boolean_t cu_interpose);

/*
 * Unprogram CPC counters on current CPU
 */
extern void kcpc_unprogram(kcpc_ctx_t *ctx, boolean_t cu_interpose);

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

extern void kcpc_free(kcpc_ctx_t *ctx, int isexec);

/*
 * 'dtrace_cpc_in_use' contains the number of currently active cpc provider
 * based enablings. See the block comment in uts/common/os/dtrace_subr.c for
 * details of its actual usage.
 */
extern uint32_t		dtrace_cpc_in_use;
extern void (*dtrace_cpc_fire)(uint64_t);

extern void kcpc_free_set(kcpc_set_t *set);

extern void *kcpc_next_config(void *token, void *current,
    uint64_t **data);
extern void kcpc_invalidate_config(void *token);
extern char *kcpc_list_attrs(void);
extern char *kcpc_list_events(uint_t pic);
extern void kcpc_free_configs(kcpc_set_t *set);
extern uint_t kcpc_pcbe_capabilities(void);
extern int kcpc_pcbe_loaded(void);

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
