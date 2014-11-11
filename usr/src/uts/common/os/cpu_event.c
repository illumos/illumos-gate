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
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

/*
 * Introduction
 * This file implements a CPU event notification mechanism to signal clients
 * which are interested in CPU related events.
 * Currently it only supports CPU idle state change events which will be
 * triggered just before CPU entering hardware idle state and just after CPU
 * wakes up from hardware idle state.
 * Please refer to PSARC/2009/115 for detail information.
 *
 * Lock Strategy
 * 1) cpu_idle_prop_busy/free are protected by cpu_idle_prop_lock.
 * 2) No protection for cpu_idle_cb_state because it's per-CPU data.
 * 3) cpu_idle_cb_busy is protected by cpu_idle_cb_lock.
 * 4) cpu_idle_cb_array is protected by pause_cpus/start_cpus logic.
 * 5) cpu_idle_cb_max/curr are protected by both cpu_idle_cb_lock and
 *    pause_cpus/start_cpus logic.
 * We have optimized the algorithm for hot path on read side access.
 * In the current algorithm, it's lock free on read side access.
 * On write side, we use pause_cpus() to keep other CPUs in the pause thread,
 * which will guarantee that no other threads will access
 * cpu_idle_cb_max/curr/array data structure.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/cpu.h>
#include <sys/kmem.h>
#include <sys/machcpuvar.h>
#include <sys/sdt.h>
#include <sys/sysmacros.h>
#include <sys/synch.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#if defined(__sparc)
#include <sys/machsystm.h>
#elif defined(__x86)
#include <sys/archsystm.h>
#endif
#include <sys/cpu_event.h>

/* Define normal state for CPU on different platforms. */
#if defined(__x86)
#define	CPU_IDLE_STATE_NORMAL		IDLE_STATE_C0
#elif defined(__sparc)
/*
 * At the time of this implementation IDLE_STATE_NORMAL is defined
 * in mach_startup.c, and not in a header file.  So if we find it is
 * undefined, then we set it to the value as defined in mach_startup.c
 * Should it eventually be defined, we will pick it up.
 */
#ifndef	IDLE_STATE_NORMAL
#define	IDLE_STATE_NORMAL	0
#endif
#define	CPU_IDLE_STATE_NORMAL	IDLE_STATE_NORMAL
#endif

/*
 * To improve cache efficiency and avoid cache false sharing, CPU idle
 * properties are grouped into cache lines as below:
 * |     CPU0      |     CPU1      |.........|     CPUn      |
 * | cache line 0  | cache line 1  |.........| cache line n  |
 * | v0 | ... | vm | v0 | ... | vm |.........| v0 | ... | vm |
 * To access value of property m for CPU n, using following value as index:
 *    index = seq_id_of_CPUn * CPU_IDLE_VALUE_GROUP_SIZE + m.
 */
#define	CPU_IDLE_VALUE_GROUP_SIZE	\
	(CPU_CACHE_COHERENCE_SIZE / sizeof (cpu_idle_prop_value_t))

/* Get callback context handle for current CPU. */
#define	CPU_IDLE_GET_CTX(cp)		\
	((cpu_idle_callback_context_t)(intptr_t)((cp)->cpu_seqid))

/* Get CPU sequential id from ctx. */
#define	CPU_IDLE_CTX2CPUID(ctx)		((processorid_t)(intptr_t)(ctx))

/* Compute index from callback context handle. */
#define	CPU_IDLE_CTX2IDX(ctx)		\
	(((int)(intptr_t)(ctx)) * CPU_IDLE_VALUE_GROUP_SIZE)

#define	CPU_IDLE_HDL2VALP(hdl, idx)	\
	(&((cpu_idle_prop_impl_t *)(hdl))->value[(idx)])

/*
 * When cpu_idle_cb_array is NULL or full, increase CPU_IDLE_ARRAY_CAPACITY_INC
 * entries every time. Here we prefer linear growth instead of exponential.
 */
#define	CPU_IDLE_ARRAY_CAPACITY_INC	0x10

typedef struct cpu_idle_prop_impl {
	cpu_idle_prop_value_t		*value;
	struct cpu_idle_prop_impl	*next;
	char				*name;
	cpu_idle_prop_update_t		update;
	void				*private;
	cpu_idle_prop_type_t		type;
	uint32_t			refcnt;
} cpu_idle_prop_impl_t;

typedef struct cpu_idle_prop_item {
	cpu_idle_prop_type_t		type;
	char				*name;
	cpu_idle_prop_update_t		update;
	void				*arg;
	cpu_idle_prop_handle_t		handle;
} cpu_idle_prop_item_t;

/* Structure to maintain registered callbacks in list. */
typedef struct cpu_idle_cb_impl {
	struct cpu_idle_cb_impl		*next;
	cpu_idle_callback_t		*callback;
	void				*argument;
	int				priority;
} cpu_idle_cb_impl_t;

/*
 * Structure to maintain registered callbacks in priority order and also
 * optimized for cache efficiency for reading access.
 */
typedef struct cpu_idle_cb_item {
	cpu_idle_enter_cbfn_t		enter;
	cpu_idle_exit_cbfn_t		exit;
	void				*arg;
	cpu_idle_cb_impl_t		*impl;
} cpu_idle_cb_item_t;

/* Per-CPU state aligned to CPU_CACHE_COHERENCE_SIZE to avoid false sharing. */
typedef union cpu_idle_cb_state {
	struct {
		/* Index of already invoked callbacks. */
		int			index;
		/* Invoke registered callbacks if true. */
		boolean_t		enabled;
		/* Property values are valid if true. */
		boolean_t		ready;
		/* Pointers to per-CPU properties. */
		cpu_idle_prop_value_t	*idle_state;
		cpu_idle_prop_value_t	*enter_ts;
		cpu_idle_prop_value_t	*exit_ts;
		cpu_idle_prop_value_t	*last_idle;
		cpu_idle_prop_value_t	*last_busy;
		cpu_idle_prop_value_t	*total_idle;
		cpu_idle_prop_value_t	*total_busy;
		cpu_idle_prop_value_t	*intr_cnt;
	} v;
#ifdef _LP64
	char				align[2 * CPU_CACHE_COHERENCE_SIZE];
#else
	char				align[CPU_CACHE_COHERENCE_SIZE];
#endif
} cpu_idle_cb_state_t;

static kmutex_t				cpu_idle_prop_lock;
static cpu_idle_prop_impl_t		*cpu_idle_prop_busy = NULL;
static cpu_idle_prop_impl_t		*cpu_idle_prop_free = NULL;

static kmutex_t				cpu_idle_cb_lock;
static cpu_idle_cb_impl_t		*cpu_idle_cb_busy = NULL;
static cpu_idle_cb_item_t		*cpu_idle_cb_array = NULL;
static int				cpu_idle_cb_curr = 0;
static int				cpu_idle_cb_max = 0;

static cpu_idle_cb_state_t		*cpu_idle_cb_state;

#ifdef	__x86
/*
 * cpuset used to intercept CPUs before powering them off.
 * The control CPU sets the bit corresponding to the target CPU and waits
 * until the bit is cleared.
 * The target CPU disables interrupts before clearing corresponding bit and
 * then loops for ever.
 */
static cpuset_t				cpu_idle_intercept_set;
#endif

static int cpu_idle_prop_update_intr_cnt(void *arg, uint64_t seqnum,
    cpu_idle_prop_value_t *valp);

static cpu_idle_prop_item_t cpu_idle_prop_array[] = {
	{
	    CPU_IDLE_PROP_TYPE_INTPTR, CPU_IDLE_PROP_IDLE_STATE,
	    NULL, NULL, NULL
	},
	{
	    CPU_IDLE_PROP_TYPE_HRTIME, CPU_IDLE_PROP_ENTER_TIMESTAMP,
	    NULL, NULL, NULL
	},
	{
	    CPU_IDLE_PROP_TYPE_HRTIME, CPU_IDLE_PROP_EXIT_TIMESTAMP,
	    NULL, NULL, NULL
	},
	{
	    CPU_IDLE_PROP_TYPE_HRTIME, CPU_IDLE_PROP_LAST_IDLE_TIME,
	    NULL, NULL, NULL
	},
	{
	    CPU_IDLE_PROP_TYPE_HRTIME, CPU_IDLE_PROP_LAST_BUSY_TIME,
	    NULL, NULL, NULL
	},
	{
	    CPU_IDLE_PROP_TYPE_HRTIME, CPU_IDLE_PROP_TOTAL_IDLE_TIME,
	    NULL, NULL, NULL
	},
	{
	    CPU_IDLE_PROP_TYPE_HRTIME, CPU_IDLE_PROP_TOTAL_BUSY_TIME,
	    NULL, NULL, NULL
	},
	{
	    CPU_IDLE_PROP_TYPE_UINT64, CPU_IDLE_PROP_INTERRUPT_COUNT,
	    cpu_idle_prop_update_intr_cnt, NULL, NULL
	},
};

#define	CPU_IDLE_PROP_IDX_IDLE_STATE	0
#define	CPU_IDLE_PROP_IDX_ENTER_TS	1
#define	CPU_IDLE_PROP_IDX_EXIT_TS	2
#define	CPU_IDLE_PROP_IDX_LAST_IDLE	3
#define	CPU_IDLE_PROP_IDX_LAST_BUSY	4
#define	CPU_IDLE_PROP_IDX_TOTAL_IDLE	5
#define	CPU_IDLE_PROP_IDX_TOTAL_BUSY	6
#define	CPU_IDLE_PROP_IDX_INTR_CNT	7

/*ARGSUSED*/
static void
cpu_idle_dtrace_enter(void *arg, cpu_idle_callback_context_t ctx,
    cpu_idle_check_wakeup_t check_func, void *check_arg)
{
	int state;

	state = cpu_idle_prop_get_intptr(
	    cpu_idle_prop_array[CPU_IDLE_PROP_IDX_IDLE_STATE].handle, ctx);
	DTRACE_PROBE1(idle__state__transition, uint_t, state);
}

/*ARGSUSED*/
static void
cpu_idle_dtrace_exit(void *arg, cpu_idle_callback_context_t ctx, int flag)
{
	DTRACE_PROBE1(idle__state__transition, uint_t, CPU_IDLE_STATE_NORMAL);
}

static cpu_idle_callback_handle_t cpu_idle_cb_handle_dtrace;
static cpu_idle_callback_t cpu_idle_callback_dtrace = {
	CPU_IDLE_CALLBACK_VERS,
	cpu_idle_dtrace_enter,
	cpu_idle_dtrace_exit,
};

#if defined(__x86) && !defined(__xpv)
extern void tlb_going_idle(void);
extern void tlb_service(void);

static cpu_idle_callback_handle_t cpu_idle_cb_handle_tlb;
static cpu_idle_callback_t cpu_idle_callback_tlb = {
	CPU_IDLE_CALLBACK_VERS,
	(cpu_idle_enter_cbfn_t)tlb_going_idle,
	(cpu_idle_exit_cbfn_t)tlb_service,
};
#endif

void
cpu_event_init(void)
{
	int i, idx;
	size_t sz;
	intptr_t buf;
	cpu_idle_cb_state_t *sp;
	cpu_idle_prop_item_t *ip;

	mutex_init(&cpu_idle_cb_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&cpu_idle_prop_lock, NULL, MUTEX_DRIVER, NULL);

	/* Create internal properties. */
	for (i = 0, ip = cpu_idle_prop_array;
	    i < sizeof (cpu_idle_prop_array) / sizeof (cpu_idle_prop_array[0]);
	    i++, ip++) {
		(void) cpu_idle_prop_create_property(ip->name, ip->type,
		    ip->update, ip->arg, &ip->handle);
		ASSERT(ip->handle != NULL);
	}

	/* Allocate buffer and align to CPU_CACHE_COHERENCE_SIZE. */
	sz = sizeof (cpu_idle_cb_state_t) * max_ncpus;
	sz += CPU_CACHE_COHERENCE_SIZE;
	buf = (intptr_t)kmem_zalloc(sz, KM_SLEEP);
	cpu_idle_cb_state = (cpu_idle_cb_state_t *)P2ROUNDUP(buf,
	    CPU_CACHE_COHERENCE_SIZE);

	/* Cache frequently used property value pointers. */
	for (sp = cpu_idle_cb_state, i = 0; i < max_ncpus; i++, sp++) {
		idx = CPU_IDLE_CTX2IDX(i);
#define	___INIT_P(f, i)	\
	sp->v.f = CPU_IDLE_HDL2VALP(cpu_idle_prop_array[(i)].handle, idx)
		___INIT_P(idle_state, CPU_IDLE_PROP_IDX_IDLE_STATE);
		___INIT_P(enter_ts, CPU_IDLE_PROP_IDX_ENTER_TS);
		___INIT_P(exit_ts, CPU_IDLE_PROP_IDX_EXIT_TS);
		___INIT_P(last_idle, CPU_IDLE_PROP_IDX_LAST_IDLE);
		___INIT_P(last_busy, CPU_IDLE_PROP_IDX_LAST_BUSY);
		___INIT_P(total_idle, CPU_IDLE_PROP_IDX_TOTAL_IDLE);
		___INIT_P(total_busy, CPU_IDLE_PROP_IDX_TOTAL_BUSY);
		___INIT_P(last_idle, CPU_IDLE_PROP_IDX_INTR_CNT);
#undef	___INIT_P
	}

	/* Register built-in callbacks. */
	if (cpu_idle_register_callback(CPU_IDLE_CB_PRIO_DTRACE,
	    &cpu_idle_callback_dtrace, NULL, &cpu_idle_cb_handle_dtrace) != 0) {
		cmn_err(CE_PANIC,
		    "cpu_idle: failed to register callback for dtrace.");
	}
#if defined(__x86) && !defined(__xpv)
	if (cpu_idle_register_callback(CPU_IDLE_CB_PRIO_TLB,
	    &cpu_idle_callback_tlb, NULL, &cpu_idle_cb_handle_tlb) != 0) {
		cmn_err(CE_PANIC,
		    "cpu_idle: failed to register callback for tlb_flush.");
	}
#endif
}

/*
 * This function is called to initialize per CPU state when starting CPUs.
 */
void
cpu_event_init_cpu(cpu_t *cp)
{
	ASSERT(cp->cpu_seqid < max_ncpus);
	cpu_idle_cb_state[cp->cpu_seqid].v.index = 0;
	cpu_idle_cb_state[cp->cpu_seqid].v.ready = B_FALSE;
	cpu_idle_cb_state[cp->cpu_seqid].v.enabled = B_TRUE;
}

/*
 * This function is called to clean up per CPU state when stopping CPUs.
 */
void
cpu_event_fini_cpu(cpu_t *cp)
{
	ASSERT(cp->cpu_seqid < max_ncpus);
	cpu_idle_cb_state[cp->cpu_seqid].v.enabled = B_FALSE;
	cpu_idle_cb_state[cp->cpu_seqid].v.ready = B_FALSE;
}

static void
cpu_idle_insert_callback(cpu_idle_cb_impl_t *cip)
{
	int unlock = 0, unpause = 0;
	int i, cnt_new = 0, cnt_old = 0;
	char *buf_new = NULL, *buf_old = NULL;

	ASSERT(MUTEX_HELD(&cpu_idle_cb_lock));

	/*
	 * Expand array if it's full.
	 * Memory must be allocated out of pause/start_cpus() scope because
	 * kmem_zalloc() can't be called with KM_SLEEP flag within that scope.
	 */
	if (cpu_idle_cb_curr == cpu_idle_cb_max) {
		cnt_new = cpu_idle_cb_max + CPU_IDLE_ARRAY_CAPACITY_INC;
		buf_new = (char *)kmem_zalloc(cnt_new *
		    sizeof (cpu_idle_cb_item_t), KM_SLEEP);
	}

	/* Try to acquire cpu_lock if not held yet. */
	if (!MUTEX_HELD(&cpu_lock)) {
		mutex_enter(&cpu_lock);
		unlock = 1;
	}
	/*
	 * Pause all other CPUs (and let them run pause thread).
	 * It's guaranteed that no other threads will access cpu_idle_cb_array
	 * after pause_cpus().
	 */
	if (!cpus_paused()) {
		pause_cpus(NULL, NULL);
		unpause = 1;
	}

	/* Copy content to new buffer if needed. */
	if (buf_new != NULL) {
		buf_old = (char *)cpu_idle_cb_array;
		cnt_old = cpu_idle_cb_max;
		if (buf_old != NULL) {
			ASSERT(cnt_old != 0);
			bcopy(cpu_idle_cb_array, buf_new,
			    sizeof (cpu_idle_cb_item_t) * cnt_old);
		}
		cpu_idle_cb_array = (cpu_idle_cb_item_t *)buf_new;
		cpu_idle_cb_max = cnt_new;
	}

	/* Insert into array according to priority. */
	ASSERT(cpu_idle_cb_curr < cpu_idle_cb_max);
	for (i = cpu_idle_cb_curr; i > 0; i--) {
		if (cpu_idle_cb_array[i - 1].impl->priority >= cip->priority) {
			break;
		}
		cpu_idle_cb_array[i] = cpu_idle_cb_array[i - 1];
	}
	cpu_idle_cb_array[i].arg = cip->argument;
	cpu_idle_cb_array[i].enter = cip->callback->idle_enter;
	cpu_idle_cb_array[i].exit = cip->callback->idle_exit;
	cpu_idle_cb_array[i].impl = cip;
	cpu_idle_cb_curr++;

	/* Resume other CPUs from paused state if needed. */
	if (unpause) {
		start_cpus();
	}
	if (unlock) {
		mutex_exit(&cpu_lock);
	}

	/* Free old resource if needed. */
	if (buf_old != NULL) {
		ASSERT(cnt_old != 0);
		kmem_free(buf_old, cnt_old * sizeof (cpu_idle_cb_item_t));
	}
}

static void
cpu_idle_remove_callback(cpu_idle_cb_impl_t *cip)
{
	int i, found = 0;
	int unlock = 0, unpause = 0;
	cpu_idle_cb_state_t *sp;

	ASSERT(MUTEX_HELD(&cpu_idle_cb_lock));

	/* Try to acquire cpu_lock if not held yet. */
	if (!MUTEX_HELD(&cpu_lock)) {
		mutex_enter(&cpu_lock);
		unlock = 1;
	}
	/*
	 * Pause all other CPUs.
	 * It's guaranteed that no other threads will access cpu_idle_cb_array
	 * after pause_cpus().
	 */
	if (!cpus_paused()) {
		pause_cpus(NULL, NULL);
		unpause = 1;
	}

	/* Remove cip from array. */
	for (i = 0; i < cpu_idle_cb_curr; i++) {
		if (found == 0) {
			if (cpu_idle_cb_array[i].impl == cip) {
				found = 1;
			}
		} else {
			cpu_idle_cb_array[i - 1] = cpu_idle_cb_array[i];
		}
	}
	ASSERT(found != 0);
	cpu_idle_cb_curr--;

	/*
	 * Reset property ready flag for all CPUs if no registered callback
	 * left because cpu_idle_enter/exit will stop updating property if
	 * there's no callback registered.
	 */
	if (cpu_idle_cb_curr == 0) {
		for (sp = cpu_idle_cb_state, i = 0; i < max_ncpus; i++, sp++) {
			sp->v.ready = B_FALSE;
		}
	}

	/* Resume other CPUs from paused state if needed. */
	if (unpause) {
		start_cpus();
	}
	if (unlock) {
		mutex_exit(&cpu_lock);
	}
}

int
cpu_idle_register_callback(uint_t prio, cpu_idle_callback_t *cbp,
    void *arg, cpu_idle_callback_handle_t *hdlp)
{
	cpu_idle_cb_state_t *sp;
	cpu_idle_cb_impl_t *cip = NULL;

	/* First validate parameters. */
	ASSERT(!CPU_ON_INTR(CPU));
	ASSERT(CPU->cpu_seqid < max_ncpus);
	sp = &cpu_idle_cb_state[CPU->cpu_seqid];
	if (sp->v.index != 0) {
		cmn_err(CE_NOTE,
		    "!cpu_event: register_callback called from callback.");
		return (EBUSY);
	} else if (cbp == NULL || hdlp == NULL) {
		cmn_err(CE_NOTE,
		    "!cpu_event: NULL parameters in register_callback.");
		return (EINVAL);
	} else if (prio < CPU_IDLE_CB_PRIO_LOW_BASE ||
	    prio >= CPU_IDLE_CB_PRIO_RESV_BASE) {
		cmn_err(CE_NOTE,
		    "!cpu_event: priority 0x%x out of range.", prio);
		return (EINVAL);
	} else if (cbp->version != CPU_IDLE_CALLBACK_VERS) {
		cmn_err(CE_NOTE,
		    "!cpu_event: callback version %d is not supported.",
		    cbp->version);
		return (EINVAL);
	}

	mutex_enter(&cpu_idle_cb_lock);
	/* Check whether callback with priority exists if not dynamic. */
	if (prio != CPU_IDLE_CB_PRIO_DYNAMIC) {
		for (cip = cpu_idle_cb_busy; cip != NULL;
		    cip = cip->next) {
			if (cip->priority == prio) {
				mutex_exit(&cpu_idle_cb_lock);
				cmn_err(CE_NOTE, "!cpu_event: callback with "
				    "priority 0x%x already exists.", prio);
				return (EEXIST);
			}
		}
	}

	cip = kmem_zalloc(sizeof (*cip), KM_SLEEP);
	cip->callback = cbp;
	cip->argument = arg;
	cip->priority = prio;
	cip->next = cpu_idle_cb_busy;
	cpu_idle_cb_busy = cip;
	cpu_idle_insert_callback(cip);
	mutex_exit(&cpu_idle_cb_lock);

	*hdlp = (cpu_idle_callback_handle_t)cip;

	return (0);
}

int
cpu_idle_unregister_callback(cpu_idle_callback_handle_t hdl)
{
	int rc = ENODEV;
	cpu_idle_cb_state_t *sp;
	cpu_idle_cb_impl_t *ip, **ipp;

	ASSERT(!CPU_ON_INTR(CPU));
	ASSERT(CPU->cpu_seqid < max_ncpus);
	sp = &cpu_idle_cb_state[CPU->cpu_seqid];
	if (sp->v.index != 0) {
		cmn_err(CE_NOTE,
		    "!cpu_event: unregister_callback called from callback.");
		return (EBUSY);
	} else if (hdl == NULL) {
		cmn_err(CE_NOTE,
		    "!cpu_event: hdl is NULL in unregister_callback.");
		return (EINVAL);
	}

	ip = (cpu_idle_cb_impl_t *)hdl;
	mutex_enter(&cpu_idle_cb_lock);
	for (ipp = &cpu_idle_cb_busy; *ipp != NULL; ipp = &(*ipp)->next) {
		if (*ipp == ip) {
			*ipp = ip->next;
			cpu_idle_remove_callback(ip);
			rc = 0;
			break;
		}
	}
	mutex_exit(&cpu_idle_cb_lock);

	if (rc == 0) {
		kmem_free(ip, sizeof (*ip));
	} else {
		cmn_err(CE_NOTE,
		    "!cpu_event: callback handle %p not found.", (void *)hdl);
	}

	return (rc);
}

static int
cpu_idle_enter_state(cpu_idle_cb_state_t *sp, intptr_t state)
{
	sp->v.idle_state->cipv_intptr = state;
	sp->v.enter_ts->cipv_hrtime = gethrtime_unscaled();
	sp->v.last_busy->cipv_hrtime = sp->v.enter_ts->cipv_hrtime -
	    sp->v.exit_ts->cipv_hrtime;
	sp->v.total_busy->cipv_hrtime += sp->v.last_busy->cipv_hrtime;
	if (sp->v.ready == B_FALSE) {
		sp->v.ready = B_TRUE;
		return (0);
	}

	return (1);
}

static void
cpu_idle_exit_state(cpu_idle_cb_state_t *sp)
{
	sp->v.idle_state->cipv_intptr = CPU_IDLE_STATE_NORMAL;
	sp->v.exit_ts->cipv_hrtime = gethrtime_unscaled();
	sp->v.last_idle->cipv_hrtime = sp->v.exit_ts->cipv_hrtime -
	    sp->v.enter_ts->cipv_hrtime;
	sp->v.total_idle->cipv_hrtime += sp->v.last_idle->cipv_hrtime;
}

/*ARGSUSED*/
int
cpu_idle_enter(int state, int flag,
    cpu_idle_check_wakeup_t check_func, void *check_arg)
{
	int i;
	cpu_idle_cb_item_t *cip;
	cpu_idle_cb_state_t *sp;
	cpu_idle_callback_context_t ctx;
#if defined(__x86)
	ulong_t iflags;
#endif

	ctx = CPU_IDLE_GET_CTX(CPU);
	ASSERT(CPU->cpu_seqid < max_ncpus);
	sp = &cpu_idle_cb_state[CPU->cpu_seqid];
	ASSERT(sp->v.index == 0);
	if (sp->v.enabled == B_FALSE) {
#if defined(__x86)
		/* Intercept CPU at a safe point before powering off it. */
		if (CPU_IN_SET(cpu_idle_intercept_set, CPU->cpu_id)) {
			iflags = intr_clear();
			CPUSET_ATOMIC_DEL(cpu_idle_intercept_set, CPU->cpu_id);
			/*CONSTCOND*/
			while (1) {
				SMT_PAUSE();
			}
		}
#endif

		return (0);
	}

	/*
	 * On x86, cpu_idle_enter can be called from idle thread with either
	 * interrupts enabled or disabled, so we need to make sure interrupts
	 * are disabled here.
	 * On SPARC, cpu_idle_enter will be called from idle thread with
	 * interrupt disabled, so no special handling necessary.
	 */
#if defined(__x86)
	iflags = intr_clear();
#endif

	/* Skip calling callback if state is not ready for current CPU. */
	if (cpu_idle_enter_state(sp, state) == 0) {
#if defined(__x86)
		intr_restore(iflags);
#endif
		return (0);
	}

	for (i = 0, cip = cpu_idle_cb_array; i < cpu_idle_cb_curr; i++, cip++) {
		/*
		 * Increase index so corresponding idle_exit callback
		 * will be invoked should interrupt happen during
		 * idle_enter callback.
		 */
		sp->v.index++;

		/* Call idle_enter callback function if it's not NULL. */
		if (cip->enter != NULL) {
			cip->enter(cip->arg, ctx, check_func, check_arg);

			/*
			 * cpu_idle_enter runs with interrupts
			 * disabled, so the idle_enter callbacks will
			 * also be called with interrupts disabled.
			 * It is permissible for the callbacks to
			 * enable the interrupts, if they can also
			 * handle the condition if the interrupt
			 * occurs.
			 *
			 * However, if an interrupt occurs and we
			 * return here without dealing with it, we
			 * return to the cpu_idle_enter() caller
			 * with an EBUSY, and the caller will not
			 * enter the idle state.
			 *
			 * We detect the interrupt, by checking the
			 * index value of the state pointer.  If it
			 * is not the index we incremented above,
			 * then it was cleared while processing
			 * the interrupt.
			 *
			 * Also note, that at this point of the code
			 * the normal index value will be one greater
			 * than the variable 'i' in the loop, as it
			 * hasn't yet been incremented.
			 */
			if (sp->v.index != i + 1) {
#if defined(__x86)
				intr_restore(iflags);
#endif
				return (EBUSY);
			}
		}
	}
#if defined(__x86)
	intr_restore(iflags);
#endif

	return (0);
}

void
cpu_idle_exit(int flag)
{
	int i;
	cpu_idle_cb_item_t *cip;
	cpu_idle_cb_state_t *sp;
	cpu_idle_callback_context_t ctx;
#if defined(__x86)
	ulong_t iflags;
#endif

	ASSERT(CPU->cpu_seqid < max_ncpus);
	sp = &cpu_idle_cb_state[CPU->cpu_seqid];

#if defined(__sparc)
	/*
	 * On SPARC, cpu_idle_exit will only be called from idle thread
	 * with interrupt disabled.
	 */

	if (sp->v.index != 0) {
		ctx = CPU_IDLE_GET_CTX(CPU);
		cpu_idle_exit_state(sp);
		for (i = sp->v.index - 1; i >= 0; i--) {
			cip = &cpu_idle_cb_array[i];
			if (cip->exit != NULL) {
				cip->exit(cip->arg, ctx, flag);
			}
		}
		sp->v.index = 0;
	}
#elif defined(__x86)
	/*
	 * On x86, cpu_idle_exit will be called from idle thread or interrupt
	 * handler. When called from interrupt handler, interrupts will be
	 * disabled. When called from idle thread, interrupts may be disabled
	 * or enabled.
	 */

	/* Called from interrupt, interrupts are already disabled. */
	if (flag & CPU_IDLE_CB_FLAG_INTR) {
		/*
		 * return if cpu_idle_exit already called or
		 * there is no registered callback.
		 */
		if (sp->v.index == 0) {
			return;
		}
		ctx = CPU_IDLE_GET_CTX(CPU);
		cpu_idle_exit_state(sp);
		for (i = sp->v.index - 1; i >= 0; i--) {
			cip = &cpu_idle_cb_array[i];
			if (cip->exit != NULL) {
				cip->exit(cip->arg, ctx, flag);
			}
		}
		sp->v.index = 0;

	/* Called from idle thread, need to disable interrupt. */
	} else {
		iflags = intr_clear();
		if (sp->v.index != 0) {
			ctx = CPU_IDLE_GET_CTX(CPU);
			cpu_idle_exit_state(sp);
			for (i = sp->v.index - 1; i >= 0; i--) {
				cip = &cpu_idle_cb_array[i];
				if (cip->exit != NULL) {
					cip->exit(cip->arg, ctx, flag);
				}
			}
			sp->v.index = 0;
		}
		intr_restore(iflags);
	}
#endif
}

cpu_idle_callback_context_t
cpu_idle_get_context(void)
{
	return (CPU_IDLE_GET_CTX(CPU));
}

/*
 * Allocate property structure in group of CPU_IDLE_VALUE_GROUP_SIZE to improve
 * cache efficiency. To simplify implementation, allocated memory for property
 * structure won't be freed.
 */
static void
cpu_idle_prop_allocate_impl(void)
{
	int i;
	size_t sz;
	intptr_t buf;
	cpu_idle_prop_impl_t *prop;
	cpu_idle_prop_value_t *valp;

	ASSERT(!CPU_ON_INTR(CPU));
	prop = kmem_zalloc(sizeof (*prop) * CPU_IDLE_VALUE_GROUP_SIZE,
	    KM_SLEEP);
	sz = sizeof (*valp) * CPU_IDLE_VALUE_GROUP_SIZE * max_ncpus;
	sz += CPU_CACHE_COHERENCE_SIZE;
	buf = (intptr_t)kmem_zalloc(sz, KM_SLEEP);
	valp = (cpu_idle_prop_value_t *)P2ROUNDUP(buf,
	    CPU_CACHE_COHERENCE_SIZE);

	for (i = 0; i < CPU_IDLE_VALUE_GROUP_SIZE; i++, prop++, valp++) {
		prop->value = valp;
		prop->next = cpu_idle_prop_free;
		cpu_idle_prop_free = prop;
	}
}

int
cpu_idle_prop_create_property(const char *name, cpu_idle_prop_type_t type,
    cpu_idle_prop_update_t update, void *arg, cpu_idle_prop_handle_t *hdlp)
{
	int rc = EEXIST;
	cpu_idle_prop_impl_t *prop;

	ASSERT(!CPU_ON_INTR(CPU));
	if (name == NULL || hdlp == NULL) {
		cmn_err(CE_WARN,
		    "!cpu_event: NULL parameters in create_property.");
		return (EINVAL);
	}

	mutex_enter(&cpu_idle_prop_lock);
	for (prop = cpu_idle_prop_busy; prop != NULL; prop = prop->next) {
		if (strcmp(prop->name, name) == 0) {
			cmn_err(CE_NOTE,
			    "!cpu_event: property %s already exists.", name);
			break;
		}
	}
	if (prop == NULL) {
		if (cpu_idle_prop_free == NULL) {
			cpu_idle_prop_allocate_impl();
		}
		ASSERT(cpu_idle_prop_free != NULL);
		prop = cpu_idle_prop_free;
		cpu_idle_prop_free = prop->next;
		prop->next = cpu_idle_prop_busy;
		cpu_idle_prop_busy = prop;

		ASSERT(prop->value != NULL);
		prop->name = strdup(name);
		prop->type = type;
		prop->update = update;
		prop->private = arg;
		prop->refcnt = 1;
		*hdlp = prop;
		rc = 0;
	}
	mutex_exit(&cpu_idle_prop_lock);

	return (rc);
}

int
cpu_idle_prop_destroy_property(cpu_idle_prop_handle_t hdl)
{
	int rc = ENODEV;
	cpu_idle_prop_impl_t *prop, **propp;
	cpu_idle_prop_value_t *valp;

	ASSERT(!CPU_ON_INTR(CPU));
	if (hdl == NULL) {
		cmn_err(CE_WARN,
		    "!cpu_event: hdl is NULL in destroy_property.");
		return (EINVAL);
	}

	prop = (cpu_idle_prop_impl_t *)hdl;
	mutex_enter(&cpu_idle_prop_lock);
	for (propp = &cpu_idle_prop_busy; *propp != NULL;
	    propp = &(*propp)->next) {
		if (*propp == prop) {
			ASSERT(prop->refcnt > 0);
			if (atomic_cas_32(&prop->refcnt, 1, 0) == 1) {
				*propp = prop->next;
				strfree(prop->name);
				valp = prop->value;
				bzero(prop, sizeof (*prop));
				prop->value = valp;
				prop->next = cpu_idle_prop_free;
				cpu_idle_prop_free = prop;
				rc = 0;
			} else {
				rc = EBUSY;
			}
			break;
		}
	}
	mutex_exit(&cpu_idle_prop_lock);

	return (rc);
}

int
cpu_idle_prop_create_handle(const char *name, cpu_idle_prop_handle_t *hdlp)
{
	int rc = ENODEV;
	cpu_idle_prop_impl_t *prop;

	ASSERT(!CPU_ON_INTR(CPU));
	if (name == NULL || hdlp == NULL) {
		cmn_err(CE_WARN,
		    "!cpu_event: NULL parameters in create_handle.");
		return (EINVAL);
	}

	mutex_enter(&cpu_idle_prop_lock);
	for (prop = cpu_idle_prop_busy; prop != NULL; prop = prop->next) {
		if (strcmp(prop->name, name) == 0) {
			/* Hold one refcount on object. */
			ASSERT(prop->refcnt > 0);
			atomic_inc_32(&prop->refcnt);
			*hdlp = (cpu_idle_prop_handle_t)prop;
			rc = 0;
			break;
		}
	}
	mutex_exit(&cpu_idle_prop_lock);

	return (rc);
}

int
cpu_idle_prop_destroy_handle(cpu_idle_prop_handle_t hdl)
{
	int rc = ENODEV;
	cpu_idle_prop_impl_t *prop;

	ASSERT(!CPU_ON_INTR(CPU));
	if (hdl == NULL) {
		cmn_err(CE_WARN,
		    "!cpu_event: hdl is NULL in destroy_handle.");
		return (EINVAL);
	}

	mutex_enter(&cpu_idle_prop_lock);
	for (prop = cpu_idle_prop_busy; prop != NULL; prop = prop->next) {
		if (prop == hdl) {
			/* Release refcnt held in create_handle. */
			ASSERT(prop->refcnt > 1);
			atomic_dec_32(&prop->refcnt);
			rc = 0;
			break;
		}
	}
	mutex_exit(&cpu_idle_prop_lock);

	return (rc);
}

cpu_idle_prop_type_t
cpu_idle_prop_get_type(cpu_idle_prop_handle_t hdl)
{
	ASSERT(hdl != NULL);
	return (((cpu_idle_prop_impl_t *)hdl)->type);
}

const char *
cpu_idle_prop_get_name(cpu_idle_prop_handle_t hdl)
{
	ASSERT(hdl != NULL);
	return (((cpu_idle_prop_impl_t *)hdl)->name);
}

int
cpu_idle_prop_get_value(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx, cpu_idle_prop_value_t *valp)
{
	int idx, rc = 0;
	cpu_idle_prop_impl_t *prop = (cpu_idle_prop_impl_t *)hdl;

	ASSERT(CPU_IDLE_CTX2CPUID(ctx) < max_ncpus);
	if (hdl == NULL || valp == NULL) {
		cmn_err(CE_NOTE, "!cpu_event: NULL parameters in prop_get.");
		return (EINVAL);
	}
	idx = CPU_IDLE_CTX2IDX(ctx);
	if (prop->update != NULL) {
		cpu_idle_cb_state_t *sp;

		ASSERT(CPU->cpu_seqid < max_ncpus);
		sp = &cpu_idle_cb_state[CPU->cpu_seqid];
		/* CPU's idle enter timestamp as sequence number. */
		rc = prop->update(prop->private,
		    (uint64_t)sp->v.enter_ts->cipv_hrtime, &prop->value[idx]);
	}
	if (rc == 0) {
		*valp = prop->value[idx];
	}

	return (rc);
}

uint32_t
cpu_idle_prop_get_uint32(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx)
{
	int idx;
	cpu_idle_prop_impl_t *prop = (cpu_idle_prop_impl_t *)hdl;

	ASSERT(hdl != NULL);
	ASSERT(CPU_IDLE_CTX2CPUID(ctx) < max_ncpus);
	idx = CPU_IDLE_CTX2IDX(ctx);
	return (prop->value[idx].cipv_uint32);
}

uint64_t
cpu_idle_prop_get_uint64(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx)
{
	int idx;
	cpu_idle_prop_impl_t *prop = (cpu_idle_prop_impl_t *)hdl;

	ASSERT(hdl != NULL);
	ASSERT(CPU_IDLE_CTX2CPUID(ctx) < max_ncpus);
	idx = CPU_IDLE_CTX2IDX(ctx);
	return (prop->value[idx].cipv_uint64);
}

intptr_t
cpu_idle_prop_get_intptr(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx)
{
	int idx;
	cpu_idle_prop_impl_t *prop = (cpu_idle_prop_impl_t *)hdl;

	ASSERT(hdl != NULL);
	ASSERT(CPU_IDLE_CTX2CPUID(ctx) < max_ncpus);
	idx = CPU_IDLE_CTX2IDX(ctx);
	return (prop->value[idx].cipv_intptr);
}

hrtime_t
cpu_idle_prop_get_hrtime(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx)
{
	int idx;
	cpu_idle_prop_impl_t *prop = (cpu_idle_prop_impl_t *)hdl;

	ASSERT(hdl != NULL);
	ASSERT(CPU_IDLE_CTX2CPUID(ctx) < max_ncpus);
	idx = CPU_IDLE_CTX2IDX(ctx);
	return (prop->value[idx].cipv_hrtime);
}

void
cpu_idle_prop_set_value(cpu_idle_prop_handle_t hdl,
    cpu_idle_callback_context_t ctx, cpu_idle_prop_value_t val)
{
	int idx;
	cpu_idle_prop_impl_t *prop = (cpu_idle_prop_impl_t *)hdl;

	ASSERT(hdl != NULL);
	ASSERT(CPU_IDLE_CTX2CPUID(ctx) < max_ncpus);
	idx = CPU_IDLE_CTX2IDX(ctx);
	prop->value[idx] = val;
}

void
cpu_idle_prop_set_all(cpu_idle_prop_handle_t hdl, cpu_idle_prop_value_t val)
{
	int i, idx;
	cpu_idle_prop_impl_t *prop = (cpu_idle_prop_impl_t *)hdl;

	ASSERT(hdl != NULL);
	for (i = 0; i < max_ncpus; i++) {
		idx = CPU_IDLE_CTX2IDX(i);
		prop->value[idx] = val;
	}
}

/*ARGSUSED*/
static int cpu_idle_prop_update_intr_cnt(void *arg, uint64_t seqnum,
    cpu_idle_prop_value_t *valp)
{
	int i;
	uint64_t val;

	for (val = 0, i = 0; i < PIL_MAX; i++) {
		val += CPU->cpu_stats.sys.intr[i];
	}
	valp->cipv_uint64 = val;

	return (0);
}

uint_t
cpu_idle_get_cpu_state(cpu_t *cp)
{
	ASSERT(cp != NULL && cp->cpu_seqid < max_ncpus);
	return ((uint_t)cpu_idle_prop_get_uint32(
	    cpu_idle_prop_array[CPU_IDLE_PROP_IDX_IDLE_STATE].handle,
	    CPU_IDLE_GET_CTX(cp)));
}

#if defined(__x86)
/*
 * Intercept CPU at a safe point in idle() before powering it off.
 */
void
cpu_idle_intercept_cpu(cpu_t *cp)
{
	ASSERT(cp->cpu_seqid < max_ncpus);
	ASSERT(cpu_idle_cb_state[cp->cpu_seqid].v.enabled == B_FALSE);

	/* Set flag to intercept CPU. */
	CPUSET_ATOMIC_ADD(cpu_idle_intercept_set, cp->cpu_id);
	/* Wake up CPU from possible sleep state. */
	poke_cpu(cp->cpu_id);
	while (CPU_IN_SET(cpu_idle_intercept_set, cp->cpu_id)) {
		DELAY(1);
	}
	/*
	 * Now target CPU is spinning in a pause loop with interrupts disabled.
	 */
}
#endif
