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

#include <sys/param.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/inttypes.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/ksynch.h>
#include <sys/systm.h>
#include <sys/kcpc.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/atomic.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sdt.h>
#include <sys/archsystm.h>
#include <sys/promif.h>
#include <sys/x_call.h>
#include <sys/cap_util.h>
#if defined(__x86)
#include <asm/clock.h>
#include <sys/xc_levels.h>
#endif

static kmutex_t	kcpc_ctx_llock[CPC_HASH_BUCKETS];	/* protects ctx_list */
static kcpc_ctx_t *kcpc_ctx_list[CPC_HASH_BUCKETS];	/* head of list */


krwlock_t	kcpc_cpuctx_lock;	/* lock for 'kcpc_cpuctx' below */
int		kcpc_cpuctx;		/* number of cpu-specific contexts */

int kcpc_counts_include_idle = 1; /* Project Private /etc/system variable */

/*
 * These are set when a PCBE module is loaded.
 */
uint_t		cpc_ncounters = 0;
pcbe_ops_t	*pcbe_ops = NULL;

/*
 * Statistics on (mis)behavior
 */
static uint32_t kcpc_intrctx_count;    /* # overflows in an interrupt handler */
static uint32_t kcpc_nullctx_count;    /* # overflows in a thread with no ctx */

/*
 * By setting 'kcpc_nullctx_panic' to 1, any overflow interrupts in a thread
 * with no valid context will result in a panic.
 */
static int kcpc_nullctx_panic = 0;

static void kcpc_lwp_create(kthread_t *t, kthread_t *ct);
static void kcpc_restore(kcpc_ctx_t *ctx);
static void kcpc_save(kcpc_ctx_t *ctx);
static void kcpc_ctx_clone(kcpc_ctx_t *ctx, kcpc_ctx_t *cctx);
static int kcpc_tryassign(kcpc_set_t *set, int starting_req, int *scratch);
static kcpc_set_t *kcpc_dup_set(kcpc_set_t *set);
static kcpc_set_t *kcpc_set_create(kcpc_request_t *reqs, int nreqs,
    int set_flags, int kmem_flags);

/*
 * Macros to manipulate context flags. All flag updates should use one of these
 * two macros
 *
 * Flags should be always be updated atomically since some of the updates are
 * not protected by locks.
 */
#define	KCPC_CTX_FLAG_SET(ctx, flag) atomic_or_uint(&(ctx)->kc_flags, (flag))
#define	KCPC_CTX_FLAG_CLR(ctx, flag) atomic_and_uint(&(ctx)->kc_flags, ~(flag))

/*
 * The IS_HIPIL() macro verifies that the code is executed either from a
 * cross-call or from high-PIL interrupt
 */
#ifdef DEBUG
#define	IS_HIPIL() (getpil() >= XCALL_PIL)
#else
#define	IS_HIPIL()
#endif	/* DEBUG */


extern int kcpc_hw_load_pcbe(void);

/*
 * Return value from kcpc_hw_load_pcbe()
 */
static int kcpc_pcbe_error = 0;

/*
 * Perform one-time initialization of kcpc framework.
 * This function performs the initialization only the first time it is called.
 * It is safe to call it multiple times.
 */
int
kcpc_init(void)
{
	long hash;
	static uint32_t kcpc_initialized = 0;

	/*
	 * We already tried loading platform pcbe module and failed
	 */
	if (kcpc_pcbe_error != 0)
		return (-1);

	/*
	 * The kcpc framework should be initialized at most once
	 */
	if (atomic_cas_32(&kcpc_initialized, 0, 1) != 0)
		return (0);

	rw_init(&kcpc_cpuctx_lock, NULL, RW_DEFAULT, NULL);
	for (hash = 0; hash < CPC_HASH_BUCKETS; hash++)
		mutex_init(&kcpc_ctx_llock[hash],
		    NULL, MUTEX_DRIVER, (void *)(uintptr_t)15);

	/*
	 * Load platform-specific pcbe module
	 */
	kcpc_pcbe_error = kcpc_hw_load_pcbe();

	return (kcpc_pcbe_error == 0 ? 0 : -1);
}

void
kcpc_register_pcbe(pcbe_ops_t *ops)
{
	pcbe_ops = ops;
	cpc_ncounters = pcbe_ops->pcbe_ncounters();
}

void
kcpc_register_dcpc(void (*func)(uint64_t))
{
	dtrace_cpc_fire = func;
}

void
kcpc_unregister_dcpc(void)
{
	dtrace_cpc_fire = NULL;
}

int
kcpc_bind_cpu(kcpc_set_t *set, processorid_t cpuid, int *subcode)
{
	cpu_t		*cp;
	kcpc_ctx_t	*ctx;
	int		error;
	int		save_spl;

	ctx = kcpc_ctx_alloc(KM_SLEEP);

	if (kcpc_assign_reqs(set, ctx) != 0) {
		kcpc_ctx_free(ctx);
		*subcode = CPC_RESOURCE_UNAVAIL;
		return (EINVAL);
	}

	ctx->kc_cpuid = cpuid;
	ctx->kc_thread = curthread;

	set->ks_data = kmem_zalloc(set->ks_nreqs * sizeof (uint64_t), KM_SLEEP);

	if ((error = kcpc_configure_reqs(ctx, set, subcode)) != 0) {
		kmem_free(set->ks_data, set->ks_nreqs * sizeof (uint64_t));
		kcpc_ctx_free(ctx);
		return (error);
	}

	set->ks_ctx = ctx;
	ctx->kc_set = set;

	/*
	 * We must hold cpu_lock to prevent DR, offlining, or unbinding while
	 * we are manipulating the cpu_t and programming the hardware, else the
	 * the cpu_t could go away while we're looking at it.
	 */
	mutex_enter(&cpu_lock);
	cp = cpu_get(cpuid);

	if (cp == NULL)
		/*
		 * The CPU could have been DRd out while we were getting set up.
		 */
		goto unbound;

	mutex_enter(&cp->cpu_cpc_ctxlock);
	kpreempt_disable();
	save_spl = spl_xcall();

	/*
	 * Check to see whether counters for CPU already being used by someone
	 * other than kernel for capacity and utilization (since kernel will
	 * let go of counters for user in kcpc_program() below)
	 */
	if (cp->cpu_cpc_ctx != NULL && !CU_CPC_ON(cp)) {
		/*
		 * If this CPU already has a bound set, return an error.
		 */
		splx(save_spl);
		kpreempt_enable();
		mutex_exit(&cp->cpu_cpc_ctxlock);
		goto unbound;
	}

	if (curthread->t_bind_cpu != cpuid) {
		splx(save_spl);
		kpreempt_enable();
		mutex_exit(&cp->cpu_cpc_ctxlock);
		goto unbound;
	}

	kcpc_program(ctx, B_FALSE, B_TRUE);

	splx(save_spl);
	kpreempt_enable();

	mutex_exit(&cp->cpu_cpc_ctxlock);
	mutex_exit(&cpu_lock);

	mutex_enter(&set->ks_lock);
	set->ks_state |= KCPC_SET_BOUND;
	cv_signal(&set->ks_condv);
	mutex_exit(&set->ks_lock);

	return (0);

unbound:
	mutex_exit(&cpu_lock);
	set->ks_ctx = NULL;
	kmem_free(set->ks_data, set->ks_nreqs * sizeof (uint64_t));
	kcpc_ctx_free(ctx);
	return (EAGAIN);
}

int
kcpc_bind_thread(kcpc_set_t *set, kthread_t *t, int *subcode)
{
	kcpc_ctx_t	*ctx;
	int		error;

	/*
	 * Only one set is allowed per context, so ensure there is no
	 * existing context.
	 */

	if (t->t_cpc_ctx != NULL)
		return (EEXIST);

	ctx = kcpc_ctx_alloc(KM_SLEEP);

	/*
	 * The context must begin life frozen until it has been properly
	 * programmed onto the hardware. This prevents the context ops from
	 * worrying about it until we're ready.
	 */
	KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_FREEZE);
	ctx->kc_hrtime = gethrtime();

	if (kcpc_assign_reqs(set, ctx) != 0) {
		kcpc_ctx_free(ctx);
		*subcode = CPC_RESOURCE_UNAVAIL;
		return (EINVAL);
	}

	ctx->kc_cpuid = -1;
	if (set->ks_flags & CPC_BIND_LWP_INHERIT)
		KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_LWPINHERIT);
	ctx->kc_thread = t;
	t->t_cpc_ctx = ctx;
	/*
	 * Permit threads to look at their own hardware counters from userland.
	 */
	KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_NONPRIV);

	/*
	 * Create the data store for this set.
	 */
	set->ks_data = kmem_alloc(set->ks_nreqs * sizeof (uint64_t), KM_SLEEP);

	if ((error = kcpc_configure_reqs(ctx, set, subcode)) != 0) {
		kmem_free(set->ks_data, set->ks_nreqs * sizeof (uint64_t));
		kcpc_ctx_free(ctx);
		t->t_cpc_ctx = NULL;
		return (error);
	}

	set->ks_ctx = ctx;
	ctx->kc_set = set;

	/*
	 * Add a device context to the subject thread.
	 */
	installctx(t, ctx, kcpc_save, kcpc_restore, NULL,
	    kcpc_lwp_create, NULL, kcpc_free);

	/*
	 * Ask the backend to program the hardware.
	 */
	if (t == curthread) {
		int save_spl;

		kpreempt_disable();
		save_spl = spl_xcall();
		kcpc_program(ctx, B_TRUE, B_TRUE);
		splx(save_spl);
		kpreempt_enable();
	} else {
		/*
		 * Since we are the agent LWP, we know the victim LWP is stopped
		 * until we're done here; no need to worry about preemption or
		 * migration here. We still use an atomic op to clear the flag
		 * to ensure the flags are always self-consistent; they can
		 * still be accessed from, for instance, another CPU doing a
		 * kcpc_invalidate_all().
		 */
		KCPC_CTX_FLAG_CLR(ctx, KCPC_CTX_FREEZE);
	}

	mutex_enter(&set->ks_lock);
	set->ks_state |= KCPC_SET_BOUND;
	cv_signal(&set->ks_condv);
	mutex_exit(&set->ks_lock);

	return (0);
}

/*
 * Walk through each request in the set and ask the PCBE to configure a
 * corresponding counter.
 */
int
kcpc_configure_reqs(kcpc_ctx_t *ctx, kcpc_set_t *set, int *subcode)
{
	int		i;
	int		ret;
	kcpc_request_t	*rp;

	for (i = 0; i < set->ks_nreqs; i++) {
		int n;
		rp = &set->ks_req[i];

		n = rp->kr_picnum;

		ASSERT(n >= 0 && n < cpc_ncounters);

		ASSERT(ctx->kc_pics[n].kp_req == NULL);

		if (rp->kr_flags & CPC_OVF_NOTIFY_EMT) {
			if ((pcbe_ops->pcbe_caps & CPC_CAP_OVERFLOW_INTERRUPT)
			    == 0) {
				*subcode = -1;
				return (ENOTSUP);
			}
			/*
			 * If any of the counters have requested overflow
			 * notification, we flag the context as being one that
			 * cares about overflow.
			 */
			KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_SIGOVF);
		}

		rp->kr_config = NULL;
		if ((ret = pcbe_ops->pcbe_configure(n, rp->kr_event,
		    rp->kr_preset, rp->kr_flags, rp->kr_nattrs, rp->kr_attr,
		    &(rp->kr_config), (void *)ctx)) != 0) {
			kcpc_free_configs(set);
			*subcode = ret;
			switch (ret) {
			case CPC_ATTR_REQUIRES_PRIVILEGE:
			case CPC_HV_NO_ACCESS:
				return (EACCES);
			default:
				return (EINVAL);
			}
		}

		ctx->kc_pics[n].kp_req = rp;
		rp->kr_picp = &ctx->kc_pics[n];
		rp->kr_data = set->ks_data + rp->kr_index;
		*rp->kr_data = rp->kr_preset;
	}

	return (0);
}

void
kcpc_free_configs(kcpc_set_t *set)
{
	int i;

	for (i = 0; i < set->ks_nreqs; i++)
		if (set->ks_req[i].kr_config != NULL)
			pcbe_ops->pcbe_free(set->ks_req[i].kr_config);
}

/*
 * buf points to a user address and the data should be copied out to that
 * address in the current process.
 */
int
kcpc_sample(kcpc_set_t *set, uint64_t *buf, hrtime_t *hrtime, uint64_t *tick)
{
	kcpc_ctx_t	*ctx = set->ks_ctx;
	int		save_spl;

	mutex_enter(&set->ks_lock);
	if ((set->ks_state & KCPC_SET_BOUND) == 0) {
		mutex_exit(&set->ks_lock);
		return (EINVAL);
	}
	mutex_exit(&set->ks_lock);

	/*
	 * Kernel preemption must be disabled while reading the hardware regs,
	 * and if this is a CPU-bound context, while checking the CPU binding of
	 * the current thread.
	 */
	kpreempt_disable();
	save_spl = spl_xcall();

	if (ctx->kc_flags & KCPC_CTX_INVALID) {
		splx(save_spl);
		kpreempt_enable();
		return (EAGAIN);
	}

	if ((ctx->kc_flags & KCPC_CTX_FREEZE) == 0) {
		if (ctx->kc_cpuid != -1) {
			if (curthread->t_bind_cpu != ctx->kc_cpuid) {
				splx(save_spl);
				kpreempt_enable();
				return (EAGAIN);
			}
		}

		if (ctx->kc_thread == curthread) {
			uint64_t curtick = KCPC_GET_TICK();

			ctx->kc_hrtime = gethrtime_waitfree();
			pcbe_ops->pcbe_sample(ctx);
			ctx->kc_vtick += curtick - ctx->kc_rawtick;
			ctx->kc_rawtick = curtick;
		}

		/*
		 * The config may have been invalidated by
		 * the pcbe_sample op.
		 */
		if (ctx->kc_flags & KCPC_CTX_INVALID) {
			splx(save_spl);
			kpreempt_enable();
			return (EAGAIN);
		}

	}

	splx(save_spl);
	kpreempt_enable();

	if (copyout(set->ks_data, buf,
	    set->ks_nreqs * sizeof (uint64_t)) == -1)
		return (EFAULT);
	if (copyout(&ctx->kc_hrtime, hrtime, sizeof (uint64_t)) == -1)
		return (EFAULT);
	if (copyout(&ctx->kc_vtick, tick, sizeof (uint64_t)) == -1)
		return (EFAULT);

	return (0);
}

/*
 * Stop the counters on the CPU this context is bound to.
 */
static void
kcpc_stop_hw(kcpc_ctx_t *ctx)
{
	cpu_t *cp;

	kpreempt_disable();

	if (ctx->kc_cpuid == CPU->cpu_id) {
		cp = CPU;
	} else {
		cp = cpu_get(ctx->kc_cpuid);
	}

	ASSERT(cp != NULL && cp->cpu_cpc_ctx == ctx);
	kcpc_cpu_stop(cp, B_FALSE);

	kpreempt_enable();
}

int
kcpc_unbind(kcpc_set_t *set)
{
	kcpc_ctx_t	*ctx;
	kthread_t	*t;

	/*
	 * We could be racing with the process's agent thread as it
	 * binds the set; we must wait for the set to finish binding
	 * before attempting to tear it down.
	 */
	mutex_enter(&set->ks_lock);
	while ((set->ks_state & KCPC_SET_BOUND) == 0)
		cv_wait(&set->ks_condv, &set->ks_lock);
	mutex_exit(&set->ks_lock);

	ctx = set->ks_ctx;

	/*
	 * Use kc_lock to synchronize with kcpc_restore().
	 */
	mutex_enter(&ctx->kc_lock);
	KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_INVALID);
	mutex_exit(&ctx->kc_lock);

	if (ctx->kc_cpuid == -1) {
		t = ctx->kc_thread;
		/*
		 * The context is thread-bound and therefore has a device
		 * context.  It will be freed via removectx() calling
		 * freectx() calling kcpc_free().
		 */
		if (t == curthread) {
			int save_spl;

			kpreempt_disable();
			save_spl = spl_xcall();
			if (!(ctx->kc_flags & KCPC_CTX_INVALID_STOPPED))
				kcpc_unprogram(ctx, B_TRUE);
			splx(save_spl);
			kpreempt_enable();
		}
#ifdef DEBUG
		if (removectx(t, ctx, kcpc_save, kcpc_restore, NULL,
		    kcpc_lwp_create, NULL, kcpc_free) == 0)
			panic("kcpc_unbind: context %p not preset on thread %p",
			    (void *)ctx, (void *)t);
#else
		(void) removectx(t, ctx, kcpc_save, kcpc_restore, NULL,
		    kcpc_lwp_create, NULL, kcpc_free);
#endif /* DEBUG */
		t->t_cpc_set = NULL;
		t->t_cpc_ctx = NULL;
	} else {
		/*
		 * If we are unbinding a CPU-bound set from a remote CPU, the
		 * native CPU's idle thread could be in the midst of programming
		 * this context onto the CPU. We grab the context's lock here to
		 * ensure that the idle thread is done with it. When we release
		 * the lock, the CPU no longer has a context and the idle thread
		 * will move on.
		 *
		 * cpu_lock must be held to prevent the CPU from being DR'd out
		 * while we disassociate the context from the cpu_t.
		 */
		cpu_t *cp;
		mutex_enter(&cpu_lock);
		cp = cpu_get(ctx->kc_cpuid);
		if (cp != NULL) {
			/*
			 * The CPU may have been DR'd out of the system.
			 */
			mutex_enter(&cp->cpu_cpc_ctxlock);
			if ((ctx->kc_flags & KCPC_CTX_INVALID_STOPPED) == 0)
				kcpc_stop_hw(ctx);
			ASSERT(ctx->kc_flags & KCPC_CTX_INVALID_STOPPED);
			mutex_exit(&cp->cpu_cpc_ctxlock);
		}
		mutex_exit(&cpu_lock);
		if (ctx->kc_thread == curthread) {
			kcpc_free(ctx, 0);
			curthread->t_cpc_set = NULL;
		}
	}

	return (0);
}

int
kcpc_preset(kcpc_set_t *set, int index, uint64_t preset)
{
	int i;

	ASSERT(set != NULL);
	ASSERT(set->ks_state & KCPC_SET_BOUND);
	ASSERT(set->ks_ctx->kc_thread == curthread);
	ASSERT(set->ks_ctx->kc_cpuid == -1);

	if (index < 0 || index >= set->ks_nreqs)
		return (EINVAL);

	for (i = 0; i < set->ks_nreqs; i++)
		if (set->ks_req[i].kr_index == index)
			break;
	ASSERT(i != set->ks_nreqs);

	set->ks_req[i].kr_preset = preset;
	return (0);
}

int
kcpc_restart(kcpc_set_t *set)
{
	kcpc_ctx_t	*ctx = set->ks_ctx;
	int		i;
	int		save_spl;

	ASSERT(set->ks_state & KCPC_SET_BOUND);
	ASSERT(ctx->kc_thread == curthread);
	ASSERT(ctx->kc_cpuid == -1);

	for (i = 0; i < set->ks_nreqs; i++) {
		*(set->ks_req[i].kr_data) = set->ks_req[i].kr_preset;
		pcbe_ops->pcbe_configure(0, NULL, set->ks_req[i].kr_preset,
		    0, 0, NULL, &set->ks_req[i].kr_config, NULL);
	}

	kpreempt_disable();
	save_spl = spl_xcall();

	/*
	 * If the user is doing this on a running set, make sure the counters
	 * are stopped first.
	 */
	if ((ctx->kc_flags & KCPC_CTX_FREEZE) == 0)
		pcbe_ops->pcbe_allstop();

	/*
	 * Ask the backend to program the hardware.
	 */
	ctx->kc_rawtick = KCPC_GET_TICK();
	KCPC_CTX_FLAG_CLR(ctx, KCPC_CTX_FREEZE);
	pcbe_ops->pcbe_program(ctx);
	splx(save_spl);
	kpreempt_enable();

	return (0);
}

/*
 * Caller must hold kcpc_cpuctx_lock.
 */
int
kcpc_enable(kthread_t *t, int cmd, int enable)
{
	kcpc_ctx_t	*ctx = t->t_cpc_ctx;
	kcpc_set_t	*set = t->t_cpc_set;
	kcpc_set_t	*newset;
	int		i;
	int		flag;
	int		err;

	ASSERT(RW_READ_HELD(&kcpc_cpuctx_lock));

	if (ctx == NULL) {
		/*
		 * This thread has a set but no context; it must be a
		 * CPU-bound set.
		 */
		ASSERT(t->t_cpc_set != NULL);
		ASSERT(t->t_cpc_set->ks_ctx->kc_cpuid != -1);
		return (EINVAL);
	} else if (ctx->kc_flags & KCPC_CTX_INVALID)
		return (EAGAIN);

	if (cmd == CPC_ENABLE) {
		if ((ctx->kc_flags & KCPC_CTX_FREEZE) == 0)
			return (EINVAL);
		kpreempt_disable();
		KCPC_CTX_FLAG_CLR(ctx, KCPC_CTX_FREEZE);
		kcpc_restore(ctx);
		kpreempt_enable();
	} else if (cmd == CPC_DISABLE) {
		if (ctx->kc_flags & KCPC_CTX_FREEZE)
			return (EINVAL);
		kpreempt_disable();
		kcpc_save(ctx);
		KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_FREEZE);
		kpreempt_enable();
	} else if (cmd == CPC_USR_EVENTS || cmd == CPC_SYS_EVENTS) {
		/*
		 * Strategy for usr/sys: stop counters and update set's presets
		 * with current counter values, unbind, update requests with
		 * new config, then re-bind.
		 */
		flag = (cmd == CPC_USR_EVENTS) ?
		    CPC_COUNT_USER: CPC_COUNT_SYSTEM;

		kpreempt_disable();
		KCPC_CTX_FLAG_SET(ctx,
		    KCPC_CTX_INVALID | KCPC_CTX_INVALID_STOPPED);
		pcbe_ops->pcbe_allstop();
		kpreempt_enable();

		for (i = 0; i < set->ks_nreqs; i++) {
			set->ks_req[i].kr_preset = *(set->ks_req[i].kr_data);
			if (enable)
				set->ks_req[i].kr_flags |= flag;
			else
				set->ks_req[i].kr_flags &= ~flag;
		}
		newset = kcpc_dup_set(set);
		if (kcpc_unbind(set) != 0)
			return (EINVAL);
		t->t_cpc_set = newset;
		if (kcpc_bind_thread(newset, t, &err) != 0) {
			t->t_cpc_set = NULL;
			kcpc_free_set(newset);
			return (EINVAL);
		}
	} else
		return (EINVAL);

	return (0);
}

/*
 * Provide PCBEs with a way of obtaining the configs of every counter which will
 * be programmed together.
 *
 * If current is NULL, provide the first config.
 *
 * If data != NULL, caller wants to know where the data store associated with
 * the config we return is located.
 */
void *
kcpc_next_config(void *token, void *current, uint64_t **data)
{
	int		i;
	kcpc_pic_t	*pic;
	kcpc_ctx_t *ctx = (kcpc_ctx_t *)token;

	if (current == NULL) {
		/*
		 * Client would like the first config, which may not be in
		 * counter 0; we need to search through the counters for the
		 * first config.
		 */
		for (i = 0; i < cpc_ncounters; i++)
			if (ctx->kc_pics[i].kp_req != NULL)
				break;
		/*
		 * There are no counters configured for the given context.
		 */
		if (i == cpc_ncounters)
			return (NULL);
	} else {
		/*
		 * There surely is a faster way to do this.
		 */
		for (i = 0; i < cpc_ncounters; i++) {
			pic = &ctx->kc_pics[i];

			if (pic->kp_req != NULL &&
			    current == pic->kp_req->kr_config)
				break;
		}

		/*
		 * We found the current config at picnum i. Now search for the
		 * next configured PIC.
		 */
		for (i++; i < cpc_ncounters; i++) {
			pic = &ctx->kc_pics[i];
			if (pic->kp_req != NULL)
				break;
		}

		if (i == cpc_ncounters)
			return (NULL);
	}

	if (data != NULL) {
		*data = ctx->kc_pics[i].kp_req->kr_data;
	}

	return (ctx->kc_pics[i].kp_req->kr_config);
}


kcpc_ctx_t *
kcpc_ctx_alloc(int kmem_flags)
{
	kcpc_ctx_t	*ctx;
	long		hash;

	ctx = (kcpc_ctx_t *)kmem_zalloc(sizeof (kcpc_ctx_t), kmem_flags);
	if (ctx == NULL)
		return (NULL);

	hash = CPC_HASH_CTX(ctx);
	mutex_enter(&kcpc_ctx_llock[hash]);
	ctx->kc_next = kcpc_ctx_list[hash];
	kcpc_ctx_list[hash] = ctx;
	mutex_exit(&kcpc_ctx_llock[hash]);

	ctx->kc_pics = (kcpc_pic_t *)kmem_zalloc(sizeof (kcpc_pic_t) *
	    cpc_ncounters, KM_SLEEP);

	ctx->kc_cpuid = -1;

	return (ctx);
}

/*
 * Copy set from ctx to the child context, cctx, if it has CPC_BIND_LWP_INHERIT
 * in the flags.
 */
static void
kcpc_ctx_clone(kcpc_ctx_t *ctx, kcpc_ctx_t *cctx)
{
	kcpc_set_t	*ks = ctx->kc_set, *cks;
	int		i, j;
	int		code;

	ASSERT(ks != NULL);

	if ((ks->ks_flags & CPC_BIND_LWP_INHERIT) == 0)
		return;

	cks = kmem_zalloc(sizeof (*cks), KM_SLEEP);
	cks->ks_state &= ~KCPC_SET_BOUND;
	cctx->kc_set = cks;
	cks->ks_flags = ks->ks_flags;
	cks->ks_nreqs = ks->ks_nreqs;
	cks->ks_req = kmem_alloc(cks->ks_nreqs *
	    sizeof (kcpc_request_t), KM_SLEEP);
	cks->ks_data = kmem_alloc(cks->ks_nreqs * sizeof (uint64_t),
	    KM_SLEEP);
	cks->ks_ctx = cctx;

	for (i = 0; i < cks->ks_nreqs; i++) {
		cks->ks_req[i].kr_index = ks->ks_req[i].kr_index;
		cks->ks_req[i].kr_picnum = ks->ks_req[i].kr_picnum;
		(void) strncpy(cks->ks_req[i].kr_event,
		    ks->ks_req[i].kr_event, CPC_MAX_EVENT_LEN);
		cks->ks_req[i].kr_preset = ks->ks_req[i].kr_preset;
		cks->ks_req[i].kr_flags = ks->ks_req[i].kr_flags;
		cks->ks_req[i].kr_nattrs = ks->ks_req[i].kr_nattrs;
		if (ks->ks_req[i].kr_nattrs > 0) {
			cks->ks_req[i].kr_attr =
			    kmem_alloc(ks->ks_req[i].kr_nattrs *
			    sizeof (kcpc_attr_t), KM_SLEEP);
		}
		for (j = 0; j < ks->ks_req[i].kr_nattrs; j++) {
			(void) strncpy(cks->ks_req[i].kr_attr[j].ka_name,
			    ks->ks_req[i].kr_attr[j].ka_name,
			    CPC_MAX_ATTR_LEN);
			cks->ks_req[i].kr_attr[j].ka_val =
			    ks->ks_req[i].kr_attr[j].ka_val;
		}
	}
	if (kcpc_configure_reqs(cctx, cks, &code) != 0)
		kcpc_invalidate_config(cctx);

	mutex_enter(&cks->ks_lock);
	cks->ks_state |= KCPC_SET_BOUND;
	cv_signal(&cks->ks_condv);
	mutex_exit(&cks->ks_lock);
}


void
kcpc_ctx_free(kcpc_ctx_t *ctx)
{
	kcpc_ctx_t	**loc;
	long		hash = CPC_HASH_CTX(ctx);

	mutex_enter(&kcpc_ctx_llock[hash]);
	loc = &kcpc_ctx_list[hash];
	ASSERT(*loc != NULL);
	while (*loc != ctx)
		loc = &(*loc)->kc_next;
	*loc = ctx->kc_next;
	mutex_exit(&kcpc_ctx_llock[hash]);

	kmem_free(ctx->kc_pics, cpc_ncounters * sizeof (kcpc_pic_t));
	cv_destroy(&ctx->kc_condv);
	mutex_destroy(&ctx->kc_lock);
	kmem_free(ctx, sizeof (*ctx));
}

/*
 * Generic interrupt handler used on hardware that generates
 * overflow interrupts.
 *
 * Note: executed at high-level interrupt context!
 */
/*ARGSUSED*/
kcpc_ctx_t *
kcpc_overflow_intr(caddr_t arg, uint64_t bitmap)
{
	kcpc_ctx_t	*ctx;
	kthread_t	*t = curthread;
	int		i;

	/*
	 * On both x86 and UltraSPARC, we may deliver the high-level
	 * interrupt in kernel mode, just after we've started to run an
	 * interrupt thread.  (That's because the hardware helpfully
	 * delivers the overflow interrupt some random number of cycles
	 * after the instruction that caused the overflow by which time
	 * we're in some part of the kernel, not necessarily running on
	 * the right thread).
	 *
	 * Check for this case here -- find the pinned thread
	 * that was running when the interrupt went off.
	 */
	if (t->t_flag & T_INTR_THREAD) {
		klwp_t *lwp;

		atomic_inc_32(&kcpc_intrctx_count);

		/*
		 * Note that t_lwp is always set to point at the underlying
		 * thread, thus this will work in the presence of nested
		 * interrupts.
		 */
		ctx = NULL;
		if ((lwp = t->t_lwp) != NULL) {
			t = lwptot(lwp);
			ctx = t->t_cpc_ctx;
		}
	} else
		ctx = t->t_cpc_ctx;

	if (ctx == NULL) {
		/*
		 * This can easily happen if we're using the counters in
		 * "shared" mode, for example, and an overflow interrupt
		 * occurs while we are running cpustat.  In that case, the
		 * bound thread that has the context that belongs to this
		 * CPU is almost certainly sleeping (if it was running on
		 * the CPU we'd have found it above), and the actual
		 * interrupted thread has no knowledge of performance counters!
		 */
		ctx = curthread->t_cpu->cpu_cpc_ctx;
		if (ctx != NULL) {
			/*
			 * Return the bound context for this CPU to
			 * the interrupt handler so that it can synchronously
			 * sample the hardware counters and restart them.
			 */
			return (ctx);
		}

		/*
		 * As long as the overflow interrupt really is delivered early
		 * enough after trapping into the kernel to avoid switching
		 * threads, we must always be able to find the cpc context,
		 * or something went terribly wrong i.e. we ended up
		 * running a passivated interrupt thread, a kernel
		 * thread or we interrupted idle, all of which are Very Bad.
		 *
		 * We also could end up here owing to an incredibly unlikely
		 * race condition that exists on x86 based architectures when
		 * the cpc provider is in use; overflow interrupts are directed
		 * to the cpc provider if the 'dtrace_cpc_in_use' variable is
		 * set when we enter the handler. This variable is unset after
		 * overflow interrupts have been disabled on all CPUs and all
		 * contexts have been torn down. To stop interrupts, the cpc
		 * provider issues a xcall to the remote CPU before it tears
		 * down that CPUs context. As high priority xcalls, on an x86
		 * architecture, execute at a higher PIL than this handler, it
		 * is possible (though extremely unlikely) that the xcall could
		 * interrupt the overflow handler before the handler has
		 * checked the 'dtrace_cpc_in_use' variable, stop the counters,
		 * return to the cpc provider which could then rip down
		 * contexts and unset 'dtrace_cpc_in_use' *before* the CPUs
		 * overflow handler has had a chance to check the variable. In
		 * that case, the handler would direct the overflow into this
		 * code and no valid context will be found. The default behavior
		 * when no valid context is found is now to shout a warning to
		 * the console and bump the 'kcpc_nullctx_count' variable.
		 */
		if (kcpc_nullctx_panic)
			panic("null cpc context, thread %p", (void *)t);
#ifdef DEBUG
		cmn_err(CE_NOTE,
		    "null cpc context found in overflow handler!\n");
#endif
		atomic_inc_32(&kcpc_nullctx_count);
	} else if ((ctx->kc_flags & KCPC_CTX_INVALID) == 0) {
		/*
		 * Schedule an ast to sample the counters, which will
		 * propagate any overflow into the virtualized performance
		 * counter(s), and may deliver a signal.
		 */
		ttolwp(t)->lwp_pcb.pcb_flags |= CPC_OVERFLOW;
		/*
		 * If a counter has overflowed which was counting on behalf of
		 * a request which specified CPC_OVF_NOTIFY_EMT, send the
		 * process a signal.
		 */
		for (i = 0; i < cpc_ncounters; i++) {
			if (ctx->kc_pics[i].kp_req != NULL &&
			    bitmap & (1 << i) &&
			    ctx->kc_pics[i].kp_req->kr_flags &
			    CPC_OVF_NOTIFY_EMT) {
				/*
				 * A signal has been requested for this PIC, so
				 * so freeze the context. The interrupt handler
				 * has already stopped the counter hardware.
				 */
				KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_FREEZE);
				atomic_or_uint(&ctx->kc_pics[i].kp_flags,
				    KCPC_PIC_OVERFLOWED);
			}
		}
		aston(t);
	} else if (ctx->kc_flags & KCPC_CTX_INVALID_STOPPED) {
		/*
		 * Thread context is no longer valid, but here may be a valid
		 * CPU context.
		 */
		return (curthread->t_cpu->cpu_cpc_ctx);
	}

	return (NULL);
}

/*
 * The current thread context had an overflow interrupt; we're
 * executing here in high-level interrupt context.
 */
/*ARGSUSED*/
uint_t
kcpc_hw_overflow_intr(caddr_t arg1, caddr_t arg2)
{
	kcpc_ctx_t *ctx;
	uint64_t bitmap;
	uint8_t *state;
	int	save_spl;

	if (pcbe_ops == NULL ||
	    (bitmap = pcbe_ops->pcbe_overflow_bitmap()) == 0)
		return (DDI_INTR_UNCLAIMED);

	/*
	 * Prevent any further interrupts.
	 */
	pcbe_ops->pcbe_allstop();

	if (dtrace_cpc_in_use) {
		state = &cpu_core[CPU->cpu_id].cpuc_dcpc_intr_state;

		/*
		 * Set the per-CPU state bit to indicate that we are currently
		 * processing an interrupt if it is currently free. Drop the
		 * interrupt if the state isn't free (i.e. a configuration
		 * event is taking place).
		 */
		if (atomic_cas_8(state, DCPC_INTR_FREE,
		    DCPC_INTR_PROCESSING) == DCPC_INTR_FREE) {
			int i;
			kcpc_request_t req;

			ASSERT(dtrace_cpc_fire != NULL);

			(*dtrace_cpc_fire)(bitmap);

			ctx = curthread->t_cpu->cpu_cpc_ctx;
			if (ctx == NULL) {
#ifdef DEBUG
				cmn_err(CE_NOTE, "null cpc context in"
				    "hardware overflow handler!\n");
#endif
				return (DDI_INTR_CLAIMED);
			}

			/* Reset any counters that have overflowed */
			for (i = 0; i < ctx->kc_set->ks_nreqs; i++) {
				req = ctx->kc_set->ks_req[i];

				if (bitmap & (1 << req.kr_picnum)) {
					pcbe_ops->pcbe_configure(req.kr_picnum,
					    req.kr_event, req.kr_preset,
					    req.kr_flags, req.kr_nattrs,
					    req.kr_attr, &(req.kr_config),
					    (void *)ctx);
				}
			}
			pcbe_ops->pcbe_program(ctx);

			/*
			 * We've finished processing the interrupt so set
			 * the state back to free.
			 */
			cpu_core[CPU->cpu_id].cpuc_dcpc_intr_state =
			    DCPC_INTR_FREE;
			membar_producer();
		}
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * DTrace isn't involved so pass on accordingly.
	 *
	 * If the interrupt has occurred in the context of an lwp owning
	 * the counters, then the handler posts an AST to the lwp to
	 * trigger the actual sampling, and optionally deliver a signal or
	 * restart the counters, on the way out of the kernel using
	 * kcpc_hw_overflow_ast() (see below).
	 *
	 * On the other hand, if the handler returns the context to us
	 * directly, then it means that there are no other threads in
	 * the middle of updating it, no AST has been posted, and so we
	 * should sample the counters here, and restart them with no
	 * further fuss.
	 *
	 * The CPU's CPC context may disappear as a result of cross-call which
	 * has higher PIL on x86, so protect the context by raising PIL to the
	 * cross-call level.
	 */
	save_spl = spl_xcall();
	if ((ctx = kcpc_overflow_intr(arg1, bitmap)) != NULL) {
		uint64_t curtick = KCPC_GET_TICK();

		ctx->kc_hrtime = gethrtime_waitfree();
		ctx->kc_vtick += curtick - ctx->kc_rawtick;
		ctx->kc_rawtick = curtick;
		pcbe_ops->pcbe_sample(ctx);
		pcbe_ops->pcbe_program(ctx);
	}
	splx(save_spl);

	return (DDI_INTR_CLAIMED);
}

/*
 * Called from trap() when processing the ast posted by the high-level
 * interrupt handler.
 */
int
kcpc_overflow_ast()
{
	kcpc_ctx_t	*ctx = curthread->t_cpc_ctx;
	int		i;
	int		found = 0;
	uint64_t	curtick = KCPC_GET_TICK();

	ASSERT(ctx != NULL);	/* Beware of interrupt skid. */

	/*
	 * An overflow happened: sample the context to ensure that
	 * the overflow is propagated into the upper bits of the
	 * virtualized 64-bit counter(s).
	 */
	kpreempt_disable();
	ctx->kc_hrtime = gethrtime_waitfree();
	pcbe_ops->pcbe_sample(ctx);
	kpreempt_enable();

	ctx->kc_vtick += curtick - ctx->kc_rawtick;

	/*
	 * The interrupt handler has marked any pics with KCPC_PIC_OVERFLOWED
	 * if that pic generated an overflow and if the request it was counting
	 * on behalf of had CPC_OVERFLOW_REQUEST specified. We go through all
	 * pics in the context and clear the KCPC_PIC_OVERFLOWED flags. If we
	 * found any overflowed pics, keep the context frozen and return true
	 * (thus causing a signal to be sent).
	 */
	for (i = 0; i < cpc_ncounters; i++) {
		if (ctx->kc_pics[i].kp_flags & KCPC_PIC_OVERFLOWED) {
			atomic_and_uint(&ctx->kc_pics[i].kp_flags,
			    ~KCPC_PIC_OVERFLOWED);
			found = 1;
		}
	}
	if (found)
		return (1);

	/*
	 * Otherwise, re-enable the counters and continue life as before.
	 */
	kpreempt_disable();
	KCPC_CTX_FLAG_CLR(ctx, KCPC_CTX_FREEZE);
	pcbe_ops->pcbe_program(ctx);
	kpreempt_enable();
	return (0);
}

/*
 * Called when switching away from current thread.
 */
static void
kcpc_save(kcpc_ctx_t *ctx)
{
	int err;
	int save_spl;

	kpreempt_disable();
	save_spl = spl_xcall();

	if (ctx->kc_flags & KCPC_CTX_INVALID) {
		if (ctx->kc_flags & KCPC_CTX_INVALID_STOPPED) {
			splx(save_spl);
			kpreempt_enable();
			return;
		}
		/*
		 * This context has been invalidated but the counters have not
		 * been stopped. Stop them here and mark the context stopped.
		 */
		kcpc_unprogram(ctx, B_TRUE);
		splx(save_spl);
		kpreempt_enable();
		return;
	}

	pcbe_ops->pcbe_allstop();
	if (ctx->kc_flags & KCPC_CTX_FREEZE) {
		splx(save_spl);
		kpreempt_enable();
		return;
	}

	/*
	 * Need to sample for all reqs into each req's current mpic.
	 */
	ctx->kc_hrtime = gethrtime_waitfree();
	ctx->kc_vtick += KCPC_GET_TICK() - ctx->kc_rawtick;
	pcbe_ops->pcbe_sample(ctx);

	/*
	 * Program counter for measuring capacity and utilization since user
	 * thread isn't using counter anymore
	 */
	ASSERT(ctx->kc_cpuid == -1);
	cu_cpc_program(CPU, &err);
	splx(save_spl);
	kpreempt_enable();
}

static void
kcpc_restore(kcpc_ctx_t *ctx)
{
	int save_spl;

	mutex_enter(&ctx->kc_lock);

	if ((ctx->kc_flags & (KCPC_CTX_INVALID | KCPC_CTX_INVALID_STOPPED)) ==
	    KCPC_CTX_INVALID) {
		/*
		 * The context is invalidated but has not been marked stopped.
		 * We mark it as such here because we will not start the
		 * counters during this context switch.
		 */
		KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_INVALID_STOPPED);
	}

	if (ctx->kc_flags & (KCPC_CTX_INVALID | KCPC_CTX_FREEZE)) {
		mutex_exit(&ctx->kc_lock);
		return;
	}

	/*
	 * Set kc_flags to show that a kcpc_restore() is in progress to avoid
	 * ctx & set related memory objects being freed without us knowing.
	 * This can happen if an agent thread is executing a kcpc_unbind(),
	 * with this thread as the target, whilst we're concurrently doing a
	 * restorectx() during, for example, a proc_exit().  Effectively, by
	 * doing this, we're asking kcpc_free() to cv_wait() until
	 * kcpc_restore() has completed.
	 */
	KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_RESTORE);
	mutex_exit(&ctx->kc_lock);

	/*
	 * While programming the hardware, the counters should be stopped. We
	 * don't do an explicit pcbe_allstop() here because they should have
	 * been stopped already by the last consumer.
	 */
	kpreempt_disable();
	save_spl = spl_xcall();
	kcpc_program(ctx, B_TRUE, B_TRUE);
	splx(save_spl);
	kpreempt_enable();

	/*
	 * Wake the agent thread if it's waiting in kcpc_free().
	 */
	mutex_enter(&ctx->kc_lock);
	KCPC_CTX_FLAG_CLR(ctx, KCPC_CTX_RESTORE);
	cv_signal(&ctx->kc_condv);
	mutex_exit(&ctx->kc_lock);
}

/*
 * If kcpc_counts_include_idle is set to 0 by the sys admin, we add the the
 * following context operators to the idle thread on each CPU. They stop the
 * counters when the idle thread is switched on, and they start them again when
 * it is switched off.
 */
/*ARGSUSED*/
void
kcpc_idle_save(struct cpu *cp)
{
	/*
	 * The idle thread shouldn't be run anywhere else.
	 */
	ASSERT(CPU == cp);

	/*
	 * We must hold the CPU's context lock to ensure the context isn't freed
	 * while we're looking at it.
	 */
	mutex_enter(&cp->cpu_cpc_ctxlock);

	if ((cp->cpu_cpc_ctx == NULL) ||
	    (cp->cpu_cpc_ctx->kc_flags & KCPC_CTX_INVALID)) {
		mutex_exit(&cp->cpu_cpc_ctxlock);
		return;
	}

	pcbe_ops->pcbe_program(cp->cpu_cpc_ctx);
	mutex_exit(&cp->cpu_cpc_ctxlock);
}

void
kcpc_idle_restore(struct cpu *cp)
{
	/*
	 * The idle thread shouldn't be run anywhere else.
	 */
	ASSERT(CPU == cp);

	/*
	 * We must hold the CPU's context lock to ensure the context isn't freed
	 * while we're looking at it.
	 */
	mutex_enter(&cp->cpu_cpc_ctxlock);

	if ((cp->cpu_cpc_ctx == NULL) ||
	    (cp->cpu_cpc_ctx->kc_flags & KCPC_CTX_INVALID)) {
		mutex_exit(&cp->cpu_cpc_ctxlock);
		return;
	}

	pcbe_ops->pcbe_allstop();
	mutex_exit(&cp->cpu_cpc_ctxlock);
}

/*ARGSUSED*/
static void
kcpc_lwp_create(kthread_t *t, kthread_t *ct)
{
	kcpc_ctx_t	*ctx = t->t_cpc_ctx, *cctx;
	int		i;

	if (ctx == NULL || (ctx->kc_flags & KCPC_CTX_LWPINHERIT) == 0)
		return;

	rw_enter(&kcpc_cpuctx_lock, RW_READER);
	if (ctx->kc_flags & KCPC_CTX_INVALID) {
		rw_exit(&kcpc_cpuctx_lock);
		return;
	}
	cctx = kcpc_ctx_alloc(KM_SLEEP);
	kcpc_ctx_clone(ctx, cctx);
	rw_exit(&kcpc_cpuctx_lock);

	/*
	 * Copy the parent context's kc_flags field, but don't overwrite
	 * the child's in case it was modified during kcpc_ctx_clone.
	 */
	KCPC_CTX_FLAG_SET(cctx,  ctx->kc_flags);
	cctx->kc_thread = ct;
	cctx->kc_cpuid = -1;
	ct->t_cpc_set = cctx->kc_set;
	ct->t_cpc_ctx = cctx;

	if (cctx->kc_flags & KCPC_CTX_SIGOVF) {
		kcpc_set_t *ks = cctx->kc_set;
		/*
		 * Our contract with the user requires us to immediately send an
		 * overflow signal to all children if we have the LWPINHERIT
		 * and SIGOVF flags set. In addition, all counters should be
		 * set to UINT64_MAX, and their pic's overflow flag turned on
		 * so that our trap() processing knows to send a signal.
		 */
		KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_FREEZE);
		for (i = 0; i < ks->ks_nreqs; i++) {
			kcpc_request_t *kr = &ks->ks_req[i];

			if (kr->kr_flags & CPC_OVF_NOTIFY_EMT) {
				*(kr->kr_data) = UINT64_MAX;
				atomic_or_uint(&kr->kr_picp->kp_flags,
				    KCPC_PIC_OVERFLOWED);
			}
		}
		ttolwp(ct)->lwp_pcb.pcb_flags |= CPC_OVERFLOW;
		aston(ct);
	}

	installctx(ct, cctx, kcpc_save, kcpc_restore,
	    NULL, kcpc_lwp_create, NULL, kcpc_free);
}

/*
 * Counter Stoppage Theory
 *
 * The counters may need to be stopped properly at the following occasions:
 *
 * 1) An LWP exits.
 * 2) A thread exits.
 * 3) An LWP performs an exec().
 * 4) A bound set is unbound.
 *
 * In addition to stopping the counters, the CPC context (a kcpc_ctx_t) may need
 * to be freed as well.
 *
 * Case 1: kcpc_passivate(), called via lwp_exit(), stops the counters. Later on
 * when the thread is freed, kcpc_free(), called by freectx(), frees the
 * context.
 *
 * Case 2: same as case 1 except kcpc_passivate is called from thread_exit().
 *
 * Case 3: kcpc_free(), called via freectx() via exec(), recognizes that it has
 * been called from exec. It stops the counters _and_ frees the context.
 *
 * Case 4: kcpc_unbind() stops the hardware _and_ frees the context.
 *
 * CPU-bound counters are always stopped via kcpc_unbind().
 */

/*
 * We're being called to delete the context; we ensure that all associated data
 * structures are freed, and that the hardware is passivated if this is an exec.
 */

/*ARGSUSED*/
void
kcpc_free(kcpc_ctx_t *ctx, int isexec)
{
	int		i;
	kcpc_set_t	*set = ctx->kc_set;

	ASSERT(set != NULL);

	/*
	 * Wait for kcpc_restore() to finish before we tear things down.
	 */
	mutex_enter(&ctx->kc_lock);
	while (ctx->kc_flags & KCPC_CTX_RESTORE)
		cv_wait(&ctx->kc_condv, &ctx->kc_lock);
	KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_INVALID);
	mutex_exit(&ctx->kc_lock);

	if (isexec) {
		/*
		 * This thread is execing, and after the exec it should not have
		 * any performance counter context. Stop the counters properly
		 * here so the system isn't surprised by an overflow interrupt
		 * later.
		 */
		if (ctx->kc_cpuid != -1) {
			cpu_t *cp;
			/*
			 * CPU-bound context; stop the appropriate CPU's ctrs.
			 * Hold cpu_lock while examining the CPU to ensure it
			 * doesn't go away.
			 */
			mutex_enter(&cpu_lock);
			cp = cpu_get(ctx->kc_cpuid);
			/*
			 * The CPU could have been DR'd out, so only stop the
			 * CPU and clear its context pointer if the CPU still
			 * exists.
			 */
			if (cp != NULL) {
				mutex_enter(&cp->cpu_cpc_ctxlock);
				kcpc_stop_hw(ctx);
				mutex_exit(&cp->cpu_cpc_ctxlock);
			}
			mutex_exit(&cpu_lock);
			ASSERT(curthread->t_cpc_ctx == NULL);
		} else {
			int save_spl;

			/*
			 * Thread-bound context; stop _this_ CPU's counters.
			 */
			kpreempt_disable();
			save_spl = spl_xcall();
			kcpc_unprogram(ctx, B_TRUE);
			curthread->t_cpc_ctx = NULL;
			splx(save_spl);
			kpreempt_enable();
		}

		/*
		 * Since we are being called from an exec and we know that
		 * exec is not permitted via the agent thread, we should clean
		 * up this thread's CPC state completely, and not leave dangling
		 * CPC pointers behind.
		 */
		ASSERT(ctx->kc_thread == curthread);
		curthread->t_cpc_set = NULL;
	}

	/*
	 * Walk through each request in this context's set and free the PCBE's
	 * configuration if it exists.
	 */
	for (i = 0; i < set->ks_nreqs; i++) {
		if (set->ks_req[i].kr_config != NULL)
			pcbe_ops->pcbe_free(set->ks_req[i].kr_config);
	}

	kmem_free(set->ks_data, set->ks_nreqs * sizeof (uint64_t));
	kcpc_ctx_free(ctx);
	kcpc_free_set(set);
}

/*
 * Free the memory associated with a request set.
 */
void
kcpc_free_set(kcpc_set_t *set)
{
	int		i;
	kcpc_request_t	*req;

	ASSERT(set->ks_req != NULL);

	for (i = 0; i < set->ks_nreqs; i++) {
		req = &set->ks_req[i];

		if (req->kr_nattrs != 0) {
			kmem_free(req->kr_attr,
			    req->kr_nattrs * sizeof (kcpc_attr_t));
		}
	}

	kmem_free(set->ks_req, sizeof (kcpc_request_t) * set->ks_nreqs);
	cv_destroy(&set->ks_condv);
	mutex_destroy(&set->ks_lock);
	kmem_free(set, sizeof (kcpc_set_t));
}

/*
 * Grab every existing context and mark it as invalid.
 */
void
kcpc_invalidate_all(void)
{
	kcpc_ctx_t *ctx;
	long hash;

	for (hash = 0; hash < CPC_HASH_BUCKETS; hash++) {
		mutex_enter(&kcpc_ctx_llock[hash]);
		for (ctx = kcpc_ctx_list[hash]; ctx; ctx = ctx->kc_next)
			KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_INVALID);
		mutex_exit(&kcpc_ctx_llock[hash]);
	}
}

/*
 * Interface for PCBEs to signal that an existing configuration has suddenly
 * become invalid.
 */
void
kcpc_invalidate_config(void *token)
{
	kcpc_ctx_t *ctx = token;

	ASSERT(ctx != NULL);

	KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_INVALID);
}

/*
 * Called from lwp_exit() and thread_exit()
 */
void
kcpc_passivate(void)
{
	kcpc_ctx_t *ctx = curthread->t_cpc_ctx;
	kcpc_set_t *set = curthread->t_cpc_set;
	int	save_spl;

	if (set == NULL)
		return;

	if (ctx == NULL) {
		/*
		 * This thread has a set but no context; it must be a CPU-bound
		 * set. The hardware will be stopped via kcpc_unbind() when the
		 * process exits and closes its file descriptors with
		 * kcpc_close(). Our only job here is to clean up this thread's
		 * state; the set will be freed with the unbind().
		 */
		(void) kcpc_unbind(set);
		/*
		 * Unbinding a set belonging to the current thread should clear
		 * its set pointer.
		 */
		ASSERT(curthread->t_cpc_set == NULL);
		return;
	}

	kpreempt_disable();
	save_spl = spl_xcall();
	curthread->t_cpc_set = NULL;

	/*
	 * This thread/LWP is exiting but context switches will continue to
	 * happen for a bit as the exit proceeds.  Kernel preemption must be
	 * disabled here to prevent a race between checking or setting the
	 * INVALID_STOPPED flag here and kcpc_restore() setting the flag during
	 * a context switch.
	 */
	if ((ctx->kc_flags & KCPC_CTX_INVALID_STOPPED) == 0) {
		kcpc_unprogram(ctx, B_TRUE);
		KCPC_CTX_FLAG_SET(ctx,
		    KCPC_CTX_INVALID | KCPC_CTX_INVALID_STOPPED);
	}

	/*
	 * We're cleaning up after this thread; ensure there are no dangling
	 * CPC pointers left behind. The context and set will be freed by
	 * freectx().
	 */
	curthread->t_cpc_ctx = NULL;

	splx(save_spl);
	kpreempt_enable();
}

/*
 * Assign the requests in the given set to the PICs in the context.
 * Returns 0 if successful, -1 on failure.
 */
/*ARGSUSED*/
int
kcpc_assign_reqs(kcpc_set_t *set, kcpc_ctx_t *ctx)
{
	int i;
	int *picnum_save;

	ASSERT(set->ks_nreqs <= cpc_ncounters);

	/*
	 * Provide kcpc_tryassign() with scratch space to avoid doing an
	 * alloc/free with every invocation.
	 */
	picnum_save = kmem_alloc(set->ks_nreqs * sizeof (int), KM_SLEEP);
	/*
	 * kcpc_tryassign() blindly walks through each request in the set,
	 * seeing if a counter can count its event. If yes, it assigns that
	 * counter. However, that counter may have been the only capable counter
	 * for _another_ request's event. The solution is to try every possible
	 * request first. Note that this does not cover all solutions, as
	 * that would require all unique orderings of requests, an n^n operation
	 * which would be unacceptable for architectures with many counters.
	 */
	for (i = 0; i < set->ks_nreqs; i++)
		if (kcpc_tryassign(set, i, picnum_save) == 0)
			break;

	kmem_free(picnum_save, set->ks_nreqs * sizeof (int));
	if (i == set->ks_nreqs)
		return (-1);
	return (0);
}

static int
kcpc_tryassign(kcpc_set_t *set, int starting_req, int *scratch)
{
	int		i;
	int		j;
	uint64_t	bitmap = 0, resmap = 0;
	uint64_t	ctrmap;

	/*
	 * We are attempting to assign the reqs to pics, but we may fail. If we
	 * fail, we need to restore the state of the requests to what it was
	 * when we found it, as some reqs may have been explicitly assigned to
	 * a specific PIC beforehand. We do this by snapshotting the assignments
	 * now and restoring from it later if we fail.
	 *
	 * Also we note here which counters have already been claimed by
	 * requests with explicit counter assignments.
	 */
	for (i = 0; i < set->ks_nreqs; i++) {
		scratch[i] = set->ks_req[i].kr_picnum;
		if (set->ks_req[i].kr_picnum != -1)
			resmap |= (1 << set->ks_req[i].kr_picnum);
	}

	/*
	 * Walk through requests assigning them to the first PIC that is
	 * capable.
	 */
	i = starting_req;
	do {
		if (set->ks_req[i].kr_picnum != -1) {
			ASSERT((bitmap & (1 << set->ks_req[i].kr_picnum)) == 0);
			bitmap |= (1 << set->ks_req[i].kr_picnum);
			if (++i == set->ks_nreqs)
				i = 0;
			continue;
		}

		ctrmap = pcbe_ops->pcbe_event_coverage(set->ks_req[i].kr_event);
		for (j = 0; j < cpc_ncounters; j++) {
			if (ctrmap & (1 << j) && (bitmap & (1 << j)) == 0 &&
			    (resmap & (1 << j)) == 0) {
				/*
				 * We can assign this counter because:
				 *
				 * 1. It can count the event (ctrmap)
				 * 2. It hasn't been assigned yet (bitmap)
				 * 3. It wasn't reserved by a request (resmap)
				 */
				bitmap |= (1 << j);
				break;
			}
		}
		if (j == cpc_ncounters) {
			for (i = 0; i < set->ks_nreqs; i++)
				set->ks_req[i].kr_picnum = scratch[i];
			return (-1);
		}
		set->ks_req[i].kr_picnum = j;

		if (++i == set->ks_nreqs)
			i = 0;
	} while (i != starting_req);

	return (0);
}

kcpc_set_t *
kcpc_dup_set(kcpc_set_t *set)
{
	kcpc_set_t	*new;
	int		i;
	int		j;

	new = kmem_zalloc(sizeof (*new), KM_SLEEP);
	new->ks_state &= ~KCPC_SET_BOUND;
	new->ks_flags = set->ks_flags;
	new->ks_nreqs = set->ks_nreqs;
	new->ks_req = kmem_alloc(set->ks_nreqs * sizeof (kcpc_request_t),
	    KM_SLEEP);
	new->ks_data = NULL;
	new->ks_ctx = NULL;

	for (i = 0; i < new->ks_nreqs; i++) {
		new->ks_req[i].kr_config = NULL;
		new->ks_req[i].kr_index = set->ks_req[i].kr_index;
		new->ks_req[i].kr_picnum = set->ks_req[i].kr_picnum;
		new->ks_req[i].kr_picp = NULL;
		new->ks_req[i].kr_data = NULL;
		(void) strncpy(new->ks_req[i].kr_event, set->ks_req[i].kr_event,
		    CPC_MAX_EVENT_LEN);
		new->ks_req[i].kr_preset = set->ks_req[i].kr_preset;
		new->ks_req[i].kr_flags = set->ks_req[i].kr_flags;
		new->ks_req[i].kr_nattrs = set->ks_req[i].kr_nattrs;
		new->ks_req[i].kr_attr = kmem_alloc(new->ks_req[i].kr_nattrs *
		    sizeof (kcpc_attr_t), KM_SLEEP);
		for (j = 0; j < new->ks_req[i].kr_nattrs; j++) {
			new->ks_req[i].kr_attr[j].ka_val =
			    set->ks_req[i].kr_attr[j].ka_val;
			(void) strncpy(new->ks_req[i].kr_attr[j].ka_name,
			    set->ks_req[i].kr_attr[j].ka_name,
			    CPC_MAX_ATTR_LEN);
		}
	}

	return (new);
}

int
kcpc_allow_nonpriv(void *token)
{
	return (((kcpc_ctx_t *)token)->kc_flags & KCPC_CTX_NONPRIV);
}

void
kcpc_invalidate(kthread_t *t)
{
	kcpc_ctx_t *ctx = t->t_cpc_ctx;

	if (ctx != NULL)
		KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_INVALID);
}

/*
 * Given a PCBE ID, attempt to load a matching PCBE module. The strings given
 * are used to construct PCBE names, starting with the most specific,
 * "pcbe.first.second.third.fourth" and ending with the least specific,
 * "pcbe.first".
 *
 * Returns 0 if a PCBE was successfully loaded and -1 upon error.
 */
int
kcpc_pcbe_tryload(const char *prefix, uint_t first, uint_t second, uint_t third)
{
	uint_t s[3];

	s[0] = first;
	s[1] = second;
	s[2] = third;

	return (modload_qualified("pcbe",
	    "pcbe", prefix, ".", s, 3, NULL) < 0 ? -1 : 0);
}

/*
 * Create one or more CPC context for given CPU with specified counter event
 * requests
 *
 * If number of requested counter events is less than or equal number of
 * hardware counters on a CPU and can all be assigned to the counters on a CPU
 * at the same time, then make one CPC context.
 *
 * Otherwise, multiple CPC contexts are created to allow multiplexing more
 * counter events than existing counters onto the counters by iterating through
 * all of the CPC contexts, programming the counters with each CPC context one
 * at a time and measuring the resulting counter values.  Each of the resulting
 * CPC contexts contains some number of requested counter events less than or
 * equal the number of counters on a CPU depending on whether all the counter
 * events can be programmed on all the counters at the same time or not.
 *
 * Flags to kmem_{,z}alloc() are passed in as an argument to allow specifying
 * whether memory allocation should be non-blocking or not.  The code will try
 * to allocate *whole* CPC contexts if possible.  If there is any memory
 * allocation failure during the allocations needed for a given CPC context, it
 * will skip allocating that CPC context because it cannot allocate the whole
 * thing.  Thus, the only time that it will end up allocating none (ie. no CPC
 * contexts whatsoever) is when it cannot even allocate *one* whole CPC context
 * without a memory allocation failure occurring.
 */
int
kcpc_cpu_ctx_create(cpu_t *cp, kcpc_request_list_t *req_list, int kmem_flags,
    kcpc_ctx_t ***ctx_ptr_array, size_t *ctx_ptr_array_sz)
{
	kcpc_ctx_t	**ctx_ptrs;
	int		nctx;
	int		nctx_ptrs;
	int		nreqs;
	kcpc_request_t	*reqs;

	if (cp == NULL || ctx_ptr_array == NULL || ctx_ptr_array_sz == NULL ||
	    req_list == NULL || req_list->krl_cnt < 1)
		return (-1);

	/*
	 * Allocate number of sets assuming that each set contains one and only
	 * one counter event request for each counter on a CPU
	 */
	nreqs = req_list->krl_cnt;
	nctx_ptrs = (nreqs + cpc_ncounters - 1) / cpc_ncounters;
	ctx_ptrs = kmem_zalloc(nctx_ptrs * sizeof (kcpc_ctx_t *), kmem_flags);
	if (ctx_ptrs == NULL)
		return (-2);

	/*
	 * Fill in sets of requests
	 */
	nctx = 0;
	reqs = req_list->krl_list;
	while (nreqs > 0) {
		kcpc_ctx_t	*ctx;
		kcpc_set_t	*set;
		int		subcode;

		/*
		 * Allocate CPC context and set for requested counter events
		 */
		ctx = kcpc_ctx_alloc(kmem_flags);
		set = kcpc_set_create(reqs, nreqs, 0, kmem_flags);
		if (set == NULL) {
			kcpc_ctx_free(ctx);
			break;
		}

		/*
		 * Determine assignment of requested counter events to specific
		 * counters
		 */
		if (kcpc_assign_reqs(set, ctx) != 0) {
			/*
			 * May not be able to assign requested counter events
			 * to all counters since all counters may not be able
			 * to do all events, so only do one counter event in
			 * set of counter requests when this happens since at
			 * least one of the counters must be able to do the
			 * event.
			 */
			kcpc_free_set(set);
			set = kcpc_set_create(reqs, 1, 0, kmem_flags);
			if (set == NULL) {
				kcpc_ctx_free(ctx);
				break;
			}
			if (kcpc_assign_reqs(set, ctx) != 0) {
#ifdef DEBUG
				cmn_err(CE_NOTE, "!kcpc_cpu_ctx_create: can't "
				    "assign counter event %s!\n",
				    set->ks_req->kr_event);
#endif
				kcpc_free_set(set);
				kcpc_ctx_free(ctx);
				reqs++;
				nreqs--;
				continue;
			}
		}

		/*
		 * Allocate memory needed to hold requested counter event data
		 */
		set->ks_data = kmem_zalloc(set->ks_nreqs * sizeof (uint64_t),
		    kmem_flags);
		if (set->ks_data == NULL) {
			kcpc_free_set(set);
			kcpc_ctx_free(ctx);
			break;
		}

		/*
		 * Configure requested counter events
		 */
		if (kcpc_configure_reqs(ctx, set, &subcode) != 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE,
			    "!kcpc_cpu_ctx_create: can't configure "
			    "set of counter event requests!\n");
#endif
			reqs += set->ks_nreqs;
			nreqs -= set->ks_nreqs;
			kmem_free(set->ks_data,
			    set->ks_nreqs * sizeof (uint64_t));
			kcpc_free_set(set);
			kcpc_ctx_free(ctx);
			continue;
		}

		/*
		 * Point set of counter event requests at this context and fill
		 * in CPC context
		 */
		set->ks_ctx = ctx;
		ctx->kc_set = set;
		ctx->kc_cpuid = cp->cpu_id;
		ctx->kc_thread = curthread;

		ctx_ptrs[nctx] = ctx;

		/*
		 * Update requests and how many are left to be assigned to sets
		 */
		reqs += set->ks_nreqs;
		nreqs -= set->ks_nreqs;

		/*
		 * Increment number of CPC contexts and allocate bigger array
		 * for context pointers as needed
		 */
		nctx++;
		if (nctx >= nctx_ptrs) {
			kcpc_ctx_t	**new;
			int		new_cnt;

			/*
			 * Allocate more CPC contexts based on how many
			 * contexts allocated so far and how many counter
			 * requests left to assign
			 */
			new_cnt = nctx_ptrs +
			    ((nreqs + cpc_ncounters - 1) / cpc_ncounters);
			new = kmem_zalloc(new_cnt * sizeof (kcpc_ctx_t *),
			    kmem_flags);
			if (new == NULL)
				break;

			/*
			 * Copy contents of old sets into new ones
			 */
			bcopy(ctx_ptrs, new,
			    nctx_ptrs * sizeof (kcpc_ctx_t *));

			/*
			 * Free old array of context pointers and use newly
			 * allocated one instead now
			 */
			kmem_free(ctx_ptrs, nctx_ptrs * sizeof (kcpc_ctx_t *));
			ctx_ptrs = new;
			nctx_ptrs = new_cnt;
		}
	}

	/*
	 * Return NULL if no CPC contexts filled in
	 */
	if (nctx == 0) {
		kmem_free(ctx_ptrs, nctx_ptrs * sizeof (kcpc_ctx_t *));
		*ctx_ptr_array = NULL;
		*ctx_ptr_array_sz = 0;
		return (-2);
	}

	*ctx_ptr_array = ctx_ptrs;
	*ctx_ptr_array_sz = nctx_ptrs * sizeof (kcpc_ctx_t *);
	return (nctx);
}

/*
 * Return whether PCBE supports given counter event
 */
boolean_t
kcpc_event_supported(char *event)
{
	if (pcbe_ops == NULL || pcbe_ops->pcbe_event_coverage(event) == 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Program counters on current CPU with given CPC context
 *
 * If kernel is interposing on counters to measure hardware capacity and
 * utilization, then unprogram counters for kernel *before* programming them
 * with specified CPC context.
 *
 * kcpc_{program,unprogram}() may be called either directly by a thread running
 * on the target CPU or from a cross-call from another CPU. To protect
 * programming and unprogramming from being interrupted by cross-calls, callers
 * who execute kcpc_{program,unprogram} should raise PIL to the level used by
 * cross-calls.
 */
void
kcpc_program(kcpc_ctx_t *ctx, boolean_t for_thread, boolean_t cu_interpose)
{
	int	error;

	ASSERT(IS_HIPIL());

	/*
	 * CPC context shouldn't be NULL, its CPU field should specify current
	 * CPU or be -1 to specify any CPU when the context is bound to a
	 * thread, and preemption should be disabled
	 */
	ASSERT(ctx != NULL && (ctx->kc_cpuid == CPU->cpu_id ||
	    ctx->kc_cpuid == -1) && curthread->t_preempt > 0);
	if (ctx == NULL || (ctx->kc_cpuid != CPU->cpu_id &&
	    ctx->kc_cpuid != -1) || curthread->t_preempt < 1)
		return;

	/*
	 * Unprogram counters for kernel measuring hardware capacity and
	 * utilization
	 */
	if (cu_interpose == B_TRUE) {
		cu_cpc_unprogram(CPU, &error);
	} else {
		kcpc_set_t *set = ctx->kc_set;
		int i;

		ASSERT(set != NULL);

		/*
		 * Since cu_interpose is false, we are programming CU context.
		 * In general, PCBE can continue from the state saved in the
		 * set, but it is not very reliable, so we start again from the
		 * preset value.
		 */
		for (i = 0; i < set->ks_nreqs; i++) {
			/*
			 * Reset the virtual counter value to the preset value.
			 */
			*(set->ks_req[i].kr_data) = set->ks_req[i].kr_preset;

			/*
			 * Reset PCBE to the preset value.
			 */
			pcbe_ops->pcbe_configure(0, NULL,
			    set->ks_req[i].kr_preset,
			    0, 0, NULL, &set->ks_req[i].kr_config, NULL);
		}
	}

	/*
	 * Program counters with specified CPC context
	 */
	ctx->kc_rawtick = KCPC_GET_TICK();
	pcbe_ops->pcbe_program(ctx);

	/*
	 * Denote that counters programmed for thread or CPU CPC context
	 * differently
	 */
	if (for_thread == B_TRUE)
		KCPC_CTX_FLAG_CLR(ctx, KCPC_CTX_FREEZE);
	else
		CPU->cpu_cpc_ctx = ctx;
}

/*
 * Unprogram counters with given CPC context on current CPU
 *
 * If kernel is interposing on counters to measure hardware capacity and
 * utilization, then program counters for the kernel capacity and utilization
 * *after* unprogramming them for given CPC context.
 *
 * See the comment for kcpc_program regarding the synchronization with
 * cross-calls.
 */
void
kcpc_unprogram(kcpc_ctx_t *ctx, boolean_t cu_interpose)
{
	int	error;

	ASSERT(IS_HIPIL());

	/*
	 * CPC context shouldn't be NULL, its CPU field should specify current
	 * CPU or be -1 to specify any CPU when the context is bound to a
	 * thread, and preemption should be disabled
	 */
	ASSERT(ctx != NULL && (ctx->kc_cpuid == CPU->cpu_id ||
	    ctx->kc_cpuid == -1) && curthread->t_preempt > 0);

	if (ctx == NULL || (ctx->kc_cpuid != CPU->cpu_id &&
	    ctx->kc_cpuid != -1) || curthread->t_preempt < 1 ||
	    (ctx->kc_flags & KCPC_CTX_INVALID_STOPPED) != 0) {
		return;
	}

	/*
	 * Specified CPC context to be unprogrammed should be bound to current
	 * CPU or thread
	 */
	ASSERT(CPU->cpu_cpc_ctx == ctx || curthread->t_cpc_ctx == ctx);

	/*
	 * Stop counters
	 */
	pcbe_ops->pcbe_allstop();
	KCPC_CTX_FLAG_SET(ctx, KCPC_CTX_INVALID_STOPPED);

	/*
	 * Allow kernel to interpose on counters and program them for its own
	 * use to measure hardware capacity and utilization if cu_interpose
	 * argument is true
	 */
	if (cu_interpose == B_TRUE)
		cu_cpc_program(CPU, &error);
}

/*
 * Read CPU Performance Counter (CPC) on current CPU and call specified update
 * routine with data for each counter event currently programmed on CPU
 */
int
kcpc_read(kcpc_update_func_t update_func)
{
	kcpc_ctx_t	*ctx;
	int		i;
	kcpc_request_t	*req;
	int		retval;
	kcpc_set_t	*set;

	ASSERT(IS_HIPIL());

	/*
	 * Can't grab locks or block because may be called inside dispatcher
	 */
	kpreempt_disable();

	ctx = CPU->cpu_cpc_ctx;
	if (ctx == NULL) {
		kpreempt_enable();
		return (0);
	}

	/*
	 * Read counter data from current CPU
	 */
	pcbe_ops->pcbe_sample(ctx);

	set = ctx->kc_set;
	if (set == NULL || set->ks_req == NULL) {
		kpreempt_enable();
		return (0);
	}

	/*
	 * Call update function with preset pointer and data for each CPC event
	 * request currently programmed on current CPU
	 */
	req = set->ks_req;
	retval = 0;
	for (i = 0; i < set->ks_nreqs; i++) {
		int	ret;

		if (req[i].kr_data == NULL)
			break;

		ret = update_func(req[i].kr_ptr, *req[i].kr_data);
		if (ret < 0)
			retval = ret;
	}

	kpreempt_enable();

	return (retval);
}

/*
 * Initialize list of counter event requests
 */
kcpc_request_list_t *
kcpc_reqs_init(int nreqs, int kmem_flags)
{
	kcpc_request_list_t	*req_list;
	kcpc_request_t		*reqs;

	if (nreqs < 1)
		return (NULL);

	req_list = kmem_zalloc(sizeof (kcpc_request_list_t), kmem_flags);
	if (req_list == NULL)
		return (NULL);

	reqs = kmem_zalloc(nreqs * sizeof (kcpc_request_t), kmem_flags);
	if (reqs == NULL) {
		kmem_free(req_list, sizeof (kcpc_request_list_t));
		return (NULL);
	}

	req_list->krl_list = reqs;
	req_list->krl_cnt = 0;
	req_list->krl_max = nreqs;
	return (req_list);
}


/*
 * Add counter event request to given list of counter event requests
 */
int
kcpc_reqs_add(kcpc_request_list_t *req_list, char *event, uint64_t preset,
    uint_t flags, uint_t nattrs, kcpc_attr_t *attr, void *ptr, int kmem_flags)
{
	kcpc_request_t	*req;

	if (req_list == NULL || req_list->krl_list == NULL)
		return (-1);

	ASSERT(req_list->krl_max != 0);

	/*
	 * Allocate more space (if needed)
	 */
	if (req_list->krl_cnt > req_list->krl_max) {
		kcpc_request_t	*new;
		kcpc_request_t	*old;

		old = req_list->krl_list;
		new = kmem_zalloc((req_list->krl_max +
		    cpc_ncounters) * sizeof (kcpc_request_t), kmem_flags);
		if (new == NULL)
			return (-2);

		req_list->krl_list = new;
		bcopy(old, req_list->krl_list,
		    req_list->krl_cnt * sizeof (kcpc_request_t));
		kmem_free(old, req_list->krl_max * sizeof (kcpc_request_t));
		req_list->krl_cnt = 0;
		req_list->krl_max += cpc_ncounters;
	}

	/*
	 * Fill in request as much as possible now, but some fields will need
	 * to be set when request is assigned to a set.
	 */
	req = &req_list->krl_list[req_list->krl_cnt];
	req->kr_config = NULL;
	req->kr_picnum = -1;	/* have CPC pick this */
	req->kr_index = -1;	/* set when assigning request to set */
	req->kr_data = NULL;	/* set when configuring request */
	(void) strcpy(req->kr_event, event);
	req->kr_preset = preset;
	req->kr_flags = flags;
	req->kr_nattrs = nattrs;
	req->kr_attr = attr;
	/*
	 * Keep pointer given by caller to give to update function when this
	 * counter event is sampled/read
	 */
	req->kr_ptr = ptr;

	req_list->krl_cnt++;

	return (0);
}

/*
 * Reset list of CPC event requests so its space can be used for another set
 * of requests
 */
int
kcpc_reqs_reset(kcpc_request_list_t *req_list)
{
	/*
	 * Return when pointer to request list structure or request is NULL or
	 * when max requests is less than or equal to 0
	 */
	if (req_list == NULL || req_list->krl_list == NULL ||
	    req_list->krl_max <= 0)
		return (-1);

	/*
	 * Zero out requests and number of requests used
	 */
	bzero(req_list->krl_list, req_list->krl_max * sizeof (kcpc_request_t));
	req_list->krl_cnt = 0;
	return (0);
}

/*
 * Free given list of counter event requests
 */
int
kcpc_reqs_fini(kcpc_request_list_t *req_list)
{
	kmem_free(req_list->krl_list,
	    req_list->krl_max * sizeof (kcpc_request_t));
	kmem_free(req_list, sizeof (kcpc_request_list_t));
	return (0);
}

/*
 * Create set of given counter event requests
 */
static kcpc_set_t *
kcpc_set_create(kcpc_request_t *reqs, int nreqs, int set_flags, int kmem_flags)
{
	int		i;
	kcpc_set_t	*set;

	/*
	 * Allocate set and assign number of requests in set and flags
	 */
	set = kmem_zalloc(sizeof (kcpc_set_t), kmem_flags);
	if (set == NULL)
		return (NULL);

	if (nreqs < cpc_ncounters)
		set->ks_nreqs = nreqs;
	else
		set->ks_nreqs = cpc_ncounters;

	set->ks_flags = set_flags;

	/*
	 * Allocate requests needed, copy requests into set, and set index into
	 * data for each request (which may change when we assign requested
	 * counter events to counters)
	 */
	set->ks_req = (kcpc_request_t *)kmem_zalloc(sizeof (kcpc_request_t) *
	    set->ks_nreqs, kmem_flags);
	if (set->ks_req == NULL) {
		kmem_free(set, sizeof (kcpc_set_t));
		return (NULL);
	}

	bcopy(reqs, set->ks_req, sizeof (kcpc_request_t) * set->ks_nreqs);

	for (i = 0; i < set->ks_nreqs; i++)
		set->ks_req[i].kr_index = i;

	return (set);
}


/*
 * Stop counters on current CPU.
 *
 * If preserve_context is true, the caller is interested in the CPU's CPC
 * context and wants it to be preserved.
 *
 * If preserve_context is false, the caller does not need the CPU's CPC context
 * to be preserved, so it is set to NULL.
 */
static void
kcpc_cpustop_func(boolean_t preserve_context)
{
	kpreempt_disable();

	/*
	 * Someone already stopped this context before us, so there is nothing
	 * to do.
	 */
	if (CPU->cpu_cpc_ctx == NULL) {
		kpreempt_enable();
		return;
	}

	kcpc_unprogram(CPU->cpu_cpc_ctx, B_TRUE);
	/*
	 * If CU does not use counters, then clear the CPU's CPC context
	 * If the caller requested to preserve context it should disable CU
	 * first, so there should be no CU context now.
	 */
	ASSERT(!preserve_context || !CU_CPC_ON(CPU));
	if (!preserve_context && CPU->cpu_cpc_ctx != NULL && !CU_CPC_ON(CPU))
		CPU->cpu_cpc_ctx = NULL;

	kpreempt_enable();
}

/*
 * Stop counters on given CPU and set its CPC context to NULL unless
 * preserve_context is true.
 */
void
kcpc_cpu_stop(cpu_t *cp, boolean_t preserve_context)
{
	cpu_call(cp, (cpu_call_func_t)kcpc_cpustop_func,
	    preserve_context, 0);
}

/*
 * Program the context on the current CPU
 */
static void
kcpc_remoteprogram_func(kcpc_ctx_t *ctx, uintptr_t arg)
{
	boolean_t for_thread = (boolean_t)arg;

	ASSERT(ctx != NULL);

	kpreempt_disable();
	kcpc_program(ctx, for_thread, B_TRUE);
	kpreempt_enable();
}

/*
 * Program counters on given CPU
 */
void
kcpc_cpu_program(cpu_t *cp, kcpc_ctx_t *ctx)
{
	cpu_call(cp, (cpu_call_func_t)kcpc_remoteprogram_func, (uintptr_t)ctx,
	    (uintptr_t)B_FALSE);
}

char *
kcpc_list_attrs(void)
{
	ASSERT(pcbe_ops != NULL);

	return (pcbe_ops->pcbe_list_attrs());
}

char *
kcpc_list_events(uint_t pic)
{
	ASSERT(pcbe_ops != NULL);

	return (pcbe_ops->pcbe_list_events(pic));
}

uint_t
kcpc_pcbe_capabilities(void)
{
	ASSERT(pcbe_ops != NULL);

	return (pcbe_ops->pcbe_caps);
}

int
kcpc_pcbe_loaded(void)
{
	return (pcbe_ops == NULL ? -1 : 0);
}
