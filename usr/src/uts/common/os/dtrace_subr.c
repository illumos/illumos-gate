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

#include <sys/dtrace.h>
#include <sys/cmn_err.h>
#include <sys/tnf.h>
#include <sys/atomic.h>
#include <sys/prsystm.h>
#include <sys/modctl.h>
#include <sys/aio_impl.h>

#ifdef __sparc
#include <sys/privregs.h>
#endif

void (*dtrace_cpu_init)(processorid_t);
void (*dtrace_modload)(struct modctl *);
void (*dtrace_modunload)(struct modctl *);
void (*dtrace_helpers_cleanup)(void);
void (*dtrace_helpers_fork)(proc_t *, proc_t *);
void (*dtrace_cpustart_init)(void);
void (*dtrace_cpustart_fini)(void);
void (*dtrace_cpc_fire)(uint64_t);
void (*dtrace_closef)(void);

void (*dtrace_debugger_init)(void);
void (*dtrace_debugger_fini)(void);

dtrace_vtime_state_t dtrace_vtime_active = 0;
dtrace_cacheid_t dtrace_predcache_id = DTRACE_CACHEIDNONE + 1;

/*
 * dtrace_cpc_in_use usage statement: this global variable is used by the cpc
 * hardware overflow interrupt handler and the kernel cpc framework to check
 * whether or not the DTrace cpc provider is currently in use. The variable is
 * set before counters are enabled with the first enabling and cleared when
 * the last enabling is disabled. Its value at any given time indicates the
 * number of active dcpc based enablings. The global 'kcpc_cpuctx_lock' rwlock
 * is held during initial setting to protect races between kcpc_open() and the
 * first enabling. The locking provided by the DTrace subsystem, the kernel
 * cpc framework and the cpu management framework protect consumers from race
 * conditions on enabling and disabling probes.
 */
uint32_t dtrace_cpc_in_use = 0;

typedef struct dtrace_hrestime {
	lock_t		dthr_lock;		/* lock for this element */
	timestruc_t	dthr_hrestime;		/* hrestime value */
	int64_t		dthr_adj;		/* hrestime_adj value */
	hrtime_t	dthr_hrtime;		/* hrtime value */
} dtrace_hrestime_t;

static dtrace_hrestime_t dtrace_hrestime[2];

/*
 * Making available adjustable high-resolution time in DTrace is regrettably
 * more complicated than one might think it should be.  The problem is that
 * the variables related to adjusted high-resolution time (hrestime,
 * hrestime_adj and friends) are adjusted under hres_lock -- and this lock may
 * be held when we enter probe context.  One might think that we could address
 * this by having a single snapshot copy that is stored under a different lock
 * from hres_tick(), using the snapshot iff hres_lock is locked in probe
 * context.  Unfortunately, this too won't work:  because hres_lock is grabbed
 * in more than just hres_tick() context, we could enter probe context
 * concurrently on two different CPUs with both locks (hres_lock and the
 * snapshot lock) held.  As this implies, the fundamental problem is that we
 * need to have access to a snapshot of these variables that we _know_ will
 * not be locked in probe context.  To effect this, we have two snapshots
 * protected by two different locks, and we mandate that these snapshots are
 * recorded in succession by a single thread calling dtrace_hres_tick().  (We
 * assure this by calling it out of the same CY_HIGH_LEVEL cyclic that calls
 * hres_tick().)  A single thread can't be in two places at once:  one of the
 * snapshot locks is guaranteed to be unheld at all times.  The
 * dtrace_gethrestime() algorithm is thus to check first one snapshot and then
 * the other to find the unlocked snapshot.
 */
void
dtrace_hres_tick(void)
{
	int i;
	ushort_t spl;

	for (i = 0; i < 2; i++) {
		dtrace_hrestime_t tmp;

		spl = hr_clock_lock();
		tmp.dthr_hrestime = hrestime;
		tmp.dthr_adj = hrestime_adj;
		tmp.dthr_hrtime = dtrace_gethrtime();
		hr_clock_unlock(spl);

		lock_set(&dtrace_hrestime[i].dthr_lock);
		dtrace_hrestime[i].dthr_hrestime = tmp.dthr_hrestime;
		dtrace_hrestime[i].dthr_adj = tmp.dthr_adj;
		dtrace_hrestime[i].dthr_hrtime = tmp.dthr_hrtime;
		dtrace_membar_producer();

		/*
		 * To allow for lock-free examination of this lock, we use
		 * the same trick that is used hres_lock; for more details,
		 * see the description of this technique in sun4u/sys/clock.h.
		 */
		dtrace_hrestime[i].dthr_lock++;
	}
}

hrtime_t
dtrace_gethrestime(void)
{
	dtrace_hrestime_t snap;
	hrtime_t now;
	int i = 0, adj, nslt;

	for (;;) {
		snap.dthr_lock = dtrace_hrestime[i].dthr_lock;
		dtrace_membar_consumer();
		snap.dthr_hrestime = dtrace_hrestime[i].dthr_hrestime;
		snap.dthr_hrtime = dtrace_hrestime[i].dthr_hrtime;
		snap.dthr_adj = dtrace_hrestime[i].dthr_adj;
		dtrace_membar_consumer();

		if ((snap.dthr_lock & ~1) == dtrace_hrestime[i].dthr_lock)
			break;

		/*
		 * If we're here, the lock was either locked, or it
		 * transitioned while we were taking the snapshot.  Either
		 * way, we're going to try the other dtrace_hrestime element;
		 * we know that it isn't possible for both to be locked
		 * simultaneously, so we will ultimately get a good snapshot.
		 */
		i ^= 1;
	}

	/*
	 * We have a good snapshot.  Now perform any necessary adjustments.
	 */
	nslt = dtrace_gethrtime() - snap.dthr_hrtime;
	ASSERT(nslt >= 0);

	now = ((hrtime_t)snap.dthr_hrestime.tv_sec * (hrtime_t)NANOSEC) +
	    snap.dthr_hrestime.tv_nsec;

	if (snap.dthr_adj != 0) {
		if (snap.dthr_adj > 0) {
			adj = (nslt >> adj_shift);
			if (adj > snap.dthr_adj)
				adj = (int)snap.dthr_adj;
		} else {
			adj = -(nslt >> adj_shift);
			if (adj < snap.dthr_adj)
				adj = (int)snap.dthr_adj;
		}
		now += adj;
	}

	return (now);
}

void
dtrace_vtime_enable(void)
{
	dtrace_vtime_state_t state, nstate;

	do {
		state = dtrace_vtime_active;

		switch (state) {
		case DTRACE_VTIME_INACTIVE:
			nstate = DTRACE_VTIME_ACTIVE;
			break;

		case DTRACE_VTIME_INACTIVE_TNF:
			nstate = DTRACE_VTIME_ACTIVE_TNF;
			break;

		case DTRACE_VTIME_ACTIVE:
		case DTRACE_VTIME_ACTIVE_TNF:
			panic("DTrace virtual time already enabled");
			/*NOTREACHED*/
		}

	} while	(cas32((uint32_t *)&dtrace_vtime_active,
	    state, nstate) != state);
}

void
dtrace_vtime_disable(void)
{
	dtrace_vtime_state_t state, nstate;

	do {
		state = dtrace_vtime_active;

		switch (state) {
		case DTRACE_VTIME_ACTIVE:
			nstate = DTRACE_VTIME_INACTIVE;
			break;

		case DTRACE_VTIME_ACTIVE_TNF:
			nstate = DTRACE_VTIME_INACTIVE_TNF;
			break;

		case DTRACE_VTIME_INACTIVE:
		case DTRACE_VTIME_INACTIVE_TNF:
			panic("DTrace virtual time already disabled");
			/*NOTREACHED*/
		}

	} while	(cas32((uint32_t *)&dtrace_vtime_active,
	    state, nstate) != state);
}

void
dtrace_vtime_enable_tnf(void)
{
	dtrace_vtime_state_t state, nstate;

	do {
		state = dtrace_vtime_active;

		switch (state) {
		case DTRACE_VTIME_ACTIVE:
			nstate = DTRACE_VTIME_ACTIVE_TNF;
			break;

		case DTRACE_VTIME_INACTIVE:
			nstate = DTRACE_VTIME_INACTIVE_TNF;
			break;

		case DTRACE_VTIME_ACTIVE_TNF:
		case DTRACE_VTIME_INACTIVE_TNF:
			panic("TNF already active");
			/*NOTREACHED*/
		}

	} while	(cas32((uint32_t *)&dtrace_vtime_active,
	    state, nstate) != state);
}

void
dtrace_vtime_disable_tnf(void)
{
	dtrace_vtime_state_t state, nstate;

	do {
		state = dtrace_vtime_active;

		switch (state) {
		case DTRACE_VTIME_ACTIVE_TNF:
			nstate = DTRACE_VTIME_ACTIVE;
			break;

		case DTRACE_VTIME_INACTIVE_TNF:
			nstate = DTRACE_VTIME_INACTIVE;
			break;

		case DTRACE_VTIME_ACTIVE:
		case DTRACE_VTIME_INACTIVE:
			panic("TNF already inactive");
			/*NOTREACHED*/
		}

	} while	(cas32((uint32_t *)&dtrace_vtime_active,
	    state, nstate) != state);
}

void
dtrace_vtime_switch(kthread_t *next)
{
	dtrace_icookie_t cookie;
	hrtime_t ts;

	if (tnf_tracing_active) {
		tnf_thread_switch(next);

		if (dtrace_vtime_active == DTRACE_VTIME_INACTIVE_TNF)
			return;
	}

	cookie = dtrace_interrupt_disable();
	ts = dtrace_gethrtime();

	if (curthread->t_dtrace_start != 0) {
		curthread->t_dtrace_vtime += ts - curthread->t_dtrace_start;
		curthread->t_dtrace_start = 0;
	}

	next->t_dtrace_start = ts;

	dtrace_interrupt_enable(cookie);
}

void (*dtrace_fasttrap_fork_ptr)(proc_t *, proc_t *);
void (*dtrace_fasttrap_exec_ptr)(proc_t *);
void (*dtrace_fasttrap_exit_ptr)(proc_t *);

/*
 * This function is called by cfork() in the event that it appears that
 * there may be dtrace tracepoints active in the parent process's address
 * space. This first confirms the existence of dtrace tracepoints in the
 * parent process and calls into the fasttrap module to remove the
 * corresponding tracepoints from the child. By knowing that there are
 * existing tracepoints, and ensuring they can't be removed, we can rely
 * on the fasttrap module remaining loaded.
 */
void
dtrace_fasttrap_fork(proc_t *p, proc_t *cp)
{
	ASSERT(p->p_proc_flag & P_PR_LOCK);
	ASSERT(p->p_dtrace_count > 0);
	ASSERT(dtrace_fasttrap_fork_ptr != NULL);

	dtrace_fasttrap_fork_ptr(p, cp);
}
