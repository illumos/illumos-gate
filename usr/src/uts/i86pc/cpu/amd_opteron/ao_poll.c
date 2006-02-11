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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * AMD Athlon64/Opteron CPU Module Machine-Check Poller
 *
 * The AMD Opteron processor doesn't yet report correctable errors via #mc's.
 * Instead, it fixes the problem, silently updates the error state MSRs, and
 * resumes operation.  In order to discover occurrances of correctable errors,
 * we have to poll in the background using the omni cyclics mechanism.  The
 * error injector also has the ability to manually request an immediate poll.
 * Locking is fairly simple within the poller: the per-CPU mutex
 * ao->ao_mca.ao_mca_poll_lock ensures that only one poll request is active.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/x86_archext.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/sdt.h>

#include "ao.h"

static uint_t ao_mca_poll_trace_nent = 100;
#ifdef DEBUG
static uint_t ao_mca_poll_trace_always = 1;
#else
static uint_t ao_mca_poll_trace_always = 0;
#endif

static cyclic_id_t ao_mca_poll_cycid;
static hrtime_t ao_mca_poll_interval = NANOSEC * 10ULL;

static void
ao_mca_poll_trace(ao_mca_t *mca, uint32_t what, uint32_t nerr)
{
	uint_t next;
	ao_mca_poll_trace_t *pt;

	ASSERT(MUTEX_HELD(&mca->ao_mca_poll_lock));
	DTRACE_PROBE2(ao__poll__trace, uint32_t, what, uint32_t, nerr);

	if (mca->ao_mca_poll_trace == NULL)
		return; /* poll trace buffer is disabled */

	next = (mca->ao_mca_poll_curtrace + 1) % ao_mca_poll_trace_nent;
	pt = &mca->ao_mca_poll_trace[next];

	pt->mpt_when = 0;
	pt->mpt_what = what;

	if (what == AO_MPT_WHAT_CYC_ERR)
		pt->mpt_nerr = MIN(nerr, UINT8_MAX);

	pt->mpt_when = gethrtime();
	mca->ao_mca_poll_curtrace = next;
}

static void
ao_mca_poll_common(ao_mca_t *mca, int what)
{
	ao_cpu_logout_t *acl = &mca->ao_mca_logout[AO_MCA_LOGOUT_POLLER];
	int i, n, fatal;

	if (mca->ao_mca_flags & AO_MCA_F_UNFAULTING) {
		mca->ao_mca_flags &= ~AO_MCA_F_UNFAULTING;
		ao_mca_poll_trace(mca, AO_MPT_WHAT_UNFAULTING, 0);

		/*
		 * On the first poll after re-enabling a faulty CPU we clear
		 * the status registers; see ao_faulted_exit() for more info.
		 */
		if (what == AO_MPT_WHAT_CYC_ERR) {
			for (i = 0; i < AMD_MCA_BANK_COUNT; i++)
				wrmsr(ao_bank_regs[i].abr_status, 0);
			return;
		}
	}

	fatal = ao_mca_logout(acl, NULL, &n);
	ao_mca_poll_trace(mca, what, n);

	if (fatal && cmi_panic_on_uncorrectable_error)
		fm_panic("Unrecoverable Machine-Check Exception");
}

static void
ao_mca_poll_cyclic(void *arg)
{
	ao_data_t *ao = arg;

	if (ao != NULL && mutex_tryenter(&ao->ao_mca.ao_mca_poll_lock)) {
		ao_mca_poll_common(&ao->ao_mca, AO_MPT_WHAT_CYC_ERR);
		mutex_exit(&ao->ao_mca.ao_mca_poll_lock);
	}
}

void
ao_mca_poke(void *arg)
{
	ao_data_t *ao = arg;

	mutex_enter(&ao->ao_mca.ao_mca_poll_lock);
	ao_mca_poll_common(&ao->ao_mca, AO_MPT_WHAT_POKE_ERR);
	mutex_exit(&ao->ao_mca.ao_mca_poll_lock);
}

/*ARGSUSED*/
static void
ao_mca_poll_online(void *arg, cpu_t *cpu, cyc_handler_t *cyh, cyc_time_t *cyt)
{
	cyt->cyt_when = 0;
	cyh->cyh_level = CY_LOW_LEVEL;

	/*
	 * If the CPU coming on-line isn't supported by this CPU module, then
	 * disable the cylic by cranking cyt_interval and setting arg to NULL.
	 */
	if (cpu->cpu_m.mcpu_cmi != NULL &&
	    cpu->cpu_m.mcpu_cmi->cmi_ops != &_cmi_ops) {
		cyt->cyt_interval = INT64_MAX;
		cyh->cyh_func = ao_mca_poll_cyclic;
		cyh->cyh_arg = NULL;
	} else {
		cyt->cyt_interval = ao_mca_poll_interval;
		cyh->cyh_func = ao_mca_poll_cyclic;
		cyh->cyh_arg = cpu->cpu_m.mcpu_cmidata;
	}
}

/*ARGSUSED*/
static void
ao_mca_poll_offline(void *arg, cpu_t *cpu, void *cyh_arg)
{
	/* nothing to do here */
}

void
ao_mca_poll_init(ao_mca_t *mca)
{
	mutex_init(&mca->ao_mca_poll_lock, NULL, MUTEX_DRIVER, NULL);

	if (ao_mca_poll_trace_always) {
		mca->ao_mca_poll_trace =
		    kmem_zalloc(sizeof (ao_mca_poll_trace_t) *
		    ao_mca_poll_trace_nent, KM_SLEEP);
		mca->ao_mca_poll_curtrace = 0;
	}
}

void
ao_mca_poll_start(void)
{
	cyc_omni_handler_t cyo;

	if (ao_mca_poll_interval == 0)
		return; /* if manually tuned to zero, disable polling */

	cyo.cyo_online = ao_mca_poll_online;
	cyo.cyo_offline = ao_mca_poll_offline;
	cyo.cyo_arg = NULL;

	mutex_enter(&cpu_lock);
	ao_mca_poll_cycid = cyclic_add_omni(&cyo);
	mutex_exit(&cpu_lock);
}
