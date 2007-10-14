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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Generic x86 CPU MCA poller.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cyclic.h>
#include <sys/x86_archext.h>
#include <sys/mca_x86.h>
#include <sys/sdt.h>
#include <sys/cmn_err.h>

#include "gcpu.h"

uint_t gcpu_mca_poll_trace_nent = 100;
#ifdef DEBUG
int gcpu_mca_poll_trace_always = 1;
#else
int gcpu_mca_poll_trace_always = 0;
#endif

cyclic_id_t gcpu_mca_poll_cycid;
hrtime_t gcpu_mca_poll_interval = NANOSEC * 10ULL;	/* tuneable */

static kmutex_t mch_poll_lock;
static hrtime_t mch_poll_timestamp;
static cmi_hdl_t mch_poll_owner;

/*
 * Return nonzero of the given handle should poll the MCH.  We stick with
 * the same handle as before unless the timestamp has not been updated
 * for a while.  There is no need to keep a hold on the mch_poll_owner
 * handle.
 */
static int
gcpu_mch_pollowner(cmi_hdl_t hdl)
{
	hrtime_t now = gethrtime_waitfree();
	int dopoll = 0;

	mutex_enter(&mch_poll_lock);
	if (now - mch_poll_timestamp > 2 * gcpu_mca_poll_interval ||
	    mch_poll_timestamp == 0) {
		mch_poll_owner = hdl;
		dopoll = 1;
	} else if (mch_poll_owner == hdl) {
		dopoll = 1;
	}

	if (dopoll)
		mch_poll_timestamp = now;

	mutex_exit(&mch_poll_lock);
	return (dopoll);
}

static void
gcpu_mca_poll_trace(gcpu_mca_poll_trace_ctl_t *ptc, uint8_t what, uint8_t nerr)
{
	uint_t next;
	gcpu_mca_poll_trace_t *pt;

	DTRACE_PROBE2(gcpu__mca__poll__trace, uint32_t, what, uint32_t, nerr);

	if (ptc->mptc_tbufs == NULL)
		return; /* poll trace buffer is disabled */

	next = (ptc->mptc_curtrace + 1) % gcpu_mca_poll_trace_nent;
	pt = &ptc->mptc_tbufs[next];

	pt->mpt_when = 0;
	pt->mpt_what = what;

	if (what == GCPU_MPT_WHAT_CYC_ERR)
		pt->mpt_nerr = MIN(nerr, UINT8_MAX);

	pt->mpt_when = gethrtime_waitfree();
	ptc->mptc_curtrace = next;
}

#ifndef	__xpv
/*
 * Perform a native poll of MCA state.
 */
static void
gcpu_ntv_mca_poll(cmi_hdl_t hdl, int what)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	gcpu_mca_t *mca = &gcpu->gcpu_mca;
	gcpu_mca_poll_trace_ctl_t *ptc = &gcpu->gcpu_mca.gcpu_mca_polltrace;
	gcpu_mce_status_t mce;
	int willpanic;

	ASSERT(MUTEX_HELD(&gcpu->gcpu_shared->gcpus_poll_lock));

	if (mca->gcpu_mca_flags & GCPU_MCA_F_UNFAULTING) {
		int i;

		mca->gcpu_mca_flags &= ~GCPU_MCA_F_UNFAULTING;
		gcpu_mca_poll_trace(ptc, GCPU_MPT_WHAT_UNFAULTING, 0);

		/*
		 * On the first cyclic poll after unfaulting a CPU we
		 * clear the status registers; see gcpu_faulted_exit
		 * for details.  We don't do this if the poll was
		 * initiated manually (presumably from some injection
		 * activity).
		 */
		if (what == GCPU_MPT_WHAT_CYC_ERR) {
			for (i = 0; i < mca->gcpu_mca_nbanks; i++) {
				(void) cmi_hdl_wrmsr(hdl,
				    IA32_MSR_MC(i, STATUS), 0ULL);
			}
			return;
		}
	}

	/*
	 * Logout errors of the MCA banks of this cpu.
	 */
	gcpu_mca_logout(hdl, NULL,
	    cms_poll_ownermask(hdl, gcpu_mca_poll_interval), &mce, B_TRUE);

	gcpu_mca_poll_trace(ptc, what, mce.mce_nerr);
	mca->gcpu_mca_lastpoll = gethrtime_waitfree();

	willpanic = mce.mce_disp & CMI_ERRDISP_FORCEFATAL && cmi_panic_on_ue();

	/*
	 * Call to the memory-controller driver which may report some
	 * errors not visible under the MCA (for off-chip NB).
	 * Since there is typically a single MCH we arrange that
	 * just one cpu perform this task at each cyclic fire.
	 */
	if (gcpu_mch_pollowner(hdl))
		cmi_mc_logout(hdl, 0, willpanic);

	/*
	 * In the common case any polled error is considered non-fatal,
	 * even if it indicates PCC or UC etc.  The only condition on which
	 * we will panic for a polled error is if model-specific support
	 * forces the error to be terminal regardless of how it is
	 * encountered.
	 */
	if (willpanic) {
#ifdef DEBUG
		cmn_err(CE_WARN, "MCA Poll: %u errors, disp=0x%llx, "
		    "%u PCC (%u ok), "
		    "%u UC (%u ok, %u poisoned), "
		    "%u forcefatal, %u ignored",
		    mce.mce_nerr, (u_longlong_t)mce.mce_disp,
		    mce.mce_npcc, mce.mce_npcc_ok,
		    mce.mce_nuc, mce.mce_nuc_ok, mce.mce_nuc_poisoned,
		    mce.mce_forcefatal, mce.mce_ignored);

#endif
		fm_panic("Unrecoverable Machine-Check Exception (Polled)");
	}
}

/*
 * See gcpu_mca_trap for an explanation of why preemption is disabled here.
 * Note that we disable preemption and then contend for an adaptive mutex -
 * we could block during the mutex operation, but once we return with the
 * mutex held we nust perform no operation that can block and we cannot
 * be preempted so we will stay on cpu for the duration.  The disabling
 * of preemption also means we cannot migrate cpus once we have returned
 * with the mutex held - cyclic invocations can't migrate, anyway, but
 * others could if they have failed to bind before this point.
 */
static void
gcpu_ntv_mca_poll_wrapper(cmi_hdl_t hdl, int what)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);

	kpreempt_disable();
	mutex_enter(&gcpu->gcpu_shared->gcpus_poll_lock);
	gcpu_ntv_mca_poll(hdl, what);
	mutex_exit(&gcpu->gcpu_shared->gcpus_poll_lock);
	kpreempt_enable();
}

static void
gcpu_ntv_mca_poll_cyclic(void *arg)
{
	gcpu_ntv_mca_poll_wrapper((cmi_hdl_t)arg, GCPU_MPT_WHAT_CYC_ERR);
}


/*ARGSUSED*/
static void
gcpu_ntv_mca_poll_online(void *arg, cpu_t *cp, cyc_handler_t *cyh,
    cyc_time_t *cyt)
{
	cmi_hdl_t hdl;

	/* cmi_hdl_lookup holds any handle it finds - release in offline */
	if ((hdl = cmi_hdl_lookup(CMI_HDL_NATIVE, cmi_ntv_hwchipid(cp),
	    cmi_ntv_hwcoreid(cp), cmi_ntv_hwstrandid(cp))) == NULL)
		return;

	cyt->cyt_when = 0;
	cyt->cyt_interval = gcpu_mca_poll_interval;
	cyh->cyh_func = gcpu_ntv_mca_poll_cyclic;
	cyh->cyh_arg = (void *)hdl;
	cyh->cyh_level = CY_LOW_LEVEL;
}

/*ARGSUSED*/
static void
gcpu_ntv_mca_poll_offline(void *arg, cpu_t *cpu, void *cyh_arg)
{
	cmi_hdl_t hdl = (cmi_hdl_t)cyh_arg;

	cmi_hdl_rele(hdl);
}
#endif	/* __xpv */

/*
 * gcpu_mca_poll_init is called from gcpu_mca_init for each cpu handle
 * that we initialize for.  It should prepare for polling by allocating
 * control structures and the like, but must not kick polling off yet.
 *
 * In the native case our polling technique (see gcpu_mca_poll_start) will
 * be to install an omnipresent cyclic to fire on all online cpus (cpu_t),
 * and they will poll the real hardware beneath them.
 *
 * In the xVM MCA case the hypervisor performs polling and makes telemetry
 * available to dom0 -  a cyclic on each virtual cpu is inappropriate.
 * Instead we will create a single unbound cyclic which will consume the
 * hypervisor-provided telemetry when it fires, and submit it into
 * common logging code.
 */

void
gcpu_mca_poll_init(cmi_hdl_t hdl)
{
	gcpu_mca_poll_trace_t *tbufs = NULL;

	switch (cmi_hdl_class(hdl)) {
	case CMI_HDL_NATIVE: {
		gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
		gcpu_mca_t *mca = &gcpu->gcpu_mca;

		if (gcpu_mca_poll_trace_always) {
			tbufs = kmem_zalloc(sizeof (gcpu_mca_poll_trace_t) *
			    gcpu_mca_poll_trace_nent, KM_SLEEP);
		}
		mca->gcpu_mca_polltrace.mptc_tbufs = tbufs;
		mca->gcpu_mca_polltrace.mptc_curtrace = 0;
		break;
	}

	case CMI_HDL_SOLARIS_xVM_MCA:
		/*
		 * Implementation should move the kmem_alloc above to before
		 * the switch, and stash the trace buffer and current record
		 * pointer in a static structure.  This should be done
		 * just once, despite this init function potentially being
		 * called multiple times.
		 */
		/*FALLTHRU*/

	default:
		break;
	}
}

static void
gcpu_ntv_mca_poll_start(void)
{
#ifndef	__xpv
	cyc_omni_handler_t cyo;

	if (gcpu_mca_poll_interval == 0)
		return;

	cyo.cyo_online = gcpu_ntv_mca_poll_online;
	cyo.cyo_offline = gcpu_ntv_mca_poll_offline;
	cyo.cyo_arg = NULL;

	mutex_enter(&cpu_lock);
	gcpu_mca_poll_cycid = cyclic_add_omni(&cyo);
	mutex_exit(&cpu_lock);
#endif	/* __xpv */
}

void
gcpu_mca_poll_start(cmi_hdl_t hdl)
{
	switch (cmi_hdl_class(hdl)) {
	case CMI_HDL_NATIVE:
		gcpu_ntv_mca_poll_start();
		break;

	case CMI_HDL_SOLARIS_xVM_MCA:
		/*
		 * Implementation should call a new function to install
		 * an unbound cyclic that will process hypervisor-provided
		 * telemetry.
		 */
		/*FALLTHRU*/

	default:
		break;
	}
}

void
gcpu_hdl_poke(cmi_hdl_t hdl)
{
	switch (cmi_hdl_class(hdl)) {
	case CMI_HDL_NATIVE:
		gcpu_ntv_mca_poll_wrapper(hdl, GCPU_MPT_WHAT_POKE_ERR);
		break;

	case CMI_HDL_SOLARIS_xVM_MCA:
		/*
		 * Implementation will call the xPV poll wrapper.
		 */
	default:
		break;
	}
}
