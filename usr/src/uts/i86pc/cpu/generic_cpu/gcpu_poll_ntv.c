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
 * Copyright (c) 2018, Joyent, Inc.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

/*
 * Native MCA polling.  We establish an ommipresent cyclic to fire on all
 * online cpus to check their MCA state and log any valid errors for
 * diagnosis.
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/cyclic.h>
#include <sys/x86_archext.h>
#include <sys/mca_x86.h>

#include "gcpu.h"

hrtime_t gcpu_mca_poll_interval = NANOSEC * 10ULL;	/* tuneable */
static cyclic_id_t gcpu_mca_poll_cycid;
static volatile uint_t gcpu_mca_poll_inits;
extern int gcpu_poll_trace_always;
extern uint_t gcpu_poll_trace_nent;

/*
 * Return nonzero of the given handle should poll the MCH.  We stick with
 * the same handle as before unless the timestamp has not been updated
 * for a while.  There is no need to keep a hold on the mch_poll_owner
 * handle.
 */

static kmutex_t mch_poll_lock;
static hrtime_t mch_poll_timestamp;
static cmi_hdl_t mch_poll_owner;

static int
mch_pollowner(cmi_hdl_t hdl)
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
gcpu_ntv_mca_poll(cmi_hdl_t hdl, int what)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	gcpu_mca_t *mca = &gcpu->gcpu_mca;
	gcpu_mce_status_t mce;
	int willpanic;
	uint64_t bankmask;

	ASSERT(MUTEX_HELD(&gcpu->gcpu_shared->gcpus_poll_lock));

	/* Enable CMCI in first poll if is supported */
	if ((mca->gcpu_mca_flags & GCPU_MCA_F_CMCI_ENABLE) != 0 &&
	    (!mca->gcpu_mca_first_poll_cmci_enabled)) {
		int i;
		uint64_t ctl2;

		for (i = 0; i < mca->gcpu_mca_nbanks; i++) {
			if (mca->gcpu_bank_cmci[i].cmci_cap) {
				(void) cmi_hdl_rdmsr(hdl, IA32_MSR_MC_CTL2(i),
				    &ctl2);
				ctl2 |= MSR_MC_CTL2_EN;
				(void) cmi_hdl_wrmsr(hdl, IA32_MSR_MC_CTL2(i),
				    ctl2);
				mca->gcpu_bank_cmci[i].cmci_enabled = 1;
			}
		}
		mca->gcpu_mca_first_poll_cmci_enabled = 1;
	}

	if (mca->gcpu_mca_flags & GCPU_MCA_F_UNFAULTING) {
		int i;

		mca->gcpu_mca_flags &= ~GCPU_MCA_F_UNFAULTING;
		gcpu_poll_trace(&gcpu->gcpu_mca.gcpu_polltrace,
		    GCPU_MPT_WHAT_UNFAULTING, 0);

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
	if (what == GCPU_MPT_WHAT_CMCI_ERR) {
		/*
		 * for CMCI, all banks should be scanned for log out
		 */
		bankmask = -1ULL;
	} else {
		bankmask = cms_poll_ownermask(hdl, gcpu_mca_poll_interval);
	}
	gcpu_mca_logout(hdl, NULL, bankmask, &mce, B_TRUE, what);

	if (mce.mce_nerr != 0)
		gcpu_poll_trace(&gcpu->gcpu_mca.gcpu_polltrace, what,
		    mce.mce_nerr);

	mca->gcpu_mca_lastpoll = gethrtime_waitfree();

	willpanic = mce.mce_disp & CMI_ERRDISP_FORCEFATAL && cmi_panic_on_ue();

	if (what != GCPU_MPT_WHAT_CMCI_ERR) {
		/*
		 * Call to the memory-controller driver which may report some
		 * errors not visible under the MCA (for off-chip NB).
		 * Since there is typically a single MCH we arrange that
		 * just one cpu perform this task at each cyclic fire.
		 */
		if (mch_pollowner(hdl))
			cmi_mc_logout(hdl, 0, willpanic);
	}

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
	gcpu_data_t *gcpu;

	if (hdl == NULL || (gcpu = cmi_hdl_getcmidata(hdl)) == NULL ||
	    gcpu->gcpu_mca.gcpu_mca_lgsz == 0)
		return;

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

	/*
	 * Lookup and hold a handle for this cpu (any hold released in
	 * our offline function).  If we chose not to initialize a handle
	 * for this cpu back at cmi_init time then this lookup will return
	 * NULL, so the cyh_func we appoint must be prepared for that.
	 */
	hdl = cmi_hdl_lookup(CMI_HDL_NATIVE, cmi_ntv_hwchipid(cp),
	    cmi_ntv_hwcoreid(cp), cmi_ntv_hwstrandid(cp));

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

	if (hdl != NULL)
		cmi_hdl_rele(hdl);
}

static void
gcpu_ntv_mca_poll_start(void)
{
	cyc_omni_handler_t cyo;

	if (gcpu_mca_poll_interval == 0 || gcpu_mca_poll_inits == 0)
		return;

	cyo.cyo_online = gcpu_ntv_mca_poll_online;
	cyo.cyo_offline = gcpu_ntv_mca_poll_offline;
	cyo.cyo_arg = NULL;

	mutex_enter(&cpu_lock);
	gcpu_mca_poll_cycid = cyclic_add_omni(&cyo);
	mutex_exit(&cpu_lock);
}

/*
 * gcpu_mca_poll_init is called from gcpu_mca_init for each cpu handle
 * that we initialize for.  It should prepare for polling by allocating
 * control structures and the like, but must not kick polling off yet.
 */

void
gcpu_mca_poll_init(cmi_hdl_t hdl)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	gcpu_poll_trace_ctl_t *ptc = &gcpu->gcpu_mca.gcpu_polltrace;

	ASSERT(cmi_hdl_class(hdl) == CMI_HDL_NATIVE);

	gcpu_poll_trace_init(ptc);

	atomic_inc_uint(&gcpu_mca_poll_inits);
}

/* deconfigure gcpu_mca_poll_init() */
void
gcpu_mca_poll_fini(cmi_hdl_t hdl)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	gcpu_poll_trace_ctl_t *ptc = &gcpu->gcpu_mca.gcpu_polltrace;

	ASSERT(cmi_hdl_class(hdl) == CMI_HDL_NATIVE);

	if (gcpu_poll_trace_always && (ptc->mptc_tbufs != NULL)) {
		kmem_free(ptc->mptc_tbufs, sizeof (gcpu_poll_trace_t) *
		    gcpu_poll_trace_nent);
	}

	atomic_dec_uint(&gcpu_mca_poll_inits);
}

void
gcpu_mca_poll_start(cmi_hdl_t hdl)
{
	ASSERT(cmi_hdl_class(hdl) == CMI_HDL_NATIVE);
	gcpu_ntv_mca_poll_start();
}

void
gcpu_hdl_poke(cmi_hdl_t hdl)
{
	ASSERT(cmi_hdl_class(hdl) == CMI_HDL_NATIVE);
	gcpu_ntv_mca_poll_wrapper(hdl, GCPU_MPT_WHAT_POKE_ERR);
}

void
gcpu_cmci_trap(cmi_hdl_t hdl)
{
	gcpu_ntv_mca_poll_wrapper(hdl, GCPU_MPT_WHAT_CMCI_ERR);
}
