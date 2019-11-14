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

/*
 * "Polled" MCA events in an i86xpv dom0.  A timeout runs in the hypervisor
 * and checks MCA state.  If it observes valid MCA state in a bank and if
 * it sees that dom0 has registered a handler for the VIRQ_MCA then it
 * raises that VIRQ to dom0.  The interrupt handler performs a
 * hypercall to retrieve the polled telemetry and then pushes that telemetry
 * into the MSR interpose hash and calls the generic logout code which
 * will then find the provided interposed MSR values when it performs
 * cmi_hdl_rdmsr so logout code works unchanged for native or i86xpv dom0.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/x86_archext.h>
#include <sys/mca_x86.h>
#include <sys/ddi.h>
#include <sys/spl.h>
#include <sys/sunddi.h>
#include <sys/evtchn_impl.h>
#include <sys/hypervisor.h>

#include "../../i86pc/cpu/generic_cpu/gcpu.h"

extern int *gcpu_xpv_telem_read(mc_info_t *, int, uint64_t *);
extern void gcpu_xpv_telem_ack(int, uint64_t);
extern void gcpu_xpv_mci_process(mc_info_t *, int, cmi_mca_regs_t *, size_t);

int gcpu_xpv_mch_poll_interval_secs = 10;
int gcpu_xpv_virq_level = 3;

static timeout_id_t gcpu_xpv_mch_poll_timeoutid;

static int gcpu_xpv_virq_vect = -1;

static mc_info_t gcpu_xpv_polldata;
static kmutex_t gcpu_xpv_polldata_lock;

static cmi_mca_regs_t *gcpu_xpv_poll_bankregs;
static size_t gcpu_xpv_poll_bankregs_sz;

static uint32_t gcpu_xpv_intr_unclaimed;
static uint32_t gcpu_xpv_mca_hcall_busy;

static gcpu_poll_trace_ctl_t gcpu_xpv_poll_trace_ctl;

#define	GCPU_XPV_ARCH_NREGS		3
#define	GCPU_XPV_MCH_POLL_REARM		((void *)1)
#define	GCPU_XPV_MCH_POLL_NO_REARM	NULL

static uint_t
gcpu_xpv_virq_intr(caddr_t arg __unused, caddr_t arg1 __unused)
{
	int types[] = { XEN_MC_URGENT, XEN_MC_NONURGENT };
	uint64_t fetch_id;
	int count = 0;
	int i;

	if (gcpu_xpv_virq_vect == -1 || gcpu_xpv_poll_bankregs_sz == 0) {
		gcpu_xpv_intr_unclaimed++;
		return (DDI_INTR_UNCLAIMED);
	}

	if (!mutex_tryenter(&gcpu_xpv_polldata_lock)) {
		gcpu_xpv_mca_hcall_busy++;
		return (DDI_INTR_CLAIMED);
	}

	for (i = 0; i < sizeof (types) / sizeof (types[0]); i++) {
		while (gcpu_xpv_telem_read(&gcpu_xpv_polldata, types[i],
		    &fetch_id)) {
			gcpu_poll_trace(&gcpu_xpv_poll_trace_ctl,
			    GCPU_MPT_WHAT_XPV_VIRQ,
			    x86_mcinfo_nentries(&gcpu_xpv_polldata));
			gcpu_xpv_mci_process(&gcpu_xpv_polldata, types[i],
			    gcpu_xpv_poll_bankregs, gcpu_xpv_poll_bankregs_sz);
			gcpu_xpv_telem_ack(types[i], fetch_id);
			count++;
		}
	}

	mutex_exit(&gcpu_xpv_polldata_lock);

	return (DDI_INTR_CLAIMED);
}

static void
gcpu_xpv_mch_poll(void *arg)
{
	cmi_hdl_t hdl = cmi_hdl_any();

	if (hdl != NULL) {
		cmi_mc_logout(hdl, 0, 0);
		cmi_hdl_rele(hdl);
	}

	if (arg == GCPU_XPV_MCH_POLL_REARM &&
	    gcpu_xpv_mch_poll_interval_secs != 0) {
		gcpu_xpv_mch_poll_timeoutid = timeout(gcpu_xpv_mch_poll,
		    GCPU_XPV_MCH_POLL_REARM,
		    drv_usectohz(gcpu_xpv_mch_poll_interval_secs * MICROSEC));
	}
}

/*
 * gcpu_mca_poll_init is called from gcpu_mca_init for each cpu handle
 * that we initialize for.  It should prepare for polling by allocating
 * control structures and the like, but must not kick polling off yet.
 *
 * Since we initialize all cpus in a serialized loop there is no race
 * on allocating the bankregs structure, nor in free'ing and enlarging
 * it if we find the number of MCA banks is not uniform in the system
 * (unlikely) since polling is only started post mp startup.
 */

void
gcpu_mca_poll_init(cmi_hdl_t hdl)
{
	gcpu_data_t *gcpu = cmi_hdl_getcmidata(hdl);
	int nbanks = gcpu->gcpu_mca.gcpu_mca_nbanks;
	size_t sz = nbanks * GCPU_XPV_ARCH_NREGS * sizeof (cmi_mca_regs_t);

	ASSERT(cmi_hdl_class(hdl) == CMI_HDL_SOLARIS_xVM_MCA);

	if (gcpu_xpv_poll_bankregs == NULL || sz > gcpu_xpv_poll_bankregs_sz) {
		if (gcpu_xpv_poll_bankregs != NULL) {
			kmem_free(gcpu_xpv_poll_bankregs,
			    gcpu_xpv_poll_bankregs_sz);
		} else {
			gcpu_poll_trace_init(&gcpu_xpv_poll_trace_ctl);
		}

		gcpu_xpv_poll_bankregs_sz = sz;
		gcpu_xpv_poll_bankregs = kmem_zalloc(sz, KM_SLEEP);

	}
}

/* deconfigure gcpu_mca_poll_init() */
void
gcpu_mca_poll_fini(cmi_hdl_t hdl)
{
}

void
gcpu_mca_poll_start(cmi_hdl_t hdl)
{
	ASSERT(cmi_hdl_class(hdl) == CMI_HDL_SOLARIS_xVM_MCA);
	/*
	 * We are on the boot cpu (cpu 0), called at the end of its
	 * multiprocessor startup.
	 */
	if (gcpu_xpv_poll_bankregs_sz != 0 && gcpu_xpv_virq_vect == -1) {
		/*
		 * The hypervisor will poll MCA state for us, but it cannot
		 * poll MCH state so we do that via a timeout.
		 */
		if (gcpu_xpv_mch_poll_interval_secs != 0) {
			gcpu_xpv_mch_poll_timeoutid =
			    timeout(gcpu_xpv_mch_poll, GCPU_XPV_MCH_POLL_REARM,
			    drv_usectohz(gcpu_xpv_mch_poll_interval_secs *
			    MICROSEC));
		}

		/*
		 * Register handler for VIRQ_MCA; once this is in place
		 * the hypervisor will begin to forward polled MCA observations
		 * to us.
		 */
		gcpu_xpv_virq_vect = ec_bind_virq_to_irq(VIRQ_MCA, 0);
		(void) add_avintr(NULL, gcpu_xpv_virq_level,
		    gcpu_xpv_virq_intr, "MCA", gcpu_xpv_virq_vect,
		    NULL, NULL, NULL, NULL);
	}
}
