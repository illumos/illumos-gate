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

#ifndef __xpv
#error "This file is for i86xpv only"
#endif

#include <sys/types.h>
#include <sys/mca_x86.h>
#include <sys/archsystm.h>
#include <sys/hypervisor.h>

#include "../../i86pc/cpu/generic_cpu/gcpu.h"

extern xpv_mca_panic_data_t *xpv_mca_panic_data;

mc_info_t gcpu_mce_data;

enum mctelem_direction {
	MCTELEM_FORWARD,
	MCTELEM_REVERSE
};

static uint32_t gcpu_xpv_hdl_lookupfails;
static uint32_t gcpu_xpv_bankhdr_found;
static uint32_t gcpu_xpv_spechdr_found;

static uint32_t gcpu_xpv_mca_hcall_fails[16];
static uint32_t gcpu_xpv_globalhdr_found;

static cmi_mca_regs_t *gcpu_xpv_bankregs;
size_t gcpu_xpv_bankregs_sz;

#define	GCPU_XPV_ARCH_NREGS	3

void
gcpu_xpv_mca_init(int nbanks)
{
	if (gcpu_xpv_bankregs == NULL) {
		gcpu_xpv_bankregs_sz = nbanks * GCPU_XPV_ARCH_NREGS *
		    sizeof (cmi_mca_regs_t);

		gcpu_xpv_bankregs = kmem_zalloc(gcpu_xpv_bankregs_sz, KM_SLEEP);
	}
}

static void
gcpu_xpv_proxy_logout(int what, struct mc_info *mi, struct mcinfo_common **micp,
    int *idxp, cmi_mca_regs_t *bankregs, size_t bankregs_sz)
{
	struct mcinfo_global *mgi = (struct mcinfo_global *)(uintptr_t)*micp;
	struct mcinfo_common *mic;
	struct mcinfo_bank *mib;
	cmi_hdl_t hdl = NULL;
	cmi_mca_regs_t *mcrp;
	int idx = *idxp;
	int tried = 0;
	int j;

	/* Skip over the MC_TYPE_GLOBAL record */
	ASSERT(mgi->common.type == MC_TYPE_GLOBAL);
	mic = x86_mcinfo_next((struct mcinfo_common *)(uintptr_t)mgi);
	idx++;

	/*
	 * Process all MC_TYPE_BANK and MC_TYPE_EXTENDED records that
	 * follow the MC_TYPE_GLOBAL record, ending when we reach any
	 * other record type or when we're out of record.
	 *
	 * We skip over MC_TYPE_EXTENDED for now - nothing consumes
	 * the extended MSR data even in native Solaris.
	 */
	while (idx < x86_mcinfo_nentries(mi) &&
	    (mic->type == MC_TYPE_BANK || mic->type == MC_TYPE_EXTENDED)) {
		if (mic->type == MC_TYPE_EXTENDED) {
			gcpu_xpv_spechdr_found++;
			goto next_record;
		} else {
			gcpu_xpv_bankhdr_found++;
		}

		if (hdl == NULL && !tried++) {
			if ((hdl = cmi_hdl_lookup(CMI_HDL_SOLARIS_xVM_MCA,
			    mgi->mc_socketid, mgi->mc_coreid,
			    mgi->mc_core_threadid)) == NULL) {
				gcpu_xpv_hdl_lookupfails++;
				goto next_record;
			} else {
				bzero(bankregs, bankregs_sz);
				mcrp = bankregs;
			}
		}

		mib = (struct mcinfo_bank *)(uintptr_t)mic;

		mcrp->cmr_msrnum = IA32_MSR_MC(mib->mc_bank, STATUS);
		mcrp->cmr_msrval = mib->mc_status;
		mcrp++;

		mcrp->cmr_msrnum = IA32_MSR_MC(mib->mc_bank, ADDR);
		mcrp->cmr_msrval = mib->mc_addr;
		mcrp++;

		mcrp->cmr_msrnum = IA32_MSR_MC(mib->mc_bank, MISC);
		mcrp->cmr_msrval = mib->mc_misc;
		mcrp++;

next_record:
		idx++;
		mic = x86_mcinfo_next(mic);
	}

	/*
	 * If we found some telemetry and a handle to associate it with
	 * then "forward" that telemetry into the MSR interpose layer
	 * and then request logout which will find that interposed
	 * telemetry.  Indicate that logout code should clear bank
	 * status registers so that it can invalidate them in the interpose
	 * layer - they won't actually make it as far as real MSR writes.
	 */
	if (hdl != NULL) {
		cmi_mca_regs_t gsr;
		gcpu_mce_status_t mce;

		gsr.cmr_msrnum = IA32_MSR_MCG_STATUS;
		gsr.cmr_msrval = mgi->mc_gstatus;
		cmi_hdl_msrforward(hdl, &gsr, 1);

		cmi_hdl_msrforward(hdl, bankregs, mcrp - bankregs);
		gcpu_mca_logout(hdl, NULL, (uint64_t)-1, &mce, B_TRUE, what);
		cmi_hdl_rele(hdl);
	}

	/*
	 * We must move the index on at least one record or our caller
	 * may loop forever;  our initial increment over the global
	 * record assures this.
	 */
	ASSERT(idx > *idxp);
	*idxp = idx;
	*micp = mic;
}

/*
 * Process a struct mc_info.
 *
 * There are x86_mcinfo_nentries(mi) entries.  An entry of type
 * MC_TYPE_GLOBAL precedes a number (potentially zero) of
 * entries of type MC_TYPE_BANK for telemetry from MCA banks
 * of the resource identified in the MC_TYPE_GLOBAL entry.
 * I think there can be multiple MC_TYPE_GLOBAL entries per buffer.
 */
void
gcpu_xpv_mci_process(mc_info_t *mi, int type,
    cmi_mca_regs_t *bankregs, size_t bankregs_sz)
{
	struct mcinfo_common *mic;
	int idx;

	mic = x86_mcinfo_first(mi);

	idx = 0;
	while (idx < x86_mcinfo_nentries(mi)) {
		if (mic->type == MC_TYPE_GLOBAL) {
			gcpu_xpv_globalhdr_found++;
			gcpu_xpv_proxy_logout(type == XEN_MC_URGENT ?
			    GCPU_MPT_WHAT_MC_ERR : GCPU_MPT_WHAT_XPV_VIRQ,
			    mi, &mic, &idx, bankregs, bankregs_sz);
		} else {
			idx++;
			mic = x86_mcinfo_next(mic);
		}
	}
}

int
gcpu_xpv_telem_read(mc_info_t *mci, int type, uint64_t *idp)
{
	xen_mc_t xmc;
	xen_mc_fetch_t *mcf = &xmc.u.mc_fetch;
	long err;

	mcf->flags = type;
	set_xen_guest_handle(mcf->data, mci);

	if ((err = HYPERVISOR_mca(XEN_MC_fetch, &xmc)) != 0) {
		gcpu_xpv_mca_hcall_fails[err < 16 ? err : 0]++;
		return (0);
	}

	if (mcf->flags == XEN_MC_OK) {
		*idp = mcf->fetch_id;
		return (1);
	} else {
		*idp = 0;
		return (0);
	}
}

void
gcpu_xpv_telem_ack(int type, uint64_t fetch_id)
{
	xen_mc_t xmc;
	struct xen_mc_fetch *mcf = &xmc.u.mc_fetch;

	mcf->flags = type | XEN_MC_ACK;
	mcf->fetch_id = fetch_id;
	(void) HYPERVISOR_mca(XEN_MC_fetch, &xmc);
}

static void
mctelem_traverse(void *head, enum mctelem_direction direction,
    boolean_t urgent)
{
	char *tep = head, **ntepp;
	int noff = (direction == MCTELEM_FORWARD) ?
	    xpv_mca_panic_data->mpd_fwdptr_offset :
	    xpv_mca_panic_data->mpd_revptr_offset;


	while (tep != NULL) {
		struct mc_info **mcip = (struct mc_info **)
		    (tep + xpv_mca_panic_data->mpd_dataptr_offset);

		gcpu_xpv_mci_process(*mcip,
		    urgent ? XEN_MC_URGENT : XEN_MC_NONURGENT,
		    gcpu_xpv_bankregs, gcpu_xpv_bankregs_sz);

		ntepp = (char **)(tep + noff);
		tep = *ntepp;
	}
}

/*
 * Callback made from panicsys.  We may have reached panicsys from a
 * Solaris-initiated panic or a hypervisor-initiated panic;  for the
 * latter we may not perform any hypercalls.  Our task is to retrieve
 * unprocessed MCA telemetry from the hypervisor and shovel it into
 * errorqs for later processing during panic.
 */
void
gcpu_xpv_panic_callback(void)
{
	if (IN_XPV_PANIC()) {
		xpv_mca_panic_data_t *ti = xpv_mca_panic_data;

		if (ti == NULL ||
		    ti->mpd_magic != MCA_PANICDATA_MAGIC ||
		    ti->mpd_version != MCA_PANICDATA_VERS)
			return;

		mctelem_traverse(ti->mpd_urgent_processing, MCTELEM_FORWARD,
		    B_TRUE);
		mctelem_traverse(ti->mpd_urgent_dangling, MCTELEM_REVERSE,
		    B_TRUE);
		mctelem_traverse(ti->mpd_urgent_committed, MCTELEM_REVERSE,
		    B_TRUE);

		mctelem_traverse(ti->mpd_nonurgent_processing, MCTELEM_FORWARD,
		    B_FALSE);
		mctelem_traverse(ti->mpd_nonurgent_dangling, MCTELEM_REVERSE,
		    B_FALSE);
		mctelem_traverse(ti->mpd_nonurgent_committed, MCTELEM_REVERSE,
		    B_FALSE);
	} else {
		int types[] = { XEN_MC_URGENT, XEN_MC_NONURGENT };
		uint64_t fetch_id;
		int i;

		for (i = 0; i < sizeof (types) / sizeof (types[0]); i++) {
			while (gcpu_xpv_telem_read(&gcpu_mce_data,
			    types[i], &fetch_id)) {
				gcpu_xpv_mci_process(&gcpu_mce_data, types[i],
				    gcpu_xpv_bankregs, gcpu_xpv_bankregs_sz);
				gcpu_xpv_telem_ack(types[i], fetch_id);
			}
		}
	}
}
