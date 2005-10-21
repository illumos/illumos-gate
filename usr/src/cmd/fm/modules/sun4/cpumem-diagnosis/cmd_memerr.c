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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ereport-handling routines for memory errors
 */

#include <cmd_mem.h>
#include <cmd_dimm.h>
#include <cmd_bank.h>
#include <cmd_page.h>
#include <cmd_cpu.h>
#include <cmd.h>

#include <strings.h>
#include <string.h>
#include <errno.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <sys/fm/io/sun4upci.h>
#include <sys/async.h>
#include <sys/cheetahregs.h>
#include <sys/pci/pcisch.h>
#include <sys/errclassify.h>

/* Jalapeno-specific values from cheetahregs.h */
#define	USIIIi_AFSR_AID		0x0000000000003e00ull /* AID causing UE/CE */
#define	USIIIi_AFSR_AID_SHIFT	9
#define	USIIIi_AFSR_JREQ	0x0000000007000000ull /* Active JBus req */
#define	USIIIi_AFSR_JREQ_SHIFT	24
#define	TOM_AID_MATCH_MASK	0xe

typedef cmd_evdisp_t xe_handler_f(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, uint64_t, uint8_t, uint16_t, uint8_t, ce_dispact_t, uint64_t,
    nvlist_t *);

struct ce_name2type {
	const char *name;
	ce_dispact_t type;
};

ce_dispact_t
cmd_mem_name2type(const char *name, int minorvers)
{
	static const struct ce_name2type old[] = {
		{ ERR_TYPE_DESC_INTERMITTENT,	CE_DISP_INTERMITTENT },
		{ ERR_TYPE_DESC_PERSISTENT,	CE_DISP_PERS },
		{ ERR_TYPE_DESC_STICKY,		CE_DISP_STICKY },
		{ ERR_TYPE_DESC_UNKNOWN,	CE_DISP_UNKNOWN },
		{ NULL }
	};
	static const struct ce_name2type new[] = {
		{ CE_DISP_DESC_U,		CE_DISP_UNKNOWN },
		{ CE_DISP_DESC_I,		CE_DISP_INTERMITTENT },
		{ CE_DISP_DESC_PP,		CE_DISP_POSS_PERS },
		{ CE_DISP_DESC_P,		CE_DISP_PERS },
		{ CE_DISP_DESC_L,		CE_DISP_LEAKY },
		{ CE_DISP_DESC_PS,		CE_DISP_POSS_STICKY },
		{ CE_DISP_DESC_S,		CE_DISP_STICKY },
		{ NULL }
	};
	const struct ce_name2type *names = (minorvers == 0) ? &old[0] : &new[0];
	const struct ce_name2type *tp;

	for (tp = names; tp->name != NULL; tp++)
		if (strcasecmp(name, tp->name) == 0)
			return (tp->type);

	return (CE_DISP_UNKNOWN);
}

static void
ce_thresh_check(fmd_hdl_t *hdl, cmd_dimm_t *dimm)
{
	nvlist_t *flt;
	fmd_case_t *cp;
	cmd_dimm_t *d;
	nvlist_t *dflt;
	uint_t nret, dret;
	int foundrw;

	if (dimm->dimm_flags & CMD_MEM_F_FAULTING) {
		/* We've already complained about this DIMM */
		return;
	}

	nret = dimm->dimm_nretired;
	if (dimm->dimm_bank != NULL)
		nret += dimm->dimm_bank->bank_nretired;

	if (!cmd_mem_thresh_check(hdl, nret))
		return; /* Don't warn until over specified % of system memory */

	/* Look for CEs on DIMMs in other banks */
	for (foundrw = 0, dret = 0, d = cmd_list_next(&cmd.cmd_dimms);
	    d != NULL; d = cmd_list_next(d)) {
		if (d == dimm) {
			dret += d->dimm_nretired;
			continue;
		}

		if (dimm->dimm_bank != NULL && d->dimm_bank == dimm->dimm_bank)
			continue;

		if (d->dimm_nretired > cmd.cmd_thresh_abs_badrw) {
			foundrw = 1;
			dret += d->dimm_nretired;
		}
	}

	if (foundrw) {
		/*
		 * Found a DIMM in another bank with a significant number of
		 * retirements.  Something strange is going on, perhaps in the
		 * datapath or with a bad CPU.  A real person will need to
		 * figure out what's really happening.  Emit a fault designed
		 * to trigger just that.
		 */
		cp = fmd_case_open(hdl, NULL);
		for (d = cmd_list_next(&cmd.cmd_dimms); d != NULL;
		    d = cmd_list_next(d)) {

			if (d != dimm && d->dimm_bank != NULL &&
			    d->dimm_bank == dimm->dimm_bank)
				continue;

			if (d->dimm_nretired <= cmd.cmd_thresh_abs_badrw)
				continue;

			if (!(d->dimm_flags & CMD_MEM_F_FAULTING)) {
				d->dimm_flags |= CMD_MEM_F_FAULTING;
				cmd_dimm_dirty(hdl, d);
			}

			flt = cmd_dimm_create_fault(hdl, d,
			    "fault.memory.datapath",
			    d->dimm_nretired * 100 / dret);
			fmd_case_add_suspect(hdl, cp, flt);
		}

		fmd_case_solve(hdl, cp);
		return;
	}

	dimm->dimm_flags |= CMD_MEM_F_FAULTING;
	cmd_dimm_dirty(hdl, dimm);

	cp = fmd_case_open(hdl, NULL);
	dflt = cmd_dimm_create_fault(hdl, dimm, "fault.memory.dimm",
	    CMD_FLTMAXCONF);
	fmd_case_add_suspect(hdl, cp, dflt);
	fmd_case_solve(hdl, cp);
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_ce_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, uint64_t afar, uint8_t afar_status, uint16_t synd,
    uint8_t synd_status, ce_dispact_t type, uint64_t disp, nvlist_t *asru)
{
	cmd_dimm_t *dimm;
	cmd_page_t *page;
	const char *uuid;

	if (afar_status != AFLT_STAT_VALID ||
	    synd_status != AFLT_STAT_VALID)
		return (CMD_EVD_UNUSED);

	if ((page = cmd_page_lookup(afar)) != NULL && page->page_case != NULL &&
	    fmd_case_solved(hdl, page->page_case))
		return (CMD_EVD_REDUND);

	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (NULL);
	}

	if ((dimm = cmd_dimm_lookup(hdl, asru)) == NULL &&
	    (dimm = cmd_dimm_create(hdl, asru)) == NULL)
		return (CMD_EVD_UNUSED);

	switch (type) {
	case CE_DISP_UNKNOWN:
		CMD_STAT_BUMP(ce_unknown);
		return (CMD_EVD_UNUSED);
	case CE_DISP_INTERMITTENT:
		CMD_STAT_BUMP(ce_interm);
		return (CMD_EVD_UNUSED);
	case CE_DISP_POSS_PERS:
		CMD_STAT_BUMP(ce_ppersis);
		break;
	case CE_DISP_PERS:
		CMD_STAT_BUMP(ce_persis);
		break;
	case CE_DISP_LEAKY:
		CMD_STAT_BUMP(ce_leaky);
		break;
	case CE_DISP_POSS_STICKY:

	/*
	 * The following code is a workaround for a misfix of 6316055
	 * error-type member of DAC ereports is often intermittent .
	 * The bug number for the workaround is 6326938.
	 *
	 * In sun4u, a memory CE ereport classified as PS (Possibly
	 * Sticky) is ignored, because it means that the ereport itself
	 * is possibly corrupted.
	 *
	 * In sun4v when this hv bug is present, a Possibly Sticky CE could be
	 * either Sticky or Persistent in reality.  In this portion of the
	 * workaround, we first prevent the e-report from being discarded.
	 * In the second part of the workaround (subsequent #ifdef sun4v)
	 * we cause a Possibly Sticky ereport to be treated in the same way
	 * as a Persistent or Possibly Persistent ereport.
	 * If we are being too cautious (these ereports denote a truly stuck
	 * bit in memory), then page retirements will still happen, albeit
	 * more slowly than if we had treated these PS ereports as Sticky.
	 *
	 * After the hv bug is fixed, we should no longer receive any PS
	 * ereports, and this workaround is safe.
	 */

#ifdef sun4v
		CMD_STAT_BUMP(ce_psticky_noptnr);
		break;
#else
	{
		uchar_t ptnrinfo = CE_XDIAG_PTNRINFO(disp);

		if (CE_XDIAG_TESTVALID(ptnrinfo)) {
			int ce1 = CE_XDIAG_CE1SEEN(ptnrinfo);
			int ce2 = CE_XDIAG_CE2SEEN(ptnrinfo);

			if (ce1 && ce2) {
				/* Should have been CE_DISP_STICKY */
				return (CMD_EVD_BAD);
			} else if (ce1) {
				/* Partner could see and could fix CE */
				CMD_STAT_BUMP(ce_psticky_ptnrclrd);
			} else {
				/* Partner could not see ce1 (ignore ce2) */
				CMD_STAT_BUMP(ce_psticky_ptnrnoerr);
			}
		} else {
			CMD_STAT_BUMP(ce_psticky_noptnr);
		}
		return (CMD_EVD_UNUSED);
	}
#endif  /* sun4v */
	case CE_DISP_STICKY:
		CMD_STAT_BUMP(ce_sticky);
		break;
	default:
		return (CMD_EVD_BAD);
	}

	if (dimm->dimm_case.cc_cp == NULL) {
		dimm->dimm_case.cc_cp = cmd_case_create(hdl,
		    &dimm->dimm_header, CMD_PTR_DIMM_CASE, &uuid);
	}

	switch (type) {
	case CE_DISP_POSS_PERS:
	case CE_DISP_PERS:
#ifdef sun4v
	case CE_DISP_POSS_STICKY:
#endif /* sun4v */
		fmd_hdl_debug(hdl, "adding %sPersistent event to CE serd "
		    "engine\n", type == CE_DISP_POSS_PERS ? "Possible-" : "");

		if (dimm->dimm_case.cc_serdnm == NULL) {
			dimm->dimm_case.cc_serdnm = cmd_mem_serdnm_create(hdl,
			    "dimm", dimm->dimm_unum);

			fmd_serd_create(hdl, dimm->dimm_case.cc_serdnm,
			    fmd_prop_get_int32(hdl, "ce_n"),
			    fmd_prop_get_int64(hdl, "ce_t"));
		}

		if (fmd_serd_record(hdl, dimm->dimm_case.cc_serdnm, ep) ==
		    FMD_B_FALSE)
				return (CMD_EVD_OK); /* engine hasn't fired */

		fmd_hdl_debug(hdl, "ce serd fired\n");
		fmd_case_add_serd(hdl, dimm->dimm_case.cc_cp,
		    dimm->dimm_case.cc_serdnm);
		fmd_serd_reset(hdl, dimm->dimm_case.cc_serdnm);
		break;	/* to retire */

	case CE_DISP_LEAKY:
	case CE_DISP_STICKY:
		fmd_case_add_ereport(hdl, dimm->dimm_case.cc_cp, ep);
		break;	/* to retire */
	}

	dimm->dimm_nretired++;
	dimm->dimm_retstat.fmds_value.ui64++;
	cmd_dimm_dirty(hdl, dimm);

	cmd_page_fault(hdl, dimm->dimm_asru_nvl, cmd_dimm_fru(dimm), ep, afar);
	ce_thresh_check(hdl, dimm);

	return (CMD_EVD_OK);
}

static void
cmd_bank_fault(fmd_hdl_t *hdl, cmd_bank_t *bank)
{
	fmd_case_t *cp;
	nvlist_t *flt;

	if (bank->bank_flags & CMD_MEM_F_FAULTING)
		return; /* Only complain once per bank */

	bank->bank_flags |= CMD_MEM_F_FAULTING;
	cmd_bank_dirty(hdl, bank);

	cp = fmd_case_open(hdl, NULL);
	flt = cmd_bank_create_fault(hdl, bank, "fault.memory.bank",
	    CMD_FLTMAXCONF);
	fmd_case_add_suspect(hdl, cp, flt);
	fmd_case_solve(hdl, cp);
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_ue_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, uint64_t afar, uint8_t afar_status, uint16_t synd,
    uint8_t synd_status, ce_dispact_t type, uint64_t disp, nvlist_t *asru)
{
	cmd_page_t *page;
	cmd_bank_t *bank;
	cmd_cpu_t *cpu;

	cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class);

	if (cpu == NULL) {
		fmd_hdl_debug(hdl, "cmd_ue_common: cpu not found\n");
		return (CMD_EVD_UNUSED);
	}

	if (synd_status != AFLT_STAT_VALID) {
	    fmd_hdl_debug(hdl, "cmd_ue_common: syndrome not valid\n");
	    return (CMD_EVD_UNUSED);
	}

	if (cmd_mem_synd_check(hdl, afar, afar_status, synd, synd_status,
	    cpu) == CMD_EVD_UNUSED)
		return (CMD_EVD_UNUSED);

	/*
	 * The following code applies only to sun4u, because sun4u does
	 * not poison data in L2 cache resulting from the fetch of a
	 * memory UE.
	 */

#ifdef sun4u
	if (afar_status != AFLT_STAT_VALID) {
		/*
		 * Had this report's AFAR been valid, it would have
		 * contributed an address to the UE cache.  We don't
		 * know what the AFAR would have been, and thus we can't
		 * add anything to the cache.  If a xxU is caused by
		 * this UE, we won't be able to detect it, and will thus
		 * erroneously offline the CPU.  To prevent this
		 * situation, we need to assume that all xxUs generated
		 * through the next E$ flush are attributable to the UE.
		 */
		cmd_cpu_uec_set_allmatch(hdl, cpu);
	} else {
		cmd_cpu_uec_add(hdl, cpu, afar);
	}
#endif /* sun4u */

	if (afar_status != AFLT_STAT_VALID)
		return (CMD_EVD_UNUSED);

	if ((page = cmd_page_lookup(afar)) != NULL && page->page_case != NULL &&
	    fmd_case_solved(hdl, page->page_case))
		return (CMD_EVD_REDUND);

	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (NULL);
	}

	if ((bank = cmd_bank_lookup(hdl, asru)) == NULL &&
	    (bank = cmd_bank_create(hdl, asru)) == NULL)
		return (CMD_EVD_UNUSED);

	if (bank->bank_case.cc_cp == NULL) {
		const char *uuid;
		bank->bank_case.cc_cp = cmd_case_create(hdl, &bank->bank_header,
		    CMD_PTR_BANK_CASE, &uuid);
	}

	fmd_case_add_ereport(hdl, bank->bank_case.cc_cp, ep);

	bank->bank_nretired++;
	bank->bank_retstat.fmds_value.ui64++;
	cmd_bank_dirty(hdl, bank);

	cmd_page_fault(hdl, bank->bank_asru_nvl, cmd_bank_fru(bank), ep, afar);
	cmd_bank_fault(hdl, bank);

	return (CMD_EVD_OK);
}

void
cmd_dimm_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_dimm_destroy(hdl, arg);
}

void
cmd_bank_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_bank_destroy(hdl, arg);
}

/*
 * When we complete an IOxE/RxE FRx pair, we have enough information to
 * create either a CE or a UE, as appropriate.  Before dispatching the
 * joined event to the xE handler, we need to generate the FMRI for the
 * named DIMM.  While one of the events may already contain a resource FMRI,
 * said FMRI is incomplete.  The detector didn't have the necessary
 * information (the AFAR, the AFSR, *and* the syndrome) needed to create
 * a DIMM-level FMRI.
 */
static cmd_evdisp_t
iorxefrx_synthesize(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, uint64_t afar, uint8_t afar_status, uint64_t afsr,
    uint16_t synd, uint8_t synd_status, ce_dispact_t type, uint64_t disp,
    xe_handler_f *hdlr)
{
	nvlist_t *fmri;
	int rc;

	if ((fmri = cmd_dimm_fmri_derive(hdl, afar, synd, afsr)) == NULL)
		return (CMD_EVD_UNUSED);

	rc = hdlr(hdl, ep, nvl, class, afar, afar_status, synd, synd_status,
	    type, disp, fmri);

	nvlist_free(fmri);

	return (rc);
}

static cmd_iorxefrx_t *
iorxefrx_match(fmd_hdl_t *hdl, cmd_errcl_t errcl, cmd_errcl_t matchmask,
    uint_t det_agentid, uint_t afsr_agentid)
{
	cmd_iorxefrx_t *rf;

	for (rf = cmd_list_next(&cmd.cmd_iorxefrx); rf != NULL;
	    rf = cmd_list_next(rf)) {

		fmd_hdl_debug(hdl, "rf->rf_errcl = %llx, matchmask = %llx\n"
		    "rf->rf_det_agentid = %lx, afsr_agentid = %lx\n"
		    "rf->rf_afsr_agentid = %lx, det_agentid = %lx\n",
		    rf->rf_errcl, matchmask, rf->rf_det_agentid, afsr_agentid,
		    rf->rf_afsr_agentid, det_agentid);

		if ((rf->rf_errcl & matchmask) == 0)
			continue;

		/*
		 * For IOxEs we are unable to match based on both the detector
		 * and the captured Agent Id in the AFSR, because the bridge
		 * captures it's own Agent Id instead of the remote CPUs.
		 *
		 * Also, the LSB of Tomatillo's jpid is aliased for each chip
		 * and therefore needs to be factored out of our matching.
		 */
		if ((CMD_ERRCL_ISIOXE(rf->rf_errcl) ||
		    CMD_ERRCL_ISIOXE(errcl)) &&
		    ((rf->rf_afsr_agentid & TOM_AID_MATCH_MASK) ==
		    (afsr_agentid & TOM_AID_MATCH_MASK)))
			return (rf);

		/*
		 * Check for both here since IOxE is not involved
		 */
		if ((rf->rf_afsr_agentid == det_agentid) &&
		    (rf->rf_det_agentid == afsr_agentid))
			return (rf);
	}

	return (NULL);
}

/*
 * Got an RxE or an FRx.  FRx ereports can be matched with RxE ereports and
 * vice versa.  FRx ereports can also be matched with IOxE ereports.
 */
cmd_evdisp_t
cmd_rxefrx_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode, cmd_errcl_t matchmask)
{
	xe_handler_f *hdlr;
	cmd_iorxefrx_t *rfmatch, *rferr;
	cmd_cpu_t *cpu;
	char *typenm;
	int isrxe = CMD_ERRCL_MATCH(clcode, CMD_ERRCL_RCE | CMD_ERRCL_RUE);
	int isce = CMD_ERRCL_MATCH(clcode, CMD_ERRCL_RCE | CMD_ERRCL_FRC);
	int rc;
	int minorvers = 1;

	rferr = fmd_hdl_zalloc(hdl, sizeof (cmd_iorxefrx_t), FMD_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    FM_EREPORT_PAYLOAD_NAME_SYND, DATA_TYPE_UINT16, &rferr->rf_synd,
	    FM_EREPORT_PAYLOAD_NAME_SYND_STATUS, DATA_TYPE_UINT8,
	    &rferr->rf_synd_status,
	    FM_EREPORT_PAYLOAD_NAME_AFAR, DATA_TYPE_UINT64, &rferr->rf_afar,
	    FM_EREPORT_PAYLOAD_NAME_AFAR_STATUS, DATA_TYPE_UINT8,
	    &rferr->rf_afar_status,
	    FM_EREPORT_PAYLOAD_NAME_AFSR, DATA_TYPE_UINT64, &rferr->rf_afsr,
	    FM_EREPORT_PAYLOAD_NAME_ERR_TYPE, DATA_TYPE_STRING, &typenm,
	    NULL) != 0) {
		fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));
		return (CMD_EVD_BAD);
	}
	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_ERR_DISP,
	    &rferr->rf_disp) != 0)
		minorvers = 0;

	rferr->rf_type = cmd_mem_name2type(typenm, minorvers);

	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class)) == NULL) {
		fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));
		return (CMD_EVD_UNUSED);
	}

	if (!isrxe && rferr->rf_synd_status != AFLT_STAT_VALID) {
		fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));
		return (CMD_EVD_UNUSED);
	}

	if (isrxe) {
		rferr->rf_afsr_agentid = (rferr->rf_afsr &
		    USIIIi_AFSR_JREQ) >> USIIIi_AFSR_JREQ_SHIFT;
	} else {
		rferr->rf_afsr_agentid = (rferr->rf_afsr &
		    USIIIi_AFSR_AID) >> USIIIi_AFSR_AID_SHIFT;
	}

	rferr->rf_errcl = clcode;
	rferr->rf_det_agentid = cpu->cpu_cpuid;

	if ((rfmatch = iorxefrx_match(hdl, clcode, matchmask,
	    rferr->rf_det_agentid, rferr->rf_afsr_agentid)) == NULL) {
		cmd_iorxefrx_queue(hdl, rferr);
		return (CMD_EVD_OK);
	}

	/*
	 * Found a match.  Send a synthesized ereport to the appropriate
	 * routine.
	 */
	fmd_hdl_debug(hdl, "matched %cE %llx with %llx", "UC"[isce],
	    rferr->rf_errcl, rfmatch->rf_errcl);

	hdlr = (isce ? cmd_ce_common : cmd_ue_common);
	if (isrxe) {
		rc = iorxefrx_synthesize(hdl, ep, nvl, class, rferr->rf_afar,
		    rferr->rf_afar_status, rfmatch->rf_afsr, rfmatch->rf_synd,
		    rfmatch->rf_synd_status, rferr->rf_type, rferr->rf_disp,
		    hdlr);
	} else {
		rc = iorxefrx_synthesize(hdl, ep, nvl, class, rfmatch->rf_afar,
		    rfmatch->rf_afar_status, rferr->rf_afsr, rferr->rf_synd,
		    rferr->rf_synd_status, rfmatch->rf_type, rferr->rf_disp,
		    hdlr);
	}

	cmd_iorxefrx_free(hdl, rfmatch);
	fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));

	return (rc);
}

/* This IOxE must be matched with an FRx before UE/CE processing is possible */
static cmd_evdisp_t
cmd_ioxefrx_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t errcl, cmd_errcl_t matchmask)
{
	xe_handler_f *hdlr;
	cmd_iorxefrx_t *rfmatch, *rferr;
	char *typenm;
	int isce = CMD_ERRCL_MATCH(errcl, CMD_ERRCL_IOCE);
	char *portid_str;
	char *path = NULL;
	nvlist_t *det = NULL;
	int rc;
	int minorvers = 1;

	rferr = fmd_hdl_zalloc(hdl, sizeof (cmd_iorxefrx_t), FMD_SLEEP);

	if (nvlist_lookup_pairs(nvl, 0,
	    PCI_ECC_AFAR, DATA_TYPE_UINT64, &rferr->rf_afar,
	    PCI_ECC_AFSR, DATA_TYPE_UINT64, &rferr->rf_afsr,
	    PCI_ECC_SYND, DATA_TYPE_UINT16, &rferr->rf_synd,
	    PCI_ECC_TYPE, DATA_TYPE_STRING, &typenm,
	    NULL) != 0) {
		fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));
		return (CMD_EVD_BAD);
	}

	if (nvlist_lookup_uint64(nvl, PCI_ECC_DISP, &rferr->rf_disp) != 0)
		minorvers = 0;

	rferr->rf_type = cmd_mem_name2type(typenm, minorvers);
	rferr->rf_errcl = errcl;

	/*
	 * Lookup device path of host bridge.
	 */
	(void) nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &det);
	(void) nvlist_lookup_string(det, FM_FMRI_DEV_PATH, &path);

	/*
	 * get Jbus port id from the device path
	 */
	portid_str = strrchr(path, '@') + 1;
	rferr->rf_det_agentid = strtol(portid_str, NULL, 16);

	rferr->rf_afsr_agentid = (rferr->rf_afsr &
	    SCHIZO_ECC_UE_AFSR_AGENT_MID) >> SCHIZO_ECC_UE_AFSR_AGENT_MID_SHIFT;

	/*
	 * Only 4 bits of the Jbus AID are sent on the Jbus.  MSB is the one
	 * that is chosen not to make the trip.  This is not in any of the Jbus
	 * or Tomatillo documents and was discovered during testing and verified
	 * by Jalapeno H/W designer.
	 */
	rferr->rf_afsr_agentid &= 0xf;
	rferr->rf_afar_status = AFLT_STAT_VALID;
	rferr->rf_synd_status = AFLT_STAT_VALID;

	/*
	 * Need to send in the io_jpid that we get from the device path above
	 * for both the det_agentid and the afsr_agentid, since the CPU does not
	 * capture the same address as the bridge.  The bridge has the LSB
	 * aliased and the CPU is missing the MSB.
	 */
	if ((rfmatch = iorxefrx_match(hdl, rferr->rf_errcl, matchmask,
	    rferr->rf_det_agentid, rferr->rf_afsr_agentid)) == NULL) {
		cmd_iorxefrx_queue(hdl, rferr);
		return (CMD_EVD_OK);
	}

	/* Found a match.  Synthesize an ereport for UE/CE processing. */
	fmd_hdl_debug(hdl, "matched %cE %llx with %llx\n", "UC"[isce],
	    rferr->rf_errcl, rfmatch->rf_errcl);

	hdlr = (isce ? cmd_ce_common : cmd_ue_common);
	rc = iorxefrx_synthesize(hdl, ep, nvl, class, rferr->rf_afar,
	    rferr->rf_afar_status, rfmatch->rf_afsr, rfmatch->rf_synd,
	    rfmatch->rf_synd_status, rferr->rf_type, rferr->rf_disp, hdlr);

	cmd_iorxefrx_free(hdl, rfmatch);
	fmd_hdl_free(hdl, rferr, sizeof (cmd_iorxefrx_t));

	return (rc);
}

/* IOxE ereports that don't need matching with FRx ereports */
static cmd_evdisp_t
ioxe_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	int isce = CMD_ERRCL_MATCH(clcode, CMD_ERRCL_IOCE);
	xe_handler_f *hdlr = isce ? cmd_ce_common : cmd_ue_common;
	uint64_t afar;
	uint16_t synd;
	nvlist_t *rsrc;
	char *typenm;
	uint64_t disp;
	int minorvers = 1;

	if (nvlist_lookup_pairs(nvl, 0,
	    PCI_ECC_AFAR, DATA_TYPE_UINT64, &afar,
	    PCI_ECC_SYND, DATA_TYPE_UINT16, &synd,
	    PCI_ECC_TYPE, DATA_TYPE_STRING, &typenm,
	    PCI_ECC_RESOURCE, DATA_TYPE_NVLIST, &rsrc,
	    NULL) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_uint64(nvl, PCI_ECC_DISP, &disp) != 0)
		minorvers = 0;

	return (hdlr(hdl, ep, nvl, class, afar, AFLT_STAT_VALID, synd,
	    AFLT_STAT_VALID, cmd_mem_name2type(typenm, minorvers), disp,
	    rsrc));
}

cmd_evdisp_t
cmd_rxe(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	cmd_errcl_t matchmask = (clcode == CMD_ERRCL_RCE ? CMD_ERRCL_FRC :
	    CMD_ERRCL_FRU);

	return (cmd_rxefrx_common(hdl, ep, nvl, class, clcode, matchmask));
}

cmd_evdisp_t
cmd_ioxe(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	cmd_errcl_t matchmask = (clcode == CMD_ERRCL_IOCE ? CMD_ERRCL_FRC :
	    CMD_ERRCL_FRU);

	if (fmd_nvl_class_match(hdl, nvl, "ereport.io.tom.*")) {
		return (cmd_ioxefrx_common(hdl, ep, nvl, class, clcode,
		    matchmask));
	} else
		return (ioxe_common(hdl, ep, nvl, class, clcode));
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_ioxe_sec(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	/*
	 * Secondary IOxE's can't be used to identify failed or failing
	 * resources, as they don't contain enough information.  Ignore them.
	 */
	return (CMD_EVD_OK);
}
