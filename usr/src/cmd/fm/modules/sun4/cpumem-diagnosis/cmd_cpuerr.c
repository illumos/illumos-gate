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
 * Ereport-handling routines for CPU errors
 */

#include <cmd_cpu.h>
#include <cmd.h>

#include <strings.h>
#include <string.h>
#include <errno.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/async.h>
#ifdef sun4u
#include <sys/fm/cpu/UltraSPARC-III.h>
#include <cmd_Lxcache.h>
#include <cmd_opl.h>
#endif

/*
 * We follow the same algorithm for handling all L1$, TLB, and L2/L3 cache
 * tag events so we can have one common routine into which each handler
 * calls.  The two tests of (strcmp(serdnm, "") != 0) are used to eliminate
 * the need for a separate macro for UEs which override SERD engine
 * counting CEs leading to same fault.
 */
/*ARGSUSED9*/
static cmd_evdisp_t
cmd_cpuerr_common(fmd_hdl_t *hdl, fmd_event_t *ep, cmd_cpu_t *cpu,
    cmd_case_t *cc, cmd_ptrsubtype_t pstype, const char *serdnm,
    const char *serdn, const char *serdt, const char *fltnm,
    cmd_errcl_t clcode)
{
	const char *uuid;

	if (cc->cc_cp != NULL && fmd_case_solved(hdl, cc->cc_cp))
		return (CMD_EVD_REDUND);

	if (cc->cc_cp == NULL) {
		cc->cc_cp = cmd_case_create(hdl, &cpu->cpu_header, pstype,
		    &uuid);
		if (strcmp(serdnm, "") != 0) {
			cc->cc_serdnm = cmd_cpu_serdnm_create(hdl, cpu,
			    serdnm);
			fmd_serd_create(hdl, cc->cc_serdnm,
			    fmd_prop_get_int32(hdl, serdn),
			    fmd_prop_get_int64(hdl, serdt));
		}
	}

	if (strcmp(serdnm, "") != 0) {
		fmd_hdl_debug(hdl, "adding event to %s\n", cc->cc_serdnm);
		if (fmd_serd_record(hdl, cc->cc_serdnm, ep) == FMD_B_FALSE)
			return (CMD_EVD_OK); /* serd engine hasn't fired yet */

		fmd_case_add_serd(hdl, cc->cc_cp, cc->cc_serdnm);
	} else {
		if (cc->cc_serdnm != NULL) {
			fmd_hdl_debug(hdl,
			    "destroying existing %s state for class %x\n",
			    cc->cc_serdnm, clcode);
			fmd_serd_destroy(hdl, cc->cc_serdnm);
			fmd_hdl_strfree(hdl, cc->cc_serdnm);
			cc->cc_serdnm = NULL;
		}
		fmd_case_reset(hdl, cc->cc_cp);
		fmd_case_add_ereport(hdl, cc->cc_cp, ep);
	}

	cmd_cpu_create_faultlist(hdl, cc->cc_cp, cpu, fltnm, NULL, 100);

	fmd_case_solve(hdl, cc->cc_cp);

	return (CMD_EVD_OK);
}
#ifdef sun4u

#define	CMD_CPU_TAGHANDLER(name, casenm, ptr, ntname, fltname)	\
cmd_evdisp_t								\
cmd_##name(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,		\
    const char *class, cmd_errcl_t clcode)				\
{									\
	uint8_t level = clcode & CMD_ERRCL_LEVEL_EXTRACT;		\
	cmd_cpu_t *cpu;							\
									\
	clcode &= CMD_ERRCL_LEVEL_MASK;					\
	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class,	\
	    level)) == NULL || cpu->cpu_faulting)			\
		return (CMD_EVD_UNUSED);				\
									\
	if ((strstr(class, "ultraSPARC-IVplus.l3-thce") != 0) ||	\
		(strstr(class, "ultraSPARC-IVplus.thce") != 0)) {	\
		return (cmd_us4plus_tag_err(hdl, ep, nvl, cpu,	\
		    ptr, ntname "_n", ntname "_t", fltname, clcode));	\
	}								\
	return (cmd_cpuerr_common(hdl, ep, cpu, &cpu->cpu_##casenm,	\
	    ptr, ntname, ntname "_n", ntname "_t", fltname, clcode));	\
}
#endif

#define	CMD_CPU_SIMPLEHANDLER(name, casenm, ptr, ntname, fltname)	\
cmd_evdisp_t								\
cmd_##name(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,		\
    const char *class, cmd_errcl_t clcode)				\
{									\
	uint8_t level = clcode & CMD_ERRCL_LEVEL_EXTRACT;		\
	cmd_cpu_t *cpu;							\
									\
	clcode &= CMD_ERRCL_LEVEL_MASK;					\
	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class,	\
	    level)) == NULL || cpu->cpu_faulting)			\
		return (CMD_EVD_UNUSED);				\
									\
	return (cmd_cpuerr_common(hdl, ep, cpu, &cpu->cpu_##casenm,	\
	    ptr, ntname, ntname "_n", ntname "_t", fltname, clcode));	\
}

#ifdef sun4u
CMD_CPU_TAGHANDLER(txce, l2tag, CMD_PTR_CPU_L2TAG, "l2tag", "l2cachetag")
CMD_CPU_TAGHANDLER(l3_thce, l3tag, CMD_PTR_CPU_L3TAG, "l3tag", "l3cachetag")
#else
CMD_CPU_SIMPLEHANDLER(txce, l2tag, CMD_PTR_CPU_L2TAG, "l2tag", "l2cachetag")
CMD_CPU_SIMPLEHANDLER(l3_thce, l3tag, CMD_PTR_CPU_L3TAG, "l3tag", "l3cachetag")
#endif
CMD_CPU_SIMPLEHANDLER(icache, icache, CMD_PTR_CPU_ICACHE, "icache", "icache")
CMD_CPU_SIMPLEHANDLER(dcache, dcache, CMD_PTR_CPU_DCACHE, "dcache", "dcache")
CMD_CPU_SIMPLEHANDLER(pcache, pcache, CMD_PTR_CPU_PCACHE, "pcache", "pcache")
CMD_CPU_SIMPLEHANDLER(itlb, itlb, CMD_PTR_CPU_ITLB, "itlb", "itlb")
CMD_CPU_SIMPLEHANDLER(dtlb, dtlb, CMD_PTR_CPU_DTLB, "dtlb", "dtlb")
CMD_CPU_SIMPLEHANDLER(irc, ireg, CMD_PTR_CPU_IREG, "ireg", "ireg")
CMD_CPU_SIMPLEHANDLER(frc, freg, CMD_PTR_CPU_FREG, "freg", "freg")
CMD_CPU_SIMPLEHANDLER(mau, mau, CMD_PTR_CPU_MAU, "mau", "mau")
CMD_CPU_SIMPLEHANDLER(miscregs_ce, misc_regs, CMD_PTR_CPU_MISC_REGS,
	"misc_regs", "misc_reg")
CMD_CPU_SIMPLEHANDLER(l2c, l2data, CMD_PTR_CPU_L2DATA, "l2data", "l2data-c")

CMD_CPU_SIMPLEHANDLER(fpu, fpu, CMD_PTR_CPU_FPU, "", "fpu")
CMD_CPU_SIMPLEHANDLER(l2ctl, l2ctl, CMD_PTR_CPU_L2CTL, "", "l2cachectl")
CMD_CPU_SIMPLEHANDLER(iru, ireg, CMD_PTR_CPU_IREG, "", "ireg")
CMD_CPU_SIMPLEHANDLER(fru, freg, CMD_PTR_CPU_FREG, "", "freg")
CMD_CPU_SIMPLEHANDLER(miscregs_ue, misc_regs, CMD_PTR_CPU_MISC_REGS,
	"", "misc_reg")
CMD_CPU_SIMPLEHANDLER(l2u, l2data, CMD_PTR_CPU_L2DATA, "", "l2data-u")
CMD_CPU_SIMPLEHANDLER(lfu_ue, lfu, CMD_PTR_CPU_LFU, "", "lfu-u")
CMD_CPU_SIMPLEHANDLER(lfu_ce, lfu, CMD_PTR_CPU_LFU, "", "lfu-f")
CMD_CPU_SIMPLEHANDLER(lfu_pe, lfu, CMD_PTR_CPU_LFU, "", "lfu-p")


#ifdef sun4u
/*
 * The following macro handles UEs or CPU errors.
 * It handles the error cases in which there is with or
 * without "resource".
 *
 * If the "fltname" "core" is to be generated, the sibling CPUs
 * within the core will be added to the suspect list.
 * If the "fltname" "chip" is to be generated, the sibling CPUs
 * within the chip will be added to the suspect list.
 * If the "fltname" "strand" is to be generated, the strand
 * itself will be in the suspect list.
 */
#define	CMD_OPL_UEHANDLER(name, casenm, ptr, fltname, has_rsrc)		\
cmd_evdisp_t								\
cmd_##name(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,		\
    const char *class, cmd_errcl_t clcode)				\
{									\
	cmd_cpu_t *cpu;							\
	cmd_case_t *cc;							\
	cmd_evdisp_t rc;						\
	nvlist_t  *rsrc = NULL;						\
	uint8_t cpumask, version = 1;					\
	uint8_t lookup_rsrc = has_rsrc;					\
									\
	fmd_hdl_debug(hdl,						\
	    "Enter cmd_opl_ue_cpu for class %x\n", clcode);		\
									\
	if (lookup_rsrc) {						\
		if (nvlist_lookup_nvlist(nvl,				\
		    FM_EREPORT_PAYLOAD_NAME_RESOURCE, &rsrc) != 0)	\
			return (CMD_EVD_BAD);				\
									\
		if ((cpu = cmd_cpu_lookup(hdl, rsrc, class,		\
		    CMD_CPU_LEVEL_THREAD)) == NULL ||			\
		    cpu->cpu_faulting)					\
			return (CMD_EVD_UNUSED);			\
	} else {							\
		if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class,\
		    CMD_CPU_LEVEL_THREAD)) == NULL || cpu->cpu_faulting)\
			return (CMD_EVD_UNUSED);			\
									\
		(void) nvlist_lookup_nvlist(nvl,			\
		    FM_EREPORT_DETECTOR, &rsrc);			\
	}								\
									\
	if (nvlist_lookup_uint8(rsrc, FM_VERSION, &version) != 0 ||	\
	    version > FM_CPU_SCHEME_VERSION ||				\
	    nvlist_lookup_uint8(rsrc, FM_FMRI_CPU_MASK, &cpumask) != 0)	\
		return (CMD_EVD_BAD);					\
									\
	cc = &cpu->cpu_##casenm;					\
	rc = cmd_opl_ue_cpu(hdl, ep, class, fltname,			\
	    ptr, cpu, cc, cpumask);					\
	return (rc);							\
}

/*
 * CPU errors without resource
 */
CMD_OPL_UEHANDLER(oplinv_urg, opl_inv_urg, CMD_PTR_CPU_UGESR_INV_URG, "core", 0)
CMD_OPL_UEHANDLER(oplcre, opl_cre, CMD_PTR_CPU_UGESR_CRE, "core", 0)
CMD_OPL_UEHANDLER(opltsb_ctx, opl_tsb_ctx, CMD_PTR_CPU_UGESR_TSB_CTX, "core", 0)
CMD_OPL_UEHANDLER(opltsbp, opl_tsbp, CMD_PTR_CPU_UGESR_TSBP, "core", 0)
CMD_OPL_UEHANDLER(oplpstate, opl_pstate, CMD_PTR_CPU_UGESR_PSTATE, "core", 0)
CMD_OPL_UEHANDLER(opltstate, opl_tstate, CMD_PTR_CPU_UGESR_TSTATE, "core", 0)
CMD_OPL_UEHANDLER(opliug_f, opl_iug_f, CMD_PTR_CPU_UGESR_IUG_F, "core", 0)
CMD_OPL_UEHANDLER(opliug_r, opl_iug_r, CMD_PTR_CPU_UGESR_IUG_R, "core", 0)
CMD_OPL_UEHANDLER(oplsdc, opl_sdc, CMD_PTR_CPU_UGESR_SDC, "chip", 0)
CMD_OPL_UEHANDLER(oplwdt, opl_wdt, CMD_PTR_CPU_UGESR_WDT, "core", 0)
CMD_OPL_UEHANDLER(opldtlb, opl_dtlb, CMD_PTR_CPU_UGESR_DTLB, "core", 0)
CMD_OPL_UEHANDLER(oplitlb, opl_itlb, CMD_PTR_CPU_UGESR_ITLB, "core", 0)
CMD_OPL_UEHANDLER(oplcore_err, opl_core_err, CMD_PTR_CPU_UGESR_CORE_ERR,
"core", 0)
CMD_OPL_UEHANDLER(opldae, opl_dae, CMD_PTR_CPU_UGESR_DAE, "core", 0)
CMD_OPL_UEHANDLER(opliae, opl_iae, CMD_PTR_CPU_UGESR_IAE, "core", 0)
CMD_OPL_UEHANDLER(opluge, opl_uge, CMD_PTR_CPU_UGESR_UGE, "core", 0)

/*
 * UEs with resource
 */
CMD_OPL_UEHANDLER(oplinv_sfsr, opl_invsfsr, CMD_PTR_CPU_INV_SFSR, "strand", 1)
CMD_OPL_UEHANDLER(opluecpu_detcpu, oplue_detcpu, CMD_PTR_CPU_UE_DET_CPU,
"core", 1)
CMD_OPL_UEHANDLER(opluecpu_detio, oplue_detio, CMD_PTR_CPU_UE_DET_IO, "core", 1)
CMD_OPL_UEHANDLER(oplmtlb, opl_mtlb, CMD_PTR_CPU_MTLB, "core", 1)
CMD_OPL_UEHANDLER(opltlbp, opl_tlbp, CMD_PTR_CPU_TLBP, "core", 1)
#endif	/* sun4u */

/*ARGSUSED*/
static void
cmd_nop_hdlr(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep)
{
	fmd_hdl_debug(hdl, "nop train resolved for clcode %llx\n",
	    xr->xr_clcode);
}

/*ARGSUSED*/
static void
cmd_xxu_hdlr(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep)
{
	const errdata_t *ed;
	cmd_cpu_t *cpu = xr->xr_cpu;
	cmd_case_t *cc;
	const char *uuid;
	nvlist_t *rsrc = NULL;

	cmd_fill_errdata(xr->xr_clcode, cpu, &cc, &ed);

	if (cpu->cpu_faulting) {
		CMD_STAT_BUMP(xxu_retr_flt);
		return;
	}

	if (cmd_afar_status_check(xr->xr_afar_status, xr->xr_clcode) < 0) {
		fmd_hdl_debug(hdl, "xxU dropped, afar not VALID\n");
		return;
	}

	if (cmd_cpu_synd_check(xr->xr_synd, xr->xr_clcode) < 0) {
		fmd_hdl_debug(hdl, "xxU/LDxU dropped due to syndrome\n");
		return;
	}

#ifdef sun4u
	/*
	 * UE cache needed for sun4u only, because sun4u doesn't poison
	 * uncorrectable data loaded into L2/L3 cache.
	 */
	if (cmd_cpu_uec_match(xr->xr_cpu, xr->xr_afar)) {
		fmd_hdl_debug(hdl, "ue matched in UE cache\n");
		CMD_STAT_BUMP(xxu_ue_match);
		return;
	}
#endif /* sun4u */

	/*
	 * We didn't match in the UE cache.  We don't need to sleep for UE
	 * arrival, as we've already slept once for the train match.
	 */

	if (cc->cc_cp == NULL) {
		cc->cc_cp = cmd_case_create(hdl, &cpu->cpu_header, ed->ed_pst,
		    &uuid);
	} else if (cc->cc_serdnm != NULL) {
		fmd_hdl_debug(hdl, "destroying existing %s state\n",
		    cc->cc_serdnm);

		fmd_serd_destroy(hdl, cc->cc_serdnm);
		fmd_hdl_strfree(hdl, cc->cc_serdnm);
		cc->cc_serdnm = NULL;

		fmd_case_reset(hdl, cc->cc_cp);
	}

	if (xr->xr_rsrc_nvl != NULL && nvlist_dup(xr->xr_rsrc_nvl,
	    &rsrc, 0) != 0) {
		fmd_hdl_abort(hdl, "failed to duplicate resource FMRI for "
		    "%s fault", ed->ed_fltnm);
	}

	fmd_case_add_ereport(hdl, cc->cc_cp, ep);

	cmd_cpu_create_faultlist(hdl, cc->cc_cp, cpu, ed->ed_fltnm, rsrc, 100);
	nvlist_free(rsrc);
	fmd_case_solve(hdl, cc->cc_cp);
}

static void
cmd_xxc_hdlr(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep)
{
	const errdata_t *ed;
	cmd_cpu_t *cpu = xr->xr_cpu;
	cmd_case_t *cc;
	const char *uuid;
	nvlist_t *rsrc = NULL;

#ifdef	sun4u
	if (cmd_cache_ce_panther(hdl, ep, xr) == 0) {
		return;
	}
#endif
	cmd_fill_errdata(xr->xr_clcode, cpu, &cc, &ed);

	if (cpu->cpu_faulting || (cc->cc_cp != NULL &&
	    fmd_case_solved(hdl, cc->cc_cp)))
		return;

	if (cc->cc_cp == NULL) {
		cc->cc_cp = cmd_case_create(hdl, &cpu->cpu_header, ed->ed_pst,
		    &uuid);
		cc->cc_serdnm = cmd_cpu_serdnm_create(hdl, cpu,
		    ed->ed_serd->cs_name);

		fmd_serd_create(hdl, cc->cc_serdnm, ed->ed_serd->cs_n,
		    ed->ed_serd->cs_t);
	}

	fmd_hdl_debug(hdl, "adding event to %s\n", cc->cc_serdnm);

	if (fmd_serd_record(hdl, cc->cc_serdnm, ep) == FMD_B_FALSE)
		return; /* serd engine hasn't fired yet */

	if (xr->xr_rsrc_nvl != NULL && nvlist_dup(xr->xr_rsrc_nvl,
	    &rsrc, 0) != 0) {
		fmd_hdl_abort(hdl, "failed to duplicate resource FMRI for "
		    "%s fault", ed->ed_fltnm);
	}

	fmd_case_add_serd(hdl, cc->cc_cp, cc->cc_serdnm);
	cmd_cpu_create_faultlist(hdl, cc->cc_cp, cpu, ed->ed_fltnm, rsrc, 100);
	nvlist_free(rsrc);
	fmd_case_solve(hdl, cc->cc_cp);
}

/*
 * We're back from the timeout.  Check to see if this event was part of a train.
 * If it was, make sure to only process the cause of the train.  If not,
 * process the event directly.
 */
static void
cmd_xxcu_resolve(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep,
    cmd_xr_hdlr_f *hdlr)
{
	cmd_xxcu_trw_t *trw;
	cmd_errcl_t cause;
	uint64_t afar;


	afar = 0;

	if (xr->xr_afar_status == AFLT_STAT_VALID)
		afar = xr->xr_afar;

	if ((trw = cmd_trw_lookup(xr->xr_ena,
	    xr->xr_afar_status, afar)) == NULL) {
		fmd_hdl_debug(hdl, "cmd_trw_lookup: Not found\n");
		return;
	}

	fmd_hdl_debug(hdl, "found waiter with mask 0x%08llx\n", trw->trw_mask);

	trw->trw_flags |= CMD_TRW_F_DELETING;

	/*
	 * In sun4v, the matching train rule is changed. It matches only
	 * a portion of the train mask, so can't discard the rest of
	 * the error in the train mask.
	 */
#ifdef sun4u
	if (trw->trw_flags & CMD_TRW_F_CAUSESEEN) {
		fmd_hdl_debug(hdl, "cause already seen -- discarding\n");
		goto done;
	}
#endif

	if ((cause = cmd_train_match(trw->trw_mask, xr->xr_clcode)) == 0) {
		/*
		 * We didn't match in a train, so we're going to process each
		 * event individually.
		 */
		fmd_hdl_debug(hdl, "didn't match in a train\n");
		hdlr(hdl, xr, ep);
		goto done;
	}

	fmd_hdl_debug(hdl, "found a match for train.  cause is %llx, "
	    "this is %llx\n", cause, xr->xr_clcode);

	/*
	 * We've got a train match.  If this event is the cause of the train,
	 * process it.
	 */
	if (cause == xr->xr_clcode) {
		trw->trw_flags |= CMD_TRW_F_CAUSESEEN;
		hdlr(hdl, xr, ep);
	}

done:
	cmd_trw_deref(hdl, trw);
}

void
cmd_xxc_resolve(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep)
{
	cmd_xxcu_resolve(hdl, xr, ep, cmd_xxc_hdlr);
}

void
cmd_xxu_resolve(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep)
{
	cmd_xxcu_resolve(hdl, xr, ep, cmd_xxu_hdlr);
}

void
cmd_nop_resolve(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep)
{
	cmd_xxcu_resolve(hdl, xr, ep, cmd_nop_hdlr);
}

cmd_evdisp_t
cmd_xxcu_initial(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode, uint_t hdlrid)
{
	cmd_xxcu_trw_t *trw;
	cmd_case_t *cc;
	cmd_cpu_t *cpu;
	cmd_xr_t *xr;
	uint64_t ena;
	uint64_t afar;
	uint8_t level = clcode & CMD_ERRCL_LEVEL_EXTRACT;
	uint8_t	afar_status;
	const errdata_t *ed = NULL;
	int ref_incremented = 0;

	clcode &= CMD_ERRCL_LEVEL_MASK; /* keep level bits out of train masks */

	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class,
	    level)) == NULL || cpu->cpu_faulting)
		return (CMD_EVD_UNUSED);

	cmd_fill_errdata(clcode, cpu, &cc, &ed);

	if (cc->cc_cp != NULL && fmd_case_solved(hdl, cc->cc_cp))
		return (CMD_EVD_REDUND);

	(void) nvlist_lookup_uint64(nvl, FM_EREPORT_ENA, &ena);

	if (cmd_afar_valid(hdl, nvl, clcode, &afar) != 0) {
		afar_status = AFLT_STAT_INVALID;
		afar = 0;
	} else {
		afar_status = AFLT_STAT_VALID;
	}

	fmd_hdl_debug(hdl, "scheduling %s (%llx) for redelivery\n",
	    class, clcode);
	fmd_hdl_debug(hdl, "looking up ena %llx,afar %llx with\n", ena, afar);

	fmd_hdl_debug(hdl, "afar status of %02x\n", afar_status);

	if ((trw = cmd_trw_lookup(ena, afar_status, afar)) == NULL) {
		if ((trw = cmd_trw_alloc(ena, afar)) == NULL) {
			fmd_hdl_debug(hdl, "failed to get new trw\n");
			goto redeliver;
		}
	}

	if (trw->trw_flags & CMD_TRW_F_DELETING)
		goto redeliver;

	if (trw->trw_mask & clcode) {
		fmd_hdl_debug(hdl, "clcode %llx is already in trw "
		    "(mask %llx)\n", clcode, trw->trw_mask);
		return (CMD_EVD_UNUSED);
	}

	cmd_trw_ref(hdl, trw, clcode);
	ref_incremented++;

	fmd_hdl_debug(hdl, "trw rescheduled for train delivery\n");

redeliver:
	if ((xr = cmd_xr_create(hdl, ep, nvl, cpu, clcode)) == NULL) {
		fmd_hdl_debug(hdl, "cmd_xr_create failed");
		if (ref_incremented)
			cmd_trw_deref(hdl, trw);
		return (CMD_EVD_BAD);
	}

	return (cmd_xr_reschedule(hdl, xr, hdlrid));
}


cmd_evdisp_t
cmd_xxu(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (cmd_xxcu_initial(hdl, ep, nvl, class, clcode, CMD_XR_HDLR_XXU));
}

cmd_evdisp_t
cmd_xxc(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (cmd_xxcu_initial(hdl, ep, nvl, class, clcode, CMD_XR_HDLR_XXC));
}

cmd_evdisp_t
cmd_nop_train(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	return (cmd_xxcu_initial(hdl, ep, nvl, class, clcode, CMD_XR_HDLR_NOP));
}

cmd_evdisp_t
cmd_miscregs_train(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	return (cmd_xxcu_initial(hdl, ep, nvl, class, clcode,
	    CMD_XR_HDLR_XXC));
}

void
cmd_cpuerr_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_cpu_destroy(hdl, arg);
}
