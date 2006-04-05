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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

/*
 * We follow the same algorithm for handling all L1$, TLB, and L2/L3 cache
 * tag events so we can have one common routine into which each handler
 * calls.
 */
/*ARGSUSED9*/
static cmd_evdisp_t
cmd_cpuerr_common(fmd_hdl_t *hdl, fmd_event_t *ep, cmd_cpu_t *cpu,
    cmd_case_t *cc, cmd_ptrsubtype_t pstype, const char *serdnm,
    const char *serdn, const char *serdt, const char *fltnm,
    cmd_errcl_t clcode)
{
	nvlist_t *flt;
	const char *uuid;

	if (cc->cc_cp != NULL && fmd_case_solved(hdl, cc->cc_cp))
		return (CMD_EVD_REDUND);

	if (cc->cc_cp == NULL) {
		cc->cc_cp = cmd_case_create(hdl, &cpu->cpu_header, pstype,
		    &uuid);
		cc->cc_serdnm = cmd_cpu_serdnm_create(hdl, cpu, serdnm);

		fmd_serd_create(hdl, cc->cc_serdnm,
		    fmd_prop_get_int32(hdl, serdn),
		    fmd_prop_get_int64(hdl, serdt));
	}

	fmd_hdl_debug(hdl, "adding event to %s\n", cc->cc_serdnm);
	if (fmd_serd_record(hdl, cc->cc_serdnm, ep) == FMD_B_FALSE)
		return (CMD_EVD_OK); /* serd engine hasn't fired yet */

	fmd_case_add_serd(hdl, cc->cc_cp, cc->cc_serdnm);

	flt = cmd_cpu_create_fault(hdl, cpu, fltnm, NULL, 100);
	fmd_case_add_suspect(hdl, cc->cc_cp, flt);

	fmd_case_solve(hdl, cc->cc_cp);

	return (CMD_EVD_OK);
}

#define	CMD_CPU_SIMPLEHANDLER(name, casenm, ptr, ntname, fltname)	\
cmd_evdisp_t								\
cmd_##name(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,		\
    const char *class, cmd_errcl_t clcode)				\
{									\
	cmd_cpu_t *cpu;							\
									\
	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class)) ==	\
	    NULL || cpu->cpu_faulting)					\
		return (CMD_EVD_UNUSED);				\
									\
	return (cmd_cpuerr_common(hdl, ep, cpu, &cpu->cpu_##casenm,	\
	    ptr, ntname, ntname "_n", ntname "_t", fltname, clcode)); 	\
}

CMD_CPU_SIMPLEHANDLER(txce, l2tag, CMD_PTR_CPU_L2TAG, "l2tag", "l2cachetag")
CMD_CPU_SIMPLEHANDLER(l3_thce, l3tag, CMD_PTR_CPU_L3TAG, "l3tag", "l3cachetag")
CMD_CPU_SIMPLEHANDLER(icache, icache, CMD_PTR_CPU_ICACHE, "icache", "icache")
CMD_CPU_SIMPLEHANDLER(dcache, dcache, CMD_PTR_CPU_DCACHE, "dcache", "dcache")
CMD_CPU_SIMPLEHANDLER(pcache, pcache, CMD_PTR_CPU_PCACHE, "pcache", "pcache")
CMD_CPU_SIMPLEHANDLER(itlb, itlb, CMD_PTR_CPU_ITLB, "itlb", "itlb")
CMD_CPU_SIMPLEHANDLER(dtlb, dtlb, CMD_PTR_CPU_DTLB, "dtlb", "dtlb")
CMD_CPU_SIMPLEHANDLER(irc, ireg, CMD_PTR_CPU_IREG, "ireg", "ireg")
CMD_CPU_SIMPLEHANDLER(frc, freg, CMD_PTR_CPU_FREG, "freg", "freg")
CMD_CPU_SIMPLEHANDLER(mau, mau, CMD_PTR_CPU_MAU, "mau", "mau")

/*
 * The following macro handles UE errors for CPUs.
 * The UE may or may not share a fault with one or more
 * CEs, but this doesn't matter.  We look for existence of a
 * SERD engine, blow it away if it exists, and close the case
 * as solved.
 */

#define	CMD_CPU_UEHANDLER(name, casenm, ptr, fltname)			\
cmd_evdisp_t								\
cmd_##name(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,		\
    const char *class, cmd_errcl_t clcode)				\
{									\
	const char *uuid;						\
	cmd_cpu_t *cpu;							\
	nvlist_t *flt;							\
	cmd_case_t *cc;							\
									\
	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class)) ==	\
	    NULL || cpu->cpu_faulting)					\
		return (CMD_EVD_UNUSED);				\
									\
	cc = &cpu->cpu_##casenm;					\
	if (cc->cc_cp != NULL && fmd_case_solved(hdl, cc->cc_cp))	\
		return (CMD_EVD_REDUND);				\
									\
	if (cc->cc_cp == NULL) {					\
		cc->cc_cp = cmd_case_create(hdl, &cpu->cpu_header,	\
		    ptr, &uuid);					\
	}								\
									\
	if (cc->cc_serdnm != NULL) {					\
		fmd_hdl_debug(hdl,					\
		    "destroying existing %s state for class %x\n",	\
		    cc->cc_serdnm, clcode);				\
		fmd_serd_destroy(hdl, cc->cc_serdnm);			\
		fmd_hdl_strfree(hdl, cc->cc_serdnm);			\
		cc->cc_serdnm = NULL;					\
		fmd_case_reset(hdl, cc->cc_cp);				\
	}								\
									\
	fmd_case_add_ereport(hdl, cc->cc_cp, ep);			\
	flt = cmd_cpu_create_fault(hdl, cpu, fltname, NULL, 100);	\
	fmd_case_add_suspect(hdl, cc->cc_cp, flt);			\
	fmd_case_solve(hdl, cc->cc_cp);					\
	return (CMD_EVD_OK);						\
}

CMD_CPU_UEHANDLER(fpu, fpu, CMD_PTR_CPU_FPU, "fpu")
CMD_CPU_UEHANDLER(l2ctl, l2ctl, CMD_PTR_CPU_L2CTL, "l2ctl")
CMD_CPU_UEHANDLER(iru, ireg, CMD_PTR_CPU_IREG, "ireg")
CMD_CPU_UEHANDLER(fru, freg, CMD_PTR_CPU_FREG, "freg")

typedef struct errdata {
	cmd_serd_t *ed_serd;
	const char *ed_fltnm;
	const cmd_ptrsubtype_t ed_pst;
} errdata_t;

static const errdata_t l3errdata =
	{ &cmd.cmd_l3data_serd, "l3cachedata", CMD_PTR_CPU_L3DATA  };
static const errdata_t l2errdata =
	{ &cmd.cmd_l2data_serd, "l2cachedata", CMD_PTR_CPU_L2DATA };

/*ARGSUSED*/
static void
cmd_xxu_hdlr(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep)
{
	int isl3 = CMD_ERRCL_ISL3XXCU(xr->xr_clcode);
	const errdata_t *ed = isl3 ? &l3errdata : &l2errdata;
	cmd_cpu_t *cpu = xr->xr_cpu;
	cmd_case_t *cc = isl3 ? &cpu->cpu_l3data : &cpu->cpu_l2data;
	const char *uuid;
	nvlist_t *rsrc = NULL;
	nvlist_t *flt;

	if (cpu->cpu_faulting) {
		CMD_STAT_BUMP(xxu_retr_flt);
		return;
	}

	if (xr->xr_afar_status != AFLT_STAT_VALID) {
		fmd_hdl_debug(hdl, "xxU dropped, afar not VALID\n");
		return;
	}

	if (cmd_cpu_synd_check(xr->xr_synd) < 0) {
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
	flt = cmd_cpu_create_fault(hdl, cpu, ed->ed_fltnm, rsrc, 100);
	fmd_case_add_suspect(hdl, cc->cc_cp, flt);
	fmd_case_solve(hdl, cc->cc_cp);
}

static void
cmd_xxc_hdlr(fmd_hdl_t *hdl, cmd_xr_t *xr, fmd_event_t *ep)
{
	int isl3 = CMD_ERRCL_ISL3XXCU(xr->xr_clcode);
	const errdata_t *ed = isl3 ? &l3errdata : &l2errdata;
	cmd_cpu_t *cpu = xr->xr_cpu;
	cmd_case_t *cc = isl3 ? &cpu->cpu_l3data : &cpu->cpu_l2data;
	const char *uuid;
	nvlist_t *rsrc = NULL;
	nvlist_t *flt;

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
	flt = cmd_cpu_create_fault(hdl, cpu, ed->ed_fltnm, rsrc, 100);
	fmd_case_add_suspect(hdl, cc->cc_cp, flt);
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

	if ((trw = cmd_trw_lookup(xr->xr_ena)) == NULL) {
		hdlr(hdl, xr, ep);
		return;
	}

	fmd_hdl_debug(hdl, "found waiter with mask 0x%08llx\n", trw->trw_mask);

	trw->trw_flags |= CMD_TRW_F_DELETING;

	if (trw->trw_flags & CMD_TRW_F_CAUSESEEN) {
		fmd_hdl_debug(hdl, "cause already seen -- discarding\n");
		goto done;
	}

	if ((cause = cmd_xxcu_train_match(trw->trw_mask)) == 0) {
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

static cmd_evdisp_t
cmd_xxcu_initial(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode, uint_t hdlrid)
{
	cmd_xxcu_trw_t *trw;
	cmd_case_t *cc;
	cmd_cpu_t *cpu;
	cmd_xr_t *xr;
	uint64_t ena;

	if ((cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class)) == NULL ||
	    cpu->cpu_faulting)
		return (CMD_EVD_UNUSED);

	cc = CMD_ERRCL_ISL2XXCU(clcode) ? &cpu->cpu_l2data : &cpu->cpu_l3data;
	if (cc->cc_cp != NULL && fmd_case_solved(hdl, cc->cc_cp))
		return (CMD_EVD_REDUND);

	(void) nvlist_lookup_uint64(nvl, FM_EREPORT_ENA, &ena);

	fmd_hdl_debug(hdl, "scheduling %s (%llx) for redelivery\n",
	    class, clcode);

	if ((trw = cmd_trw_lookup(ena)) == NULL) {
		if ((trw = cmd_trw_alloc(ena)) == NULL) {
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

	fmd_hdl_debug(hdl, "trw rescheduled for train delivery\n");

redeliver:
	if ((xr = cmd_xr_create(hdl, ep, nvl, cpu, clcode)) == NULL)
		return (CMD_EVD_BAD);

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

void
cmd_cpuerr_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_cpu_destroy(hdl, arg);
}
