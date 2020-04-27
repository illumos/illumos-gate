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

/*
 * Ereport-handling routines for memory errors
 */

#include <cmd_mem.h>
#include <cmd_dimm.h>
#include <cmd_bank.h>
#include <cmd_page.h>
#include <cmd_cpu.h>
#ifdef sun4u
#include <cmd_dp.h>
#include <cmd_dp_page.h>
#endif
#include <cmd.h>

#include <strings.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/async.h>
#include <sys/errclassify.h>
#include <assert.h>

#ifdef sun4v
#include <cmd_hc_sun4v.h>
#endif /* sun4v */

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

/*
 * check if a dimm has n CEs with the same symbol-in-error
 */
static int
upos_thresh_check(cmd_dimm_t *dimm, uint16_t upos, uint32_t threshold)
{
	int i;
	cmd_mq_t *ip, *next;
	int count = 0;

	for (i = 0; i < CMD_MAX_CKWDS; i++) {
		for (ip = cmd_list_next(&dimm->mq_root[i]); ip != NULL;
		    ip = next) {
			next = cmd_list_next(ip);
			if (ip->mq_unit_position == upos) {
				count++;
				if (count >= threshold)
					return (1);
			}
		}
	}
	return (0);
}

/*
 * check if smaller number of retired pages > 1/16 of larger
 * number of retired pages
 */
static int
check_bad_rw_retired_pages(fmd_hdl_t *hdl, cmd_dimm_t *d1, cmd_dimm_t *d2)
{
	uint_t sret, lret;
	double ratio;
	uint_t d1_nretired, d2_nretired;

	sret = lret = 0;

	d1_nretired = d1->dimm_nretired;
	d2_nretired = d2->dimm_nretired;

	if (d1->dimm_bank != NULL)
		d1_nretired += d1->dimm_bank->bank_nretired;

	if (d2->dimm_bank != NULL)
		d2_nretired += d2->dimm_bank->bank_nretired;

	if (d2_nretired < d1_nretired) {
		sret = d2_nretired;
		lret = d1_nretired;
	} else if (d2_nretired > d1_nretired) {
		sret = d1_nretired;
		lret = d2_nretired;
	} else
		return (0);

	ratio = lret * CMD_PAGE_RATIO;

	if (sret > ratio) {
		fmd_hdl_debug(hdl, "sret=%d lret=%d ratio=%.3f\n",
		    sret, lret, ratio);
		return (1);
	}
	return (0);
}

/*
 * check bad rw between two DIMMs
 * the check succeeds if
 * - each DIMM has 4 CEs with the same symbol-in-error.
 * - the smaller number of retired pages > 1/16 larger number of retired pages
 */
static int
check_bad_rw_between_dimms(fmd_hdl_t *hdl, cmd_dimm_t *d1, cmd_dimm_t *d2,
    uint16_t *rupos)
{
	int i;
	cmd_mq_t *ip, *next;
	uint16_t upos;

	for (i = 0; i < CMD_MAX_CKWDS; i++) {
		for (ip = cmd_list_next(&d1->mq_root[i]); ip != NULL;
		    ip = next) {
			next = cmd_list_next(ip);
			upos = ip->mq_unit_position;
			if (upos_thresh_check(d1, upos, cmd.cmd_nupos)) {
				if (upos_thresh_check(d2, upos,
				    cmd.cmd_nupos)) {
					if (check_bad_rw_retired_pages(hdl,
					    d1, d2)) {
						*rupos = upos;
						return (1);
					}
				}
			}
		}
	}

	return (0);
}

static void
bad_reader_writer_check(fmd_hdl_t *hdl, cmd_dimm_t *ce_dimm, nvlist_t *det)
{
	cmd_dimm_t *d, *next;
	uint16_t upos;

	for (d = cmd_list_next(&cmd.cmd_dimms); d != NULL; d = next) {
		next = cmd_list_next(d);
		if (d == ce_dimm)
			continue;
		if (!cmd_same_datapath_dimms(ce_dimm, d))
			continue;
		if (check_bad_rw_between_dimms(hdl, ce_dimm, d, &upos)) {
			cmd_gen_datapath_fault(hdl, ce_dimm, d, upos, det);
			cmd_dimm_save_symbol_error(ce_dimm, upos);
			fmd_hdl_debug(hdl,
			    "check_bad_rw_dimms succeeded: %s %s",
			    ce_dimm->dimm_unum, d->dimm_unum);
			return;
		}
	}
}

/*
 * rule 5a checking. The check succeeds if
 * - nretired >= 512
 * - nretired >= 128 and (addr_hi - addr_low) / (nretired - 1) > 512KB
 */
static void
ce_thresh_check(fmd_hdl_t *hdl, cmd_dimm_t *dimm)
{
	nvlist_t *flt;
	fmd_case_t *cp;
	uint_t nret;
	uint64_t delta_addr = 0;

	if (dimm->dimm_flags & CMD_MEM_F_FAULTING)
		/* We've already complained about this DIMM */
		return;

	nret = dimm->dimm_nretired;
	if (dimm->dimm_bank != NULL)
		nret += dimm->dimm_bank->bank_nretired;

	if (nret < cmd.cmd_low_ce_thresh)
		return;

	if (dimm->dimm_phys_addr_hi >= dimm->dimm_phys_addr_low)
		delta_addr =
		    (dimm->dimm_phys_addr_hi - dimm->dimm_phys_addr_low) /
		    (nret - 1);

	if (nret >= cmd.cmd_hi_ce_thresh || delta_addr > CMD_MQ_512KB) {

		dimm->dimm_flags |= CMD_MEM_F_FAULTING;
		cmd_dimm_dirty(hdl, dimm);

		cp = fmd_case_open(hdl, NULL);
		flt = cmd_dimm_create_fault(hdl, dimm,
		    "fault.memory.dimm-page-retires-excessive", CMD_FLTMAXCONF);
		fmd_case_add_suspect(hdl, cp, flt);
		fmd_case_solve(hdl, cp);
		fmd_hdl_debug(hdl, "ce_thresh_check succeeded nretired %d\n",
		    nret);

	}
}

/*
 * rule 5b checking. The check succeeds if
 * more than 120 non-intermittent CEs are reported against one symbol
 * position of one afar in 72 hours.
 */
static void
mq_5b_check(fmd_hdl_t *hdl, cmd_dimm_t *dimm)
{
	nvlist_t *flt;
	fmd_case_t *cp;
	cmd_mq_t *ip, *next;
	int cw;

	for (cw = 0; cw < CMD_MAX_CKWDS; cw++) {
		for (ip = cmd_list_next(&dimm->mq_root[cw]);
		    ip != NULL; ip = next) {
			next = cmd_list_next(ip);
			if (ip->mq_dupce_count >= cmd.cmd_dupce) {
				cp = fmd_case_open(hdl, NULL);
				flt = cmd_dimm_create_fault(hdl, dimm,
				    "fault.memory.dimm-page-retires-excessive",
				    CMD_FLTMAXCONF);
				dimm->dimm_flags |= CMD_MEM_F_FAULTING;
				cmd_dimm_dirty(hdl, dimm);
				fmd_case_add_suspect(hdl, cp, flt);
				fmd_case_solve(hdl, cp);
				fmd_hdl_debug(hdl,
				    "mq_5b_check succeeded: duplicate CE=%d",
				    ip->mq_dupce_count);
				return;
			}
		}
	}
}

/*
 * delete the expired duplicate CE time stamps
 */
void
mq_prune_dup(fmd_hdl_t *hdl, cmd_mq_t *ip, uint64_t now)
{
	tstamp_t *tsp, *next;

	for (tsp = cmd_list_next(&ip->mq_dupce_tstamp); tsp != NULL;
	    tsp = next) {
		next = cmd_list_next(tsp);
		if (tsp->tstamp < now - CMD_MQ_TIMELIM) {
			cmd_list_delete(&ip->mq_dupce_tstamp, &tsp->ts_l);
			fmd_hdl_free(hdl, tsp, sizeof (tstamp_t));
			ip->mq_dupce_count--;
		}
	}
}

void
mq_update(fmd_hdl_t *hdl, fmd_event_t *ep, cmd_mq_t *ip, uint64_t now,
    uint32_t cpuid)
{
	tstamp_t *tsp;

	ip->mq_tstamp = now;
	ip->mq_cpuid = cpuid;
	ip->mq_ep = ep;

	if (fmd_serd_exists(hdl, ip->mq_serdnm))
		fmd_serd_destroy(hdl, ip->mq_serdnm);
	fmd_serd_create(hdl, ip->mq_serdnm, CMD_MQ_SERDN, CMD_MQ_SERDT);
	(void) fmd_serd_record(hdl, ip->mq_serdnm, ep);

	tsp = fmd_hdl_zalloc(hdl, sizeof (tstamp_t), FMD_SLEEP);
	tsp->tstamp = now;
	cmd_list_append(&ip->mq_dupce_tstamp, tsp);
	ip->mq_dupce_count++;
}

/* Create a fresh index block for MQSC CE correlation. */
cmd_mq_t *
mq_create(fmd_hdl_t *hdl, fmd_event_t *ep,
    uint64_t afar, uint16_t upos, uint64_t now, uint32_t cpuid)
{
	cmd_mq_t *cp;
	tstamp_t *tsp;
	uint16_t ckwd = (afar & 0x30) >> 4;

	cp = fmd_hdl_zalloc(hdl, sizeof (cmd_mq_t), FMD_SLEEP);
	cp->mq_tstamp = now;
	cp->mq_ckwd = ckwd;
	cp->mq_phys_addr = afar;
	cp->mq_unit_position = upos;
	cp->mq_ep = ep;
	cp->mq_serdnm =
	    cmd_mq_serdnm_create(hdl, "mq", afar, ckwd, upos);

	tsp = fmd_hdl_zalloc(hdl, sizeof (tstamp_t), FMD_SLEEP);
	tsp->tstamp = now;
	cmd_list_append(&cp->mq_dupce_tstamp, tsp);
	cp->mq_dupce_count = 1;
	cp->mq_cpuid = cpuid;

	/*
	 * Create SERD to keep this event from being removed
	 * by fmd which may not know there is an event pointer
	 * saved here. This SERD is *never* meant to fire.
	 * NOTE: wouldn't need to do this if there were an fmd
	 * api to 'hold' an event.
	 */
	if (fmd_serd_exists(hdl, cp->mq_serdnm)) {
		/* clean up dup */
		fmd_serd_destroy(hdl, cp->mq_serdnm);
	}
	fmd_serd_create(hdl, cp->mq_serdnm, CMD_MQ_SERDN, CMD_MQ_SERDT);
	(void) fmd_serd_record(hdl, cp->mq_serdnm, ep);

	return (cp);
}

/* Destroy MQSC tracking block as well as event tracking SERD. */

cmd_mq_t *
mq_destroy(fmd_hdl_t *hdl, cmd_list_t *lp, cmd_mq_t *ip)
{
	cmd_mq_t *jp = cmd_list_next(ip);
	tstamp_t *tsp, *next;

	if (ip->mq_serdnm != NULL) {
		if (fmd_serd_exists(hdl, ip->mq_serdnm))
			fmd_serd_destroy(hdl, ip->mq_serdnm);
		fmd_hdl_strfree(hdl, ip->mq_serdnm);
		ip->mq_serdnm = NULL;
	}

	for (tsp = cmd_list_next(&ip->mq_dupce_tstamp); tsp != NULL;
	    tsp = next) {
		next = cmd_list_next(tsp);
		cmd_list_delete(&ip->mq_dupce_tstamp, &tsp->ts_l);
		fmd_hdl_free(hdl, tsp, sizeof (tstamp_t));
	}

	cmd_list_delete(lp, &ip->mq_l);
	fmd_hdl_free(hdl, ip, sizeof (cmd_mq_t));

	return (jp);
}

/*
 * Add an index block for a new CE, sorted
 * a) by ascending unit position
 * b) order of arrival (~= time order)
 */

void
mq_add(fmd_hdl_t *hdl, cmd_dimm_t *dimm, fmd_event_t *ep,
    uint64_t afar, uint16_t synd, uint64_t now, uint32_t cpuid)
{
	cmd_mq_t *ip, *jp;
	int cw, unit_position;

	cw = (afar & 0x30) >> 4;		/* 0:3 */
	if ((unit_position = cmd_synd2upos(synd)) < 0)
		return;				/* not a CE */

	for (ip = cmd_list_next(&dimm->mq_root[cw]); ip != NULL; ) {
		if (ip->mq_unit_position > unit_position) {
			/* list is in unit position order */
			break;
		} else if (ip->mq_unit_position == unit_position &&
		    ip->mq_phys_addr == afar) {
			/*
			 * Found a duplicate cw, unit_position, and afar.
			 * update the mq_t with the new information
			 */
			mq_update(hdl, ep, ip, now, cpuid);
			return;
		} else {
			ip = cmd_list_next(ip);
		}
	}

	jp = mq_create(hdl, ep, afar, unit_position, now, cpuid);
	if (ip == NULL)
		cmd_list_append(&dimm->mq_root[cw], jp);
	else
		cmd_list_insert_before(&dimm->mq_root[cw], ip, jp);
}

/*
 * Prune the MQSC index lists (one for each checkword), by deleting
 * outdated index blocks from each list.
 */

void
mq_prune(fmd_hdl_t *hdl, cmd_dimm_t *dimm, uint64_t now)
{
	cmd_mq_t *ip;
	int cw;

	for (cw = 0; cw < CMD_MAX_CKWDS; cw++) {
		for (ip = cmd_list_next(&dimm->mq_root[cw]); ip != NULL; ) {
			if (ip->mq_tstamp < now - CMD_MQ_TIMELIM) {
				/*
				 * This event has timed out - delete the
				 * mq block as well as serd for the event.
				 */
				ip = mq_destroy(hdl, &dimm->mq_root[cw], ip);
			} else {
				/* tstamp < now - ce_t */
				mq_prune_dup(hdl, ip, now);
				ip = cmd_list_next(ip);
			}
		} /* per checkword */
	} /* cw = 0...3 */
}

/*
 * Check the MQSC index lists (one for each checkword) by making a
 * complete pass through each list, checking if the criteria for
 * Rule 4A has been met.  Rule 4A checking is done for each checkword.
 *
 * Rule 4A: fault a DIMM  "whenever Solaris reports two or more CEs from
 * two or more different physical addresses on each of two or more different
 * bit positions from the same DIMM within 72 hours of each other, and all
 * the addresses are in the same relative checkword (that is, the AFARs
 * are all the same modulo 64).  [Note: This means at least 4 CEs; two
 * from one bit position, with unique addresses, and two from another,
 * also with unique addresses, and the lower 6 bits of all the addresses
 * are the same."
 */

void
mq_check(fmd_hdl_t *hdl, cmd_dimm_t *dimm)
{
	int upos_pairs, curr_upos, cw, i, j;
	nvlist_t *flt;
	typedef struct upos_pair {
		int upos;
		cmd_mq_t *mq1;
		cmd_mq_t *mq2;
	} upos_pair_t;
	upos_pair_t upos_array[8]; /* max per cw = 2, * 4 cw's */
	cmd_mq_t *ip;

	/*
	 * Each upos_array[] member represents a pair of CEs for the same
	 * unit position (symbol) which on a sun4u is a bit, and on sun4v
	 * is a (4 bit) nibble.
	 * MQSC rule 4 requires pairs of CEs from the same symbol (same DIMM
	 * for rule 4A, and same DRAM for rule 4B) for a violation - this
	 * is why CE pairs are tracked.
	 */
	upos_pairs = 0;
	upos_array[0].mq1 = NULL;

	/* Loop through all checkwords */
	for (cw = 0; cw < CMD_MAX_CKWDS; cw++) {
		i = upos_pairs;
		curr_upos = -1;

		/*
		 * mq_root[] is an array of cumulative lists of CEs
		 * indexed by checkword where the list is in unit position
		 * order. Loop through checking for duplicate unit position
		 * entries (filled in at mq_create()).
		 * The upos_array[] is filled in each time a duplicate
		 * unit position is found; the first time through the loop
		 * of a unit position sets curr_upos but does not fill in
		 * upos_array[] until the second symbol is found.
		 */
		for (ip = cmd_list_next(&dimm->mq_root[cw]); ip != NULL;
		    ip = cmd_list_next(ip)) {
			if (curr_upos != ip->mq_unit_position) {
				/* Set initial current position */
				curr_upos = ip->mq_unit_position;
			} else if (i > upos_pairs &&
			    curr_upos == upos_array[i-1].upos) {
				/*
				 * Only keep track of CE pairs; skip
				 * triples, quads, etc...
				 */
				continue;
			} else if (upos_array[i].mq1 == NULL) {
				/*
				 * Have a pair, add to upos_array[].
				 */
				upos_array[i].upos = curr_upos;
				upos_array[i].mq1 = cmd_list_prev(ip);
				upos_array[i].mq2 = ip;
				upos_array[++i].mq1 = NULL;
			}
		}

		if (i - upos_pairs >= 2) {
			/* Rule 4A Violation. */
			flt = cmd_dimm_create_fault(hdl,
			    dimm, "fault.memory.dimm-ue-imminent",
			    CMD_FLTMAXCONF);
			for (j = upos_pairs; j < i; j++) {
				fmd_case_add_ereport(hdl,
				    dimm->dimm_case.cc_cp,
				    upos_array[j].mq1->mq_ep);
				fmd_case_add_ereport(hdl,
				    dimm->dimm_case.cc_cp,
				    upos_array[j].mq2->mq_ep);
			}
			dimm->dimm_flags |= CMD_MEM_F_FAULTING;
			cmd_dimm_dirty(hdl, dimm);
			fmd_case_add_suspect(hdl, dimm->dimm_case.cc_cp, flt);
			fmd_case_solve(hdl, dimm->dimm_case.cc_cp);
			return;
		}
		upos_pairs = i;
		assert(upos_pairs < 8);
	}
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
	uint64_t *now;
	uint_t nelem;
	uint32_t cpuid;
	nvlist_t *det;
	uint64_t addr;
	int skip_error = 0;

	if (afar_status != AFLT_STAT_VALID ||
	    synd_status != AFLT_STAT_VALID)
		return (CMD_EVD_UNUSED);

	if ((page = cmd_page_lookup(afar)) != NULL &&
	    page->page_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, page->page_case.cc_cp))
		return (CMD_EVD_REDUND);

#ifdef sun4u
	if (cmd_dp_error(hdl) || cmd_dp_fault(hdl, afar)) {
		CMD_STAT_BUMP(dp_ignored_ce);
		return (CMD_EVD_UNUSED);
	}
#endif /* sun4u */

	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (CMD_EVD_BAD);
	}

	if ((dimm = cmd_dimm_lookup(hdl, asru)) == NULL &&
	    (dimm = cmd_dimm_create(hdl, asru)) == NULL)
		return (CMD_EVD_UNUSED);

	if (dimm->dimm_case.cc_cp == NULL) {
		dimm->dimm_case.cc_cp = cmd_case_create(hdl,
		    &dimm->dimm_header, CMD_PTR_DIMM_CASE, &uuid);
	}

	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &det) != 0)
		return (CMD_EVD_BAD);

	/*
	 * Add to MQSC correlation lists all CEs which pass validity
	 * checks above.
	 * Add mq_t when there is no bad r/w or dimm fault.
	 * Always prune the expired mq_t.
	 */
	skip_error = cmd_dimm_check_symbol_error(dimm, synd);

	if (nvlist_lookup_uint64_array(nvl,
	    "__tod", &now, &nelem) == 0) {

		if (!skip_error || !(dimm->dimm_flags & CMD_MEM_F_FAULTING)) {
			if (nvlist_lookup_uint32(det, FM_FMRI_CPU_ID, &cpuid)
			    != 0)
				cpuid = ULONG_MAX;

			mq_add(hdl, dimm, ep, afar, synd, *now, cpuid);
		}

		mq_prune(hdl, dimm, *now);

		if (!skip_error)
			bad_reader_writer_check(hdl, dimm, det);

		if (!(dimm->dimm_flags & CMD_MEM_F_FAULTING)) {
			mq_check(hdl, dimm);
			mq_5b_check(hdl, dimm);
		}
	}

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
	case CE_DISP_STICKY:
		CMD_STAT_BUMP(ce_sticky);
		break;
	default:
		return (CMD_EVD_BAD);
	}

	if (cmd_dimm_check_symbol_error(dimm, synd))
		return (CMD_EVD_REDUND);

	if (page == NULL)
		page = cmd_page_create(hdl, asru, afar);

	if (page->page_case.cc_cp == NULL) {
		page->page_case.cc_cp = cmd_case_create(hdl,
		    &page->page_header, CMD_PTR_PAGE_CASE, &uuid);
	}

	switch (type) {
	case CE_DISP_POSS_PERS:
	case CE_DISP_PERS:
		fmd_hdl_debug(hdl, "adding %sPersistent event to CE serd "
		    "engine\n", type == CE_DISP_POSS_PERS ? "Possible-" : "");

		if (page->page_case.cc_serdnm == NULL) {
			page->page_case.cc_serdnm = cmd_page_serdnm_create(hdl,
			    "page", page->page_physbase);

			fmd_serd_create(hdl, page->page_case.cc_serdnm,
			    fmd_prop_get_int32(hdl, "ce_n"),
			    fmd_prop_get_int64(hdl, "ce_t"));
		}

		if (fmd_serd_record(hdl, page->page_case.cc_serdnm, ep) ==
		    FMD_B_FALSE)
				return (CMD_EVD_OK); /* engine hasn't fired */

		fmd_hdl_debug(hdl, "ce page serd fired\n");
		fmd_case_add_serd(hdl, page->page_case.cc_cp,
		    page->page_case.cc_serdnm);
		fmd_serd_reset(hdl, page->page_case.cc_serdnm);
		break;	/* to retire */

	case CE_DISP_LEAKY:
	case CE_DISP_STICKY:
		fmd_case_add_ereport(hdl, page->page_case.cc_cp, ep);
		break;	/* to retire */
	}

	if (page->page_flags & CMD_MEM_F_FAULTING ||
	    fmd_nvl_fmri_unusable(hdl, page->page_asru_nvl))
		return (CMD_EVD_OK);

	/*
	 * convert a unhashed address to hashed address
	 */
	cmd_to_hashed_addr(&addr, afar, class);

	if (afar > dimm->dimm_phys_addr_hi)
		dimm->dimm_phys_addr_hi = addr;

	if (afar < dimm->dimm_phys_addr_low)
		dimm->dimm_phys_addr_low = addr;

	dimm->dimm_nretired++;
	dimm->dimm_retstat.fmds_value.ui64++;
	cmd_dimm_dirty(hdl, dimm);

	cmd_page_fault(hdl, asru, cmd_dimm_fru(dimm), ep, afar);
	ce_thresh_check(hdl, dimm);

	return (CMD_EVD_OK);
}

/*
 * Solve a bank case with suspect "fault.memory.bank".  The caller must
 * have populated bank->bank_case.cc_cp and is also responsible for adding
 * associated ereport(s) to that case.
 */
void
cmd_bank_fault(fmd_hdl_t *hdl, cmd_bank_t *bank)
{
	fmd_case_t *cp = bank->bank_case.cc_cp;
	nvlist_t *flt;

	if (bank->bank_flags & CMD_MEM_F_FAULTING)
		return; /* Only complain once per bank */

	bank->bank_flags |= CMD_MEM_F_FAULTING;
	cmd_bank_dirty(hdl, bank);

#ifdef	sun4u
	flt = cmd_bank_create_fault(hdl, bank, "fault.memory.bank",
	    CMD_FLTMAXCONF);
	fmd_case_add_suspect(hdl, cp, flt);
#else /* sun4v */
	{
		cmd_bank_memb_t *d;

		/* create separate fault for each dimm in bank */

		for (d = cmd_list_next(&bank->bank_dimms);
		    d != NULL; d = cmd_list_next(d)) {
			flt = cmd_dimm_create_fault(hdl, d->bm_dimm,
			    "fault.memory.bank", CMD_FLTMAXCONF);
			fmd_case_add_suspect(hdl, cp, flt);
		}
	}
#endif /* sun4u */
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

#ifdef sun4u
	/*
	 * Note: Currently all sun4u processors using this code share
	 * L2 and L3 cache at CMD_CPU_LEVEL_CORE.
	 */
	cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class,
	    CMD_CPU_LEVEL_CORE);
#else /* sun4v */
	cpu = cmd_cpu_lookup_from_detector(hdl, nvl, class,
	    CMD_CPU_LEVEL_THREAD);
#endif /* sun4u */

	if (cpu == NULL) {
		fmd_hdl_debug(hdl, "cmd_ue_common: cpu not found\n");
		return (CMD_EVD_UNUSED);
	}

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

	if (synd_status != AFLT_STAT_VALID) {
		fmd_hdl_debug(hdl, "cmd_ue_common: syndrome not valid\n");
		return (CMD_EVD_UNUSED);
	}

	if (cmd_mem_synd_check(hdl, afar, afar_status, synd, synd_status,
	    cpu) == CMD_EVD_UNUSED)
		return (CMD_EVD_UNUSED);

	if (afar_status != AFLT_STAT_VALID)
		return (CMD_EVD_UNUSED);

	if ((page = cmd_page_lookup(afar)) != NULL &&
	    page->page_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, page->page_case.cc_cp))
		return (CMD_EVD_REDUND);

	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (CMD_EVD_BAD);
	}

	if ((bank = cmd_bank_lookup(hdl, asru)) == NULL &&
	    (bank = cmd_bank_create(hdl, asru)) == NULL)
		return (CMD_EVD_UNUSED);

#ifdef sun4v
	{
		nvlist_t *fmri;
		char **snarray;
		unsigned int i, n;

		/*
		 * 1: locate the array of serial numbers inside the bank asru.
		 * 2: for each serial #, lookup its mem: FMRI in libtopo
		 * 3: ensure that each DIMM's FMRI is on bank's dimmlist
		 */

		if (nvlist_lookup_string_array(asru,
		    FM_FMRI_MEM_SERIAL_ID, &snarray, &n) != 0)
			fmd_hdl_abort(hdl, "Cannot locate serial #s for bank");

		for (i = 0; i < n; i++) {
			fmri = cmd_find_dimm_by_sn(hdl, FM_FMRI_SCHEME_MEM,
			    snarray[i]);
			/*
			 * If dimm structure doesn't already exist for
			 * each dimm, create and link to bank.
			 */
			if (cmd_dimm_lookup(hdl, fmri) == NULL)
				(void) cmd_dimm_create(hdl, fmri);
			nvlist_free(fmri);
		}
	}
#endif /* sun4v */

	if (bank->bank_case.cc_cp == NULL) {
		const char *uuid;
		bank->bank_case.cc_cp = cmd_case_create(hdl, &bank->bank_header,
		    CMD_PTR_BANK_CASE, &uuid);
	}

#ifdef sun4u
	if (cmd_dp_error(hdl)) {
		CMD_STAT_BUMP(dp_deferred_ue);
		cmd_dp_page_defer(hdl, asru, ep, afar);
		return (CMD_EVD_OK);
	} else if (cmd_dp_fault(hdl, afar)) {
		CMD_STAT_BUMP(dp_ignored_ue);
		return (CMD_EVD_UNUSED);
	}
#endif /* sun4u */

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
