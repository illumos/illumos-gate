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
 */


/*
 * Ereport-handling routines for memory errors
 */

#include <gmem_mem.h>
#include <gmem_dimm.h>
#include <gmem_page.h>
#include <gmem.h>

#include <strings.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <sys/async.h>
#include <sys/errclassify.h>

struct ce_name2type {
	const char *name;
	ce_dispact_t type;
};

static ce_dispact_t
gmem_mem_name2type(const char *name)
{
	static const struct ce_name2type new[] = {
		{ "mem-unk",		CE_DISP_UNKNOWN },
		{ "mem-is",		CE_DISP_INTERMITTENT },
		{ "mem-cs",		CE_DISP_PERS },
		{ "mem-ss",		CE_DISP_STICKY },
		{ NULL }
	};
	const struct ce_name2type *names = &new[0];
	const struct ce_name2type *tp;

	for (tp = names; tp->name != NULL; tp++) {
		if (strcasecmp(name, tp->name) == 0)
			return (tp->type);
	}

	return (CE_DISP_UNKNOWN);
}

static void
ce_thresh_check(fmd_hdl_t *hdl, gmem_dimm_t *dimm)
{
	fmd_case_t *cp;
	nvlist_t *dflt, *rsc;
	uint_t nret;

	if (dimm->dimm_flags & GMEM_F_FAULTING) {
		/* We've already complained about this DIMM */
		return;
	}

	nret = dimm->dimm_nretired;
	/*
	 * fault the dimm if number retired page >= max_retired_pages
	 */
	if (nret < gmem.gm_max_retired_pages)
		return;

	dimm->dimm_flags |= GMEM_F_FAULTING;
	gmem_dimm_dirty(hdl, dimm);

	cp = fmd_case_open(hdl, NULL);
	rsc = gmem_find_dimm_rsc(hdl, dimm->dimm_serial);
	dflt = fmd_nvl_create_fault(hdl, GMEM_FAULT_DIMM_PAGES, GMEM_FLTMAXCONF,
	    NULL, gmem_dimm_fru(dimm), rsc);
	fmd_case_add_suspect(hdl, cp, dflt);
	fmd_case_solve(hdl, cp);
	if (rsc != NULL)
		nvlist_free(rsc);
}

/*
 * Create a fresh index block for MQSC CE correlation.
 */
gmem_mq_t *
mq_create(fmd_hdl_t *hdl, fmd_event_t *ep,
    uint64_t afar, uint16_t upos, uint16_t dram, uint16_t ckwd, uint64_t now)
{
	gmem_mq_t *cp;
	cp = fmd_hdl_zalloc(hdl, sizeof (gmem_mq_t), FMD_SLEEP);
	cp->mq_tstamp = now;
	cp->mq_ckwd = ckwd;
	cp->mq_phys_addr = afar;
	cp->mq_unit_position = upos;
	cp->mq_dram = (int16_t)dram;
	cp->mq_ep = ep;
	cp->mq_serdnm =
	    gmem_mq_serdnm_create(hdl, "mq", afar, ckwd, upos);

	/*
	 * Create SERD to keep this event from being removed
	 * by fmd which may not know there is an event pointer
	 * saved here. This SERD is *never* meant to fire.
	 */
	if (fmd_serd_exists(hdl, cp->mq_serdnm))
		fmd_serd_destroy(hdl, cp->mq_serdnm);

	fmd_serd_create(hdl, cp->mq_serdnm, GMEM_MQ_SERDN, GMEM_MQ_SERDT);
	(void) fmd_serd_record(hdl, cp->mq_serdnm, ep);

	return (cp);
}

gmem_mq_t *
mq_destroy(fmd_hdl_t *hdl, gmem_list_t *lp, gmem_mq_t *ip)
{
	gmem_mq_t *jp = gmem_list_next(ip);

	if (ip->mq_serdnm != NULL) {
		if (fmd_serd_exists(hdl, ip->mq_serdnm))
			fmd_serd_destroy(hdl, ip->mq_serdnm);
		fmd_hdl_strfree(hdl, ip->mq_serdnm);
		ip->mq_serdnm = NULL;
	}
	gmem_list_delete(lp, &ip->mq_l);
	fmd_hdl_free(hdl, ip, sizeof (gmem_mq_t));

	return (jp);
}


/*
 * Add an index block for a new CE, sorted
 * a) by ascending unit position
 * b) order of arrival (~= time order)
 */
void
mq_add(fmd_hdl_t *hdl, gmem_dimm_t *dimm, fmd_event_t *ep,
    uint64_t afar, uint16_t unit_position, uint16_t dram, uint16_t ckwd,
    uint64_t now)
{
	gmem_mq_t *ip, *jp;
	int cw = (int)ckwd;

	for (ip = gmem_list_next(&dimm->mq_root[cw]); ip != NULL; ) {
		if (ip->mq_unit_position > unit_position) {
			/* list is in unit position order */
			break;
		} else if (ip->mq_unit_position == unit_position &&
		    ip->mq_phys_addr == afar) {
			/*
			 * Found a duplicate cw, unit_position, and afar.
			 * Delete this node, to be superseded by the new
			 * node added below.
			 */
			ip = mq_destroy(hdl, &dimm->mq_root[cw], ip);
		} else {
			ip = gmem_list_next(ip);
		}
	}
	jp = mq_create(hdl, ep, afar, unit_position, dram, cw, now);
	if (ip == NULL)
		gmem_list_append(&dimm->mq_root[cw], jp);
	else
		gmem_list_insert_before(&dimm->mq_root[cw], ip, jp);
}

/*
 * Prune the MQSC index lists (one for each checkword), by deleting
 * outdated index blocks from each list.
 */

void
mq_prune(fmd_hdl_t *hdl, gmem_dimm_t *dimm, uint64_t now)
{
	gmem_mq_t *ip;
	int cw;

	for (cw = 0; cw < GMEM_MAX_CKWDS; cw++) {
		for (ip = gmem_list_next(&dimm->mq_root[cw]); ip != NULL; ) {
			if (ip->mq_tstamp < now - GMEM_MQ_TIMELIM) {
				/*
				 * This event has timed out - delete the
				 * mq block as well as serd for the event.
				 */
				ip = mq_destroy(hdl, &dimm->mq_root[cw], ip);
			} else {
				/* tstamp < now - ce_t */
				ip = gmem_list_next(ip);
			}
		} /* per checkword */
	} /* cw = 0...3 */
}

/*
 * Check the MQSC index lists (one for each checkword) by making a
 * complete pass through each list, checking if the criteria for either
 * Rule 4A or 4B have been met.  Rule 4A checking is done for each checkword;
 * 4B check is done at end.
 *
 * Rule 4A: fault a DIMM  "whenever Solaris reports two or more CEs from
 * two or more different physical addresses on each of two or more different
 * bit positions from the same DIMM within 72 hours of each other, and all
 * the addresses are in the same relative checkword (that is, the AFARs
 * are all the same modulo 64).  [Note: This means at least 4 CEs; two
 * from one bit position, with unique addresses, and two from another,
 * also with unique addresses, and the lower 6 bits of all the addresses
 * are the same."
 *
 * Rule 4B: fault a DIMM "whenever Solaris reports two or more CEs from
 * two or more different physical addresses on each of three or more
 * different outputs from the same DRAM within 72 hours of each other, as
 * long as the three outputs do not all correspond to the same relative
 * bit position in their respective checkwords.  [Note: This means at least
 * 6 CEs; two from one DRAM output signal, with unique addresses, two from
 * another output from the same DRAM, also with unique addresses, and two
 * more from yet another output from the same DRAM, again with unique
 * addresses, as long as the three outputs do not all correspond to the
 * same relative bit position in their respective checkwords.]"
 */

void
mq_check(fmd_hdl_t *hdl, gmem_dimm_t *dimm, int16_t dram)
{
	int upos_pairs, curr_upos, cw, i, j, k;
	nvlist_t *flt, *rsc;
	typedef struct upos_pair {
		int upos;
		int dram;
		gmem_mq_t *mq1;
		gmem_mq_t *mq2;
	} upos_pair_t;
	upos_pair_t upos_array[16]; /* max per cw = 2, * 8 cw's */
	gmem_mq_t *ip;

	/*
	 * Each upos_array[] member represents a pair of CEs for the same
	 * unit position (symbol) which is a 4 bit nibble.
	 * MQSC rule 4 requires pairs of CEs from the same symbol (same DIMM
	 * for rule 4A, and same DRAM for rule 4B) for a violation - this
	 * is why CE pairs are tracked.
	 */
	upos_pairs = 0;
	upos_array[0].mq1 = NULL;

	for (cw = 0; cw < GMEM_MAX_CKWDS; cw++) {
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
		for (ip = gmem_list_next(&dimm->mq_root[cw]); ip != NULL;
		    ip = gmem_list_next(ip)) {
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
				/* Have a pair. Add to upos_array[] */
				fmd_hdl_debug(hdl, "pair:upos=%d dram=%d",
				    curr_upos, ip->mq_dram);
				upos_array[i].upos = curr_upos;
				upos_array[i].dram = ip->mq_dram;
				upos_array[i].mq1 = gmem_list_prev(ip);
				upos_array[i].mq2 = ip;
				upos_array[++i].mq1 = NULL;
			}
		}
		if (i - upos_pairs >= 2) {
			/* Rule 4A violation */
			rsc = gmem_find_dimm_rsc(hdl, dimm->dimm_serial);
			flt = fmd_nvl_create_fault(hdl, GMEM_FAULT_DIMM_4A,
			    GMEM_FLTMAXCONF, NULL, gmem_dimm_fru(dimm), rsc);
			for (j = upos_pairs; j < i; j++) {
				fmd_case_add_ereport(hdl,
				    dimm->dimm_case.cc_cp,
				    upos_array[j].mq1->mq_ep);
				fmd_case_add_ereport(hdl,
				    dimm->dimm_case.cc_cp,
				    upos_array[j].mq2->mq_ep);
			}
			dimm->dimm_flags |= GMEM_F_FAULTING;
			gmem_dimm_dirty(hdl, dimm);
			fmd_case_add_suspect(hdl, dimm->dimm_case.cc_cp, flt);
			fmd_case_solve(hdl, dimm->dimm_case.cc_cp);
			if (rsc != NULL)
				nvlist_free(rsc);
			return;
		}
		upos_pairs = i;
		assert(upos_pairs < 16);
	}

	if ((dram == INVALID_DRAM) || (upos_pairs  < 3)) {
		fmd_hdl_debug(hdl, "Skip rules 4B upos_pairs=%d\n", upos_pairs);
		return; /* 4B violation needs at least 3 pairs */
	}

	/*
	 * Walk through checking for a rule 4B violation.
	 * Since we only keep track of two CE pairs per CW we'll only have
	 * a max of potentially 16 lements in the array. So as not to run
	 * off the end of the array, need to be careful with i and j indexes.
	 */
	for (i = 0; i < (upos_pairs - 2); i++) {
		for (j = i+1; j < (upos_pairs - 1); j++) {
			if (upos_array[i].dram != upos_array[j].dram)
				/*
				 * These two pairs aren't the same dram;
				 * continue looking for pairs that are.
				 */
				continue;
			for (k = j+1; k < upos_pairs; k++) {
				if (upos_array[j].dram != upos_array[k].dram)
					/*
					 * DRAMs must be the same for a rule
					 * 4B violation. Continue looking for
					 * pairs that have the same DRAMs.
					 */
					continue;
				if ((upos_array[i].upos !=
				    upos_array[j].upos) ||
				    (upos_array[j].upos !=
				    upos_array[k].upos)) {
					rsc = gmem_find_dimm_rsc(hdl,
					    dimm->dimm_serial);
					flt = fmd_nvl_create_fault(hdl,
					    GMEM_FAULT_DIMM_4B, GMEM_FLTMAXCONF,
					    NULL, gmem_dimm_fru(dimm), rsc);
					fmd_case_add_ereport(hdl,
					    dimm->dimm_case.cc_cp,
					    upos_array[i].mq1->mq_ep);
					fmd_case_add_ereport(hdl,
					    dimm->dimm_case.cc_cp,
					    upos_array[i].mq2->mq_ep);
					fmd_case_add_ereport(hdl,
					    dimm->dimm_case.cc_cp,
					    upos_array[j].mq1->mq_ep);
					fmd_case_add_ereport(hdl,
					    dimm->dimm_case.cc_cp,
					    upos_array[j].mq2->mq_ep);
					fmd_case_add_ereport(hdl,
					    dimm->dimm_case.cc_cp,
					    upos_array[k].mq1->mq_ep);
					fmd_case_add_ereport(hdl,
					    dimm->dimm_case.cc_cp,
					    upos_array[k].mq2->mq_ep);
					fmd_case_add_suspect(hdl,
					    dimm->dimm_case.cc_cp, flt);
					fmd_case_solve(hdl,
					    dimm->dimm_case.cc_cp);
					dimm->dimm_flags |= GMEM_F_FAULTING;
					gmem_dimm_dirty(hdl, dimm);
					if (rsc != NULL)
						nvlist_free(rsc);
					return;
				}
			}
		}
	}
}

/*ARGSUSED*/
gmem_evdisp_t
gmem_ce(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	uint16_t symbol_pos, erpt_dram, cw;
	uint64_t phyaddr, offset;
	uint32_t filter_ratio = 0;
	int16_t dram;
	gmem_dimm_t *dimm;
	gmem_page_t *page;
	nvlist_t *fru = NULL;
	nvlist_t *topo_rsc = NULL;
	nvlist_t *rsrc;
	const char *uuid;
	ce_dispact_t type;
	boolean_t diagnose;
	char *sn;
	int err, rc;

	err = nvlist_lookup_boolean_value(nvl, GMEM_ERPT_PAYLOAD_DIAGNOSE,
	    &diagnose);
	if (err != 0 || diagnose == 0)
		return (GMEM_EVD_UNUSED);

	if ((nvlist_lookup_uint64(nvl, GMEM_ERPT_PAYLOAD_PHYSADDR,
	    &phyaddr) != 0) ||
	    (nvlist_lookup_uint64(nvl, GMEM_ERPT_PAYLOAD_OFFSET,
	    &offset) != 0)) {
		fmd_hdl_debug(hdl, "Can't get page phyaddr or offset");
		return (GMEM_EVD_BAD);
	}

	fmd_hdl_debug(hdl, "phyaddr %llx offset %llx", phyaddr, offset);

	if ((page = gmem_page_lookup(phyaddr)) != NULL &&
	    page->page_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, page->page_case.cc_cp))
		return (GMEM_EVD_REDUND);

	if (nvlist_lookup_nvlist(nvl, GMEM_ERPT_PAYLOAD_RESOURCE,
	    &rsrc) != 0 ||
	    nvlist_lookup_string(rsrc, FM_FMRI_HC_SERIAL_ID, &sn) != 0) {
		fmd_hdl_debug(hdl, "Can't get dimm serial\n");
		return (GMEM_EVD_BAD);
	}

	fmd_hdl_debug(hdl, "serial %s", sn);

	/*
	 * Find dimm fru by serial number.
	 */
	fru = gmem_find_dimm_fru(hdl, sn);

	if (fru == NULL) {
		fmd_hdl_debug(hdl, "Dimm is not present\n");
		return (GMEM_EVD_UNUSED);
	}

	if ((dimm = gmem_dimm_lookup(hdl, fru)) == NULL &&
	    (dimm = gmem_dimm_create(hdl, fru)) == NULL) {
		nvlist_free(fru);
		return (GMEM_EVD_UNUSED);
	}

	if (dimm->dimm_case.cc_cp == NULL) {
		dimm->dimm_case.cc_cp = gmem_case_create(hdl,
		    &dimm->dimm_header, GMEM_PTR_DIMM_CASE, &uuid);
	}

	/*
	 * Add to MQSC correlation lists all CEs which pass validity
	 * checks above. If there is no symbol_pos & relative ckword
	 * in the ereport, skip rules 4A & 4B checking.
	 * If there is no dram in the ereport, skip the rule 4B checking.
	 */
	if (nvlist_lookup_uint16(nvl, GMEM_ERPT_PAYLOAD_DRAM, &erpt_dram) != 0)
		dram = INVALID_DRAM;
	else
		dram = (int16_t)erpt_dram;

	err = nvlist_lookup_uint16(nvl, GMEM_ERPT_PAYLOAD_SYMBOLPOS,
	    &symbol_pos);
	err |= nvlist_lookup_uint16(nvl, GMEM_ERPT_PAYLOAD_CKW, &cw);

	if (err == 0)
		fmd_hdl_debug(hdl, "symbol_pos=%d dram=%d cw=%d",
		    symbol_pos, dram, cw);

	if (!(dimm->dimm_flags & GMEM_F_FAULTING) && (err == 0)) {
		uint64_t *now;
		uint_t nelem;
		if (nvlist_lookup_uint64_array(nvl,
		    "__tod", &now, &nelem) == 0) {
			mq_add(hdl, dimm, ep, phyaddr, symbol_pos, dram,
			    cw, *now);
			mq_prune(hdl, dimm, *now);
			mq_check(hdl, dimm, dram);
		}
	}

	type = gmem_mem_name2type(strstr(class, "mem"));

	switch (type) {
	case CE_DISP_UNKNOWN:
		GMEM_STAT_BUMP(ce_unknown);
		nvlist_free(fru);
		return (GMEM_EVD_UNUSED);
	case CE_DISP_INTERMITTENT:
		GMEM_STAT_BUMP(ce_interm);
		nvlist_free(fru);
		return (GMEM_EVD_UNUSED);
	case CE_DISP_PERS:
		GMEM_STAT_BUMP(ce_clearable_persis);
		break;
	case CE_DISP_STICKY:
		GMEM_STAT_BUMP(ce_sticky);
		break;
	default:
		nvlist_free(fru);
		return (GMEM_EVD_BAD);
	}

	if (page == NULL) {
		page = gmem_page_create(hdl, fru, phyaddr, offset);
		if (page == NULL) {
			nvlist_free(fru);
			return (GMEM_EVD_UNUSED);
		}
	}

	nvlist_free(fru);

	if (page->page_case.cc_cp == NULL) {
		page->page_case.cc_cp = gmem_case_create(hdl,
		    &page->page_header, GMEM_PTR_PAGE_CASE, &uuid);
	}

	switch (type) {
	case CE_DISP_PERS:
		fmd_hdl_debug(hdl, "adding persistent event to CE serd");
		if (page->page_case.cc_serdnm == NULL)
			gmem_page_serd_create(hdl, page, nvl);

		filter_ratio = gmem_get_serd_filter_ratio(nvl);

		fmd_hdl_debug(hdl, "filter_ratio %d\n", filter_ratio);

		if (gmem_serd_record(hdl, page->page_case.cc_serdnm,
		    filter_ratio, ep) == FMD_B_FALSE) {
				return (GMEM_EVD_OK); /* engine hasn't fired */
		}

		fmd_hdl_debug(hdl, "ce page serd fired\n");
		fmd_case_add_serd(hdl, page->page_case.cc_cp,
		    page->page_case.cc_serdnm);
		fmd_serd_reset(hdl, page->page_case.cc_serdnm);
		break;	/* to retire */

	case CE_DISP_STICKY:
		fmd_case_add_ereport(hdl, page->page_case.cc_cp, ep);
		break;	/* to retire */
	}


	topo_rsc = gmem_find_dimm_rsc(hdl, dimm->dimm_serial);
	rc = gmem_page_fault(hdl, gmem_dimm_fru(dimm), topo_rsc,
	    ep, phyaddr, offset);

	if (rc) {
		dimm->dimm_nretired++;
		dimm->dimm_retstat.fmds_value.ui64++;
		gmem_dimm_dirty(hdl, dimm);
		ce_thresh_check(hdl, dimm);
	}
	return (GMEM_EVD_OK);
}

void
gmem_dimm_close(fmd_hdl_t *hdl, void *arg)
{
	gmem_dimm_destroy(hdl, arg);
}
