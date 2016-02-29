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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
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

#define	OFFBIT  	0xFFFFFFFFFFFC07FFULL
#define	BIT28_32	0x00000001F0000000ULL
#define	BIT13_17	0x000000000003E000ULL
#define	BIT18_19	0x00000000000C0000ULL
#define	BIT11_12	0x0000000000001800ULL

struct ce_name2type {
	const char *name;
	ce_dispact_t type;
};

nvlist_t *fru_nvl;

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

/*ARGSUSED*/
static int
find_fault_fru(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	nvlist_t *nvl = (nvlist_t *)arg;
	nvlist_t *rsc = NULL, *fru = NULL;
	nvlist_t **hcl, **topo_hcl;
	uint_t n1, n2;
	char *name, *name1, *name2;
	char *id1, *id2;
	int err, i;

	if (topo_node_resource(node, &rsc, &err) < 0)
		return (TOPO_WALK_NEXT);

	err = nvlist_lookup_nvlist_array(rsc, FM_FMRI_HC_LIST, &topo_hcl, &n1);

	if (err != 0) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}

	(void) nvlist_lookup_string(topo_hcl[n1 - 1], FM_FMRI_HC_NAME, &name);
	if (strcmp(name, "chip") != 0) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}

	(void) nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcl, &n2);

	if (n1 != n2) {
		nvlist_free(rsc);
		return (TOPO_WALK_NEXT);
	}

	for (i = 0; i < n1; i++) {
		(void) nvlist_lookup_string(topo_hcl[i], FM_FMRI_HC_NAME,
		    &name1);
		(void) nvlist_lookup_string(topo_hcl[i], FM_FMRI_HC_ID, &id1);
		(void) nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &name2);
		(void) nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &id2);
		if (strcmp(name1, name2) != 0 || strcmp(id1, id2) != 0) {
			nvlist_free(rsc);
			return (TOPO_WALK_NEXT);
		}
	}

	(void) topo_node_fru(node, &fru, NULL, &err);
	if (fru != NULL) {
		(void) nvlist_dup(fru, &fru_nvl, NV_UNIQUE_NAME);
		nvlist_free(fru);
	}
	nvlist_free(rsc);
	return (TOPO_WALK_TERMINATE);
}

nvlist_t *
gmem_find_fault_fru(fmd_hdl_t *hdl, nvlist_t *nvl) {
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;
	fru_nvl = NULL;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return (NULL);

	if ((twp = topo_walk_init(thp, FM_FMRI_SCHEME_HC,
	    find_fault_fru, nvl, &err)) == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return (NULL);
	}

	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);
	return (fru_nvl);
}

/*
 * fault the FRU of the common detector between two DIMMs
 */
void
gmem_gen_datapath_fault(fmd_hdl_t *hdl, nvlist_t *det)
{
	char *name, *id;
	nvlist_t **hcl1, **hcl;
	uint_t n;
	int i, j;
	fmd_case_t *cp;
	nvlist_t *fltlist, *rsrc;
	nvlist_t *fru = NULL;

	if (nvlist_lookup_nvlist_array(det, FM_FMRI_HC_LIST, &hcl1, &n) < 0)
		return;

	for (i = 0; i < n; i++) {
		(void) nvlist_lookup_string(hcl1[i], FM_FMRI_HC_NAME, &name);
		if (strcmp(name, "chip") == 0)
			break;
	}

	n = i + 1;
	hcl = fmd_hdl_zalloc(hdl, sizeof (nvlist_t *) * n, FMD_SLEEP);
	if (hcl == NULL)
		return;

	for (i = 0; i < n; i++) {
		(void) nvlist_alloc(&hcl[i],
		    NV_UNIQUE_NAME|NV_UNIQUE_NAME_TYPE, 0);
	}

	for (i = 0, j = 0; i < n; i++) {
		(void) nvlist_lookup_string(hcl1[i], FM_FMRI_HC_NAME, &name);
		(void) nvlist_lookup_string(hcl1[i], FM_FMRI_HC_ID, &id);
		(void) nvlist_add_string(hcl[j], FM_FMRI_HC_NAME, name);
		(void) nvlist_add_string(hcl[j], FM_FMRI_HC_ID, id);
		j++;
		if (strcmp(name, "chip") == 0)
			break;
	}

	if (nvlist_alloc(&rsrc,  NV_UNIQUE_NAME|NV_UNIQUE_NAME_TYPE, 0) != 0) {
		for (i = 0; i < n; i++) {
			nvlist_free(hcl[i]);
		}
		fmd_hdl_free(hdl, hcl, sizeof (nvlist_t *) * n);
	}

	if (nvlist_add_uint8(rsrc, FM_VERSION, FM_HC_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(rsrc, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC) != 0 ||
	    nvlist_add_string(rsrc, FM_FMRI_HC_ROOT, "") != 0 ||
	    nvlist_add_uint32(rsrc, FM_FMRI_HC_LIST_SZ, n) != 0 ||
	    nvlist_add_nvlist_array(rsrc, FM_FMRI_HC_LIST, hcl, n) != 0) {
		for (i = 0; i < n; i++) {
			nvlist_free(hcl[i]);
		}
		fmd_hdl_free(hdl, hcl, sizeof (nvlist_t *) * n);
		nvlist_free(rsrc);
	}

	fru = gmem_find_fault_fru(hdl, rsrc);
	if (fru != NULL) {
		cp = fmd_case_open(hdl, NULL);
		fltlist = fmd_nvl_create_fault(hdl, "fault.memory.datapath",
		    100, fru, fru, fru);
		fmd_case_add_suspect(hdl, cp, fltlist);
		fmd_case_solve(hdl, cp);
		nvlist_free(fru);
	}

	for (i = 0; i < n; i++) {
		nvlist_free(hcl[i]);
	}

	fmd_hdl_free(hdl, hcl, sizeof (nvlist_t *) * n);
	nvlist_free(rsrc);
}

/*
 * formula to conver an unhashed address to hashed address
 * PA[17:11] = (PA[32:28] xor PA[17:13]) :: ((PA[19:18] xor PA[12:11])
 */
static void
gmem_to_hashed_addr(uint64_t *addr, uint64_t afar)
{

	*addr = (afar & OFFBIT) | ((afar & BIT28_32) >> 15) ^ (afar & BIT13_17)
	    | ((afar & BIT18_19) >> 7) ^ (afar & BIT11_12);
}

/*
 * check if a dimm has n CEs that have the same symbol-in-error
 */
int
upos_thresh_check(gmem_dimm_t *dimm, uint16_t upos, uint32_t threshold)
{
	int i;
	gmem_mq_t *ip, *next;
	int count = 0;

	for (i = 0; i < GMEM_MAX_CKWDS; i++) {
		for (ip = gmem_list_next(&dimm->mq_root[i]); ip != NULL;
		    ip = next) {
			next = gmem_list_next(ip);
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
 * check if smaller number of retired pages > 1/16 of larger number of
 * retired pages
 */
int
check_bad_rw_retired_pages(fmd_hdl_t *hdl, gmem_dimm_t *d1, gmem_dimm_t *d2)
{
	uint_t sret, lret;
	double ratio;

	sret = lret = 0;

	if (d2->dimm_nretired < d1->dimm_nretired) {
		sret = d2->dimm_nretired;
		lret = d1->dimm_nretired;
	} else if (d2->dimm_nretired > d1->dimm_nretired) {
		sret = d1->dimm_nretired;
		lret = d2->dimm_nretired;
	} else
		return (0);

	ratio = lret * GMEM_MQ_RATIO;

	if (sret > ratio) {
		fmd_hdl_debug(hdl, "sret=%d lret=%d ratio=%.3f",
		    sret, lret, ratio);
		return (1);
	}
	return (0);
}

/*
 * check bad rw on any two DIMMs. The check succeeds if
 * - each DIMM has a n CEs which have the same symbol-in-error,
 * - the smaller number of retired pages > 1/16 larger number of retired pages
 */
static int
check_bad_rw_between_dimms(fmd_hdl_t *hdl, gmem_dimm_t *d1, gmem_dimm_t *d2,
    uint16_t *rupos)
{
	int i;
	gmem_mq_t *ip, *next;
	uint16_t upos;

	for (i = 0; i < GMEM_MAX_CKWDS; i++) {
		for (ip = gmem_list_next(&d1->mq_root[i]); ip != NULL;
		    ip = next) {
			next = gmem_list_next(ip);
			upos = ip->mq_unit_position;
			if (upos_thresh_check(d1, upos, gmem.gm_nupos)) {
				if (upos_thresh_check(d2, upos,
				    gmem.gm_nupos)) {
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
bad_reader_writer_check(fmd_hdl_t *hdl, nvlist_t *det, gmem_dimm_t *ce_dimm)
{
	gmem_dimm_t *d, *next;
	uint16_t upos;

	for (d = gmem_list_next(&gmem.gm_dimms); d != NULL; d = next) {
		next = gmem_list_next(d);
		if (d == ce_dimm)
			continue;
		if (!gmem_same_datapath_dimms(hdl, ce_dimm, d))
			continue;
		if (check_bad_rw_between_dimms(hdl, ce_dimm, d, &upos)) {
			gmem_gen_datapath_fault(hdl, det);
			gmem_save_symbol_error(hdl, ce_dimm, upos);
			fmd_hdl_debug(hdl,
			    "check_bad_rw_dimms succeeded: %s %s\n",
			    ce_dimm->dimm_serial, d->dimm_serial);
			return;
		}
	}
}

/*
 * rule 5a checking. The check succeeds if
 * - nretired >= 512
 * - nretired >= 128 and (addr_hi - addr_low) / (nretired -1 ) > 512KB
 */
static void
ce_thresh_check(fmd_hdl_t *hdl, gmem_dimm_t *dimm)
{
	nvlist_t *flt, *rsrc;
	fmd_case_t *cp;
	uint_t nret;
	uint64_t delta_addr = 0;

	if (dimm->dimm_flags & GMEM_F_FAULTING)
		return;

	nret = dimm->dimm_nretired;

	if (nret < gmem.gm_low_ce_thresh)
		return;

	if (dimm->dimm_phys_addr_hi >= dimm->dimm_phys_addr_low)
		delta_addr =
		    (dimm->dimm_phys_addr_hi - dimm->dimm_phys_addr_low) /
		    (nret - 1);

	if (nret >= gmem.gm_max_retired_pages || delta_addr > GMEM_MQ_512KB) {

		fmd_hdl_debug(hdl, "ce_thresh_check succeeded nret=%d", nret);
		dimm->dimm_flags |= GMEM_F_FAULTING;
		gmem_dimm_dirty(hdl, dimm);

		cp = fmd_case_open(hdl, NULL);
		rsrc = gmem_find_dimm_rsc(hdl, dimm->dimm_serial);
		flt = fmd_nvl_create_fault(hdl, GMEM_FAULT_DIMM_PAGES,
		    GMEM_FLTMAXCONF, NULL, gmem_dimm_fru(dimm), rsrc);
		fmd_case_add_suspect(hdl, cp, flt);
		fmd_case_solve(hdl, cp);
		nvlist_free(rsrc);
	}
}

/*
 * rule 5b checking. The check succeeds if more than 120
 * non-intermittent CEs are reported against one symbol
 * position of one afar in 72 hours
 */
static void
mq_5b_check(fmd_hdl_t *hdl, gmem_dimm_t *dimm)
{
	nvlist_t *flt, *rsrc;
	fmd_case_t *cp;
	gmem_mq_t *ip, *next;
	int cw;

	for (cw = 0; cw < GMEM_MAX_CKWDS; cw++) {
		for (ip = gmem_list_next(&dimm->mq_root[cw]);
		    ip != NULL; ip = next) {
			next = gmem_list_next(ip);
			if (ip->mq_dupce_count >= gmem.gm_dupce) {
				fmd_hdl_debug(hdl,
				    "mq_5b_check succeeded: duplicate CE=%d",
				    ip->mq_dupce_count);
				cp = fmd_case_open(hdl, NULL);
				rsrc = gmem_find_dimm_rsc(hdl,
				    dimm->dimm_serial);
				flt = fmd_nvl_create_fault(hdl,
				    GMEM_FAULT_DIMM_PAGES, GMEM_FLTMAXCONF,
				    NULL, gmem_dimm_fru(dimm), rsrc);
				dimm->dimm_flags |= GMEM_F_FAULTING;
				gmem_dimm_dirty(hdl, dimm);
				fmd_case_add_suspect(hdl, cp, flt);
				fmd_case_solve(hdl, cp);
				nvlist_free(rsrc);
				return;
			}
		}
	}
}

/*
 * delete the expired duplicate CE time stamps
 */
static void
mq_prune_dup(fmd_hdl_t *hdl, gmem_mq_t *ip, uint64_t now)
{
	tstamp_t *tsp, *next;

	for (tsp = gmem_list_next(&ip->mq_dupce_tstamp); tsp != NULL;
	    tsp = next) {
		next = gmem_list_next(tsp);
		if (tsp->tstamp < now - GMEM_MQ_TIMELIM) {
			gmem_list_delete(&ip->mq_dupce_tstamp, &tsp->ts_l);
			fmd_hdl_free(hdl, tsp, sizeof (tstamp_t));
			ip->mq_dupce_count--;
		}
	}
}

static void
mq_update(fmd_hdl_t *hdl, fmd_event_t *ep, gmem_mq_t *ip, uint64_t now)
{
	tstamp_t *tsp;

	ip->mq_tstamp = now;
	ip->mq_ep = ep;
	if (fmd_serd_exists(hdl, ip->mq_serdnm))
		fmd_serd_destroy(hdl, ip->mq_serdnm);

	fmd_serd_create(hdl, ip->mq_serdnm, GMEM_MQ_SERDN, GMEM_MQ_SERDT);
	(void) fmd_serd_record(hdl, ip->mq_serdnm, ep);

	tsp = fmd_hdl_zalloc(hdl, sizeof (tstamp_t), FMD_SLEEP);
	tsp->tstamp = now;
	gmem_list_append(&ip->mq_dupce_tstamp, tsp);
	ip->mq_dupce_count++;
}

/*
 * Create a fresh index block for MQSC CE correlation.
 */
gmem_mq_t *
mq_create(fmd_hdl_t *hdl, fmd_event_t *ep,
    uint64_t afar, uint16_t upos, uint16_t ckwd, uint64_t now)
{
	gmem_mq_t *cp;
	tstamp_t *tsp;

	cp = fmd_hdl_zalloc(hdl, sizeof (gmem_mq_t), FMD_SLEEP);
	cp->mq_tstamp = now;
	cp->mq_ckwd = ckwd;
	cp->mq_phys_addr = afar;
	cp->mq_unit_position = upos;
	cp->mq_ep = ep;
	cp->mq_serdnm =
	    gmem_mq_serdnm_create(hdl, "mq", afar, ckwd, upos);

	tsp = fmd_hdl_zalloc(hdl, sizeof (tstamp_t), FMD_SLEEP);
	tsp->tstamp = now;
	gmem_list_append(&cp->mq_dupce_tstamp, tsp);
	cp->mq_dupce_count = 1;

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
	tstamp_t *tsp, *next;


	if (ip->mq_serdnm != NULL) {
		if (fmd_serd_exists(hdl, ip->mq_serdnm))
			fmd_serd_destroy(hdl, ip->mq_serdnm);
		fmd_hdl_strfree(hdl, ip->mq_serdnm);
		ip->mq_serdnm = NULL;
	}

	for (tsp = gmem_list_next(&ip->mq_dupce_tstamp); tsp != NULL;
	    tsp = next) {
		next = gmem_list_next(tsp);
		gmem_list_delete(&ip->mq_dupce_tstamp, &tsp->ts_l);
		fmd_hdl_free(hdl, tsp, sizeof (tstamp_t));
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
    uint64_t afar, uint16_t unit_position, uint16_t ckwd,
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
			 * update the mq_t structure
			 */
			mq_update(hdl, ep, ip, now);
			return;
		} else {
			ip = gmem_list_next(ip);
		}
	}

	jp = mq_create(hdl, ep, afar, unit_position, cw, now);
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
				mq_prune_dup(hdl, ip, now);
				/* tstamp < now - ce_t */
				ip = gmem_list_next(ip);
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
mq_check(fmd_hdl_t *hdl, gmem_dimm_t *dimm)
{
	int upos_pairs, curr_upos, cw, i, j;
	nvlist_t *flt, *rsc;
	typedef struct upos_pair {
		int upos;
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
				fmd_hdl_debug(hdl, "pair:upos=%d",
				    curr_upos);
				upos_array[i].upos = curr_upos;
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
			nvlist_free(rsc);
			return;
		}
		upos_pairs = i;
		assert(upos_pairs < 16);
	}
}

/*ARGSUSED*/
gmem_evdisp_t
gmem_ce(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	uint16_t symbol_pos, cw;
	uint64_t phyaddr, offset, addr;
	uint32_t filter_ratio = 0;
	gmem_dimm_t *dimm;
	gmem_page_t *page;
	nvlist_t *fru = NULL;
	nvlist_t *topo_rsc = NULL;
	nvlist_t *rsrc, *det;
	const char *uuid;
	ce_dispact_t type;
	boolean_t diagnose;
	char *sn;
	int err, rc;
	uint64_t *now;
	uint_t nelem;
	int skip_error = 0;

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

	if (nvlist_lookup_nvlist(nvl, GMEM_ERPT_PAYLOAD_DETECTOR, &det) != 0)
		return (GMEM_EVD_BAD);

	/*
	 * Find dimm fru by serial number.
	 */
	fru = gmem_find_dimm_fru(hdl, sn);

	if (fru == NULL) {
		fmd_hdl_debug(hdl, "Dimm is not present\n");
		return (GMEM_EVD_UNUSED);
	}

	if ((dimm = gmem_dimm_lookup(hdl, fru)) == NULL &&
	    (dimm = gmem_dimm_create(hdl, fru, det)) == NULL) {
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
	 * in the ereport, skip rule 4A checking.
	 */

	err = nvlist_lookup_uint16(nvl, GMEM_ERPT_PAYLOAD_SYMBOLPOS,
	    &symbol_pos);
	err |= nvlist_lookup_uint16(nvl, GMEM_ERPT_PAYLOAD_CKW, &cw);

	if (err == 0) {
		fmd_hdl_debug(hdl, "symbol_pos=%d cw=%d", symbol_pos, cw);

		if (nvlist_lookup_uint64_array(nvl,
		    "__tod", &now, &nelem) == 0) {
			skip_error = gmem_check_symbol_error(hdl, dimm,
			    symbol_pos);

			if (!skip_error ||
			    !(dimm->dimm_flags & GMEM_F_FAULTING))
				mq_add(hdl, dimm, ep, phyaddr, symbol_pos,
				    cw, *now);

			mq_prune(hdl, dimm, *now);

			if (!skip_error)
				bad_reader_writer_check(hdl, det, dimm);
			if (!(dimm->dimm_flags & GMEM_F_FAULTING)) {
				mq_check(hdl, dimm);
				mq_5b_check(hdl, dimm);
			}
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

	if (gmem_check_symbol_error(hdl, dimm, symbol_pos)) {
		nvlist_free(fru);
		return (GMEM_EVD_REDUND);
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
		gmem_to_hashed_addr(&addr, phyaddr);

		if (addr > dimm->dimm_phys_addr_hi)
			dimm->dimm_phys_addr_hi = addr;
		if (addr < dimm->dimm_phys_addr_low)
			dimm->dimm_phys_addr_low = addr;

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
