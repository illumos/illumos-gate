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

#include <string.h>
#include <umem.h>
#include <sys/mdesc.h>
#include <sys/fm/ldom.h>

#include <mem_mdesc.h>

void *
mem_alloc(size_t size)
{
	return (umem_alloc(size, UMEM_DEFAULT));
}

void
mem_free(void *data, size_t size)
{
	umem_free(data, size);
}

#define	MEM_BYTES_PER_CACHELINE	64

static void
mdesc_init_n1(topo_mod_t *mod, md_t *mdp, mde_cookie_t *listp,
    md_mem_info_t *mem)
{
	int idx, mdesc_dimm_count;
	mem_dimm_map_t *dm, *d;
	uint64_t sysmem_size, i;
	int dimms, min_chan, max_chan, min_rank, max_rank;
	int chan, rank, dimm, chans, chan_step;
	uint64_t mask, chan_mask, chan_value;
	uint64_t rank_mask, rank_value;
	char *unum, *serial, *part;
	mem_seg_map_t *seg;
	mem_bank_map_t *bm;
	mem_grp_t *mg;
	char s[20];

	mdesc_dimm_count = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE, md_find_name(mdp, "dimm_data"),
	    md_find_name(mdp, "fwd"), listp);

	for (idx = 0; idx < mdesc_dimm_count; idx++) {

		if (md_get_prop_str(mdp, listp[idx], "nac", &unum) < 0)
			unum = "";
		if (md_get_prop_str(mdp, listp[idx], "serial#",
		    &serial) < 0)
			serial = "";
		if (md_get_prop_str(mdp, listp[idx], "part#",
		    &part) < 0)
			part = "";

		dm = topo_mod_alloc(mod, sizeof (mem_dimm_map_t));
		dm->dm_label = topo_mod_strdup(mod, unum);
		dm->dm_serid = topo_mod_strdup(mod, serial);
		dm->dm_part = topo_mod_strdup(mod, part);

		dm->dm_next = mem->mem_dm;
		mem->mem_dm = dm;
	}

	/* N1 (MD) specific segment initialization */

	dimms = 0;
	min_chan = 99;
	max_chan = -1;
	min_rank = 99;
	max_rank = -1;

	for (d = mem->mem_dm; d != NULL; d = d->dm_next) {
		if (sscanf(d->dm_label, "MB/CMP0/CH%d/R%d/D%d",
		    &chan, &rank, &dimm) != 3) /* didn't scan all 3 values */
			return;
		min_chan = MIN(min_chan, chan);
		max_chan = MAX(max_chan, chan);
		min_rank = MIN(min_rank, rank);
		max_rank = MAX(max_rank, rank);
		dimms++;
	}

	mdesc_dimm_count = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "mblock"),
	    md_find_name(mdp, "fwd"),
	    listp);
	sysmem_size = 0;
	for (idx = 0; idx < mdesc_dimm_count; idx++) {
		uint64_t size = 0;
		if (md_get_prop_val(mdp, listp[idx], "size", &size) == 0)
			sysmem_size += size;
	}

	for (i = 1 << 30; i < sysmem_size; i = i << 1)
		;
	if (max_rank > min_rank) {
		chans = dimms/4;
		rank_mask = i >> 1;
	} else {
		chans = dimms/2;
		rank_mask = 0;
	}

	chan_mask = (uint64_t)((chans - 1) * MEM_BYTES_PER_CACHELINE);
	mask = rank_mask | chan_mask;

	if (chans > 2)
		chan_step = 1;
	else
		chan_step = max_chan - min_chan;

	seg = topo_mod_zalloc(mod, sizeof (mem_seg_map_t));
	seg->sm_next = mem->mem_seg;
	mem->mem_seg = seg;
	seg->sm_base = 0;
	seg->sm_size = sysmem_size;

	mg = topo_mod_zalloc(mod, sizeof (mem_grp_t));
	seg->sm_grp = mg;
	mem->mem_group = mg;

	for (rank = min_rank, rank_value = 0;
	    rank <= max_rank;
	    rank++, rank_value += rank_mask) {
		for (chan = min_chan, chan_value = 0;
		    chan <= max_chan;
		    chan += chan_step,
		    chan_value += MEM_BYTES_PER_CACHELINE) {
			bm = topo_mod_zalloc(mod, sizeof (mem_bank_map_t));
			bm->bm_mask = mask;
			bm->bm_match = chan_value | rank_value;
			bm->bm_shift = 1;
			bm->bm_grp = mg->mg_bank;
			mg->mg_bank = bm;
			bm->bm_next = mem->mem_bank;
			mem->mem_bank = bm;
			(void) sprintf(s, "MB/CMP0/CH%1d/R%1d", chan, rank);
			idx = 0;
			for (d = mem->mem_dm; d != NULL; d = d->dm_next) {
				if (strncmp(s, d->dm_label, strlen(s)) == 0)
					bm->bm_dimm[idx++] = d;
			}
		}
	}
}

uint16_t
mem_log2(uint64_t v)
{
	uint16_t i;
	for (i = 0; v > 1; i++) {
		v = v >> 1;
	}
	return (i);
}

mem_dimm_map_t *
mem_get_dimm_by_sn(char *sn, md_mem_info_t *mem)
{
	mem_dimm_map_t *dp;

	for (dp = mem->mem_dm; dp != NULL; dp = dp->dm_next) {
		if (strcmp(sn, dp->dm_serid) == 0)
			return (dp);
	}
	return (NULL);
}

mem_grp_t *
find_grp(mde_cookie_t *listp, size_t n, mde_cookie_t *bclist,
    mem_bank_map_t **banklist, size_t mem_bank_count, md_mem_info_t *mem) {

	mem_grp_t *mg;
	mem_bank_map_t *bp;
	size_t i, j;
	int err;

	for (mg = mem->mem_group; mg != NULL; mg = mg->mg_next) {
		if (mg->mg_size == n) {
			err = 0;
			for (i = 0, bp = mg->mg_bank;
			    i < n && bp != NULL;
			    i++, bp = bp->bm_grp) {
				for (j = 0; j < mem_bank_count; j++) {
					if (listp[i] == *(bclist+j) &&
					    bp == *(banklist+j))
						break;
				}
				if (bp == NULL) err++;
			}
		}
		else
			err++;
		if (err == 0)
			return (mg);
	}
	return (NULL);
}

mem_grp_t *
create_grp(topo_mod_t *mod, mde_cookie_t *listp, size_t n, mde_cookie_t *bclist,
    mem_bank_map_t **banklist, size_t mem_bank_count, md_mem_info_t *mem) {

	mem_grp_t *mg;
	size_t i, j;

	mg = topo_mod_zalloc(mod, sizeof (mem_grp_t));
	mg->mg_size = n;
	mg->mg_next = mem->mem_group;
	mem->mem_group = mg;

	for (i = 0; i < n; i++) {
		for (j = 0; j < mem_bank_count; j++) {
			if (listp[i] == *(bclist+j)) {
				(*(banklist+j))->bm_grp = mg->mg_bank;
				mg->mg_bank = *(banklist+j);
			}
		}
	}
	return (mg);
}

static void
mdesc_init_n2(topo_mod_t *mod, md_t *mdp, mde_cookie_t *listp,
    md_mem_info_t *mem, int num_comps)
{
	mde_cookie_t *dl, *bl, *bclist;
	int bc, idx, mdesc_dimm_count, mdesc_bank_count;
	mem_dimm_map_t *dm, **dp;
	uint64_t i;
	int n;
	uint64_t mask, match, base, size;
	char *unum, *serial, *part, *dash;
	mem_seg_map_t *smp;
	mem_bank_map_t *bmp, **banklist;
	mem_grp_t *gmp;
	char *type, *sp, *jnum, *nac;
	size_t ss;

	mdesc_dimm_count = 0;
	for (idx = 0; idx < num_comps; idx++) {
		if (md_get_prop_str(mdp, listp[idx], "type", &type) < 0)
			continue;
		if ((strcmp(type, "dimm") == 0) ||
		    (strcmp(type, "mem-board") == 0) ||
		    (strcmp(type, "memboard") == 0)) {
			mdesc_dimm_count++;
			if (md_get_prop_str(mdp, listp[idx], "nac",
			    &nac) < 0)
				nac = "";
			if (md_get_prop_str(mdp, listp[idx], "label",
			    &jnum) < 0)
				jnum = "";
			if (md_get_prop_str(mdp, listp[idx],
			    "serial_number", &serial) < 0)
				serial = "";
			if (md_get_prop_str(mdp, listp[idx],
			    "part_number", &part) < 0)
				part = "";
			if (md_get_prop_str(mdp, listp[idx],
			    "dash_number", &dash) < 0)
				dash = "";

			ss = strlen(part) + strlen(dash) + 1;
			sp = topo_mod_alloc(mod, ss);
			sp = strcpy(sp, part);
			sp = strncat(sp, dash, strlen(dash) + 1);

			dm = topo_mod_alloc(mod, sizeof (mem_dimm_map_t));

			if ((strcmp(nac, "") != 0) &&
			    (strcmp(jnum, "") != 0)) {
				ss = strlen(nac) + strlen(jnum) + 2;
				unum = topo_mod_alloc(mod, ss);
				(void) snprintf(unum, ss, "%s/%s", nac,
				    jnum);
				dm->dm_label = unum;
			} else {
				unum = nac;
				dm->dm_label = topo_mod_strdup(mod, unum);
			}

			dm->dm_serid = topo_mod_strdup(mod, serial);
			dm->dm_part = sp;

			/* The following is an insertion sort. */

			for (dp = &(mem->mem_dm); ; dp = &((*dp)->dm_next)) {
				if ((*dp == NULL) ||
				    (strcmp((*dp)->dm_label,
				    dm->dm_label) > 0)) {
					dm->dm_next = *dp;
					*dp = dm;
					break;
				}
			}
		}
	}

	/* N2 (PRI) specific segment initialization occurs here */

	mdesc_bank_count = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "memory-bank"),
	    md_find_name(mdp, "fwd"),
	    listp);

	/*
	 * banklist and bclist will be parallel arrays.  For a given bank,
	 * bclist[i] will be the PRI node id, and *banklist+i will point to the
	 * mem_bank_map_t for that bank.
	 */

	banklist = topo_mod_zalloc(mod, mdesc_bank_count *
	    sizeof (mem_bank_map_t *));
	bclist = topo_mod_zalloc(mod, mdesc_bank_count *
	    sizeof (mde_cookie_t));

	dl = topo_mod_zalloc(mod, mdesc_dimm_count * sizeof (mde_cookie_t));

	for (idx = 0; idx < mdesc_bank_count; idx++) {
		if (md_get_prop_val(mdp, listp[idx], "mask", &mask) < 0)
			mask = 0;
		if (md_get_prop_val(mdp, listp[idx], "match", &match) < 0)
			match = 0;

		bmp = topo_mod_zalloc(mod, sizeof (mem_bank_map_t));
		bmp->bm_next = mem->mem_bank;
		mem->mem_bank = bmp;
		bmp->bm_mask = mask;
		bmp->bm_match = match;
		/* link this bank to its dimms */
		n = md_scan_dag(mdp, listp[idx],
		    md_find_name(mdp, "component"),
		    md_find_name(mdp, "fwd"),
		    dl);
		bmp->bm_shift = mem_log2(n);

		bclist[idx] = listp[idx];
		*(banklist+idx) = bmp;

		for (i = 0; i < n; i++) {
			if (md_get_prop_str(mdp, dl[i],
			    "serial_number", &serial) < 0)
				continue;
			if ((dm = mem_get_dimm_by_sn(serial, mem)) == NULL)
				continue;
			bmp->bm_dimm[i] = dm;
		}
	}
	topo_mod_free(mod, dl, mdesc_dimm_count * sizeof (mde_cookie_t));

	bl = topo_mod_zalloc(mod, mdesc_bank_count * sizeof (mde_cookie_t));
	n = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "memory-segment"),
	    md_find_name(mdp, "fwd"),
	    listp);
	for (idx = 0; idx < n; idx++) {
		if (md_get_prop_val(mdp, listp[idx], "base", &base) < 0)
			base = 0;
		if (md_get_prop_val(mdp, listp[idx], "size", &size) < 0)
			size = 0;
		bc = md_scan_dag(mdp, listp[idx],
		    md_find_name(mdp, "memory-bank"),
		    md_find_name(mdp, "fwd"),
		    bl);
		smp = topo_mod_zalloc(mod, sizeof (mem_seg_map_t));
		smp->sm_next = mem->mem_seg;
		mem->mem_seg = smp;
		smp->sm_base = base;
		smp->sm_size = size;
		gmp = find_grp(bl, bc, bclist, banklist, mdesc_bank_count, mem);
		if (gmp == NULL)
			smp->sm_grp = create_grp(mod, bl, bc,
			    bclist, banklist, mdesc_bank_count, mem);
		else
			smp->sm_grp = gmp;
	}
	topo_mod_free(mod, bl, mdesc_bank_count * sizeof (mde_cookie_t));
	topo_mod_free(mod, bclist, mdesc_bank_count * sizeof (mde_cookie_t));
	topo_mod_free(mod, banklist,
	    mdesc_bank_count * sizeof (mem_bank_map_t *));
}

int
mem_mdesc_init(topo_mod_t *mod, md_mem_info_t *mem)
{
	int rc = 0;
	md_t *mdp;
	ssize_t bufsiz = 0;
	uint64_t *bufp;
	ldom_hdl_t *lhp;
	mde_cookie_t *listp;
	int num_nodes;
	int num_comps = 0;
	uint32_t type = 0;

	/* get the PRI/MD */
	if ((lhp = ldom_init(mem_alloc, mem_free)) == NULL) {
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	(void) ldom_get_type(lhp, &type);
	if ((type & LDOM_TYPE_CONTROL) != 0) {
		bufsiz = ldom_get_core_md(lhp, &bufp);
	} else {
		bufsiz = ldom_get_local_md(lhp, &bufp);
	}
	if (bufsiz <= 0) {
		topo_mod_dprintf(mod, "failed to get the PRI/MD\n");
		ldom_fini(lhp);
		return (-1);
	}

	if ((mdp = md_init_intern(bufp, mem_alloc, mem_free)) == NULL ||
	    md_node_count(mdp) <= 0) {
		mem_free(bufp, (size_t)bufsiz);
		ldom_fini(lhp);
		return (-1);
	}

	num_nodes = md_node_count(mdp);
	listp = mem_alloc(sizeof (mde_cookie_t) * num_nodes);

	num_comps = md_scan_dag(mdp,
	    MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"),
	    listp);
	if (num_comps == 0)
		mdesc_init_n1(mod, mdp, listp, mem);
	else
		mdesc_init_n2(mod, mdp, listp, mem, num_comps);

	mem_free(listp, sizeof (mde_cookie_t) * num_nodes);

	mem_free(bufp, (size_t)bufsiz);
	(void) md_fini(mdp);
	ldom_fini(lhp);

	return (rc);
}

void
mem_mdesc_fini(topo_mod_t *mod, md_mem_info_t *mem)
{
	mem_dimm_map_t *dm, *next;
	mem_bank_map_t *bm, *cm;
	mem_grp_t *gm, *hm;
	mem_seg_map_t *sm, *snext;

	for (dm = mem->mem_dm; dm != NULL; dm = next) {
		next = dm->dm_next;
		topo_mod_strfree(mod, dm->dm_label);
		topo_mod_strfree(mod, dm->dm_serid);
		topo_mod_free(mod, dm, sizeof (mem_dimm_map_t));
	}
	for (bm = mem->mem_bank; bm != NULL; bm = cm) {
		cm = bm->bm_next;
		topo_mod_free(mod, bm, sizeof (mem_bank_map_t));
	}
	for (gm = mem->mem_group; gm != NULL; gm = hm) {
		hm = gm->mg_next;
		topo_mod_free(mod, gm, sizeof (mem_grp_t));
	}
	for (sm = mem->mem_seg; dm != NULL; sm = snext) {
		snext = sm->sm_next;
		topo_mod_free(mod, sm, sizeof (mem_seg_map_t));
	}
}
