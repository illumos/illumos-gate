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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cmd_mem.h>
#include <cmd_branch.h>
#include <cmd_dimm.h>
#include <cmd.h>
#include <cmd_hc_sun4v.h>

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <sys/mem.h>
#include <sys/nvpair.h>

#define	BUF_SIZE	120
#define	LEN_CMP		6

int
is_t5440_unum(const char *unum)
{
	if ((strncmp(unum, "MB/CPU", LEN_CMP) == 0) ||
	    (strncmp(unum, "MB/MEM", LEN_CMP) == 0))
		return (1);
	return (0);
}

int
is_dimm_on_memboard(cmd_branch_t *branch)
{
	cmd_dimm_t *dimm;
	cmd_branch_memb_t *bm;

	if (is_t5440_unum(branch->branch_unum)) {
		for (bm = cmd_list_next(&branch->branch_dimms); bm != NULL;
		    bm = cmd_list_next(bm)) {
			dimm = bm->dimm;
			if (strstr(dimm->dimm_unum, "MEM") != NULL) {
				return (1);
			}
		}
	}
	return (0);
}

void
cmd_branch_add_dimm(fmd_hdl_t *hdl, cmd_branch_t *branch, cmd_dimm_t *dimm)
{
	cmd_branch_memb_t *bm;

	if (dimm == NULL)
		return;

	fmd_hdl_debug(hdl, "Attaching dimm %s to branch %s\n",
	    dimm->dimm_unum, branch->branch_unum);
	bm = fmd_hdl_zalloc(hdl, sizeof (cmd_branch_memb_t), FMD_SLEEP);
	bm->dimm = dimm;
	cmd_list_append(&branch->branch_dimms, bm);
}

void
cmd_branch_remove_dimm(fmd_hdl_t *hdl, cmd_branch_t *branch, cmd_dimm_t *dimm)
{
	cmd_branch_memb_t *bm;

	fmd_hdl_debug(hdl, "Detaching dimm %s from branch %s\n",
	    dimm->dimm_unum, branch->branch_unum);

	for (bm = cmd_list_next(&branch->branch_dimms); bm != NULL;
	    bm = cmd_list_next(bm)) {
		if (bm->dimm == dimm) {
			cmd_list_delete(&branch->branch_dimms, bm);
			fmd_hdl_free(hdl, bm, sizeof (cmd_branch_memb_t));
			return;
		}
	}

	fmd_hdl_abort(hdl,
	    "Attempt to disconnect dimm from non-parent branch\n");
}

static cmd_dimm_t *
branch_dimm_create(fmd_hdl_t *hdl, char *dimm_unum, char **serids,
    size_t nserids)
{
	nvlist_t *fmri;
	cmd_dimm_t *dimm;

	fmri = cmd_mem_fmri_create(dimm_unum, serids, nserids);

	if (fmri != NULL && (fmd_nvl_fmri_expand(hdl, fmri) == 0)) {
		dimm = cmd_dimm_create(hdl, fmri);
		if (dimm != NULL) {
			nvlist_free(fmri);
			return (dimm);
		}
	}

	nvlist_free(fmri);
	return (NULL);
}

static fmd_hdl_t *br_hdl; /* for exclusive use of callback */
static int br_dimmcount;

/*ARGSUSED*/
static int
branch_dimm_cb(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	char *lbl, *p, *q;
	char cx[BUF_SIZE], cy[BUF_SIZE];
	nvlist_t *rsrc;
	int err;
	cmd_branch_t *branch = (cmd_branch_t *)arg;
	cmd_dimm_t *dimm;
	size_t nserids;
	char **serids;

	if (topo_node_resource(node, &rsrc, &err) < 0)
		return (TOPO_WALK_NEXT);	/* no label, try next */

	if ((nvlist_lookup_string(rsrc, FM_FMRI_MEM_UNUM, &lbl) != 0) ||
	    (nvlist_lookup_string_array(rsrc, FM_FMRI_MEM_SERIAL_ID,
	    &serids, &nserids) != 0)) {
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT);
	}

	/*
	 * Massage the unum of the candidate DIMM as follows:
	 * a) remove any trailing J number.  Use result for cmd_dimm_t.
	 * b) for branch membership purposes only, remove reference to
	 * a riser card (MR%d) if one exists.
	 */
	if ((p = strstr(lbl, "/J")) != NULL) {
		(void) strncpy(cx, lbl, p - lbl);
		cx[p - lbl] = '\0';
	} else {
		(void) strcpy(cx, lbl);
	}
	(void) strcpy(cy, cx);
	if ((p = strstr(cy, "/MR")) != NULL) {
		if ((q = strchr(p + 1, '/')) != NULL)
			(void) strcpy(p, q);
		else
			*p = '\0';
	}

	/*
	 * For benefit of Batoka-like platforms, start comparison with
	 * "CMP", so that any leading "MEM" or "CPU" makes no difference.
	 */

	p = strstr(branch->branch_unum, "CMP");
	q = strstr(cy, "CMP");

	if ((p != NULL) && (q != NULL) && strncmp(p, q, strlen(p)) == 0) {
		dimm = branch_dimm_create(br_hdl, cx, serids, nserids);
		if (dimm != NULL)
			cmd_branch_add_dimm(br_hdl, branch, dimm);
	}
	nvlist_free(rsrc);
	return (TOPO_WALK_NEXT);
}


/*
 * The cmd_dimm_t structure created for a DIMM in a branch never has a
 * Jxxx in its unum; the cmd_dimm_t structure created for a DIMM containing
 * a page, or in a bank (i.e. for ECC errors)-always-has a Jxxx in its
 * unum. Therefore the set of cmd_dimm_t's created for a branch is always
 * disjoint from the set of cmd_dimm_t's created for pages and/or banks, so
 * the cmd_dimm_create will never link a 'branch' cmd_dimm_t into bank.
 * Faulting a DIMM for ECC will not prevent subsequent faulting of "same"
 * dimm for FBR/FBU and vice versa
 */
static int
branch_dimmlist_create(fmd_hdl_t *hdl, cmd_branch_t *branch)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err, dimm_count;
	cmd_list_t *bp;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return (0);
	if ((twp = topo_walk_init(thp,
	    FM_FMRI_SCHEME_MEM, branch_dimm_cb, branch, &err))
	    == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return (0);
	}
	br_hdl = hdl;
	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);

	for (dimm_count = 0, bp = &branch->branch_dimms; bp != NULL;
	    bp = cmd_list_next(bp), dimm_count++)
		;
	return (dimm_count);
}

/*
 * For t5440, the memory channel goes like this:
 * VF -> cpuboard -> D0 -> motherboard -> memboard -> D[1..3]
 * If there is a dimm on the memory board, the memory board,
 * motherboard, cpuboard, and dimms are in the suspect list.
 * If there is no dimm on the memory board, the cpu board and
 * the dimms are in the suspect list
 * memory board fault does not supported in this pharse of
 * the project.
 * The board certainty = total board certainty / number of
 * the faulty boards in the suspect list.
 */
void
cmd_branch_create_fault(fmd_hdl_t *hdl, cmd_branch_t *branch,
    const char *fltnm, nvlist_t *asru)
{
	nvlist_t *flt, *mbnvl;
	cmd_branch_memb_t *bm;
	cmd_dimm_t *dimm;
	int dimm_count = 0;
	uint_t cert = 0;
	uint_t board_cert = 0;
	char *fruloc = NULL;
	int count_board_fault = 1;
	int memb_flag = 0;

	/* attach the dimms to the branch */
	dimm_count = branch_dimmlist_create(hdl, branch);

	if (is_dimm_on_memboard(branch)) {
		mbnvl = init_mb(hdl);
		if (mbnvl != NULL)
			count_board_fault++;
		memb_flag = 1;
	}

	board_cert = CMD_BOARDS_CERT / count_board_fault;

	/* add the motherboard fault */
	if ((memb_flag) && (mbnvl != NULL)) {
		fmd_hdl_debug(hdl,
		    "cmd_branch_create_fault: create motherboard fault");
		flt = cmd_boardfru_create_fault(hdl, mbnvl, fltnm,
		    board_cert, "MB");
		if (flt != NULL)
			fmd_case_add_suspect(hdl, branch->branch_case.cc_cp,
			    flt);
		nvlist_free(mbnvl);
	}

	fruloc = cmd_getfru_loc(hdl, asru);
	flt = cmd_boardfru_create_fault(hdl, asru, fltnm, board_cert, fruloc);
	if (flt != NULL)
		fmd_case_add_suspect(hdl, branch->branch_case.cc_cp, flt);

	if (dimm_count != 0)
		cert = (100 - CMD_BOARDS_CERT) / dimm_count;

	/* create dimm faults */
	for (bm = cmd_list_next(&branch->branch_dimms); bm != NULL;
	    bm = cmd_list_next(bm)) {
		dimm = bm->dimm;
		if (dimm != NULL) {
			dimm->dimm_flags |= CMD_MEM_F_FAULTING;
			cmd_dimm_dirty(hdl, dimm);
			flt = cmd_dimm_create_fault(hdl, dimm, fltnm, cert);
			fmd_case_add_suspect(hdl, branch->branch_case.cc_cp,
			    flt);
		}
	}
	if (fruloc != NULL)
		fmd_hdl_strfree(hdl, fruloc);
}

cmd_branch_t *
cmd_branch_create(fmd_hdl_t *hdl, nvlist_t *asru)
{
	cmd_branch_t *branch;
	const char *b_unum;

	if ((b_unum = cmd_fmri_get_unum(asru)) == NULL) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (NULL);
	}

	fmd_hdl_debug(hdl, "branch_create: creating new branch %s\n", b_unum);
	CMD_STAT_BUMP(branch_creat);

	branch = fmd_hdl_zalloc(hdl, sizeof (cmd_branch_t), FMD_SLEEP);
	branch->branch_nodetype = CMD_NT_BRANCH;
	branch->branch_version = CMD_BRANCH_VERSION;

	cmd_bufname(branch->branch_bufname, sizeof (branch->branch_bufname),
	    "branch_%s", b_unum);
	cmd_fmri_init(hdl, &branch->branch_asru, asru, "branch_asru_%s",
	    b_unum);

	(void) nvlist_lookup_string(branch->branch_asru_nvl, FM_FMRI_MEM_UNUM,
	    (char **)&branch->branch_unum);

	cmd_list_append(&cmd.cmd_branches, branch);
	cmd_branch_dirty(hdl, branch);

	return (branch);
}

cmd_branch_t *
cmd_branch_lookup_by_unum(fmd_hdl_t *hdl, const char *unum)
{
	cmd_branch_t *branch;

	fmd_hdl_debug(hdl, "branch_lookup: dimm_unum %s", unum);
	/*
	 * fbr/fbu unum dimm does not have a J number
	 */
	if (strstr(unum, "J") != NULL)
		return (NULL);

	for (branch = cmd_list_next(&cmd.cmd_branches); branch != NULL;
	    branch = cmd_list_next(branch)) {
		if (strcmp(branch->branch_unum, unum) == 0)
			return (branch);
	}

	fmd_hdl_debug(hdl, "branch_lookup_by_unum: no branch is found\n");
	return (NULL);
}

cmd_branch_t *
cmd_branch_lookup(fmd_hdl_t *hdl, nvlist_t *asru)
{
	cmd_branch_t *branch;
	const char *unum;

	if ((unum = cmd_fmri_get_unum(asru)) == NULL) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (NULL);
	}

	for (branch = cmd_list_next(&cmd.cmd_branches); branch != NULL;
	    branch = cmd_list_next(branch)) {
		if (strcmp(branch->branch_unum, unum) == 0)
			return (branch);
	}

	fmd_hdl_debug(hdl, "cmd_branch_lookup: discarding old \n");
	return (NULL);
}

static cmd_branch_t *
branch_wrapv0(fmd_hdl_t *hdl, cmd_branch_pers_t *pers, size_t psz)
{
	cmd_branch_t *branch;

	if (psz != sizeof (cmd_branch_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 0 state (%u bytes).\n",
		    sizeof (cmd_branch_pers_t));
	}

	branch = fmd_hdl_zalloc(hdl, sizeof (cmd_branch_t), FMD_SLEEP);
	bcopy(pers, branch, sizeof (cmd_branch_pers_t));
	fmd_hdl_free(hdl, pers, psz);
	return (branch);
}

void *
cmd_branch_restore(fmd_hdl_t *hdl, fmd_case_t *cp, cmd_case_ptr_t *ptr)
{
	cmd_branch_t *branch;
	size_t branchsz;


	for (branch = cmd_list_next(&cmd.cmd_branches); branch != NULL;
	    branch = cmd_list_next(branch)) {
		if (strcmp(branch->branch_bufname, ptr->ptr_name) == 0)
			break;
	}

	if (branch == NULL) {
		fmd_hdl_debug(hdl, "restoring branch from %s\n", ptr->ptr_name);

		if ((branchsz = fmd_buf_size(hdl, NULL, ptr->ptr_name)) == 0) {
			fmd_hdl_abort(hdl, "branch referenced by case %s does "
			    "not exist in saved state\n",
			    fmd_case_uuid(hdl, cp));
		} else if (branchsz > CMD_BRANCH_MAXSIZE ||
		    branchsz < CMD_BRANCH_MINSIZE) {
			fmd_hdl_abort(hdl,
			    "branch buffer referenced by case %s "
			    "is out of bounds (is %u bytes, max %u, min %u)\n",
			    fmd_case_uuid(hdl, cp), branchsz,
			    CMD_BRANCH_MAXSIZE, CMD_BRANCH_MINSIZE);
		}

		if ((branch = cmd_buf_read(hdl, NULL, ptr->ptr_name,
		    branchsz)) == NULL) {
			fmd_hdl_abort(hdl, "failed to read branch buf %s",
			    ptr->ptr_name);
		}

		fmd_hdl_debug(hdl, "found %d in version field\n",
		    branch->branch_version);

		switch (branch->branch_version) {
		case CMD_BRANCH_VERSION_0:
			branch = branch_wrapv0(hdl,
			    (cmd_branch_pers_t *)branch, branchsz);
			break;
		default:
			fmd_hdl_abort(hdl, "unknown version (found %d) "
			    "for branch state referenced by case %s.\n",
			    branch->branch_version, fmd_case_uuid(hdl,
			    cp));
			break;
		}

		cmd_fmri_restore(hdl, &branch->branch_asru);

		if ((errno = nvlist_lookup_string(branch->branch_asru_nvl,
		    FM_FMRI_MEM_UNUM, (char **)&branch->branch_unum)) != 0)
			fmd_hdl_abort(hdl, "failed to retrieve unum from asru");


		cmd_list_append(&cmd.cmd_branches, branch);
	}

	switch (ptr->ptr_subtype) {
	case CMD_PTR_BRANCH_CASE:
		cmd_mem_case_restore(hdl, &branch->branch_case, cp, "branch",
		    branch->branch_unum);
		break;
	default:
		fmd_hdl_abort(hdl, "invalid %s subtype %d\n",
		    ptr->ptr_name, ptr->ptr_subtype);
	}

	return (branch);
}

void
cmd_branch_dirty(fmd_hdl_t *hdl, cmd_branch_t *branch)
{
	if (fmd_buf_size(hdl, NULL, branch->branch_bufname) !=
	    sizeof (cmd_branch_pers_t))
		fmd_buf_destroy(hdl, NULL, branch->branch_bufname);

	/* No need to rewrite the FMRIs in the branch - they don't change */
	fmd_buf_write(hdl, NULL, branch->branch_bufname, &branch->branch_pers,
	    sizeof (cmd_branch_pers_t));
}

static void
branch_dimmlist_free(fmd_hdl_t *hdl, cmd_branch_t *branch)
{
	cmd_branch_memb_t *bm;

	while ((bm = cmd_list_next(&branch->branch_dimms)) != NULL) {
		cmd_list_delete(&branch->branch_dimms, bm);
		fmd_hdl_free(hdl, bm, sizeof (cmd_branch_memb_t));
	}
}

static void
branch_free(fmd_hdl_t *hdl, cmd_branch_t *branch, int destroy)
{
	fmd_hdl_debug(hdl, "Free branch %s\n", branch->branch_unum);
	if (branch->branch_case.cc_cp != NULL) {
		if (destroy) {
			if (branch->branch_case.cc_serdnm != NULL) {
				fmd_serd_destroy(hdl,
				    branch->branch_case.cc_serdnm);
				fmd_hdl_strfree(hdl,
				    branch->branch_case.cc_serdnm);
				branch->branch_case.cc_serdnm = NULL;
			}
		}
		cmd_case_fini(hdl, branch->branch_case.cc_cp, destroy);
	}

	branch_dimmlist_free(hdl, branch);
	cmd_fmri_fini(hdl, &branch->branch_asru, destroy);

	if (destroy)
		fmd_buf_destroy(hdl, NULL, branch->branch_bufname);
	cmd_list_delete(&cmd.cmd_branches, branch);
	fmd_hdl_free(hdl, branch, sizeof (cmd_branch_t));
}

void
cmd_branch_destroy(fmd_hdl_t *hdl, cmd_branch_t *branch)
{
	branch_free(hdl, branch, FMD_B_TRUE);
}

/*ARGSUSED*/
static int
branch_exist_cb(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	char *lbl, *p, *q;
	char cy[BUF_SIZE];
	nvlist_t *rsrc;
	int err;

	cmd_branch_t *branch = (cmd_branch_t *)arg;

	if (topo_node_resource(node, &rsrc, &err) < 0)
		return (TOPO_WALK_NEXT);	/* no label, try next */

	if (nvlist_lookup_string(rsrc, "unum", &lbl) != 0) {
		nvlist_free(rsrc);
		return (TOPO_WALK_NEXT);
	}
	/*
	 * for branch membership purposes only, remove reference to
	 * a riser card (MR%d) if one exists.
	 */
	(void) strcpy(cy, lbl);
	if ((p = strstr(cy, "/MR")) != NULL) {
		if ((q = strchr(p + 1, '/')) != NULL)
			(void) strcpy(p, q);
		else
			*p = '\0';
	}
	if (strncmp(branch->branch_unum, cy,
	    strlen(branch->branch_unum)) == 0) {
		br_dimmcount++;
		nvlist_free(rsrc);
		return (TOPO_WALK_TERMINATE);
	}
	nvlist_free(rsrc);
	return (TOPO_WALK_NEXT);
}

static int
branch_exist(fmd_hdl_t *hdl, cmd_branch_t *branch)
{
	topo_hdl_t *thp;
	topo_walk_t *twp;
	int err;

	if ((thp = fmd_hdl_topo_hold(hdl, TOPO_VERSION)) == NULL)
		return (0);
	if ((twp = topo_walk_init(thp,
	    FM_FMRI_SCHEME_MEM, branch_exist_cb, branch, &err))
	    == NULL) {
		fmd_hdl_topo_rele(hdl, thp);
		return (0);
	}
	br_dimmcount = 0;
	(void) topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_hdl_topo_rele(hdl, thp);

	return (br_dimmcount);
}

/*
 * If the case has been solved, don't need to check the dimmlist
 * If the case has not been solved, the branch is valid if there is least one
 * existing dimm in the branch
 */
void
cmd_branch_validate(fmd_hdl_t *hdl)
{
	cmd_branch_t *branch, *next;

	fmd_hdl_debug(hdl, "cmd_branch_validate\n");

	for (branch = cmd_list_next(&cmd.cmd_branches); branch != NULL;
	    branch = next) {
		next = cmd_list_next(branch);
		if (branch->branch_case.cc_cp != NULL &&
		    fmd_case_solved(hdl, branch->branch_case.cc_cp))
			continue;
		if (branch_exist(hdl, branch))
			continue;
		cmd_branch_destroy(hdl, branch);
	}
}

void
cmd_branch_gc(fmd_hdl_t *hdl)
{
	fmd_hdl_debug(hdl, "cmd_branch_gc\n");
	cmd_branch_validate(hdl);
}

void
cmd_branch_fini(fmd_hdl_t *hdl)
{
	cmd_branch_t *branch;
	fmd_hdl_debug(hdl, "cmd_branch_fini\n");

	while ((branch = cmd_list_next(&cmd.cmd_branches)) != NULL)
		branch_free(hdl, branch, FMD_B_FALSE);
}
