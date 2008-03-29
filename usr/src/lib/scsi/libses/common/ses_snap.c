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

#include <scsi/libses.h>
#include "ses_impl.h"

ses_snap_page_t *
ses_snap_find_page(ses_snap_t *sp, ses2_diag_page_t page, boolean_t ctl)
{
	ses_snap_page_t *pp;

	for (pp = sp->ss_pages; pp != NULL; pp = pp->ssp_next)
		if (pp->ssp_num == page && pp->ssp_control == ctl &&
		    (pp->ssp_len > 0 || pp->ssp_control))
			return (pp);

	return (NULL);
}

static int
grow_snap_page(ses_snap_page_t *pp, size_t min)
{
	uint8_t *newbuf;

	if (min == 0 || min < pp->ssp_alloc)
		min = pp->ssp_alloc * 2;

	if ((newbuf = ses_realloc(pp->ssp_page, min)) == NULL)
		return (-1);

	pp->ssp_page = newbuf;
	pp->ssp_alloc = min;

	bzero(newbuf + pp->ssp_len, pp->ssp_alloc - pp->ssp_len);

	return (0);
}

static ses_snap_page_t *
alloc_snap_page(void)
{
	ses_snap_page_t *pp;

	if ((pp = ses_zalloc(sizeof (ses_snap_page_t))) == NULL)
		return (NULL);

	if ((pp->ssp_page = ses_zalloc(SES2_MIN_DIAGPAGE_ALLOC)) == NULL) {
		ses_free(pp);
		return (NULL);
	}

	pp->ssp_num = -1;
	pp->ssp_alloc = SES2_MIN_DIAGPAGE_ALLOC;

	return (pp);
}

static void
free_snap_page(ses_snap_page_t *pp)
{
	if (pp == NULL)
		return;

	if (pp->ssp_mmap_base)
		(void) munmap(pp->ssp_mmap_base, pp->ssp_mmap_len);
	else
		ses_free(pp->ssp_page);
	ses_free(pp);
}

static void
free_all_snap_pages(ses_snap_t *sp)
{
	ses_snap_page_t *pp, *np;

	for (pp = sp->ss_pages; pp != NULL; pp = np) {
		np = pp->ssp_next;
		free_snap_page(pp);
	}

	sp->ss_pages = NULL;
}

/*
 * Grow (if needed) the control page buffer, fill in the page code, page
 * length, and generation count, and return a pointer to the page.  The
 * caller is responsible for filling in the rest of the page data.  If 'unique'
 * is specified, then a new page instance is created instead of sharing the
 * current one.
 */
ses_snap_page_t *
ses_snap_ctl_page(ses_snap_t *sp, ses2_diag_page_t page, size_t dlen,
    boolean_t unique)
{
	ses_target_t *tp = sp->ss_target;
	spc3_diag_page_impl_t *pip;
	ses_snap_page_t *pp, *up, **loc;
	ses_pagedesc_t *dp;
	size_t len;

	pp = ses_snap_find_page(sp, page, B_TRUE);
	if (pp == NULL) {
		(void) ses_set_errno(ESES_NOTSUP);
		return (NULL);
	}

	if (pp->ssp_initialized && !unique)
		return (pp);

	if (unique) {
		/*
		 * The user has requested a unique instance of the page.  Create
		 * a new ses_snap_page_t instance and chain it off the
		 * 'ssp_instances' list of the master page.  These must be
		 * appended to the end of the chain, as the order of operations
		 * may be important (i.e. microcode download).
		 */
		if ((up = alloc_snap_page()) == NULL)
			return (NULL);

		up->ssp_num = pp->ssp_num;
		up->ssp_control = B_TRUE;

		for (loc = &pp->ssp_unique; *loc != NULL;
		    loc = &(*loc)->ssp_next)
			;

		*loc = up;
		pp = up;
	}

	dp = ses_get_pagedesc(tp, page, SES_PAGE_CTL);
	ASSERT(dp != NULL);

	len = dp->spd_ctl_len(sp->ss_n_elem, page, dlen);
	if (pp->ssp_alloc < dlen && grow_snap_page(pp, len) != 0)
		return (NULL);
	pp->ssp_len = len;
	bzero(pp->ssp_page, len);
	pp->ssp_initialized = B_TRUE;

	pip = (spc3_diag_page_impl_t *)pp->ssp_page;
	pip->sdpi_page_code = (uint8_t)page;
	SCSI_WRITE16(&pip->sdpi_page_length,
	    len - offsetof(spc3_diag_page_impl_t, sdpi_data[0]));
	if (dp->spd_gcoff != -1)
		SCSI_WRITE32((uint8_t *)pip + dp->spd_gcoff, sp->ss_generation);

	return (pp);
}

static int
read_status_page(ses_snap_t *sp, ses2_diag_page_t page)
{
	libscsi_action_t *ap;
	ses_snap_page_t *pp;
	ses_target_t *tp;
	spc3_diag_page_impl_t *pip;
	spc3_receive_diagnostic_results_cdb_t *cp;
	uint_t flags;
	uint8_t *buf;
	size_t alloc;
	uint_t retries = 0;
	ses2_diag_page_t retpage;

	for (pp = sp->ss_pages; pp != NULL; pp = pp->ssp_next)
		if (pp->ssp_num == page && !pp->ssp_control)
			break;

	/*
	 * No matching page.  Since the page number is not under consumer or
	 * device control, this must be a bug.
	 */
	ASSERT(pp != NULL);

	tp = sp->ss_target;

	flags = LIBSCSI_AF_READ | LIBSCSI_AF_SILENT | LIBSCSI_AF_DIAGNOSE |
	    LIBSCSI_AF_RQSENSE;

again:
	ap = libscsi_action_alloc(tp->st_scsi_hdl,
	    SPC3_CMD_RECEIVE_DIAGNOSTIC_RESULTS, flags, pp->ssp_page,
	    pp->ssp_alloc);

	if (ap == NULL)
		return (ses_libscsi_error(tp->st_scsi_hdl, "failed to "
		    "allocate SCSI action"));

	cp = (spc3_receive_diagnostic_results_cdb_t *)
	    libscsi_action_get_cdb(ap);

	cp->rdrc_page_code = pp->ssp_num;
	cp->rdrc_pcv = 1;
	SCSI_WRITE16(&cp->rdrc_allocation_length,
	    MIN(pp->ssp_alloc, UINT16_MAX));

	if (libscsi_exec(ap, tp->st_target) != 0) {
		libscsi_action_free(ap);
		return (ses_libscsi_error(tp->st_scsi_hdl,
		    "receive diagnostic results failed"));
	}

	if (libscsi_action_get_status(ap) != 0) {
		(void) ses_scsi_error(ap,
		    "receive diagnostic results failed");
		libscsi_action_free(ap);
		return (-1);
	}

	(void) libscsi_action_get_buffer(ap, &buf, &alloc, &pp->ssp_len);
	libscsi_action_free(ap);

	ASSERT(buf == pp->ssp_page);
	ASSERT(alloc == pp->ssp_alloc);

	if (pp->ssp_len == pp->ssp_alloc && pp->ssp_alloc < UINT16_MAX) {
		bzero(pp->ssp_page, pp->ssp_len);
		pp->ssp_len = 0;
		if (grow_snap_page(pp, 0) != 0)
			return (-1);
		goto again;
	}

	pip = (spc3_diag_page_impl_t *)buf;

	if (pip->sdpi_page_code == page)
		return (0);

	retpage = pip->sdpi_page_code;

	bzero(pp->ssp_page, pp->ssp_len);
	pp->ssp_len = 0;

	if (retpage == SES2_DIAGPAGE_ENCLOSURE_BUSY) {
		if (++retries > LIBSES_MAX_BUSY_RETRIES)
			return (ses_error(ESES_BUSY, "too many "
			    "enclosure busy responses for page 0x%x", page));
		goto again;
	}

	return (ses_error(ESES_BAD_RESPONSE, "target returned page 0x%x "
	    "instead of the requested page 0x%x", retpage, page));
}

static int
send_control_page(ses_snap_t *sp, ses_snap_page_t *pp)
{
	ses_target_t *tp;
	libscsi_action_t *ap;
	spc3_send_diagnostic_cdb_t *cp;
	uint_t flags;

	tp = sp->ss_target;

	flags = LIBSCSI_AF_WRITE | LIBSCSI_AF_SILENT | LIBSCSI_AF_DIAGNOSE |
	    LIBSCSI_AF_RQSENSE;

	ap = libscsi_action_alloc(tp->st_scsi_hdl, SPC3_CMD_SEND_DIAGNOSTIC,
	    flags, pp->ssp_page, pp->ssp_len);

	if (ap == NULL)
		return (ses_libscsi_error(tp->st_scsi_hdl, "failed to "
		    "allocate SCSI action"));

	cp = (spc3_send_diagnostic_cdb_t *)libscsi_action_get_cdb(ap);

	cp->sdc_pf = 1;
	SCSI_WRITE16(&cp->sdc_parameter_list_length, pp->ssp_len);

	if (libscsi_exec(ap, tp->st_target) != 0) {
		libscsi_action_free(ap);
		return (ses_libscsi_error(tp->st_scsi_hdl,
		    "SEND DIAGNOSTIC command failed for page 0x%x",
		    pp->ssp_num));
	}

	if (libscsi_action_get_status(ap) != 0) {
		(void) ses_scsi_error(ap, "SEND DIAGNOSTIC command "
		    "failed for page 0x%x", pp->ssp_num);
		libscsi_action_free(ap);
		return (-1);
	}

	libscsi_action_free(ap);

	return (0);
}

static int
pages_skel_create(ses_snap_t *sp)
{
	ses_snap_page_t *pp, *np;
	ses_target_t *tp = sp->ss_target;
	ses2_supported_ses_diag_page_impl_t *pip;
	ses2_diag_page_t page;
	size_t npages;
	size_t pagelen;
	off_t i;

	ASSERT(sp->ss_pages == NULL);

	if ((pp = alloc_snap_page()) == NULL)
		return (-1);

	pp->ssp_num = SES2_DIAGPAGE_SUPPORTED_PAGES;
	pp->ssp_control = B_FALSE;
	sp->ss_pages = pp;

	if (read_status_page(sp, SES2_DIAGPAGE_SUPPORTED_PAGES) != 0) {
		free_snap_page(pp);
		sp->ss_pages = NULL;
		return (-1);
	}

	pip = pp->ssp_page;
	pagelen = pp->ssp_len;

	npages = SCSI_READ16(&pip->sssdpi_page_length);

	for (i = 0; i < npages; i++) {
		if (!SES_WITHIN_PAGE(pip->sssdpi_pages + i, 1, pip,
		    pagelen))
			break;

		page = (ses2_diag_page_t)pip->sssdpi_pages[i];
		/*
		 * Skip the page we already added during the bootstrap.
		 */
		if (page == SES2_DIAGPAGE_SUPPORTED_PAGES)
			continue;
		/*
		 * The end of the page list may be padded with zeros; ignore
		 * them all.
		 */
		if (page == 0 && i > 0)
			break;
		if ((np = alloc_snap_page()) == NULL) {
			free_all_snap_pages(sp);
			return (-1);
		}
		np->ssp_num = page;
		pp->ssp_next = np;
		pp = np;

		/*
		 * Allocate a control page as well, if we can use it.
		 */
		if (ses_get_pagedesc(tp, page, SES_PAGE_CTL) != NULL) {
			if ((np = alloc_snap_page()) == NULL) {
				free_all_snap_pages(sp);
				return (-1);
			}
			np->ssp_num = page;
			np->ssp_control = B_TRUE;
			pp->ssp_next = np;
			pp = np;
		}
	}

	return (0);
}

static void
ses_snap_free(ses_snap_t *sp)
{
	free_all_snap_pages(sp);
	ses_node_teardown(sp->ss_root);
	ses_free(sp->ss_nodes);
	ses_free(sp);
}

static void
ses_snap_rele_unlocked(ses_snap_t *sp)
{
	ses_target_t *tp = sp->ss_target;

	if (--sp->ss_refcnt != 0)
		return;

	if (sp->ss_next != NULL)
		sp->ss_next->ss_prev = sp->ss_prev;

	if (sp->ss_prev != NULL)
		sp->ss_prev->ss_next = sp->ss_next;
	else
		tp->st_snapshots = sp->ss_next;

	ses_snap_free(sp);
}

ses_snap_t *
ses_snap_hold(ses_target_t *tp)
{
	ses_snap_t *sp;

	(void) pthread_mutex_lock(&tp->st_lock);
	sp = tp->st_snapshots;
	sp->ss_refcnt++;
	(void) pthread_mutex_unlock(&tp->st_lock);

	return (sp);
}

void
ses_snap_rele(ses_snap_t *sp)
{
	ses_target_t *tp = sp->ss_target;

	(void) pthread_mutex_lock(&tp->st_lock);
	ses_snap_rele_unlocked(sp);
	(void) pthread_mutex_unlock(&tp->st_lock);
}

ses_snap_t *
ses_snap_new(ses_target_t *tp)
{
	ses_snap_t *sp;
	ses_snap_page_t *pp;
	uint32_t gc;
	uint_t retries = 0;
	ses_pagedesc_t *dp;
	size_t pages, pagesize, pagelen;
	char *scratch;

	if ((sp = ses_zalloc(sizeof (ses_snap_t))) == NULL)
		return (NULL);

	sp->ss_target = tp;

again:
	free_all_snap_pages(sp);

	if (pages_skel_create(sp) != 0) {
		free(sp);
		return (NULL);
	}

	sp->ss_generation = (uint32_t)-1;
	sp->ss_time = gethrtime();

	for (pp = sp->ss_pages; pp != NULL; pp = pp->ssp_next) {
		/*
		 * We skip all of:
		 *
		 * - Control pages
		 * - Pages we've already filled in
		 * - Pages we don't understand (those with no descriptor)
		 */
		if (pp->ssp_len > 0 || pp->ssp_control)
			continue;
		if ((dp = ses_get_pagedesc(tp, pp->ssp_num,
		    SES_PAGE_DIAG)) == NULL)
			continue;

		if (read_status_page(sp, pp->ssp_num) != 0)
			continue;

		/*
		 * If the generation code has changed, we don't have a valid
		 * snapshot.  Start over.
		 */
		if (dp->spd_gcoff != -1 &&
		    dp->spd_gcoff + 4 <= pp->ssp_len) {
			gc = SCSI_READ32((uint8_t *)pp->ssp_page +
			    dp->spd_gcoff);
			if (sp->ss_generation == (uint32_t)-1) {
				sp->ss_generation = gc;
			} else if (sp->ss_generation != gc) {
				if (++retries > LIBSES_MAX_GC_RETRIES) {
					(void) ses_error(ESES_TOOMUCHCHANGE,
					    "too many generation count "
					    "mismatches: page 0x%x gc %u "
					    "previous page %u", dp->spd_gcoff,
					    gc, sp->ss_generation);
					ses_snap_free((ses_snap_t *)sp);
					return (NULL);
				}
				goto again;
			}
		}
	}

	/*
	 * The LIBSES_TRUNCATE environment variable is a debugging tool which,
	 * if set, randomly truncates all pages (except
	 * SES2_DIAGPAGE_SUPPORTED_PAGES).  In order to be truly evil, we
	 * mmap() each page with enough space after it so we can move the data
	 * up to the end of a page and unmap the following page so that any
	 * attempt to read past the end of the page results in a segfault.
	 */
	if (sp->ss_target->st_truncate) {
		pagesize = PAGESIZE;

		/*
		 * Count the maximum number of pages we will need and allocate
		 * the necessary space.
		 */
		pages = 0;
		for (pp = sp->ss_pages; pp != NULL; pp = pp->ssp_next) {
			if (pp->ssp_control || pp->ssp_len == 0)
				continue;

			pages += (P2ROUNDUP(pp->ssp_len, pagesize) /
			    pagesize) + 1;
		}

		if ((scratch = mmap(NULL, pages * pagesize,
		    PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,
		    -1, 0)) == MAP_FAILED) {
			(void) ses_error(ESES_NOMEM,
			    "failed to mmap() pages for truncation");
			ses_snap_free(sp);
			return (NULL);
		}

		for (pp = sp->ss_pages; pp != NULL; pp = pp->ssp_next) {
			if (pp->ssp_control || pp->ssp_len == 0)
				continue;

			pages = P2ROUNDUP(pp->ssp_len, pagesize) / pagesize;
			pp->ssp_mmap_base = scratch;
			pp->ssp_mmap_len = pages * pagesize;

			pagelen = lrand48() % pp->ssp_len;
			(void) memcpy(pp->ssp_mmap_base + pp->ssp_mmap_len -
			    pagelen, pp->ssp_page, pagelen);
			ses_free(pp->ssp_page);
			pp->ssp_page = pp->ssp_mmap_base + pp->ssp_mmap_len -
			    pagelen;
			pp->ssp_len = pagelen;

			(void) munmap(pp->ssp_mmap_base + pages * pagesize,
			    pagesize);
			scratch += (pages + 1) * pagesize;
		}
	}


	if (ses_fill_snap(sp) != 0) {
		ses_snap_free(sp);
		return (NULL);
	}

	(void) pthread_mutex_lock(&tp->st_lock);
	if (tp->st_snapshots != NULL)
		ses_snap_rele_unlocked(tp->st_snapshots);
	sp->ss_next = tp->st_snapshots;
	if (tp->st_snapshots != NULL)
		tp->st_snapshots->ss_prev = sp;
	tp->st_snapshots = sp;
	sp->ss_refcnt = 2;
	(void) pthread_mutex_unlock(&tp->st_lock);

	return (sp);
}

int
ses_snap_do_ctl(ses_snap_t *sp)
{
	ses_snap_page_t *pp, *up;
	int ret = -1;

	for (pp = sp->ss_pages; pp != NULL; pp = pp->ssp_next) {
		if (!pp->ssp_control)
			continue;

		if (pp->ssp_initialized && send_control_page(sp, pp) != 0)
			goto error;

		for (up = pp->ssp_unique; up != NULL; up = up->ssp_next) {
			if (send_control_page(sp, up) != 0)
				goto error;
		}
	}

	ret = 0;
error:
	for (pp = sp->ss_pages; pp != NULL; pp = pp->ssp_next) {
		if (!pp->ssp_control)
			continue;

		pp->ssp_initialized = B_FALSE;
		while ((up = pp->ssp_unique) != NULL) {
			pp->ssp_unique = up->ssp_next;
			free_snap_page(up);
		}
	}


	return (ret);
}

uint32_t
ses_snap_generation(ses_snap_t *sp)
{
	return (sp->ss_generation);
}

static ses_walk_action_t
ses_walk_node(ses_node_t *np, ses_walk_f func, void *arg)
{
	ses_walk_action_t action;

	for (; np != NULL; np = ses_node_sibling(np)) {
		action = func(np, arg);
		if (action == SES_WALK_ACTION_TERMINATE)
			return (SES_WALK_ACTION_TERMINATE);
		if (action == SES_WALK_ACTION_PRUNE ||
		    ses_node_child(np) == NULL)
			continue;
		if (ses_walk_node(ses_node_child(np), func, arg) ==
		    SES_WALK_ACTION_TERMINATE)
			return (SES_WALK_ACTION_TERMINATE);
	}

	return (SES_WALK_ACTION_CONTINUE);
}

int
ses_walk(ses_snap_t *sp, ses_walk_f func, void *arg)
{
	(void) ses_walk_node(ses_root_node(sp), func, arg);

	return (0);
}

/*ARGSUSED*/
static ses_walk_action_t
ses_fill_nodes(ses_node_t *np, void *unused)
{
	np->sn_snapshot->ss_nodes[np->sn_id] = np;

	return (SES_WALK_ACTION_CONTINUE);
}

/*
 * Given an ID returned by ses_node_id(), lookup and return the corresponding
 * node in the snapshot.  If the snapshot generation count has changed, then
 * return failure.
 */
ses_node_t *
ses_node_lookup(ses_snap_t *sp, uint64_t id)
{
	uint32_t gen = (id >> 32);
	uint32_t idx = (id & 0xFFFFFFFF);

	if (sp->ss_generation != gen) {
		(void) ses_set_errno(ESES_CHANGED);
		return (NULL);
	}

	if (idx >= sp->ss_n_nodes) {
		(void) ses_error(ESES_BAD_NODE,
		    "no such node in snapshot");
		return (NULL);
	}

	/*
	 * If this is our first lookup attempt, construct the array for fast
	 * lookups.
	 */
	if (sp->ss_nodes == NULL) {
		if ((sp->ss_nodes = ses_zalloc(
		    sp->ss_n_nodes * sizeof (void *))) == NULL)
			return (NULL);

		(void) ses_walk(sp, ses_fill_nodes, NULL);
	}

	if (sp->ss_nodes[idx] == NULL)
		(void) ses_error(ESES_BAD_NODE,
		    "no such node in snapshot");
	return (sp->ss_nodes[idx]);
}
