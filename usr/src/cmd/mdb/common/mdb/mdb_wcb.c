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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Active walks are tracked using a WCB (Walk Control Block), which is a simple
 * data structure that contains the mdb_walk_state_t passed to the various
 * walker functions for this particular walk, as well as links to other walk
 * layers if this is a layered walk.  The control block is kept in a list
 * associated with the MDB frame, so that we can clean up all the walks and
 * call their respective fini routines at the end of command processing.
 */

#include <mdb/mdb_module.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_wcb.h>
#include <mdb/mdb.h>

mdb_wcb_t *
mdb_wcb_from_state(mdb_walk_state_t *wsp)
{
	/*
	 * The walk state passed to a walker sits at the start of the
	 * walk control block, so we can ask the walker to pass this
	 * back to us and quickly obtain the control block:
	 */
	mdb_wcb_t *wcb = (mdb_wcb_t *)wsp;

	if (wcb->w_buftag != WCB_TAG_ACTIVE && wcb->w_buftag != WCB_TAG_INITIAL)
		fail("walk state %p is corrupt or not active\n", (void *)wcb);

	return (wcb);
}

mdb_wcb_t *
mdb_wcb_create(mdb_iwalker_t *iwp, mdb_walk_cb_t cb, void *data, uintptr_t addr)
{
	mdb_wcb_t *wcb = mdb_zalloc(sizeof (mdb_wcb_t), UM_SLEEP);

	wcb->w_buftag = WCB_TAG_INITIAL;
	wcb->w_walker = iwp;

	wcb->w_state.walk_callback = cb;
	wcb->w_state.walk_cbdata = data;
	wcb->w_state.walk_addr = addr;
	wcb->w_state.walk_arg = iwp->iwlk_init_arg;

	return (wcb);
}

void
mdb_wcb_destroy(mdb_wcb_t *wcb)
{
	mdb_wcb_t *p, *q;

	for (p = wcb->w_lyr_head; p != NULL; p = q) {
		q = wcb->w_lyr_link;
		mdb_wcb_destroy(p);
	}

	if (wcb->w_inited)
		wcb->w_walker->iwlk_fini(&wcb->w_state);

	mdb_free(wcb, sizeof (mdb_wcb_t));
}

void
mdb_wcb_insert(mdb_wcb_t *wcb, mdb_frame_t *fp)
{
	mdb_dprintf(MDB_DBG_WALK, "activate walk %s`%s wcb %p\n",
	    wcb->w_walker->iwlk_modp->mod_name,
	    wcb->w_walker->iwlk_name, (void *)wcb);

	wcb->w_buftag = WCB_TAG_ACTIVE;
	wcb->w_link = fp->f_wcbs;
	fp->f_wcbs = wcb;
}

void
mdb_wcb_delete(mdb_wcb_t *wcb, mdb_frame_t *fp)
{
	mdb_wcb_t **pp = &fp->f_wcbs;
	mdb_wcb_t *w;

	mdb_dprintf(MDB_DBG_WALK, "deactivate walk %s`%s wcb %p\n",
	    wcb->w_walker->iwlk_modp->mod_name,
	    wcb->w_walker->iwlk_name, (void *)wcb);

	for (w = fp->f_wcbs; w != NULL; pp = &w->w_link, w = w->w_link) {
		if (w == wcb) {
			w->w_buftag = WCB_TAG_PASSIVE;
			*pp = w->w_link;
			return;
		}
	}

	fail("attempted to remove wcb not on list: %p\n", (void *)wcb);
}

void
mdb_wcb_purge(mdb_wcb_t **wcbpp)
{
	mdb_wcb_t *n, *wcb = *wcbpp;

	while (wcb != NULL) {
		mdb_dprintf(MDB_DBG_WALK, "purge walk %s`%s wcb %p\n",
		    wcb->w_walker->iwlk_modp->mod_name,
		    wcb->w_walker->iwlk_name, (void *)wcb);

		n = wcb->w_link;
		mdb_wcb_destroy(wcb);
		wcb = n;
	}

	*wcbpp = NULL;
}
