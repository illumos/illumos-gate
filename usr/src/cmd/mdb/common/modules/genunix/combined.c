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

#include <mdb/mdb_modapi.h>

typedef struct combined_walk {
	int (*cw_init)(mdb_walk_state_t *);
	int (*cw_step)(mdb_walk_state_t *);
	void (*cw_fini)(mdb_walk_state_t *);
	struct combined_walk *cw_next;
	void *cw_data;
	boolean_t cw_initialized;
} combined_walk_t;

typedef struct combined_walk_data {
	uintptr_t cwd_initial_walk_addr;	/* to init each walk */
	combined_walk_t *cwd_current_walk;
	combined_walk_t *cwd_final_walk;	/* tail pointer */
} combined_walk_data_t;

/*
 * Initialize a combined walk to
 * A) present a single concatenated series of elements from different
 *    structures, or
 * B) select from several possible walks at runtime.
 * Multiple walks are done in the same order passed to combined_walk_add(). Each
 * walk is initialized with the same wsp->walk_addr.
 */
void
combined_walk_init(mdb_walk_state_t *wsp)
{
	combined_walk_data_t *cwd;

	cwd = mdb_alloc(sizeof (combined_walk_data_t), UM_SLEEP);

	cwd->cwd_initial_walk_addr = wsp->walk_addr;
	cwd->cwd_current_walk = cwd->cwd_final_walk = NULL;
	wsp->walk_data = cwd;
}

static void
combined_walk_append(combined_walk_data_t *cwd, combined_walk_t *cw)
{
	if (cwd->cwd_final_walk == NULL) {
		cwd->cwd_current_walk = cwd->cwd_final_walk = cw;
	} else {
		cwd->cwd_final_walk->cw_next = cw;
		cwd->cwd_final_walk = cw;
	}
}

static combined_walk_t *
combined_walk_remove_current(combined_walk_data_t *cwd)
{
	combined_walk_t *cw = cwd->cwd_current_walk;
	if (cw == NULL) {
		return (NULL);
	}
	if (cw == cwd->cwd_final_walk) {
		cwd->cwd_final_walk = cw->cw_next;
	}
	cwd->cwd_current_walk = cw->cw_next;
	cw->cw_next = NULL;
	return (cw);
}

void
combined_walk_add(mdb_walk_state_t *wsp,
	int (*walk_init)(mdb_walk_state_t *),
	int (*walk_step)(mdb_walk_state_t *),
	void (*walk_fini)(mdb_walk_state_t *))
{
	combined_walk_data_t *cwd = wsp->walk_data;
	combined_walk_t *cw;

	cw = mdb_alloc(sizeof (combined_walk_t), UM_SLEEP);

	cw->cw_init = walk_init;
	cw->cw_step = walk_step;
	cw->cw_fini = walk_fini;
	cw->cw_next = NULL;
	cw->cw_data = NULL;
	cw->cw_initialized = B_FALSE;

	combined_walk_append(cwd, cw);
}

int
combined_walk_step(mdb_walk_state_t *wsp)
{
	combined_walk_data_t *cwd = wsp->walk_data;
	combined_walk_t *cw = cwd->cwd_current_walk;
	int status;

	if (cw == NULL) {
		return (WALK_DONE);
	}

	if (cw->cw_initialized) {
		wsp->walk_data = cw->cw_data;
	} else {
		wsp->walk_addr = cwd->cwd_initial_walk_addr;
		status = cw->cw_init(wsp);
		cw->cw_data = wsp->walk_data;
		cw->cw_initialized = B_TRUE;
		if (status != WALK_NEXT) {
			wsp->walk_data = cwd;
			return (status);
		}
	}

	status = cw->cw_step(wsp);

	if (status == WALK_DONE) {
		(void) combined_walk_remove_current(cwd);
		cw->cw_fini(wsp);
		mdb_free(cw, sizeof (combined_walk_t));
		wsp->walk_data = cwd;
		return (combined_walk_step(wsp));
	}

	wsp->walk_data = cwd;
	return (status);
}

void
combined_walk_fini(mdb_walk_state_t *wsp)
{
	combined_walk_data_t *cwd = wsp->walk_data;
	combined_walk_t *cw;

	while ((cw = combined_walk_remove_current(cwd)) != NULL) {
		if (cw->cw_initialized) {
			wsp->walk_data = cw->cw_data;
			cw->cw_fini(wsp);
		}
		mdb_free(cw, sizeof (combined_walk_t));
	}

	mdb_free(cwd, sizeof (combined_walk_data_t));
}
