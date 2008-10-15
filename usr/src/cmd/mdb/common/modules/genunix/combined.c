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

	struct combined_walk_data *cwd_next;
	struct combined_walk_data *cwd_prev;
	void *cwd_tag;				/* used to find this data */
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
	cwd->cwd_next = cwd->cwd_prev = NULL;
	cwd->cwd_tag = NULL;
	wsp->walk_data = cwd;
}

/*
 * If a sub-walker's walk_step() is interrupted (by Ctrl-C or entering 'q' when
 * prompted for the next screenful of data), there won't be an opportunity to
 * switch wsp->walk_data from the sub-walker's data back to the combined walk
 * data, since control will not return from walk_step(). Since mdb is
 * single-threaded, we can save the combined walk data for combined_walk_fini()
 * to use in case it was reached from an interrupted walk_step(). To allow for
 * the possibility of nested combined walks, we'll save them on a list tagged by
 * the sub-walker's data.
 */
static combined_walk_data_t *cwd_saved;

static void
combined_walk_data_save(combined_walk_data_t *cwd, void *tag)
{
	cwd->cwd_next = cwd_saved;
	cwd->cwd_prev = NULL;
	if (cwd_saved != NULL) {
		cwd_saved->cwd_prev = cwd;
	}
	cwd_saved = cwd;
	cwd->cwd_tag = tag;
}

static void
combined_walk_data_drop(combined_walk_data_t *cwd)
{
	if (cwd->cwd_prev == NULL) {
		cwd_saved = cwd->cwd_next;
	} else {
		cwd->cwd_prev->cwd_next = cwd->cwd_next;
	}
	if (cwd->cwd_next != NULL) {
		cwd->cwd_next->cwd_prev = cwd->cwd_prev;
	}
	cwd->cwd_next = cwd->cwd_prev = NULL;
	cwd->cwd_tag = NULL;
}

static combined_walk_data_t *
combined_walk_data_find(void *tag)
{
	combined_walk_data_t *cwd;

	if (tag == NULL) {
		return (NULL);
	}

	for (cwd = cwd_saved; cwd != NULL; cwd = cwd->cwd_next) {
		if (cwd->cwd_tag == tag) {
			return (cwd);
		}
	}

	return (NULL);
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

	/* save cwd for fini() in case step() is interrupted */
	combined_walk_data_save(cwd, cw->cw_data);
	status = cw->cw_step(wsp);
	/* control may never reach here */
	combined_walk_data_drop(cwd);

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
	combined_walk_data_t *cwd;
	combined_walk_t *cw;

	/*
	 * If walk_step() was interrupted, wsp->walk_data will be the
	 * sub-walker's data, not the combined walker's data, so first check to
	 * see if there is saved combined walk data tagged by the presumed
	 * sub-walker's walk data.
	 */
	cwd = combined_walk_data_find(wsp->walk_data);
	if (cwd == NULL) {
		/*
		 * walk_step() was not interrupted, so wsp->walk_data is
		 * actually the combined walk data.
		 */
		cwd = wsp->walk_data;
	} else {
		combined_walk_data_drop(cwd);
	}

	while ((cw = combined_walk_remove_current(cwd)) != NULL) {
		if (cw->cw_initialized) {
			wsp->walk_data = cw->cw_data;
			cw->cw_fini(wsp);
		}
		mdb_free(cw, sizeof (combined_walk_t));
	}

	mdb_free(cwd, sizeof (combined_walk_data_t));
}
