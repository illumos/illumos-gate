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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file_object.c - enter objects into and load them from the backend
 *
 * The primary entry points in this layer are object_create(),
 * object_create_pg(), object_delete(), and object_fill_children().  They each
 * take an rc_node_t and use the functions in the object_info_t info array for
 * the node's type.
 */

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "configd.h"
#include "repcache_protocol.h"

typedef struct child_info {
	rc_node_t	*ci_parent;
	backend_tx_t	*ci_tx;			/* only for properties */
	rc_node_lookup_t ci_base_nl;
} child_info_t;

typedef struct delete_ent delete_ent_t;
typedef struct delete_stack delete_stack_t;
typedef struct delete_info delete_info_t;

typedef int	delete_cb_func(delete_info_t *, const delete_ent_t *);

struct delete_ent {
	delete_cb_func	*de_cb;		/* callback */
	uint32_t	de_backend;
	uint32_t	de_id;
	uint32_t	de_gen;		/* only for property groups */
};

struct delete_stack {
	struct delete_stack *ds_next;
	uint32_t	ds_size;	/* number of elements */
	uint32_t	ds_cur;		/* current offset */
	delete_ent_t	ds_buf[1];	/* actually ds_size */
};
#define	DELETE_STACK_SIZE(x)	offsetof(delete_stack_t, ds_buf[(x)])

struct delete_info {
	backend_tx_t	*di_tx;
	backend_tx_t	*di_np_tx;
	delete_stack_t	*di_stack;
	delete_stack_t	*di_free;
};

typedef struct object_info {
	uint32_t	obj_type;
	enum id_space	obj_id_space;

	int (*obj_fill_children)(rc_node_t *);
	int (*obj_setup_child_info)(rc_node_t *, uint32_t, child_info_t *);
	int (*obj_query_child)(backend_query_t *, rc_node_lookup_t *,
	    const char *);
	int (*obj_insert_child)(backend_tx_t *, rc_node_lookup_t *,
	    const char *);
	int (*obj_insert_pg_child)(backend_tx_t *, rc_node_lookup_t *,
	    const char *, const char *, uint32_t, uint32_t);
	int (*obj_delete_start)(rc_node_t *, delete_info_t *);
} object_info_t;

static void
string_to_id(const char *str, uint32_t *output, const char *fieldname)
{
	if (uu_strtouint(str, output, sizeof (*output), 0, 0, 0) == -1)
		backend_panic("invalid integer \"%s\" in field \"%s\"",
		    str, fieldname);
}

#define	NUM_NEEDED	50

static int
delete_stack_push(delete_info_t *dip, uint32_t be, delete_cb_func *cb,
    uint32_t id, uint32_t gen)
{
	delete_stack_t *cur = dip->di_stack;
	delete_ent_t *ent;

	if (cur == NULL || cur->ds_cur == cur->ds_size) {
		delete_stack_t *new = dip->di_free;
		dip->di_free = NULL;
		if (new == NULL) {
			new = uu_zalloc(DELETE_STACK_SIZE(NUM_NEEDED));
			if (new == NULL)
				return (REP_PROTOCOL_FAIL_NO_RESOURCES);
			new->ds_size = NUM_NEEDED;
		}
		new->ds_cur = 0;
		new->ds_next = dip->di_stack;
		dip->di_stack = new;
		cur = new;
	}
	assert(cur->ds_cur < cur->ds_size);
	ent = &cur->ds_buf[cur->ds_cur++];

	ent->de_backend = be;
	ent->de_cb = cb;
	ent->de_id = id;
	ent->de_gen = gen;

	return (REP_PROTOCOL_SUCCESS);
}

static int
delete_stack_pop(delete_info_t *dip, delete_ent_t *out)
{
	delete_stack_t *cur = dip->di_stack;
	delete_ent_t *ent;

	if (cur == NULL)
		return (0);
	assert(cur->ds_cur > 0 && cur->ds_cur <= cur->ds_size);
	ent = &cur->ds_buf[--cur->ds_cur];
	if (cur->ds_cur == 0) {
		dip->di_stack = cur->ds_next;
		cur->ds_next = NULL;

		if (dip->di_free != NULL)
			uu_free(dip->di_free);
		dip->di_free = cur;
	}
	if (ent == NULL)
		return (0);

	*out = *ent;
	return (1);
}

static void
delete_stack_cleanup(delete_info_t *dip)
{
	delete_stack_t *cur;
	while ((cur = dip->di_stack) != NULL) {
		dip->di_stack = cur->ds_next;

		uu_free(cur);
	}

	if ((cur = dip->di_free) != NULL) {
		assert(cur->ds_next == NULL);	/* should only be one */
		uu_free(cur);
		dip->di_free = NULL;
	}
}

struct delete_cb_info {
	delete_info_t	*dci_dip;
	uint32_t	dci_be;
	delete_cb_func	*dci_cb;
	int		dci_result;
};

/*ARGSUSED*/
static int
push_delete_callback(void *data, int columns, char **vals, char **names)
{
	struct delete_cb_info *info = data;

	const char *id_str = *vals++;
	const char *gen_str = *vals++;

	uint32_t id;
	uint32_t gen;

	assert(columns == 2);

	string_to_id(id_str, &id, "id");
	string_to_id(gen_str, &gen, "gen_id");

	info->dci_result = delete_stack_push(info->dci_dip, info->dci_be,
	    info->dci_cb, id, gen);

	if (info->dci_result != REP_PROTOCOL_SUCCESS)
		return (BACKEND_CALLBACK_ABORT);
	return (BACKEND_CALLBACK_CONTINUE);
}

static int
value_delete(delete_info_t *dip, const delete_ent_t *ent)
{
	uint32_t be = ent->de_backend;
	int r;

	backend_query_t *q;

	backend_tx_t *tx = (be == BACKEND_TYPE_NORMAL)? dip->di_tx :
	    dip->di_np_tx;

	q = backend_query_alloc();

	backend_query_add(q,
	    "SELECT 1 FROM prop_lnk_tbl WHERE (lnk_val_id = %d); "
	    "DELETE FROM value_tbl WHERE (value_id = %d); ",
	    ent->de_id, ent->de_id);
	r = backend_tx_run(tx, q, backend_fail_if_seen, NULL);
	backend_query_free(q);
	if (r == REP_PROTOCOL_DONE)
		return (REP_PROTOCOL_SUCCESS);		/* still in use */
	return (r);
}

static int
pg_lnk_tbl_delete(delete_info_t *dip, const delete_ent_t *ent)
{
	struct delete_cb_info info;
	uint32_t be = ent->de_backend;
	int r;

	backend_query_t *q;

	backend_tx_t *tx = (be == BACKEND_TYPE_NORMAL)? dip->di_tx :
	    dip->di_np_tx;

	/*
	 * For non-persistent backends, we could only have one parent, and
	 * it's already been deleted.
	 *
	 * For normal backends, we need to check to see if we're in
	 * a snapshot or are the active generation for the property
	 * group.  If we are, there's nothing to be done.
	 */
	if (be == BACKEND_TYPE_NORMAL) {
		q = backend_query_alloc();
		backend_query_add(q,
		    "SELECT 1 "
		    "FROM pg_tbl "
		    "WHERE (pg_id = %d AND pg_gen_id = %d); "
		    "SELECT 1 "
		    "FROM snaplevel_lnk_tbl "
		    "WHERE (snaplvl_pg_id = %d AND snaplvl_gen_id = %d);",
		    ent->de_id, ent->de_gen,
		    ent->de_id, ent->de_gen);
		r = backend_tx_run(tx, q, backend_fail_if_seen, NULL);
		backend_query_free(q);

		if (r == REP_PROTOCOL_DONE)
			return (REP_PROTOCOL_SUCCESS);	/* still in use */
	}

	info.dci_dip = dip;
	info.dci_be =  be;
	info.dci_cb = &value_delete;
	info.dci_result = REP_PROTOCOL_SUCCESS;

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT DISTINCT lnk_val_id, 0 FROM prop_lnk_tbl "
	    "WHERE "
	    "    (lnk_pg_id = %d AND lnk_gen_id = %d AND lnk_val_id NOTNULL); "
	    "DELETE FROM prop_lnk_tbl "
	    "WHERE (lnk_pg_id = %d AND lnk_gen_id = %d)",
	    ent->de_id, ent->de_gen, ent->de_id, ent->de_gen);

	r = backend_tx_run(tx, q, push_delete_callback, &info);
	backend_query_free(q);

	if (r == REP_PROTOCOL_DONE) {
		assert(info.dci_result != REP_PROTOCOL_SUCCESS);
		return (info.dci_result);
	}
	return (r);
}

static int
propertygrp_delete(delete_info_t *dip, const delete_ent_t *ent)
{
	uint32_t be = ent->de_backend;
	backend_query_t *q;
	uint32_t gen;

	int r;

	backend_tx_t *tx = (be == BACKEND_TYPE_NORMAL)? dip->di_tx :
	    dip->di_np_tx;

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT pg_gen_id FROM pg_tbl WHERE pg_id = %d; "
	    "DELETE FROM pg_tbl WHERE pg_id = %d",
	    ent->de_id, ent->de_id);
	r = backend_tx_run_single_int(tx, q, &gen);
	backend_query_free(q);

	if (r != REP_PROTOCOL_SUCCESS)
		return (r);

	return (delete_stack_push(dip, be, &pg_lnk_tbl_delete,
	    ent->de_id, gen));
}

static int
snaplevel_lnk_delete(delete_info_t *dip, const delete_ent_t *ent)
{
	uint32_t be = ent->de_backend;
	backend_query_t *q;
	struct delete_cb_info info;

	int r;

	backend_tx_t *tx = (be == BACKEND_TYPE_NORMAL)? dip->di_tx :
	    dip->di_np_tx;

	info.dci_dip = dip;
	info.dci_be = be;
	info.dci_cb = &pg_lnk_tbl_delete;
	info.dci_result = REP_PROTOCOL_SUCCESS;

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT snaplvl_pg_id, snaplvl_gen_id "
	    "    FROM snaplevel_lnk_tbl "
	    "    WHERE snaplvl_level_id = %d; "
	    "DELETE FROM snaplevel_lnk_tbl WHERE snaplvl_level_id = %d",
	    ent->de_id, ent->de_id);
	r = backend_tx_run(tx, q, push_delete_callback, &info);
	backend_query_free(q);

	if (r == REP_PROTOCOL_DONE) {
		assert(info.dci_result != REP_PROTOCOL_SUCCESS);
		return (info.dci_result);
	}
	return (r);
}

static int
snaplevel_tbl_delete(delete_info_t *dip, const delete_ent_t *ent)
{
	uint32_t be = ent->de_backend;
	backend_tx_t *tx = (be == BACKEND_TYPE_NORMAL)? dip->di_tx :
	    dip->di_np_tx;

	struct delete_cb_info info;
	backend_query_t *q;
	int r;

	assert(be == BACKEND_TYPE_NORMAL);

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT 1 FROM snapshot_lnk_tbl WHERE lnk_snap_id = %d",
	    ent->de_id);
	r = backend_tx_run(tx, q, backend_fail_if_seen, NULL);
	backend_query_free(q);

	if (r == REP_PROTOCOL_DONE)
		return (REP_PROTOCOL_SUCCESS);		/* still in use */

	info.dci_dip = dip;
	info.dci_be = be;
	info.dci_cb = &snaplevel_lnk_delete;
	info.dci_result = REP_PROTOCOL_SUCCESS;

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT snap_level_id, 0 FROM snaplevel_tbl WHERE snap_id = %d;"
	    "DELETE FROM snaplevel_tbl WHERE snap_id = %d",
	    ent->de_id, ent->de_id);
	r = backend_tx_run(tx, q, push_delete_callback, &info);
	backend_query_free(q);

	if (r == REP_PROTOCOL_DONE) {
		assert(info.dci_result != REP_PROTOCOL_SUCCESS);
		return (info.dci_result);
	}
	return (r);
}

static int
snapshot_lnk_delete(delete_info_t *dip, const delete_ent_t *ent)
{
	uint32_t be = ent->de_backend;
	backend_tx_t *tx = (be == BACKEND_TYPE_NORMAL)? dip->di_tx :
	    dip->di_np_tx;

	backend_query_t *q;
	uint32_t snapid;
	int r;

	assert(be == BACKEND_TYPE_NORMAL);

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT lnk_snap_id FROM snapshot_lnk_tbl WHERE lnk_id = %d; "
	    "DELETE FROM snapshot_lnk_tbl WHERE lnk_id = %d",
	    ent->de_id, ent->de_id);
	r = backend_tx_run_single_int(tx, q, &snapid);
	backend_query_free(q);

	if (r != REP_PROTOCOL_SUCCESS)
		return (r);

	return (delete_stack_push(dip, be, &snaplevel_tbl_delete, snapid, 0));
}

static int
pgparent_delete_add_pgs(delete_info_t *dip, uint32_t parent_id)
{
	struct delete_cb_info info;
	backend_query_t *q;
	int r;

	info.dci_dip = dip;
	info.dci_be = BACKEND_TYPE_NORMAL;
	info.dci_cb = &propertygrp_delete;
	info.dci_result = REP_PROTOCOL_SUCCESS;

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT pg_id, 0 FROM pg_tbl WHERE pg_parent_id = %d",
	    parent_id);

	r = backend_tx_run(dip->di_tx, q, push_delete_callback, &info);

	if (r == REP_PROTOCOL_DONE) {
		assert(info.dci_result != REP_PROTOCOL_SUCCESS);
		backend_query_free(q);
		return (info.dci_result);
	}
	if (r != REP_PROTOCOL_SUCCESS) {
		backend_query_free(q);
		return (r);
	}

	if (dip->di_np_tx != NULL) {
		info.dci_be = BACKEND_TYPE_NONPERSIST;

		r = backend_tx_run(dip->di_np_tx, q, push_delete_callback,
		    &info);

		if (r == REP_PROTOCOL_DONE) {
			assert(info.dci_result != REP_PROTOCOL_SUCCESS);
			backend_query_free(q);
			return (info.dci_result);
		}
		if (r != REP_PROTOCOL_SUCCESS) {
			backend_query_free(q);
			return (r);
		}
	}
	backend_query_free(q);
	return (REP_PROTOCOL_SUCCESS);
}

static int
service_delete(delete_info_t *dip, const delete_ent_t *ent)
{
	int r;

	r = backend_tx_run_update_changed(dip->di_tx,
	    "DELETE FROM service_tbl WHERE svc_id = %d", ent->de_id);
	if (r != REP_PROTOCOL_SUCCESS)
		return (r);

	return (pgparent_delete_add_pgs(dip, ent->de_id));
}

static int
instance_delete(delete_info_t *dip, const delete_ent_t *ent)
{
	struct delete_cb_info info;
	int r;
	backend_query_t *q;

	r = backend_tx_run_update_changed(dip->di_tx,
	    "DELETE FROM instance_tbl WHERE instance_id = %d", ent->de_id);
	if (r != REP_PROTOCOL_SUCCESS)
		return (r);

	r = pgparent_delete_add_pgs(dip, ent->de_id);
	if (r != REP_PROTOCOL_SUCCESS)
		return (r);

	info.dci_dip = dip;
	info.dci_be = BACKEND_TYPE_NORMAL;
	info.dci_cb = &snapshot_lnk_delete;
	info.dci_result = REP_PROTOCOL_SUCCESS;

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT lnk_id, 0 FROM snapshot_lnk_tbl WHERE lnk_inst_id = %d",
	    ent->de_id);
	r = backend_tx_run(dip->di_tx, q, push_delete_callback, &info);
	backend_query_free(q);

	if (r == REP_PROTOCOL_DONE) {
		assert(info.dci_result != REP_PROTOCOL_SUCCESS);
		return (info.dci_result);
	}
	return (r);
}

/*ARGSUSED*/
static int
fill_child_callback(void *data, int columns, char **vals, char **names)
{
	child_info_t *cp = data;
	rc_node_t *np;
	uint32_t main_id;
	const char *name;
	const char *cur;
	rc_node_lookup_t *lp = &cp->ci_base_nl;

	assert(columns == 2);

	name = *vals++;
	columns--;

	cur = *vals++;
	columns--;
	string_to_id(cur, &main_id, "id");

	lp->rl_main_id = main_id;

	if ((np = rc_node_alloc()) == NULL)
		return (BACKEND_CALLBACK_ABORT);

	np = rc_node_setup(np, lp, name, cp->ci_parent);
	rc_node_rele(np);

	return (BACKEND_CALLBACK_CONTINUE);
}

/*ARGSUSED*/
static int
fill_snapshot_callback(void *data, int columns, char **vals, char **names)
{
	child_info_t *cp = data;
	rc_node_t *np;
	uint32_t main_id;
	uint32_t snap_id;
	const char *name;
	const char *cur;
	const char *snap;
	rc_node_lookup_t *lp = &cp->ci_base_nl;

	assert(columns == 3);

	name = *vals++;
	columns--;

	cur = *vals++;
	columns--;
	snap = *vals++;
	columns--;

	string_to_id(cur, &main_id, "lnk_id");
	string_to_id(snap, &snap_id, "lnk_snap_id");

	lp->rl_main_id = main_id;

	if ((np = rc_node_alloc()) == NULL)
		return (BACKEND_CALLBACK_ABORT);

	np = rc_node_setup_snapshot(np, lp, name, snap_id, cp->ci_parent);
	rc_node_rele(np);

	return (BACKEND_CALLBACK_CONTINUE);
}

/*ARGSUSED*/
static int
fill_pg_callback(void *data, int columns, char **vals, char **names)
{
	child_info_t *cip = data;
	const char *name;
	const char *type;
	const char *cur;
	uint32_t main_id;
	uint32_t flags;
	uint32_t gen_id;

	rc_node_lookup_t *lp = &cip->ci_base_nl;
	rc_node_t *newnode, *pg;

	assert(columns == 5);

	name = *vals++;		/* pg_name */
	columns--;

	cur = *vals++;		/* pg_id */
	columns--;
	string_to_id(cur, &main_id, "pg_id");

	lp->rl_main_id = main_id;

	cur = *vals++;		/* pg_gen_id */
	columns--;
	string_to_id(cur, &gen_id, "pg_gen_id");

	type = *vals++;		/* pg_type */
	columns--;

	cur = *vals++;		/* pg_flags */
	columns--;
	string_to_id(cur, &flags, "pg_flags");

	if ((newnode = rc_node_alloc()) == NULL)
		return (BACKEND_CALLBACK_ABORT);

	pg = rc_node_setup_pg(newnode, lp, name, type, flags, gen_id,
	    cip->ci_parent);
	if (pg == NULL) {
		rc_node_destroy(newnode);
		return (BACKEND_CALLBACK_ABORT);
	}

	rc_node_rele(pg);

	return (BACKEND_CALLBACK_CONTINUE);
}

struct property_value_info {
	char		*pvi_base;
	size_t		pvi_pos;
	size_t		pvi_size;
	size_t		pvi_count;
};

/*ARGSUSED*/
static int
property_value_size_cb(void *data, int columns, char **vals, char **names)
{
	struct property_value_info *info = data;
	assert(columns == 1);

	info->pvi_size += strlen(vals[0]) + 1;		/* count the '\0' */

	return (BACKEND_CALLBACK_CONTINUE);
}

/*ARGSUSED*/
static int
property_value_cb(void *data, int columns, char **vals, char **names)
{
	struct property_value_info *info = data;
	size_t pos, left, len;

	assert(columns == 1);
	pos = info->pvi_pos;
	left = info->pvi_size - pos;

	pos = info->pvi_pos;
	left = info->pvi_size - pos;

	if ((len = strlcpy(&info->pvi_base[pos], vals[0], left)) >= left) {
		/*
		 * since we preallocated, above, this shouldn't happen
		 */
		backend_panic("unexpected database change");
	}

	len += 1;	/* count the '\0' */

	info->pvi_pos += len;
	info->pvi_count++;

	return (BACKEND_CALLBACK_CONTINUE);
}

/*ARGSUSED*/
void
object_free_values(const char *vals, uint32_t type, size_t count, size_t size)
{
	if (vals != NULL)
		uu_free((void *)vals);
}

/*ARGSUSED*/
static int
fill_property_callback(void *data, int columns, char **vals, char **names)
{
	child_info_t *cp = data;
	backend_tx_t *tx = cp->ci_tx;
	uint32_t main_id;
	const char *name;
	const char *cur;
	rep_protocol_value_type_t type;
	rc_node_lookup_t *lp = &cp->ci_base_nl;
	struct property_value_info info;
	int rc;

	assert(columns == 4);
	assert(tx != NULL);

	info.pvi_base = NULL;
	info.pvi_pos = 0;
	info.pvi_size = 0;
	info.pvi_count = 0;

	name = *vals++;

	cur = *vals++;
	string_to_id(cur, &main_id, "lnk_prop_id");

	cur = *vals++;
	assert(('a' <= cur[0] && 'z' >= cur[0]) ||
	    ('A' <= cur[0] && 'Z' >= cur[0]) &&
	    (cur[1] == 0 || ('a' <= cur[1] && 'z' >= cur[1]) ||
	    ('A' <= cur[1] && 'Z' >= cur[1])));
	type = cur[0] | (cur[1] << 8);

	lp->rl_main_id = main_id;

	/*
	 * fill in the values, if any
	 */
	if ((cur = *vals++) != NULL) {
		rep_protocol_responseid_t r;
		backend_query_t *q = backend_query_alloc();

		/*
		 * Ensure that select operation is reflective
		 * of repository schema.  If the repository has
		 * been upgraded,  make use of value ordering
		 * by retrieving values in order using the
		 * value_order column.  Otherwise, simply
		 * run the select with no order specified.
		 * The order-insensitive select is necessary
		 * as on first reboot post-upgrade,  the repository
		 * contents need to be read before the repository
		 * backend is writable (and upgrade is possible).
		 */
		if (backend_is_upgraded(tx)) {
			backend_query_add(q,
			    "SELECT value_value FROM value_tbl "
			    "WHERE (value_id = '%q') ORDER BY value_order",
			    cur);
		} else {
			backend_query_add(q,
			    "SELECT value_value FROM value_tbl "
			    "WHERE (value_id = '%q')",
			    cur);
		}

		switch (r = backend_tx_run(tx, q, property_value_size_cb,
		    &info)) {
		case REP_PROTOCOL_SUCCESS:
			break;

		case REP_PROTOCOL_FAIL_NO_RESOURCES:
			backend_query_free(q);
			return (BACKEND_CALLBACK_ABORT);

		case REP_PROTOCOL_DONE:
		default:
			backend_panic("backend_tx_run() returned %d", r);
		}
		if (info.pvi_size > 0) {
			info.pvi_base = uu_zalloc(info.pvi_size);
			if (info.pvi_base == NULL) {
				backend_query_free(q);
				return (BACKEND_CALLBACK_ABORT);
			}
			switch (r = backend_tx_run(tx, q, property_value_cb,
			    &info)) {
			case REP_PROTOCOL_SUCCESS:
				break;

			case REP_PROTOCOL_FAIL_NO_RESOURCES:
				uu_free(info.pvi_base);
				backend_query_free(q);
				return (BACKEND_CALLBACK_ABORT);

			case REP_PROTOCOL_DONE:
			default:
				backend_panic("backend_tx_run() returned %d",
				    r);
			}
		}
		backend_query_free(q);
	}

	rc = rc_node_create_property(cp->ci_parent, lp, name, type,
	    info.pvi_base, info.pvi_count, info.pvi_size);
	if (rc != REP_PROTOCOL_SUCCESS) {
		assert(rc == REP_PROTOCOL_FAIL_NO_RESOURCES);
		return (BACKEND_CALLBACK_ABORT);
	}

	return (BACKEND_CALLBACK_CONTINUE);
}

/*
 * The *_setup_child_info() functions fill in a child_info_t structure with the
 * information for the children of np with type type.
 *
 * They fail with
 *   _TYPE_MISMATCH - object cannot have children of type type
 */

static int
scope_setup_child_info(rc_node_t *np, uint32_t type, child_info_t *cip)
{
	if (type != REP_PROTOCOL_ENTITY_SERVICE)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	bzero(cip, sizeof (*cip));
	cip->ci_parent = np;
	cip->ci_base_nl.rl_type = type;
	cip->ci_base_nl.rl_backend = np->rn_id.rl_backend;
	return (REP_PROTOCOL_SUCCESS);
}

static int
service_setup_child_info(rc_node_t *np, uint32_t type, child_info_t *cip)
{
	switch (type) {
	case REP_PROTOCOL_ENTITY_INSTANCE:
	case REP_PROTOCOL_ENTITY_PROPERTYGRP:
		break;
	default:
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	bzero(cip, sizeof (*cip));
	cip->ci_parent = np;
	cip->ci_base_nl.rl_type = type;
	cip->ci_base_nl.rl_backend = np->rn_id.rl_backend;
	cip->ci_base_nl.rl_ids[ID_SERVICE] = np->rn_id.rl_main_id;

	return (REP_PROTOCOL_SUCCESS);
}

static int
instance_setup_child_info(rc_node_t *np, uint32_t type, child_info_t *cip)
{
	switch (type) {
	case REP_PROTOCOL_ENTITY_PROPERTYGRP:
	case REP_PROTOCOL_ENTITY_SNAPSHOT:
		break;
	default:
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);
	}

	bzero(cip, sizeof (*cip));
	cip->ci_parent = np;
	cip->ci_base_nl.rl_type = type;
	cip->ci_base_nl.rl_backend = np->rn_id.rl_backend;
	cip->ci_base_nl.rl_ids[ID_SERVICE] = np->rn_id.rl_ids[ID_SERVICE];
	cip->ci_base_nl.rl_ids[ID_INSTANCE] = np->rn_id.rl_main_id;

	return (REP_PROTOCOL_SUCCESS);
}

static int
snaplevel_setup_child_info(rc_node_t *np, uint32_t type, child_info_t *cip)
{
	if (type != REP_PROTOCOL_ENTITY_PROPERTYGRP)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	bzero(cip, sizeof (*cip));
	cip->ci_parent = np;
	cip->ci_base_nl.rl_type = type;
	cip->ci_base_nl.rl_backend = np->rn_id.rl_backend;
	cip->ci_base_nl.rl_ids[ID_SERVICE] = np->rn_id.rl_ids[ID_SERVICE];
	cip->ci_base_nl.rl_ids[ID_INSTANCE] = np->rn_id.rl_ids[ID_INSTANCE];
	cip->ci_base_nl.rl_ids[ID_NAME] = np->rn_id.rl_ids[ID_NAME];
	cip->ci_base_nl.rl_ids[ID_SNAPSHOT] = np->rn_id.rl_ids[ID_SNAPSHOT];
	cip->ci_base_nl.rl_ids[ID_LEVEL] = np->rn_id.rl_main_id;

	return (REP_PROTOCOL_SUCCESS);
}

static int
propertygrp_setup_child_info(rc_node_t *pg, uint32_t type, child_info_t *cip)
{
	if (type != REP_PROTOCOL_ENTITY_PROPERTY)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	bzero(cip, sizeof (*cip));
	cip->ci_parent = pg;
	cip->ci_base_nl.rl_type = type;
	cip->ci_base_nl.rl_backend = pg->rn_id.rl_backend;
	cip->ci_base_nl.rl_ids[ID_SERVICE] = pg->rn_id.rl_ids[ID_SERVICE];
	cip->ci_base_nl.rl_ids[ID_INSTANCE] = pg->rn_id.rl_ids[ID_INSTANCE];
	cip->ci_base_nl.rl_ids[ID_PG] = pg->rn_id.rl_main_id;
	cip->ci_base_nl.rl_ids[ID_GEN] = pg->rn_gen_id;
	cip->ci_base_nl.rl_ids[ID_NAME] = pg->rn_id.rl_ids[ID_NAME];
	cip->ci_base_nl.rl_ids[ID_SNAPSHOT] = pg->rn_id.rl_ids[ID_SNAPSHOT];
	cip->ci_base_nl.rl_ids[ID_LEVEL] = pg->rn_id.rl_ids[ID_LEVEL];

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * The *_fill_children() functions populate the children of the given rc_node_t
 * by querying the database and calling rc_node_setup_*() functions (usually
 * via a fill_*_callback()).
 *
 * They fail with
 *   _NO_RESOURCES
 */

/*
 * Returns
 *   _NO_RESOURCES
 *   _SUCCESS
 */
static int
scope_fill_children(rc_node_t *np)
{
	backend_query_t *q;
	child_info_t ci;
	int res;

	(void) scope_setup_child_info(np, REP_PROTOCOL_ENTITY_SERVICE, &ci);

	q = backend_query_alloc();
	backend_query_append(q, "SELECT svc_name, svc_id FROM service_tbl");
	res = backend_run(BACKEND_TYPE_NORMAL, q, fill_child_callback, &ci);
	backend_query_free(q);

	if (res == REP_PROTOCOL_DONE)
		res = REP_PROTOCOL_FAIL_NO_RESOURCES;
	return (res);
}

/*
 * Returns
 *   _NO_RESOURCES
 *   _SUCCESS
 */
static int
service_fill_children(rc_node_t *np)
{
	backend_query_t *q;
	child_info_t ci;
	int res;

	assert(np->rn_id.rl_backend == BACKEND_TYPE_NORMAL);

	(void) service_setup_child_info(np, REP_PROTOCOL_ENTITY_INSTANCE, &ci);

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT instance_name, instance_id FROM instance_tbl"
	    "    WHERE (instance_svc = %d)",
	    np->rn_id.rl_main_id);
	res = backend_run(BACKEND_TYPE_NORMAL, q, fill_child_callback, &ci);
	backend_query_free(q);

	if (res == REP_PROTOCOL_DONE)
		res = REP_PROTOCOL_FAIL_NO_RESOURCES;
	if (res != REP_PROTOCOL_SUCCESS)
		return (res);

	(void) service_setup_child_info(np, REP_PROTOCOL_ENTITY_PROPERTYGRP,
	    &ci);

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT pg_name, pg_id, pg_gen_id, pg_type, pg_flags FROM pg_tbl"
	    "    WHERE (pg_parent_id = %d)",
	    np->rn_id.rl_main_id);

	ci.ci_base_nl.rl_backend = BACKEND_TYPE_NORMAL;
	res = backend_run(BACKEND_TYPE_NORMAL, q, fill_pg_callback, &ci);
	if (res == REP_PROTOCOL_SUCCESS) {
		ci.ci_base_nl.rl_backend = BACKEND_TYPE_NONPERSIST;
		res = backend_run(BACKEND_TYPE_NONPERSIST, q,
		    fill_pg_callback, &ci);
		/* nonpersistant database may not exist */
		if (res == REP_PROTOCOL_FAIL_BACKEND_ACCESS)
			res = REP_PROTOCOL_SUCCESS;
	}
	if (res == REP_PROTOCOL_DONE)
		res = REP_PROTOCOL_FAIL_NO_RESOURCES;
	backend_query_free(q);

	return (res);
}

/*
 * Returns
 *   _NO_RESOURCES
 *   _SUCCESS
 */
static int
instance_fill_children(rc_node_t *np)
{
	backend_query_t *q;
	child_info_t ci;
	int res;

	assert(np->rn_id.rl_backend == BACKEND_TYPE_NORMAL);

	/* Get child property groups */
	(void) instance_setup_child_info(np, REP_PROTOCOL_ENTITY_PROPERTYGRP,
	    &ci);

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT pg_name, pg_id, pg_gen_id, pg_type, pg_flags FROM pg_tbl"
	    "    WHERE (pg_parent_id = %d)",
	    np->rn_id.rl_main_id);
	ci.ci_base_nl.rl_backend = BACKEND_TYPE_NORMAL;
	res = backend_run(BACKEND_TYPE_NORMAL, q, fill_pg_callback, &ci);
	if (res == REP_PROTOCOL_SUCCESS) {
		ci.ci_base_nl.rl_backend = BACKEND_TYPE_NONPERSIST;
		res = backend_run(BACKEND_TYPE_NONPERSIST, q,
		    fill_pg_callback, &ci);
		/* nonpersistant database may not exist */
		if (res == REP_PROTOCOL_FAIL_BACKEND_ACCESS)
			res = REP_PROTOCOL_SUCCESS;
	}
	if (res == REP_PROTOCOL_DONE)
		res = REP_PROTOCOL_FAIL_NO_RESOURCES;
	backend_query_free(q);

	if (res != REP_PROTOCOL_SUCCESS)
		return (res);

	/* Get child snapshots */
	(void) instance_setup_child_info(np, REP_PROTOCOL_ENTITY_SNAPSHOT,
	    &ci);

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT lnk_snap_name, lnk_id, lnk_snap_id FROM snapshot_lnk_tbl"
	    "    WHERE (lnk_inst_id = %d)",
	    np->rn_id.rl_main_id);
	res = backend_run(BACKEND_TYPE_NORMAL, q, fill_snapshot_callback, &ci);
	if (res == REP_PROTOCOL_DONE)
		res = REP_PROTOCOL_FAIL_NO_RESOURCES;
	backend_query_free(q);

	return (res);
}

/*
 * Returns
 *   _NO_RESOURCES
 *   _SUCCESS
 */
static int
snapshot_fill_children(rc_node_t *np)
{
	rc_node_t *nnp;
	rc_snapshot_t *sp, *oldsp;
	rc_snaplevel_t *lvl;
	rc_node_lookup_t nl;
	int r;

	/* Get the rc_snapshot_t (& its rc_snaplevel_t's). */
	(void) pthread_mutex_lock(&np->rn_lock);
	sp = np->rn_snapshot;
	(void) pthread_mutex_unlock(&np->rn_lock);
	if (sp == NULL) {
		r = rc_snapshot_get(np->rn_snapshot_id, &sp);
		if (r != REP_PROTOCOL_SUCCESS) {
			assert(r == REP_PROTOCOL_FAIL_NO_RESOURCES);
			return (r);
		}
		(void) pthread_mutex_lock(&np->rn_lock);
		oldsp = np->rn_snapshot;
		assert(oldsp == NULL || oldsp == sp);
		np->rn_snapshot = sp;
		(void) pthread_mutex_unlock(&np->rn_lock);
		if (oldsp != NULL)
			rc_snapshot_rele(oldsp);
	}

	bzero(&nl, sizeof (nl));
	nl.rl_type = REP_PROTOCOL_ENTITY_SNAPLEVEL;
	nl.rl_backend = np->rn_id.rl_backend;
	nl.rl_ids[ID_SERVICE] = np->rn_id.rl_ids[ID_SERVICE];
	nl.rl_ids[ID_INSTANCE] = np->rn_id.rl_ids[ID_INSTANCE];
	nl.rl_ids[ID_NAME] = np->rn_id.rl_main_id;
	nl.rl_ids[ID_SNAPSHOT] = np->rn_snapshot_id;

	/* Create rc_node_t's for the snapshot's rc_snaplevel_t's. */
	for (lvl = sp->rs_levels; lvl != NULL; lvl = lvl->rsl_next) {
		nnp = rc_node_alloc();
		assert(nnp != NULL);
		nl.rl_main_id = lvl->rsl_level_id;
		nnp = rc_node_setup_snaplevel(nnp, &nl, lvl, np);
		rc_node_rele(nnp);
	}

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Returns
 *   _NO_RESOURCES
 *   _SUCCESS
 */
static int
snaplevel_fill_children(rc_node_t *np)
{
	rc_snaplevel_t *lvl = np->rn_snaplevel;
	child_info_t ci;
	int res;
	backend_query_t *q;

	(void) snaplevel_setup_child_info(np, REP_PROTOCOL_ENTITY_PROPERTYGRP,
	    &ci);

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT snaplvl_pg_name, snaplvl_pg_id, snaplvl_gen_id, "
	    "    snaplvl_pg_type, snaplvl_pg_flags "
	    "    FROM snaplevel_lnk_tbl "
	    "    WHERE (snaplvl_level_id = %d)",
	    lvl->rsl_level_id);
	res = backend_run(BACKEND_TYPE_NORMAL, q, fill_pg_callback, &ci);
	if (res == REP_PROTOCOL_DONE)
		res = REP_PROTOCOL_FAIL_NO_RESOURCES;
	backend_query_free(q);

	return (res);
}

/*
 * Returns
 *   _NO_RESOURCES
 *   _SUCCESS
 */
static int
propertygrp_fill_children(rc_node_t *np)
{
	backend_query_t *q;
	child_info_t ci;
	int res;
	backend_tx_t *tx;

	backend_type_t backend = np->rn_id.rl_backend;

	(void) propertygrp_setup_child_info(np, REP_PROTOCOL_ENTITY_PROPERTY,
	    &ci);

	res = backend_tx_begin_ro(backend, &tx);
	if (res != REP_PROTOCOL_SUCCESS) {
		/*
		 * If the backend didn't exist, we wouldn't have got this
		 * property group.
		 */
		assert(res != REP_PROTOCOL_FAIL_BACKEND_ACCESS);
		return (res);
	}

	ci.ci_tx = tx;

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT lnk_prop_name, lnk_prop_id, lnk_prop_type, lnk_val_id "
	    "FROM prop_lnk_tbl "
	    "WHERE (lnk_pg_id = %d AND lnk_gen_id = %d)",
	    np->rn_id.rl_main_id, np->rn_gen_id);
	res = backend_tx_run(tx, q, fill_property_callback, &ci);
	if (res == REP_PROTOCOL_DONE)
		res = REP_PROTOCOL_FAIL_NO_RESOURCES;
	backend_query_free(q);
	backend_tx_end_ro(tx);

	return (res);
}

/*
 * Fails with
 *   _TYPE_MISMATCH - lp is not for a service
 *   _INVALID_TYPE - lp has invalid type
 *   _BAD_REQUEST - name is invalid
 */
static int
scope_query_child(backend_query_t *q, rc_node_lookup_t *lp, const char *name)
{
	uint32_t type = lp->rl_type;
	int rc;

	if (type != REP_PROTOCOL_ENTITY_SERVICE)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	if ((rc = rc_check_type_name(type, name)) != REP_PROTOCOL_SUCCESS)
		return (rc);

	backend_query_add(q,
	    "SELECT svc_id FROM service_tbl "
	    "WHERE svc_name = '%q'",
	    name);

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _NO_RESOURCES - out of memory
 */
static int
scope_insert_child(backend_tx_t *tx, rc_node_lookup_t *lp, const char *name)
{
	return (backend_tx_run_update(tx,
	    "INSERT INTO service_tbl (svc_id, svc_name) "
	    "VALUES (%d, '%q')",
	    lp->rl_main_id, name));
}

/*
 * Fails with
 *   _TYPE_MISMATCH - lp is not for an instance or property group
 *   _INVALID_TYPE - lp has invalid type
 *   _BAD_REQUEST - name is invalid
 */
static int
service_query_child(backend_query_t *q, rc_node_lookup_t *lp, const char *name)
{
	uint32_t type = lp->rl_type;
	int rc;

	if (type != REP_PROTOCOL_ENTITY_INSTANCE &&
	    type != REP_PROTOCOL_ENTITY_PROPERTYGRP)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	if ((rc = rc_check_type_name(type, name)) != REP_PROTOCOL_SUCCESS)
		return (rc);

	switch (type) {
	case REP_PROTOCOL_ENTITY_INSTANCE:
		backend_query_add(q,
		    "SELECT instance_id FROM instance_tbl "
		    "WHERE instance_name = '%q' AND instance_svc = %d",
		    name, lp->rl_ids[ID_SERVICE]);
		break;
	case REP_PROTOCOL_ENTITY_PROPERTYGRP:
		backend_query_add(q,
		    "SELECT pg_id FROM pg_tbl "
		    "    WHERE pg_name = '%q' AND pg_parent_id = %d",
		    name, lp->rl_ids[ID_SERVICE]);
		break;
	default:
		assert(0);
		abort();
	}

	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _NO_RESOURCES - out of memory
 */
static int
service_insert_child(backend_tx_t *tx, rc_node_lookup_t *lp, const char *name)
{
	return (backend_tx_run_update(tx,
	    "INSERT INTO instance_tbl "
	    "    (instance_id, instance_name, instance_svc) "
	    "VALUES (%d, '%q', %d)",
	    lp->rl_main_id, name, lp->rl_ids[ID_SERVICE]));
}

/*
 * Fails with
 *   _NO_RESOURCES - out of memory
 */
static int
instance_insert_child(backend_tx_t *tx, rc_node_lookup_t *lp, const char *name)
{
	return (backend_tx_run_update(tx,
	    "INSERT INTO snapshot_lnk_tbl "
	    "    (lnk_id, lnk_inst_id, lnk_snap_name, lnk_snap_id) "
	    "VALUES (%d, %d, '%q', 0)",
	    lp->rl_main_id, lp->rl_ids[ID_INSTANCE], name));
}

/*
 * Fails with
 *   _TYPE_MISMATCH - lp is not for a property group or snapshot
 *   _INVALID_TYPE - lp has invalid type
 *   _BAD_REQUEST - name is invalid
 */
static int
instance_query_child(backend_query_t *q, rc_node_lookup_t *lp, const char *name)
{
	uint32_t type = lp->rl_type;
	int rc;

	if (type != REP_PROTOCOL_ENTITY_PROPERTYGRP &&
	    type != REP_PROTOCOL_ENTITY_SNAPSHOT)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	if ((rc = rc_check_type_name(type, name)) != REP_PROTOCOL_SUCCESS)
		return (rc);

	switch (type) {
	case REP_PROTOCOL_ENTITY_PROPERTYGRP:
		backend_query_add(q,
		    "SELECT pg_id FROM pg_tbl "
		    "    WHERE pg_name = '%q' AND pg_parent_id = %d",
		    name, lp->rl_ids[ID_INSTANCE]);
		break;
	case REP_PROTOCOL_ENTITY_SNAPSHOT:
		backend_query_add(q,
		    "SELECT lnk_id FROM snapshot_lnk_tbl "
		    "    WHERE lnk_snap_name = '%q' AND lnk_inst_id = %d",
		    name, lp->rl_ids[ID_INSTANCE]);
		break;
	default:
		assert(0);
		abort();
	}

	return (REP_PROTOCOL_SUCCESS);
}

static int
generic_insert_pg_child(backend_tx_t *tx, rc_node_lookup_t *lp,
    const char *name, const char *pgtype, uint32_t flags, uint32_t gen)
{
	int parent_id = (lp->rl_ids[ID_INSTANCE] != 0)?
	    lp->rl_ids[ID_INSTANCE] : lp->rl_ids[ID_SERVICE];
	return (backend_tx_run_update(tx,
	    "INSERT INTO pg_tbl "
	    "    (pg_id, pg_name, pg_parent_id, pg_type, pg_flags, pg_gen_id) "
	    "VALUES (%d, '%q', %d, '%q', %d, %d)",
	    lp->rl_main_id, name, parent_id, pgtype, flags, gen));
}

static int
service_delete_start(rc_node_t *np, delete_info_t *dip)
{
	int r;
	backend_query_t *q = backend_query_alloc();

	/*
	 * Check for child instances, and refuse to delete if they exist.
	 */
	backend_query_add(q,
	    "SELECT 1 FROM instance_tbl WHERE instance_svc = %d",
	    np->rn_id.rl_main_id);

	r = backend_tx_run(dip->di_tx, q, backend_fail_if_seen, NULL);
	backend_query_free(q);

	if (r == REP_PROTOCOL_DONE)
		return (REP_PROTOCOL_FAIL_EXISTS);	/* instances exist */

	return (delete_stack_push(dip, BACKEND_TYPE_NORMAL, &service_delete,
	    np->rn_id.rl_main_id, 0));
}

static int
instance_delete_start(rc_node_t *np, delete_info_t *dip)
{
	return (delete_stack_push(dip, BACKEND_TYPE_NORMAL, &instance_delete,
	    np->rn_id.rl_main_id, 0));
}

static int
snapshot_delete_start(rc_node_t *np, delete_info_t *dip)
{
	return (delete_stack_push(dip, BACKEND_TYPE_NORMAL,
	    &snapshot_lnk_delete, np->rn_id.rl_main_id, 0));
}

static int
propertygrp_delete_start(rc_node_t *np, delete_info_t *dip)
{
	return (delete_stack_push(dip, np->rn_id.rl_backend,
	    &propertygrp_delete, np->rn_id.rl_main_id, 0));
}

static object_info_t info[] = {
	{REP_PROTOCOL_ENTITY_NONE},
	{REP_PROTOCOL_ENTITY_SCOPE,
		BACKEND_ID_INVALID,
		scope_fill_children,
		scope_setup_child_info,
		scope_query_child,
		scope_insert_child,
		NULL,
		NULL,
	},
	{REP_PROTOCOL_ENTITY_SERVICE,
		BACKEND_ID_SERVICE_INSTANCE,
		service_fill_children,
		service_setup_child_info,
		service_query_child,
		service_insert_child,
		generic_insert_pg_child,
		service_delete_start,
	},
	{REP_PROTOCOL_ENTITY_INSTANCE,
		BACKEND_ID_SERVICE_INSTANCE,
		instance_fill_children,
		instance_setup_child_info,
		instance_query_child,
		instance_insert_child,
		generic_insert_pg_child,
		instance_delete_start,
	},
	{REP_PROTOCOL_ENTITY_SNAPSHOT,
		BACKEND_ID_SNAPNAME,
		snapshot_fill_children,
		NULL,
		NULL,
		NULL,
		NULL,
		snapshot_delete_start,
	},
	{REP_PROTOCOL_ENTITY_SNAPLEVEL,
		BACKEND_ID_SNAPLEVEL,
		snaplevel_fill_children,
		snaplevel_setup_child_info,
	},
	{REP_PROTOCOL_ENTITY_PROPERTYGRP,
		BACKEND_ID_PROPERTYGRP,
		propertygrp_fill_children,
		NULL,
		NULL,
		NULL,
		NULL,
		propertygrp_delete_start,
	},
	{REP_PROTOCOL_ENTITY_PROPERTY},
	{-1UL}
};
#define	NUM_INFO (sizeof (info) / sizeof (*info))

/*
 * object_fill_children() populates the child list of an rc_node_t by calling
 * the appropriate <type>_fill_children() which runs backend queries that
 * call an appropriate fill_*_callback() which takes a row of results,
 * decodes them, and calls an rc_node_setup*() function in rc_node.c to create
 * a child.
 *
 * Fails with
 *   _NO_RESOURCES
 */
int
object_fill_children(rc_node_t *pp)
{
	uint32_t type = pp->rn_id.rl_type;
	assert(type > 0 && type < NUM_INFO);

	return ((*info[type].obj_fill_children)(pp));
}

int
object_delete(rc_node_t *pp)
{
	int rc;

	delete_info_t dip;
	delete_ent_t de;

	uint32_t type = pp->rn_id.rl_type;
	assert(type > 0 && type < NUM_INFO);

	if (info[type].obj_delete_start == NULL)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	(void) memset(&dip, '\0', sizeof (dip));
	rc = backend_tx_begin(BACKEND_TYPE_NORMAL, &dip.di_tx);
	if (rc != REP_PROTOCOL_SUCCESS)
		return (rc);

	rc = backend_tx_begin(BACKEND_TYPE_NONPERSIST, &dip.di_np_tx);
	if (rc == REP_PROTOCOL_FAIL_BACKEND_ACCESS ||
	    rc == REP_PROTOCOL_FAIL_BACKEND_READONLY)
		dip.di_np_tx = NULL;
	else if (rc != REP_PROTOCOL_SUCCESS) {
		backend_tx_rollback(dip.di_tx);
		return (rc);
	}

	if ((rc = (*info[type].obj_delete_start)(pp, &dip)) !=
	    REP_PROTOCOL_SUCCESS) {
		goto fail;
	}

	while (delete_stack_pop(&dip, &de)) {
		rc = (*de.de_cb)(&dip, &de);
		if (rc != REP_PROTOCOL_SUCCESS)
			goto fail;
	}

	rc = backend_tx_commit(dip.di_tx);
	if (rc != REP_PROTOCOL_SUCCESS)
		backend_tx_rollback(dip.di_np_tx);
	else if (dip.di_np_tx)
		(void) backend_tx_commit(dip.di_np_tx);

	delete_stack_cleanup(&dip);

	return (rc);

fail:
	backend_tx_rollback(dip.di_tx);
	backend_tx_rollback(dip.di_np_tx);
	delete_stack_cleanup(&dip);
	return (rc);
}

int
object_do_create(backend_tx_t *tx, child_info_t *cip, rc_node_t *pp,
    uint32_t type, const char *name, rc_node_t **cpp)
{
	uint32_t ptype = pp->rn_id.rl_type;

	backend_query_t *q;
	uint32_t id;
	rc_node_t *np = NULL;
	int rc;
	object_info_t *ip;

	rc_node_lookup_t *lp = &cip->ci_base_nl;

	assert(ptype > 0 && ptype < NUM_INFO);

	ip = &info[ptype];

	if (type == REP_PROTOCOL_ENTITY_PROPERTYGRP)
		return (REP_PROTOCOL_FAIL_NOT_APPLICABLE);

	if (ip->obj_setup_child_info == NULL ||
	    ip->obj_query_child == NULL ||
	    ip->obj_insert_child == NULL)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	if ((rc = (*ip->obj_setup_child_info)(pp, type, cip)) !=
	    REP_PROTOCOL_SUCCESS)
		return (rc);

	q = backend_query_alloc();
	if ((rc = (*ip->obj_query_child)(q, lp, name)) !=
	    REP_PROTOCOL_SUCCESS) {
		assert(rc == REP_PROTOCOL_FAIL_BAD_REQUEST);
		backend_query_free(q);
		return (rc);
	}

	rc = backend_tx_run_single_int(tx, q, &id);
	backend_query_free(q);

	if (rc == REP_PROTOCOL_SUCCESS)
		return (REP_PROTOCOL_FAIL_EXISTS);
	else if (rc != REP_PROTOCOL_FAIL_NOT_FOUND)
		return (rc);

	if ((lp->rl_main_id = backend_new_id(tx,
	    info[type].obj_id_space)) == 0) {
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	if ((np = rc_node_alloc()) == NULL)
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);

	if ((rc = (*ip->obj_insert_child)(tx, lp, name)) !=
	    REP_PROTOCOL_SUCCESS) {
		rc_node_destroy(np);
		return (rc);
	}

	*cpp = np;
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with
 *   _NOT_APPLICABLE - type is _PROPERTYGRP
 *   _BAD_REQUEST - cannot create children for this type of node
 *		    name is invalid
 *   _TYPE_MISMATCH - object cannot have children of type type
 *   _NO_RESOURCES - out of memory, or could not allocate new id
 *   _BACKEND_READONLY
 *   _BACKEND_ACCESS
 *   _EXISTS - child already exists
 */
int
object_create(rc_node_t *pp, uint32_t type, const char *name, rc_node_t **cpp)
{
	backend_tx_t *tx;
	rc_node_t *np = NULL;
	child_info_t ci;
	int rc;

	if ((rc = backend_tx_begin(pp->rn_id.rl_backend, &tx)) !=
	    REP_PROTOCOL_SUCCESS) {
		return (rc);
	}

	if ((rc = object_do_create(tx, &ci, pp, type, name, &np)) !=
	    REP_PROTOCOL_SUCCESS) {
		backend_tx_rollback(tx);
		return (rc);
	}

	rc = backend_tx_commit(tx);
	if (rc != REP_PROTOCOL_SUCCESS) {
		rc_node_destroy(np);
		return (rc);
	}

	*cpp = rc_node_setup(np, &ci.ci_base_nl, name, ci.ci_parent);

	return (REP_PROTOCOL_SUCCESS);
}

/*ARGSUSED*/
int
object_create_pg(rc_node_t *pp, uint32_t type, const char *name,
    const char *pgtype, uint32_t flags, rc_node_t **cpp)
{
	uint32_t ptype = pp->rn_id.rl_type;
	backend_tx_t *tx_ro, *tx_wr;
	backend_query_t *q;
	uint32_t id;
	uint32_t gen = 0;
	rc_node_t *np = NULL;
	int rc;
	int rc_wr;
	int rc_ro;
	object_info_t *ip;

	int nonpersist = (flags & SCF_PG_FLAG_NONPERSISTENT);

	child_info_t ci;
	rc_node_lookup_t *lp = &ci.ci_base_nl;

	assert(ptype > 0 && ptype < NUM_INFO);

	if (ptype != REP_PROTOCOL_ENTITY_SERVICE &&
	    ptype != REP_PROTOCOL_ENTITY_INSTANCE)
		return (REP_PROTOCOL_FAIL_BAD_REQUEST);

	ip = &info[ptype];

	assert(ip->obj_setup_child_info != NULL &&
	    ip->obj_query_child != NULL &&
	    ip->obj_insert_pg_child != NULL);

	if ((rc = (*ip->obj_setup_child_info)(pp, type, &ci)) !=
	    REP_PROTOCOL_SUCCESS)
		return (rc);

	q = backend_query_alloc();
	if ((rc = (*ip->obj_query_child)(q, lp, name)) !=
	    REP_PROTOCOL_SUCCESS) {
		backend_query_free(q);
		return (rc);
	}

	if (!nonpersist) {
		lp->rl_backend = BACKEND_TYPE_NORMAL;
		rc_wr = backend_tx_begin(BACKEND_TYPE_NORMAL, &tx_wr);
		rc_ro = backend_tx_begin_ro(BACKEND_TYPE_NONPERSIST, &tx_ro);
	} else {
		lp->rl_backend = BACKEND_TYPE_NONPERSIST;
		rc_ro = backend_tx_begin_ro(BACKEND_TYPE_NORMAL, &tx_ro);
		rc_wr = backend_tx_begin(BACKEND_TYPE_NONPERSIST, &tx_wr);
	}

	if (rc_wr != REP_PROTOCOL_SUCCESS) {
		rc = rc_wr;
		goto fail;
	}
	if (rc_ro != REP_PROTOCOL_SUCCESS &&
	    rc_ro != REP_PROTOCOL_FAIL_BACKEND_ACCESS) {
		rc = rc_ro;
		goto fail;
	}

	if (tx_ro != NULL) {
		rc = backend_tx_run_single_int(tx_ro, q, &id);

		if (rc == REP_PROTOCOL_SUCCESS) {
			backend_query_free(q);
			rc = REP_PROTOCOL_FAIL_EXISTS;
			goto fail;
		} else if (rc != REP_PROTOCOL_FAIL_NOT_FOUND) {
			backend_query_free(q);
			goto fail;
		}
	}

	rc = backend_tx_run_single_int(tx_wr, q, &id);
	backend_query_free(q);

	if (rc == REP_PROTOCOL_SUCCESS) {
		rc = REP_PROTOCOL_FAIL_EXISTS;
		goto fail;
	} else if (rc != REP_PROTOCOL_FAIL_NOT_FOUND) {
		goto fail;
	}

	if (tx_ro != NULL)
		backend_tx_end_ro(tx_ro);
	tx_ro = NULL;

	if ((lp->rl_main_id = backend_new_id(tx_wr,
	    info[type].obj_id_space)) == 0) {
		rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
		goto fail;
	}

	if ((np = rc_node_alloc()) == NULL) {
		rc = REP_PROTOCOL_FAIL_NO_RESOURCES;
		goto fail;
	}

	if ((rc = (*ip->obj_insert_pg_child)(tx_wr, lp, name, pgtype, flags,
	    gen)) != REP_PROTOCOL_SUCCESS) {
		rc_node_destroy(np);
		goto fail;
	}

	rc = backend_tx_commit(tx_wr);
	if (rc != REP_PROTOCOL_SUCCESS) {
		rc_node_destroy(np);
		return (rc);
	}

	*cpp = rc_node_setup_pg(np, lp, name, pgtype, flags, gen, ci.ci_parent);

	return (REP_PROTOCOL_SUCCESS);

fail:
	if (tx_ro != NULL)
		backend_tx_end_ro(tx_ro);
	if (tx_wr != NULL)
		backend_tx_rollback(tx_wr);
	return (rc);
}

/*
 * Given a row of snaplevel number, snaplevel id, service id, service name,
 * instance id, & instance name, create a rc_snaplevel_t & prepend it onto the
 * rs_levels list of the rc_snapshot_t passed in as data.
 * Returns _CONTINUE on success or _ABORT if any allocations fail.
 */
/*ARGSUSED*/
static int
fill_snapshot_cb(void *data, int columns, char **vals, char **names)
{
	rc_snapshot_t *sp = data;
	rc_snaplevel_t *lvl;
	char *num = vals[0];
	char *id = vals[1];
	char *service_id = vals[2];
	char *service = vals[3];
	char *instance_id = vals[4];
	char *instance = vals[5];
	assert(columns == 6);

	lvl = uu_zalloc(sizeof (*lvl));
	if (lvl == NULL)
		return (BACKEND_CALLBACK_ABORT);
	lvl->rsl_parent = sp;
	lvl->rsl_next = sp->rs_levels;
	sp->rs_levels = lvl;

	string_to_id(num, &lvl->rsl_level_num, "snap_level_num");
	string_to_id(id, &lvl->rsl_level_id, "snap_level_id");
	string_to_id(service_id, &lvl->rsl_service_id, "snap_level_service_id");
	if (instance_id != NULL)
		string_to_id(instance_id, &lvl->rsl_instance_id,
		    "snap_level_instance_id");

	lvl->rsl_scope = (const char *)"localhost";
	lvl->rsl_service = strdup(service);
	if (lvl->rsl_service == NULL) {
		uu_free(lvl);
		return (BACKEND_CALLBACK_ABORT);
	}
	if (instance) {
		assert(lvl->rsl_instance_id != 0);
		lvl->rsl_instance = strdup(instance);
		if (lvl->rsl_instance == NULL) {
			free((void *)lvl->rsl_instance);
			uu_free(lvl);
			return (BACKEND_CALLBACK_ABORT);
		}
	} else {
		assert(lvl->rsl_instance_id == 0);
	}

	return (BACKEND_CALLBACK_CONTINUE);
}

/*
 * Populate sp's rs_levels list from the snaplevel_tbl table.
 * Fails with
 *   _NO_RESOURCES
 */
int
object_fill_snapshot(rc_snapshot_t *sp)
{
	backend_query_t *q;
	rc_snaplevel_t *sl;
	int result;
	int i;

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT snap_level_num, snap_level_id, "
	    "    snap_level_service_id, snap_level_service, "
	    "    snap_level_instance_id, snap_level_instance "
	    "FROM snaplevel_tbl "
	    "WHERE snap_id = %d "
	    "ORDER BY snap_level_id DESC",
	    sp->rs_snap_id);

	result = backend_run(BACKEND_TYPE_NORMAL, q, fill_snapshot_cb, sp);
	if (result == REP_PROTOCOL_DONE)
		result = REP_PROTOCOL_FAIL_NO_RESOURCES;
	backend_query_free(q);

	if (result == REP_PROTOCOL_SUCCESS) {
		i = 0;
		for (sl = sp->rs_levels; sl != NULL; sl = sl->rsl_next) {
			if (sl->rsl_level_num != ++i) {
				backend_panic("snaplevels corrupt; expected "
				    "level %d, got %d", i, sl->rsl_level_num);
			}
		}
	}
	return (result);
}

/*
 * This represents a property group in a snapshot.
 */
typedef struct check_snapshot_elem {
	uint32_t cse_parent;
	uint32_t cse_pg_id;
	uint32_t cse_pg_gen;
	char	cse_seen;
} check_snapshot_elem_t;

#define	CSI_MAX_PARENTS		COMPOSITION_DEPTH
typedef struct check_snapshot_info {
	size_t			csi_count;
	size_t			csi_array_size;
	check_snapshot_elem_t	*csi_array;
	size_t			csi_nparents;
	uint32_t		csi_parent_ids[CSI_MAX_PARENTS];
} check_snapshot_info_t;

/*ARGSUSED*/
static int
check_snapshot_fill_cb(void *data, int columns, char **vals, char **names)
{
	check_snapshot_info_t *csip = data;
	check_snapshot_elem_t *cur;
	const char *parent;
	const char *pg_id;
	const char *pg_gen_id;

	if (columns == 1) {
		uint32_t *target;

		if (csip->csi_nparents >= CSI_MAX_PARENTS)
			backend_panic("snaplevel table has too many elements");

		target = &csip->csi_parent_ids[csip->csi_nparents++];
		string_to_id(vals[0], target, "snap_level_*_id");

		return (BACKEND_CALLBACK_CONTINUE);
	}

	assert(columns == 3);

	parent = vals[0];
	pg_id = vals[1];
	pg_gen_id = vals[2];

	if (csip->csi_count == csip->csi_array_size) {
		size_t newsz = (csip->csi_array_size > 0) ?
		    csip->csi_array_size * 2 : 8;
		check_snapshot_elem_t *new = uu_zalloc(newsz * sizeof (*new));

		if (new == NULL)
			return (BACKEND_CALLBACK_ABORT);

		(void) memcpy(new, csip->csi_array,
		    sizeof (*new) * csip->csi_array_size);
		uu_free(csip->csi_array);
		csip->csi_array = new;
		csip->csi_array_size = newsz;
	}

	cur = &csip->csi_array[csip->csi_count++];

	string_to_id(parent, &cur->cse_parent, "snap_level_*_id");
	string_to_id(pg_id, &cur->cse_pg_id, "snaplvl_pg_id");
	string_to_id(pg_gen_id, &cur->cse_pg_gen, "snaplvl_gen_id");
	cur->cse_seen = 0;

	return (BACKEND_CALLBACK_CONTINUE);
}

static int
check_snapshot_elem_cmp(const void *lhs_arg, const void *rhs_arg)
{
	const check_snapshot_elem_t *lhs = lhs_arg;
	const check_snapshot_elem_t *rhs = rhs_arg;

	if (lhs->cse_parent < rhs->cse_parent)
		return (-1);
	if (lhs->cse_parent > rhs->cse_parent)
		return (1);

	if (lhs->cse_pg_id < rhs->cse_pg_id)
		return (-1);
	if (lhs->cse_pg_id > rhs->cse_pg_id)
		return (1);

	if (lhs->cse_pg_gen < rhs->cse_pg_gen)
		return (-1);
	if (lhs->cse_pg_gen > rhs->cse_pg_gen)
		return (1);

	return (0);
}

/*ARGSUSED*/
static int
check_snapshot_check_cb(void *data, int columns, char **vals, char **names)
{
	check_snapshot_info_t *csip = data;
	check_snapshot_elem_t elem;
	check_snapshot_elem_t *cur;

	const char *parent = vals[0];
	const char *pg_id = vals[1];
	const char *pg_gen_id = vals[2];

	assert(columns == 3);

	string_to_id(parent, &elem.cse_parent, "snap_level_*_id");
	string_to_id(pg_id, &elem.cse_pg_id, "snaplvl_pg_id");
	string_to_id(pg_gen_id, &elem.cse_pg_gen, "snaplvl_gen_id");

	if ((cur = bsearch(&elem, csip->csi_array, csip->csi_count,
	    sizeof (*csip->csi_array), check_snapshot_elem_cmp)) == NULL)
		return (BACKEND_CALLBACK_ABORT);

	if (cur->cse_seen)
		backend_panic("duplicate property group reported");
	cur->cse_seen = 1;
	return (BACKEND_CALLBACK_CONTINUE);
}

/*
 * Check that a snapshot matches up with the latest in the repository.
 * Returns:
 *	REP_PROTOCOL_SUCCESS		if it is up-to-date,
 *	REP_PROTOCOL_DONE		if it is out-of-date, or
 *	REP_PROTOCOL_FAIL_NO_RESOURCES	if we ran out of memory.
 */
static int
object_check_snapshot(uint32_t snap_id)
{
	check_snapshot_info_t csi;
	backend_query_t *q;
	int result;
	size_t idx;

	/* if the snapshot has never been taken, it must be out of date. */
	if (snap_id == 0)
		return (REP_PROTOCOL_DONE);

	(void) memset(&csi, '\0', sizeof (csi));

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT\n"
	    "    CASE snap_level_instance_id\n"
	    "        WHEN 0 THEN snap_level_service_id\n"
	    "        ELSE snap_level_instance_id\n"
	    "    END\n"
	    "FROM snaplevel_tbl\n"
	    "WHERE snap_id = %d;\n"
	    "\n"
	    "SELECT\n"
	    "    CASE snap_level_instance_id\n"
	    "        WHEN 0 THEN snap_level_service_id\n"
	    "        ELSE snap_level_instance_id\n"
	    "    END,\n"
	    "    snaplvl_pg_id,\n"
	    "    snaplvl_gen_id\n"
	    "FROM snaplevel_tbl, snaplevel_lnk_tbl\n"
	    "WHERE\n"
	    "    (snaplvl_level_id = snap_level_id AND\n"
	    "    snap_id = %d);",
	    snap_id, snap_id);

	result = backend_run(BACKEND_TYPE_NORMAL, q, check_snapshot_fill_cb,
	    &csi);
	if (result == REP_PROTOCOL_DONE)
		result = REP_PROTOCOL_FAIL_NO_RESOURCES;
	backend_query_free(q);

	if (result != REP_PROTOCOL_SUCCESS)
		goto fail;

	if (csi.csi_count > 0) {
		qsort(csi.csi_array, csi.csi_count, sizeof (*csi.csi_array),
		    check_snapshot_elem_cmp);
	}

#if COMPOSITION_DEPTH == 2
	if (csi.csi_nparents != COMPOSITION_DEPTH) {
		result = REP_PROTOCOL_DONE;
		goto fail;
	}

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT "
	    "    pg_parent_id, pg_id, pg_gen_id "
	    "FROM "
	    "    pg_tbl "
	    "WHERE (pg_parent_id = %d OR pg_parent_id = %d)",
	    csi.csi_parent_ids[0], csi.csi_parent_ids[1]);

	result = backend_run(BACKEND_TYPE_NORMAL, q, check_snapshot_check_cb,
	    &csi);
#else
#error This code must be updated
#endif
	/*
	 * To succeed, the callback must not have aborted, and we must have
	 * found all of the items.
	 */
	if (result == REP_PROTOCOL_SUCCESS) {
		for (idx = 0; idx < csi.csi_count; idx++) {
			if (csi.csi_array[idx].cse_seen == 0) {
				result = REP_PROTOCOL_DONE;
				goto fail;
			}
		}
	}

fail:
	uu_free(csi.csi_array);
	return (result);
}

/*ARGSUSED*/
static int
object_copy_string(void *data_arg, int columns, char **vals, char **names)
{
	char **data = data_arg;

	assert(columns == 1);

	if (*data != NULL)
		free(*data);
	*data = NULL;

	if (vals[0] != NULL) {
		if ((*data = strdup(vals[0])) == NULL)
			return (BACKEND_CALLBACK_ABORT);
	}

	return (BACKEND_CALLBACK_CONTINUE);
}

struct snaplevel_add_info {
	backend_query_t *sai_q;
	uint32_t	sai_level_id;
	int		sai_used;		/* sai_q has been used */
};

/*ARGSUSED*/
static int
object_snaplevel_process_pg(void *data_arg, int columns, char **vals,
    char **names)
{
	struct snaplevel_add_info *data = data_arg;

	assert(columns == 5);

	backend_query_add(data->sai_q,
	    "INSERT INTO snaplevel_lnk_tbl "
	    "    (snaplvl_level_id, snaplvl_pg_id, snaplvl_pg_name, "
	    "    snaplvl_pg_type, snaplvl_pg_flags, snaplvl_gen_id)"
	    "VALUES (%d, %s, '%q', '%q', %s, %s);",
	    data->sai_level_id, vals[0], vals[1], vals[2], vals[3], vals[4]);

	data->sai_used = 1;

	return (BACKEND_CALLBACK_CONTINUE);
}

/*ARGSUSED*/
static int
object_snapshot_add_level(backend_tx_t *tx, uint32_t snap_id,
    uint32_t snap_level_num, uint32_t svc_id, const char *svc_name,
    uint32_t inst_id, const char *inst_name)
{
	struct snaplevel_add_info data;
	backend_query_t *q;
	int result;

	assert((snap_level_num == 1 && inst_name != NULL) ||
	    snap_level_num == 2 && inst_name == NULL);

	data.sai_level_id = backend_new_id(tx, BACKEND_ID_SNAPLEVEL);
	if (data.sai_level_id == 0) {
		return (REP_PROTOCOL_FAIL_NO_RESOURCES);
	}

	result = backend_tx_run_update(tx,
	    "INSERT INTO snaplevel_tbl "
	    "    (snap_id, snap_level_num, snap_level_id, "
	    "    snap_level_service_id, snap_level_service, "
	    "    snap_level_instance_id, snap_level_instance) "
	    "VALUES (%d, %d, %d, %d, %Q, %d, %Q);",
	    snap_id, snap_level_num, data.sai_level_id, svc_id, svc_name,
	    inst_id, inst_name);

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT pg_id, pg_name, pg_type, pg_flags, pg_gen_id FROM pg_tbl "
	    "WHERE (pg_parent_id = %d);",
	    (inst_name != NULL)? inst_id : svc_id);

	data.sai_q = backend_query_alloc();
	data.sai_used = 0;
	result = backend_tx_run(tx, q, object_snaplevel_process_pg,
	    &data);
	backend_query_free(q);

	if (result == REP_PROTOCOL_SUCCESS && data.sai_used != 0)
		result = backend_tx_run(tx, data.sai_q, NULL, NULL);
	backend_query_free(data.sai_q);

	return (result);
}

/*
 * Fails with:
 *	_NO_RESOURCES - no new id or out of disk space
 *	_BACKEND_READONLY - persistent backend is read-only
 */
static int
object_snapshot_do_take(uint32_t instid, const char *inst_name,
    uint32_t svcid, const char *svc_name,
    backend_tx_t **tx_out, uint32_t *snapid_out)
{
	backend_tx_t *tx;
	backend_query_t *q;
	int result;

	char *svc_name_alloc = NULL;
	char *inst_name_alloc = NULL;
	uint32_t snapid;

	result = backend_tx_begin(BACKEND_TYPE_NORMAL, &tx);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	snapid = backend_new_id(tx, BACKEND_ID_SNAPSHOT);
	if (snapid == 0) {
		result = REP_PROTOCOL_FAIL_NO_RESOURCES;
		goto fail;
	}

	if (svc_name == NULL) {
		q = backend_query_alloc();
		backend_query_add(q,
		    "SELECT svc_name FROM service_tbl "
		    "WHERE (svc_id = %d)", svcid);
		result = backend_tx_run(tx, q, object_copy_string,
		    &svc_name_alloc);
		backend_query_free(q);

		svc_name = svc_name_alloc;

		if (result == REP_PROTOCOL_DONE) {
			result = REP_PROTOCOL_FAIL_NO_RESOURCES;
			goto fail;
		}
		if (result == REP_PROTOCOL_SUCCESS && svc_name == NULL)
			backend_panic("unable to find name for svc id %d\n",
			    svcid);

		if (result != REP_PROTOCOL_SUCCESS)
			goto fail;
	}

	if (inst_name == NULL) {
		q = backend_query_alloc();
		backend_query_add(q,
		    "SELECT instance_name FROM instance_tbl "
		    "WHERE (instance_id = %d)", instid);
		result = backend_tx_run(tx, q, object_copy_string,
		    &inst_name_alloc);
		backend_query_free(q);

		inst_name = inst_name_alloc;

		if (result == REP_PROTOCOL_DONE) {
			result = REP_PROTOCOL_FAIL_NO_RESOURCES;
			goto fail;
		}

		if (result == REP_PROTOCOL_SUCCESS && inst_name == NULL)
			backend_panic(
			    "unable to find name for instance id %d\n", instid);

		if (result != REP_PROTOCOL_SUCCESS)
			goto fail;
	}

	result = object_snapshot_add_level(tx, snapid, 1,
	    svcid, svc_name, instid, inst_name);

	if (result != REP_PROTOCOL_SUCCESS)
		goto fail;

	result = object_snapshot_add_level(tx, snapid, 2,
	    svcid, svc_name, 0, NULL);

	if (result != REP_PROTOCOL_SUCCESS)
		goto fail;

	*snapid_out = snapid;
	*tx_out = tx;

	free(svc_name_alloc);
	free(inst_name_alloc);

	return (REP_PROTOCOL_SUCCESS);

fail:
	backend_tx_rollback(tx);
	free(svc_name_alloc);
	free(inst_name_alloc);
	return (result);
}

/*
 * Fails with:
 *	_TYPE_MISMATCH - pp is not an instance
 *	_NO_RESOURCES - no new id or out of disk space
 *	_BACKEND_READONLY - persistent backend is read-only
 */
int
object_snapshot_take_new(rc_node_t *pp,
    const char *svc_name, const char *inst_name,
    const char *name, rc_node_t **outp)
{
	rc_node_lookup_t *insti = &pp->rn_id;

	uint32_t instid = insti->rl_main_id;
	uint32_t svcid = insti->rl_ids[ID_SERVICE];
	uint32_t snapid = 0;
	backend_tx_t *tx = NULL;
	child_info_t ci;
	rc_node_t *np;
	int result;

	if (insti->rl_type != REP_PROTOCOL_ENTITY_INSTANCE)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	result = object_snapshot_do_take(instid, inst_name, svcid, svc_name,
	    &tx, &snapid);
	if (result != REP_PROTOCOL_SUCCESS)
		return (result);

	if ((result = object_do_create(tx, &ci, pp,
	    REP_PROTOCOL_ENTITY_SNAPSHOT, name, &np)) != REP_PROTOCOL_SUCCESS) {
		backend_tx_rollback(tx);
		return (result);
	}

	/*
	 * link the new object to the new snapshot.
	 */
	np->rn_snapshot_id = snapid;

	result = backend_tx_run_update(tx,
	    "UPDATE snapshot_lnk_tbl SET lnk_snap_id = %d WHERE lnk_id = %d;",
	    snapid, ci.ci_base_nl.rl_main_id);
	if (result != REP_PROTOCOL_SUCCESS) {
		backend_tx_rollback(tx);
		rc_node_destroy(np);
		return (result);
	}
	result = backend_tx_commit(tx);
	if (result != REP_PROTOCOL_SUCCESS) {
		rc_node_destroy(np);
		return (result);
	}

	*outp = rc_node_setup(np, &ci.ci_base_nl, name, ci.ci_parent);
	return (REP_PROTOCOL_SUCCESS);
}

/*
 * Fails with:
 *	_TYPE_MISMATCH - pp is not an instance
 *	_NO_RESOURCES - no new id or out of disk space
 *	_BACKEND_READONLY - persistent backend is read-only
 */
int
object_snapshot_attach(rc_node_lookup_t *snapi, uint32_t *snapid_ptr,
    int takesnap)
{
	uint32_t svcid = snapi->rl_ids[ID_SERVICE];
	uint32_t instid = snapi->rl_ids[ID_INSTANCE];
	uint32_t snapid = *snapid_ptr;
	uint32_t oldsnapid = 0;
	backend_tx_t *tx = NULL;
	backend_query_t *q;
	int result;

	delete_info_t dip;
	delete_ent_t de;

	if (snapi->rl_type != REP_PROTOCOL_ENTITY_SNAPSHOT)
		return (REP_PROTOCOL_FAIL_TYPE_MISMATCH);

	if (takesnap) {
		/* first, check that we're actually out of date */
		if (object_check_snapshot(snapid) == REP_PROTOCOL_SUCCESS)
			return (REP_PROTOCOL_SUCCESS);

		result = object_snapshot_do_take(instid, NULL,
		    svcid, NULL, &tx, &snapid);
		if (result != REP_PROTOCOL_SUCCESS)
			return (result);
	} else {
		result = backend_tx_begin(BACKEND_TYPE_NORMAL, &tx);
		if (result != REP_PROTOCOL_SUCCESS)
			return (result);
	}

	q = backend_query_alloc();
	backend_query_add(q,
	    "SELECT lnk_snap_id FROM snapshot_lnk_tbl WHERE lnk_id = %d; "
	    "UPDATE snapshot_lnk_tbl SET lnk_snap_id = %d WHERE lnk_id = %d;",
	    snapi->rl_main_id, snapid, snapi->rl_main_id);
	result = backend_tx_run_single_int(tx, q, &oldsnapid);
	backend_query_free(q);

	if (result == REP_PROTOCOL_FAIL_NOT_FOUND) {
		backend_tx_rollback(tx);
		backend_panic("unable to find snapshot id %d",
		    snapi->rl_main_id);
	}
	if (result != REP_PROTOCOL_SUCCESS)
		goto fail;

	/*
	 * Now we use the delete stack to handle the possible unreferencing
	 * of oldsnapid.
	 */
	(void) memset(&dip, 0, sizeof (dip));
	dip.di_tx = tx;
	dip.di_np_tx = NULL;	/* no need for non-persistant backend */

	if ((result = delete_stack_push(&dip, BACKEND_TYPE_NORMAL,
	    &snaplevel_tbl_delete, oldsnapid, 0)) != REP_PROTOCOL_SUCCESS)
		goto fail;

	while (delete_stack_pop(&dip, &de)) {
		result = (*de.de_cb)(&dip, &de);
		if (result != REP_PROTOCOL_SUCCESS)
			goto fail;
	}

	result = backend_tx_commit(tx);
	if (result != REP_PROTOCOL_SUCCESS)
		goto fail;

	delete_stack_cleanup(&dip);
	*snapid_ptr = snapid;
	return (REP_PROTOCOL_SUCCESS);

fail:
	backend_tx_rollback(tx);
	delete_stack_cleanup(&dip);
	return (result);
}
