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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Callback facility designed to allow interested parties (dmods, targets, or
 * even the core debugger framework) to register for notification when certain
 * "interesting" events occur.
 */

#include <mdb/mdb_list.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_callb.h>
#include <mdb/mdb_module.h>
#include <mdb/mdb.h>

mdb_callb_t *
mdb_callb_add(mdb_module_t *m, int class, mdb_callb_f fp, void *arg)
{
	mdb_callb_t *new = mdb_zalloc(sizeof (mdb_callb_t), UM_SLEEP);

	ASSERT(class == MDB_CALLB_STCHG || class == MDB_CALLB_PROMPT);

	new->cb_mod = m;
	new->cb_class = class;
	new->cb_func = fp;
	new->cb_arg = arg;

	if (m == NULL) {
		mdb_list_prepend(&mdb.m_cblist, new);
	} else {
		mdb_list_insert(&mdb.m_cblist, m->mod_cb, new);
		if (m->mod_cb == NULL)
			m->mod_cb = new;
	}

	return (new);
}

void
mdb_callb_remove(mdb_callb_t *cb)
{
	if (cb->cb_mod != NULL) {
		mdb_callb_t *next = mdb_list_next(cb);
		mdb_module_t *mod = cb->cb_mod;

		if (mod->mod_cb == cb) {
			if (next == NULL || next->cb_mod != mod)
				mod->mod_cb = NULL;
			else
				mod->mod_cb = next;
		}
	}

	mdb_list_delete(&mdb.m_cblist, cb);

	mdb_free(cb, sizeof (mdb_callb_t));
}

void
mdb_callb_remove_by_mod(mdb_module_t *m)
{
	while (m->mod_cb != NULL)
		mdb_callb_remove(m->mod_cb);
}

void
mdb_callb_remove_all(void)
{
	mdb_callb_t *cb;

	while ((cb = mdb_list_next(&mdb.m_cblist)) != NULL)
		mdb_callb_remove(cb);
}

void
mdb_callb_fire(int class)
{
	mdb_callb_t *cb, *next;

	ASSERT(class == MDB_CALLB_STCHG || class == MDB_CALLB_PROMPT);

	mdb_dprintf(MDB_DBG_CALLB, "invoking %s callbacks\n",
	    (class == MDB_CALLB_STCHG ? "state change" : "prompt"));

	for (cb = mdb_list_next(&mdb.m_cblist); cb != NULL; cb = next) {
		next = mdb_list_next(cb);
		if (cb->cb_class == class)
			cb->cb_func(cb->cb_arg);
	}
}
