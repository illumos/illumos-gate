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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <libdevinfo.h>
#include <fm/topo_mod.h>
#include <pcibus.h>
#include <did.h>

#include "did_impl.h"
#include "did_props.h"

static did_hash_t *did_hash_create(topo_mod_t *);
static void did_hash_destroy(did_hash_t *);

int
did_hash_init(topo_mod_t *hdl)
{
	did_hash_t *dh = did_hash_create(hdl);

	if (dh != NULL) {
		topo_mod_setspecific(hdl, (void *) dh);
		return (0);
	} else {
		return (-1);
	}
}

void
did_hash_fini(topo_mod_t *mod)
{
	did_hash_t *dh = (did_hash_t *)topo_mod_getspecific(mod);

	topo_mod_setspecific(mod, NULL);
	if (dh == NULL)
		return;
	did_hash_destroy(dh);
}

static uint64_t
did_dnhash(di_node_t key)
{
	static uint64_t key_divisor = 0;
	uint64_t keyn;

	/*
	 * A bit naughty here, we're aware that a di_info_t is a
	 * pointer to a struct.  For our hashing, we want use the size
	 * of that struct, which we determine here, somewhat
	 * impolitely.
	 */
	if (key_divisor == 0)
		key_divisor = sizeof (*key);

	keyn = (uintptr_t)key;

	return (keyn / key_divisor);
}

static did_hash_t *
did_hash_create(topo_mod_t *hdl)
{
	did_hash_t *r = topo_mod_zalloc(hdl, sizeof (did_hash_t));

	if (r == NULL) {
		(void) topo_mod_seterrno(hdl, EMOD_NOMEM);
		return (NULL);
	}
	r->dph_mod = hdl;
	r->dph_hashlen = REC_HASHLEN;
	r->dph_hash = topo_mod_zalloc(hdl,
	    r->dph_hashlen * sizeof (did_t *));
	if (r->dph_hash == NULL) {
		topo_mod_free(hdl, r, sizeof (did_hash_t));
		(void) topo_mod_seterrno(hdl, EMOD_NOMEM);
		return (NULL);
	}
	return (r);
}

static void
did_hash_destroy(did_hash_t *ht)
{
	did_t *e, *n;
	int idx;

	if (ht == NULL)
		return;
	for (idx = 0; idx < ht->dph_hashlen; idx++) {
		for (e = ht->dph_hash[idx]; e != NULL; ) {
			n = e->dp_next;
			did_destroy(e);
			e = n;
		}
	}
	topo_mod_free(ht->dph_mod,
	    ht->dph_hash, ht->dph_hashlen * sizeof (did_t *));
	topo_mod_free(ht->dph_mod, ht, sizeof (did_hash_t));
}

void
did_hash_insert(topo_mod_t *mp, di_node_t key, did_t *new)
{
	did_hash_t *tab = (did_hash_t *)topo_mod_getspecific(mp);
	did_t *assertchk;
	int idx = did_dnhash(key) % tab->dph_hashlen;

	tab->dph_nelems++;
	did_hold(new);
	topo_mod_dprintf(tab->dph_mod, "Insert [key=%p] into %p, bucket %d\n",
	    key, (void *)tab, idx);
	if (tab->dph_hash[idx] == NULL) {
		tab->dph_hash[idx] = new;
		topo_mod_dprintf(tab->dph_mod, "first entry.\n");
	} else {
		/*
		 * We should not be putting in a duplicate entry
		 */
		for (assertchk = tab->dph_hash[idx];
		    assertchk != NULL;
		    assertchk = assertchk->dp_next)
			assert(assertchk->dp_src != key);
		new->dp_next = tab->dph_hash[idx];
		tab->dph_hash[idx] = new;
	}
}

did_t *
did_hash_lookup(topo_mod_t *mp, di_node_t key)
{
	did_t *e;
	did_hash_t *tab = (did_hash_t *)topo_mod_getspecific(mp);
	int idx = did_dnhash(key) % tab->dph_hashlen;

	e = tab->dph_hash[idx];
	while (e != NULL) {
		if (e->dp_src == key) {
			did_hold(e);
			return (e);
		}
		e = e->dp_next;
	}
	return (NULL);
}
