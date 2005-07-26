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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <dlfcn.h>
#include <alloca.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systeminfo.h>
#include "topo_impl.h"
#include "topo_enum.h"

struct trim_data {
	int valid;
	struct tnode_list *children;
	struct tnode_list *self;
};

static void
trim(tnode_t *node, void *arg)
{
	struct trim_data *td;

	td = arg;
	if (td->valid == 1) {
		td->self->tnode->children = td->children;
		tnode_destroy(td->self->tnode);
		topo_free(td->self);
		td->valid = 0;
		return;
	}

	if (node->state == TOPO_LIMBO || node->state == TOPO_RANGE) {
		td->valid = 1;
		td->self = tnode_del_child(topo_parent(node), node);
		td->children = td->self->tnode->children;
		td->self->tnode->children = NULL;
	}
}

struct tenumr *topo_enumr_hash_lookup(const char *);
struct tenumr *topo_load_enumerator(const char *);

static int
enumr_ready(struct tenumr *e)
{
	struct tenumr_prvt_data *pd;

	if (e == NULL || e->te_enum == NULL)
		return (0);

	pd = (struct tenumr_prvt_data *)e->te_private;
	return (pd->status & ENUMR_INITD);
}

/*ARGSUSED*/
static void
enum_all(tnode_t *start, void *arg)
{
	struct tenumr *enumr;
	const char *enumrnm;
	tnode_t *parent;
	int inum, min, max;

	topo_out(TOPO_DEBUG, "enumall: ");
	topo_out(TOPO_DEBUG, "Enumerating %s ", topo_name(start));
	if ((inum = topo_get_instance_num(start)) >= 0) {
		topo_out(TOPO_DEBUG, "(%d)", inum);
	} else {
		topo_get_instance_range(start, &min, &max);
		topo_out(TOPO_DEBUG, "(%d - %d)", min, max);
	}
	topo_out(TOPO_DEBUG, " [%p], ", (void *)start);

	if ((parent = topo_parent(start)) == NULL) {
		topo_out(TOPO_DEBUG, "\n");
	} else {
		topo_out(TOPO_DEBUG, "Child of %s ", topo_name(parent));
		if ((inum = topo_get_instance_num(parent)) >= 0) {
			topo_out(TOPO_DEBUG, "(%d)", inum);
		} else {
			topo_get_instance_range(parent, &min, &max);
			topo_out(TOPO_DEBUG, "(%d - %d)", min, max);
		}
		topo_out(TOPO_DEBUG, "[%p]\n", (void *)parent);
	}

	if (start->state == TOPO_LIMBO || start->state == TOPO_INST)
		return;

	/*
	 * Have a range and need to get the actual instances.
	 * Determine the name of the enumerator and if we have the
	 * enumerator already loaded.
	 */
	if ((enumrnm = tealias_find(start)) == NULL)
		enumrnm = topo_name(start);

	if ((enumr = topo_enumr_hash_lookup(enumrnm)) == NULL)
		enumr = topo_load_enumerator(enumrnm);

	if (enumr_ready(enumr))
		enumr->te_enum(start);
}

void
topo_enum(tnode_t *root)
{
	struct trim_data td;

	td.valid = 0;
	td.children = td.self = NULL;

	topo_walk(root, TOPO_VISIT_SELF_FIRST, NULL, enum_all);
	topo_walk(root,
	    TOPO_DESTRUCTIVE_WALK | TOPO_VISIT_SELF_FIRST | TOPO_REVISIT_SELF,
	    &td, trim);
}

#define	ENUMR_HASHLEN 101
static struct tenumr_hash Enumerators;

void
topo_enumr_hash_create(void)
{
	Enumerators.te_hashlen = ENUMR_HASHLEN;
	Enumerators.te_hash = topo_zalloc(Enumerators.te_hashlen *
	    sizeof (struct tenumr_hashent));
}

void
topo_enumr_hash_destroy(int destroy_tes)
{
	struct tenumr_prvt_data *pd;
	struct tenumr_hashent *entry, *next;
	int idx;

	for (idx = 0; idx < Enumerators.te_hashlen; idx++) {
		entry = Enumerators.te_hash[idx];
		while (entry != NULL) {
			topo_out(TOPO_HASH,
			    "Destroy hash bucket %d entry for %s.",
			    idx,
			    entry->te_nodetype);
			pd = (struct tenumr_prvt_data *)entry->te->te_private;

			topo_out(TOPO_HASH, "  Status is %x.\n", pd->status);
			if (pd->status & ENUMR_INITD) {
				pd->status &= ~ENUMR_INITD;
				if (entry->te->te_fini)
					entry->te->te_fini();
			}
			if (destroy_tes) {
				void *dlp = pd->hdl;
				uint_t status = pd->status;

				topo_free(pd);
				entry->te->te_private = NULL;
				if (dlp != NULL)
					topo_dlclose(dlp);
				if (status & (ENUMR_NOTFOUND|ENUMR_BAD))
					topo_free(entry->te);
			}
			next = entry->te_next;
			topo_free((void *)entry->te_nodetype);
			topo_free(entry);
			entry = next;
		}
	}
	topo_free(Enumerators.te_hash);
}

void
topo_enumr_hash_insert(const char *key, struct tenumr *enumr)
{
	struct tenumr_prvt_data *pd;
	struct tenumr_hashent *new;
	int idx = topo_strhash(key) % ENUMR_HASHLEN;
	int initfail = TE_INITOK;

	Enumerators.te_nelems++;

	new = topo_zalloc(sizeof (struct tenumr_hashent));
	new->te_nodetype = key;
	new->te = enumr;

	pd = (struct tenumr_prvt_data *)new->te->te_private;
	if (!(pd->status & ENUMR_INITD)) {
		if (new->te->te_init)
			initfail = new->te->te_init();
	}

	if (initfail != TE_INITOK) {
		topo_out(TOPO_ERR, "Enumerator for %s failed to initialize.\n",
		    key);
		pd->status |= ENUMR_INITFAIL;
	} else {
		pd->status |= ENUMR_INITD;
	}

	topo_out(TOPO_HASH, "Insert [key=%s] into Enumerator bucket %d ",
	    key, idx);

	if (Enumerators.te_hash[idx] == NULL) {
		Enumerators.te_hash[idx] = new;
		topo_out(TOPO_HASH, ", first enumerator in bucket.\n");
	} else {
		new->te_next = Enumerators.te_hash[idx];
		Enumerators.te_hash[idx] = new;
		topo_out(TOPO_HASH, "\n");
	}
}

struct tenumr *
topo_enumr_hash_lookup(const char *nodetype)
{
	struct tenumr_hashent *hent;
	int idx = topo_strhash(nodetype) % ENUMR_HASHLEN;

	topo_out(TOPO_HASH, "Searching [key=%s] in Enumerator bucket %d ",
	    nodetype, idx);
	hent = Enumerators.te_hash[idx];
	while (hent != NULL) {
		if (strcmp(nodetype, hent->te_nodetype) == 0) {
			topo_out(TOPO_HASH, "found\n");
			break;
		}
		topo_out(TOPO_HASH, "%s!=%s\n", nodetype, hent->te_nodetype);
		hent = hent->te_next;
	}
	if (hent)
		return (hent->te);
	return (NULL);
}

/*ARGSUSED*/
struct tenumr *
topo_load_enumerator(const char *nodetype)
{
	struct tenumr_prvt_data *newenumr;
	struct tenumr *ret, *eret;
	char *tmpname = alloca(MAXPATHLEN);
	void *dlp;

	newenumr = topo_zalloc(sizeof (struct tenumr_prvt_data));
	ret = topo_zalloc(sizeof (struct tenumr));

	(void) snprintf(tmpname, MAXPATHLEN, "%s.so", nodetype);
	if ((dlp = topo_dlopen(tmpname)) == NULL) {
		/*
		 * create a negative hash entry to keep us from
		 * looking for the same .so's every time
		 */
		newenumr->status |= ENUMR_NOTFOUND;
		goto eloaded;
	}

	newenumr->einit = (struct tenumr *(*)())dlsym(dlp, "_enum_init");

	if (newenumr->einit == NULL) {
		topo_out(TOPO_ERR, "%s missing _enum_init()\n", tmpname);
		goto einitbad;
	}

	if ((eret = newenumr->einit()) == NULL) {
		topo_out(TOPO_ERR, "%s _enum_init() returned NULL\n", tmpname);
		goto einitbad;
	}

	if (eret->te_enum == NULL) {
		topo_out(TOPO_ERR, "%s has NULL te_enum()\n", tmpname);
		goto einitbad;
	}

	newenumr->hdl = dlp;
	topo_free(ret);
	ret = eret;
	goto eloaded;

einitbad:
	newenumr->status |= ENUMR_BAD;
	topo_dlclose(dlp);

eloaded:
	ret->te_private = (void *)newenumr;
	topo_enumr_hash_insert(topo_strdup(nodetype), ret);
	return (ret);
}

void
topo_enum_init(void)
{
	topo_enumr_hash_create();
}

void
topo_enum_fini(void)
{
	topo_enumr_hash_destroy(1);
}
