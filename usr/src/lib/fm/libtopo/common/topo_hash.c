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
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <string.h>
#include "libtopo.h"
#include "topo_impl.h"

ulong_t
topo_strhash(const char *key)
{
	ulong_t g, h = 0;
	const char *p;

	for (p = key; *p != '\0'; p++) {
		h = (h << 4) + *p;

		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

#define	REC_HASHLEN	101

struct tprop *
tprop_create(const char *name, const char *val)
{
	struct tprop *newp;

	newp = topo_zalloc(sizeof (struct tprop));
	newp->p_name = topo_strdup(name);
	newp->p_val = topo_strdup(val);
	return (newp);
}

void
tprop_destroy(struct tprop *p)
{
	topo_free((void *)p->p_name);
	topo_free((void *)p->p_val);
	topo_free(p);
}

struct tprop_hash *
tprop_hash_create(void)
{
	struct tprop_hash *r = topo_zalloc(sizeof (struct tprop_hash));

	r->tp_hashlen = REC_HASHLEN;
	r->tp_hash = topo_zalloc(r->tp_hashlen * sizeof (struct tprop *));
	return (r);
}

void
tprop_hash_destroy(struct tprop_hash *ht)
{
	struct tprop *d, *n;
	int idx;

	if (ht == NULL)
		return;

	for (idx = 0; idx < ht->tp_hashlen; idx++) {
		for (d = ht->tp_hash[idx]; d != NULL; ) {
			n = d->p_next;
			tprop_destroy(d);
			d = n;
		}
	}

	topo_free(ht->tp_hash);
	topo_free(ht);
}

void
tprop_hash_insert(struct tprop_hash *tab, const char *key, struct tprop *new)
{
	int idx = topo_strhash(key) % tab->tp_hashlen;

	tab->tp_nelems++;
	topo_out(TOPO_HASH, "Insert [key=%s] into %p, bucket %d ",
	    key, (void *)tab, idx);
	if (tab->tp_hash[idx] == NULL) {
		tab->tp_hash[idx] = new;
		topo_out(TOPO_HASH, "first entry.\n");
	} else {
		new->p_next = tab->tp_hash[idx];
		tab->tp_hash[idx] = new;
		topo_out(TOPO_HASH, "\n");
	}
}

struct tprop *
tprop_hash_lookup(struct tprop_hash *tab, const char *key)
{
	int idx = topo_strhash(key) % tab->tp_hashlen;

	return (tab->tp_hash[idx]);
}

struct tprop *
tprop_hash_lookup_next(struct tprop_hash *tab, const char *prevkey,
    struct tprop *prevprop)
{
	int idx = 0;

	if (prevprop != NULL && prevprop->p_next != NULL)
		return (prevprop->p_next);

	if (prevkey != NULL) {
		idx = topo_strhash(prevkey) % tab->tp_hashlen;
		idx++;
	}

	while (tab->tp_hash[idx] == NULL && idx < tab->tp_hashlen)
		idx++;

	if (idx >= tab->tp_hashlen)
		return (NULL);
	else
		return (tab->tp_hash[idx]);
}

struct tnode_hashent *
tnode_hashent_create(struct tnode *node)
{
	struct tnode_hashent *r = topo_zalloc(sizeof (struct tnode_hashent));
	r->e_node = node;
	return (r);
}

void
tnode_hashent_destroy(struct tnode_hashent *e)
{
	topo_free(e);
}

struct tnode_hash *
tnode_hash_create(void)
{
	struct tnode_hash *r = topo_zalloc(sizeof (struct tnode_hash));

	r->tn_hashlen = REC_HASHLEN;
	r->tn_hash = topo_zalloc(r->tn_hashlen * sizeof (struct tnode *));
	return (r);
}

void
tnode_hash_destroy(struct tnode_hash *ht)
{
	struct tnode_hashent *d, *n;
	int idx;

	if (ht == NULL)
		return;

	for (idx = 0; idx < ht->tn_hashlen; idx++) {
		for (d = ht->tn_hash[idx]; d != NULL; ) {
			n = d->e_next;
			tnode_hashent_destroy(d);
			d = n;
		}
	}

	topo_free(ht->tn_hash);
	topo_free(ht);
}

void
tnode_hash_insert(struct tnode_hash *tab, const char *key, struct tnode *new)
{
	struct tnode_hashent *newent;
	int idx = topo_strhash(key) % tab->tn_hashlen;

	newent = tnode_hashent_create(new);

	tab->tn_nelems++;
	topo_out(TOPO_HASH, "Insert [key=%s] into %p, bucket %d ",
	    key, (void *)tab, idx);
	if (tab->tn_hash[idx] == NULL) {
		tab->tn_hash[idx] = newent;
		topo_out(TOPO_HASH, "first entry.\n");
	} else {
		newent->e_next = tab->tn_hash[idx];
		tab->tn_hash[idx] = newent;
		topo_out(TOPO_HASH, "\n");
	}
}

struct tnode_hashent *
tnode_hash_lookup(struct tnode_hash *tab, const char *key)
{
	int idx = topo_strhash(key) % tab->tn_hashlen;

	topo_out(TOPO_HASH, "Lookup [key=%s] in %p falls into bucket %d\n",
	    key, (void *)tab, idx);
	return (tab->tn_hash[idx]);
}

void
tprop_index(struct tnode *node, const char *propname)
{
	struct tnode_hash *ht;
	struct tnode *rn;

	/*
	 * We keep an index of what nodes have what properties on the
	 * root node
	 */
	if ((rn = node->root) == NULL)
		return;

	if ((ht = (struct tnode_hash *)rn->extend) == NULL) {
		ht = tnode_hash_create();
		rn->extend = ht;
		topo_out(TOPO_HASH, "props index table is %p\n", (void *)ht);
	}
	tnode_hash_insert(ht, propname, node);
}

static struct tnode *
next_nv_match(const char *name, const char *val, void **more)
{
	struct tnode_hashent *e;
	struct tnode *n;
	const char *pv;

	for (;;) {
		if ((e = *more) == NULL)
			return (NULL);
		n = e->e_node;
		*more = e->e_next;
		pv = topo_get_prop(n, name);
		if (pv == NULL)
			continue;
		if (strcmp(pv, val) == 0)
			return (n);
	}
	/*NOTREACHED*/
}

struct tnode *
topo_find_propval(struct tnode *node, const char *name, const char *value,
    void **more)
{
	struct tnode *r;

	if (more == NULL || *more == (void *)1)
		return (NULL);

	if (*more == NULL) {
		struct tnode_hash *ht;
		struct tnode *rn;
		/*
		 * We keep an index of what nodes have what properties
		 * on the root node
		 */
		if ((rn = node->root) == NULL)
			return (NULL);

		if ((ht = (struct tnode_hash *)rn->extend) == NULL)
			return (NULL);

		*more = tnode_hash_lookup(ht, name);
	}

	r = next_nv_match(name, value, more);
	if (*more == NULL)
		*more = (void *)1;
	return (r);
}
