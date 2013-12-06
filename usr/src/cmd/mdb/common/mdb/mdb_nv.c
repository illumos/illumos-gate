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
/*
 * Copyright (c) 2013 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 */

#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb.h>

#define	NV_NAME(v) \
	(((v)->v_flags & MDB_NV_EXTNAME) ? (v)->v_ename : (v)->v_lname)

#define	NV_SIZE(v) \
	(((v)->v_flags & MDB_NV_EXTNAME) ? sizeof (mdb_var_t) : \
	sizeof (mdb_var_t) + strlen((v)->v_lname))

#define	NV_HASHSZ	211

static size_t
nv_hashstring(const char *key)
{
	size_t g, h = 0;
	const char *p;

	ASSERT(key != NULL);

	for (p = key; *p != '\0'; p++) {
		h = (h << 4) + *p;

		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

static mdb_var_t *
nv_var_alloc(const char *name, const mdb_nv_disc_t *disc,
	uintmax_t value, uint_t flags, uint_t um_flags, mdb_var_t *next)
{
	size_t nbytes;
	mdb_var_t *v;

	if (flags & MDB_NV_EXTNAME)
		nbytes = sizeof (mdb_var_t);
	else
		nbytes = sizeof (mdb_var_t) + strlen(name);

	v = mdb_alloc(nbytes, um_flags);

	if (v == NULL)
		return (NULL);

	if (flags & MDB_NV_EXTNAME) {
		v->v_ename = name;
		v->v_lname[0] = '\0';
	} else {
		/*
		 * We don't overflow here since the mdb_var_t itself has
		 * room for the trailing \0.
		 */
		(void) strcpy(v->v_lname, name);
		v->v_ename = NULL;
	}

	v->v_uvalue = value;
	v->v_flags = flags & ~(MDB_NV_SILENT | MDB_NV_INTERPOS);
	v->v_disc = disc;
	v->v_next = next;

	return (v);
}

static void
nv_var_free(mdb_var_t *v, uint_t um_flags)
{
	if (um_flags & UM_GC)
		return;

	if (v->v_flags & MDB_NV_OVERLOAD) {
		mdb_var_t *w, *nw;

		for (w = v->v_ndef; w != NULL; w = nw) {
			nw = w->v_ndef;
			mdb_free(w, NV_SIZE(w));
		}
	}

	mdb_free(v, NV_SIZE(v));
}

/*
 * Can return NULL only if the nv's memory allocation flags include UM_NOSLEEP
 */
mdb_nv_t *
mdb_nv_create(mdb_nv_t *nv, uint_t um_flags)
{
	nv->nv_hash = mdb_zalloc(sizeof (mdb_var_t *) * NV_HASHSZ, um_flags);

	if (nv->nv_hash == NULL)
		return (NULL);

	nv->nv_hashsz = NV_HASHSZ;
	nv->nv_nelems = 0;
	nv->nv_iter_elt = NULL;
	nv->nv_iter_bucket = 0;
	nv->nv_um_flags = um_flags;

	return (nv);
}

void
mdb_nv_destroy(mdb_nv_t *nv)
{
	mdb_var_t *v, *w;
	size_t i;

	if (nv->nv_um_flags & UM_GC)
		return;

	for (i = 0; i < nv->nv_hashsz; i++) {
		for (v = nv->nv_hash[i]; v != NULL; v = w) {
			w = v->v_next;
			nv_var_free(v, nv->nv_um_flags);
		}
	}

	mdb_free(nv->nv_hash, sizeof (mdb_var_t *) * NV_HASHSZ);
}

mdb_var_t *
mdb_nv_lookup(mdb_nv_t *nv, const char *name)
{
	size_t i = nv_hashstring(name) % nv->nv_hashsz;
	mdb_var_t *v;

	for (v = nv->nv_hash[i]; v != NULL; v = v->v_next) {
		if (strcmp(NV_NAME(v), name) == 0)
			return (v);
	}

	return (NULL);
}

/*
 * Interpose W in place of V.  We replace V with W in nv_hash, and then
 * set W's v_ndef overload chain to point at V.
 */
static mdb_var_t *
nv_var_interpos(mdb_nv_t *nv, size_t i, mdb_var_t *v, mdb_var_t *w)
{
	mdb_var_t **pvp = &nv->nv_hash[i];

	while (*pvp != v) {
		mdb_var_t *vp = *pvp;
		ASSERT(vp != NULL);
		pvp = &vp->v_next;
	}

	*pvp = w;
	w->v_next = v->v_next;
	w->v_ndef = v;
	v->v_next = NULL;

	return (w);
}

/*
 * Add W to the end of V's overload chain.  We simply follow v_ndef to the
 * end, and then append W.  We don't expect these chains to grow very long.
 */
static mdb_var_t *
nv_var_overload(mdb_var_t *v, mdb_var_t *w)
{
	while (v->v_ndef != NULL)
		v = v->v_ndef;

	v->v_ndef = w;
	return (w);
}

/*
 * Can return NULL only if the nv's memory allocation flags include UM_NOSLEEP
 */
mdb_var_t *
mdb_nv_insert(mdb_nv_t *nv, const char *name, const mdb_nv_disc_t *disc,
    uintmax_t value, uint_t flags)
{
	size_t i = nv_hashstring(name) % nv->nv_hashsz;
	mdb_var_t *v;

	ASSERT(!(flags & MDB_NV_EXTNAME) || !(flags & MDB_NV_OVERLOAD));
	ASSERT(!(flags & MDB_NV_RDONLY) || !(flags & MDB_NV_OVERLOAD));

	/*
	 * If the specified name is already hashed,
	 * and MDB_NV_OVERLOAD is set:	insert new var into overload chain
	 * and MDB_NV_RDONLY is set:	leave var unchanged, issue warning
	 * otherwise:			update var with new value
	 */
	for (v = nv->nv_hash[i]; v != NULL; v = v->v_next) {
		if (strcmp(NV_NAME(v), name) == 0) {
			if (v->v_flags & MDB_NV_OVERLOAD) {
				mdb_var_t *w = nv_var_alloc(NV_NAME(v), disc,
				    value, flags, nv->nv_um_flags, NULL);

				if (w == NULL) {
					ASSERT(nv->nv_um_flags & UM_NOSLEEP);
					return (NULL);
				}

				if (flags & MDB_NV_INTERPOS)
					v = nv_var_interpos(nv, i, v, w);
				else
					v = nv_var_overload(v, w);

			} else if (v->v_flags & MDB_NV_RDONLY) {
				if (!(flags & MDB_NV_SILENT)) {
					warn("cannot modify read-only "
					    "variable '%s'\n", NV_NAME(v));
				}
			} else
				v->v_uvalue = value;

			ASSERT(v != NULL);
			return (v);
		}
	}

	/*
	 * If the specified name was not found, initialize a new element
	 * and add it to the hash table at the beginning of this chain:
	 */
	v = nv_var_alloc(name, disc, value, flags, nv->nv_um_flags,
	    nv->nv_hash[i]);

	if (v == NULL) {
		ASSERT(nv->nv_um_flags & UM_NOSLEEP);
		return (NULL);
	}

	nv->nv_hash[i] = v;
	nv->nv_nelems++;

	return (v);
}

static void
nv_var_defn_remove(mdb_var_t *v, mdb_var_t *corpse, uint_t um_flags)
{
	mdb_var_t *w = v;

	while (v->v_ndef != NULL && v->v_ndef != corpse)
		v = v->v_ndef;

	if (v == NULL) {
		fail("var %p ('%s') not found on defn chain of %p\n",
		    (void *)corpse, NV_NAME(corpse), (void *)w);
	}

	v->v_ndef = corpse->v_ndef;
	corpse->v_ndef = NULL;
	nv_var_free(corpse, um_flags);
}

void
mdb_nv_remove(mdb_nv_t *nv, mdb_var_t *corpse)
{
	const char *cname = NV_NAME(corpse);
	size_t i = nv_hashstring(cname) % nv->nv_hashsz;
	mdb_var_t *v = nv->nv_hash[i];
	mdb_var_t **pvp;

	if (corpse->v_flags & MDB_NV_PERSIST) {
		warn("cannot remove persistent variable '%s'\n", cname);
		return;
	}

	if (v != corpse) {
		do {
			if (strcmp(NV_NAME(v), cname) == 0) {
				if (corpse->v_flags & MDB_NV_OVERLOAD) {
					nv_var_defn_remove(v, corpse,
					    nv->nv_um_flags);
					return; /* No v_next changes needed */
				} else
					goto notfound;
			}

			if (v->v_next == corpse)
				break; /* Corpse is next on the chain */

		} while ((v = v->v_next) != NULL);

		if (v == NULL)
			goto notfound;

		pvp = &v->v_next;
	} else
		pvp = &nv->nv_hash[i];

	if ((corpse->v_flags & MDB_NV_OVERLOAD) && corpse->v_ndef != NULL) {
		corpse->v_ndef->v_next = corpse->v_next;
		*pvp = corpse->v_ndef;
		corpse->v_ndef = NULL;
	} else {
		*pvp = corpse->v_next;
		nv->nv_nelems--;
	}

	nv_var_free(corpse, nv->nv_um_flags);
	return;

notfound:
	fail("var %p ('%s') not found on hash chain: nv=%p [%lu]\n",
	    (void *)corpse, cname, (void *)nv, (ulong_t)i);
}

void
mdb_nv_rewind(mdb_nv_t *nv)
{
	size_t i;

	for (i = 0; i < nv->nv_hashsz; i++) {
		if (nv->nv_hash[i] != NULL)
			break;
	}

	nv->nv_iter_elt = i < nv->nv_hashsz ? nv->nv_hash[i] : NULL;
	nv->nv_iter_bucket = i;
}

mdb_var_t *
mdb_nv_advance(mdb_nv_t *nv)
{
	mdb_var_t *v = nv->nv_iter_elt;
	size_t i;

	if (v == NULL)
		return (NULL);

	if (v->v_next != NULL) {
		nv->nv_iter_elt = v->v_next;
		return (v);
	}

	for (i = nv->nv_iter_bucket + 1; i < nv->nv_hashsz; i++) {
		if (nv->nv_hash[i] != NULL)
			break;
	}

	nv->nv_iter_elt = i < nv->nv_hashsz ? nv->nv_hash[i] : NULL;
	nv->nv_iter_bucket = i;

	return (v);
}

mdb_var_t *
mdb_nv_peek(mdb_nv_t *nv)
{
	return (nv->nv_iter_elt);
}

size_t
mdb_nv_size(mdb_nv_t *nv)
{
	return (nv->nv_nelems);
}

static int
nv_compare(const mdb_var_t **lp, const mdb_var_t **rp)
{
	return (strcmp(mdb_nv_get_name(*lp), mdb_nv_get_name(*rp)));
}

void
mdb_nv_sort_iter(mdb_nv_t *nv, int (*func)(mdb_var_t *, void *),
    void *private, uint_t um_flags)
{
	mdb_var_t **vps =
	    mdb_alloc(nv->nv_nelems * sizeof (mdb_var_t *), um_flags);

	if (nv->nv_nelems != 0 && vps != NULL) {
		mdb_var_t *v, **vpp = vps;
		size_t i;

		for (mdb_nv_rewind(nv); (v = mdb_nv_advance(nv)) != NULL; )
			*vpp++ = v;

		qsort(vps, nv->nv_nelems, sizeof (mdb_var_t *),
		    (int (*)(const void *, const void *))nv_compare);

		for (vpp = vps, i = 0; i < nv->nv_nelems; i++) {
			if (func(*vpp++, private) == -1)
				break;
		}

		if (!(um_flags & UM_GC))
			mdb_free(vps, nv->nv_nelems * sizeof (mdb_var_t *));
	}
}

void
mdb_nv_defn_iter(mdb_var_t *v, int (*func)(mdb_var_t *, void *), void *private)
{
	if (func(v, private) == -1 || !(v->v_flags & MDB_NV_OVERLOAD))
		return;

	for (v = v->v_ndef; v != NULL; v = v->v_ndef) {
		if (func(v, private) == -1)
			break;
	}
}

uintmax_t
mdb_nv_get_value(const mdb_var_t *v)
{
	if (v->v_disc)
		return (v->v_disc->disc_get(v));

	return (v->v_uvalue);
}

void
mdb_nv_set_value(mdb_var_t *v, uintmax_t l)
{
	if (v->v_flags & MDB_NV_RDONLY) {
		warn("cannot modify read-only variable '%s'\n", NV_NAME(v));
		return;
	}

	if (v->v_disc)
		v->v_disc->disc_set(v, l);
	else
		v->v_uvalue = l;
}

void *
mdb_nv_get_cookie(const mdb_var_t *v)
{
	if (v->v_disc)
		return ((void *)(uintptr_t)v->v_disc->disc_get(v));

	return (MDB_NV_COOKIE(v));
}

void
mdb_nv_set_cookie(mdb_var_t *v, void *cookie)
{
	mdb_nv_set_value(v, (uintmax_t)(uintptr_t)cookie);
}

const char *
mdb_nv_get_name(const mdb_var_t *v)
{
	return (NV_NAME(v));
}

mdb_var_t *
mdb_nv_get_ndef(const mdb_var_t *v)
{
	if (v->v_flags & MDB_NV_OVERLOAD)
		return (v->v_ndef);

	return (NULL);
}
