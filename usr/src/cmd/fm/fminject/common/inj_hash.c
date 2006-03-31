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

#include <string.h>
#include <sys/types.h>

#include <inj.h>
#include <inj_err.h>

#define	INJ_HASHSZ	211

struct inj_var {
	struct inj_var *v_next;
	uintmax_t v_uvalue;
	void *v_key;
};

void
inj_hash_create(inj_hash_t *h, ulong_t (*hfn)(void *),
    int (*cfn)(void *, void *))
{
	h->h_hash = inj_zalloc(sizeof (inj_var_t *) * INJ_HASHSZ);
	h->h_hashsz = INJ_HASHSZ;
	h->h_nelems = 0;

	h->h_hashfn = hfn;
	h->h_cmpfn = cfn;
}

static inj_var_t *
inj_var_alloc(void *key, uintmax_t value, inj_var_t *next)
{
	inj_var_t *v = inj_alloc(sizeof (inj_var_t));

	v->v_next = next;
	v->v_key = key;
	v->v_uvalue = value;

	return (v);
}

static void
inj_var_free(inj_var_t *v, void (*freefn)(inj_var_t *, void *), void *arg)
{
	if (freefn != NULL)
		freefn(v, arg);

	inj_free(v, sizeof (inj_var_t));
}

void
inj_hash_destroy(inj_hash_t *h, void (*freefn)(inj_var_t *, void *), void *arg)
{
	inj_var_t *v, *w;
	size_t i;

	for (i = 0; i < h->h_hashsz; i++) {
		for (v = h->h_hash[i]; v != NULL; v = w) {
			w = v->v_next;
			inj_var_free(v, freefn, arg);
		}
	}

	inj_free(h->h_hash, sizeof (inj_var_t *) * INJ_HASHSZ);
}

int
inj_hash_insert(inj_hash_t *h, void *key, uintmax_t value)
{
	size_t i = h->h_hashfn(key) % h->h_hashsz;
	inj_var_t *v;

	for (v = h->h_hash[i]; v != NULL; v = v->v_next) {
		if (h->h_cmpfn(v->v_key, key) == 0)
			return (-1);
	}

	/* not found - make a new one */
	v = inj_var_alloc(key, value, h->h_hash[i]);
	h->h_hash[i] = v;
	h->h_nelems++;

	return (0);
}

inj_var_t *
inj_hash_lookup(inj_hash_t *h, void *key)
{
	size_t i = h->h_hashfn(key) % h->h_hashsz;
	inj_var_t *v;

	for (v = h->h_hash[i]; v != NULL; v = v->v_next) {
		if (h->h_cmpfn(v->v_key, key) == 0)
			return (v);
	}

	return (NULL);
}

void *
inj_hash_get_key(inj_var_t *v)
{
	return (v->v_key);
}

uintmax_t
inj_hash_get_value(inj_var_t *v)
{
	return (v->v_uvalue);
}

void *
inj_hash_get_cookie(inj_var_t *v)
{
	return ((void *)(uintptr_t)v->v_uvalue);
}
