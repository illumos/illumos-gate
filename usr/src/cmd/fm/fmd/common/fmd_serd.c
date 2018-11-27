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

#include <fmd_alloc.h>
#include <fmd_string.h>
#include <fmd_subr.h>
#include <fmd_api.h>
#include <fmd_serd.h>
#include <fmd.h>

static fmd_serd_eng_t *
fmd_serd_eng_alloc(const char *name, uint64_t n, hrtime_t t)
{
	fmd_serd_eng_t *sgp = fmd_zalloc(sizeof (fmd_serd_eng_t), FMD_SLEEP);

	sgp->sg_name = fmd_strdup(name, FMD_SLEEP);
	sgp->sg_flags = FMD_SERD_DIRTY;
	sgp->sg_n = n;
	sgp->sg_t = t;

	return (sgp);
}

static void
fmd_serd_eng_free(fmd_serd_eng_t *sgp)
{
	fmd_serd_eng_reset(sgp);
	fmd_strfree(sgp->sg_name);
	fmd_free(sgp, sizeof (fmd_serd_eng_t));
}

void
fmd_serd_hash_create(fmd_serd_hash_t *shp)
{
	shp->sh_hashlen = fmd.d_str_buckets;
	shp->sh_hash = fmd_zalloc(sizeof (void *) * shp->sh_hashlen, FMD_SLEEP);
	shp->sh_count = 0;
}

void
fmd_serd_hash_destroy(fmd_serd_hash_t *shp)
{
	fmd_serd_eng_t *sgp, *ngp;
	uint_t i;

	for (i = 0; i < shp->sh_hashlen; i++) {
		for (sgp = shp->sh_hash[i]; sgp != NULL; sgp = ngp) {
			ngp = sgp->sg_next;
			fmd_serd_eng_free(sgp);
		}
	}

	fmd_free(shp->sh_hash, sizeof (void *) * shp->sh_hashlen);
	bzero(shp, sizeof (fmd_serd_hash_t));
}

void
fmd_serd_hash_apply(fmd_serd_hash_t *shp, fmd_serd_eng_f *func, void *arg)
{
	fmd_serd_eng_t *sgp;
	uint_t i;

	for (i = 0; i < shp->sh_hashlen; i++) {
		for (sgp = shp->sh_hash[i]; sgp != NULL; sgp = sgp->sg_next)
			func(sgp, arg);
	}
}

uint_t
fmd_serd_hash_count(fmd_serd_hash_t *shp)
{
	return (shp->sh_count);
}

int
fmd_serd_hash_contains(fmd_serd_hash_t *shp, fmd_event_t *ep)
{
	fmd_serd_eng_t *sgp;
	uint_t i;

	for (i = 0; i < shp->sh_hashlen; i++) {
		for (sgp = shp->sh_hash[i]; sgp != NULL; sgp = sgp->sg_next) {
			if (fmd_serd_eng_contains(sgp, ep)) {
				fmd_event_transition(ep, FMD_EVS_ACCEPTED);
				return (1);
			}
		}
	}

	return (0);
}

fmd_serd_eng_t *
fmd_serd_eng_insert(fmd_serd_hash_t *shp,
    const char *name, uint_t n, hrtime_t t)
{
	uint_t h = fmd_strhash(name) % shp->sh_hashlen;
	fmd_serd_eng_t *sgp = fmd_serd_eng_alloc(name, n, t);

	sgp->sg_next = shp->sh_hash[h];
	shp->sh_hash[h] = sgp;
	shp->sh_count++;

	return (sgp);
}

fmd_serd_eng_t *
fmd_serd_eng_lookup(fmd_serd_hash_t *shp, const char *name)
{
	uint_t h = fmd_strhash(name) % shp->sh_hashlen;
	fmd_serd_eng_t *sgp;

	for (sgp = shp->sh_hash[h]; sgp != NULL; sgp = sgp->sg_next) {
		if (strcmp(name, sgp->sg_name) == 0)
			return (sgp);
	}

	return (NULL);
}

void
fmd_serd_eng_delete(fmd_serd_hash_t *shp, const char *name)
{
	uint_t h = fmd_strhash(name) % shp->sh_hashlen;
	fmd_serd_eng_t *sgp, **pp = &shp->sh_hash[h];

	for (sgp = *pp; sgp != NULL; sgp = sgp->sg_next) {
		if (strcmp(sgp->sg_name, name) != 0)
			pp = &sgp->sg_next;
		else
			break;
	}

	if (sgp != NULL) {
		*pp = sgp->sg_next;
		fmd_serd_eng_free(sgp);
		ASSERT(shp->sh_count != 0);
		shp->sh_count--;
	}
}

static void
fmd_serd_eng_discard(fmd_serd_eng_t *sgp, fmd_serd_elem_t *sep)
{
	fmd_list_delete(&sgp->sg_list, sep);
	sgp->sg_count--;

	fmd_event_rele(sep->se_event);
	fmd_free(sep, sizeof (fmd_serd_elem_t));
}

int
fmd_serd_eng_contains(fmd_serd_eng_t *sgp, fmd_event_t *ep)
{
	fmd_serd_elem_t *sep;

	for (sep = fmd_list_next(&sgp->sg_list);
	    sep != NULL; sep = fmd_list_next(sep)) {
		if (fmd_event_equal(sep->se_event, ep))
			return (1);
	}

	return (0);
}

int
fmd_serd_eng_record(void *ptr, fmd_event_t *ep)
{
	fmd_serd_eng_t *sgp = ptr;
	fmd_serd_elem_t *sep, *oep;

	/*
	 * If the fired flag is already set, return false and discard the
	 * event.  This means that the caller will only see the engine "fire"
	 * once until fmd_serd_eng_reset() is called.  The fmd_serd_eng_fired()
	 * function can also be used in combination with fmd_serd_eng_record().
	 */
	if (sgp->sg_flags & FMD_SERD_FIRED)
		return (FMD_B_FALSE);

	while (sgp->sg_count > sgp->sg_n)
		fmd_serd_eng_discard(sgp, fmd_list_next(&sgp->sg_list));

	fmd_event_hold(ep);
	fmd_event_transition(ep, FMD_EVS_ACCEPTED);

	sep = fmd_alloc(sizeof (fmd_serd_elem_t), FMD_SLEEP);
	sep->se_event = ep;

	fmd_list_append(&sgp->sg_list, sep);
	sgp->sg_count++;

	/*
	 * Pick up the oldest element pointer for comparison to 'sep'.  We must
	 * do this after adding 'sep' because 'oep' and 'sep' can be the same.
	 */
	oep = fmd_list_next(&sgp->sg_list);

	if (sgp->sg_count > sgp->sg_n &&
	    fmd_event_delta(oep->se_event, sep->se_event) <= sgp->sg_t) {
		sgp->sg_flags |= FMD_SERD_FIRED | FMD_SERD_DIRTY;
		return (FMD_B_TRUE);
	}

	sgp->sg_flags |= FMD_SERD_DIRTY;
	return (FMD_B_FALSE);
}

int
fmd_serd_eng_fired(fmd_serd_eng_t *sgp)
{
	return (sgp->sg_flags & FMD_SERD_FIRED);
}

int
fmd_serd_eng_empty(fmd_serd_eng_t *sgp)
{
	return (sgp->sg_count == 0);
}

void
fmd_serd_eng_reset(fmd_serd_eng_t *sgp)
{
	while (sgp->sg_count != 0)
		fmd_serd_eng_discard(sgp, fmd_list_next(&sgp->sg_list));

	sgp->sg_flags &= ~FMD_SERD_FIRED;
	sgp->sg_flags |= FMD_SERD_DIRTY;
}

void
fmd_serd_eng_gc(fmd_serd_eng_t *sgp, void *arg __unused)
{
	fmd_serd_elem_t *sep, *nep;
	hrtime_t hrt;

	if (sgp->sg_count == 0 || (sgp->sg_flags & FMD_SERD_FIRED))
		return; /* no garbage collection needed if empty or fired */

	sep = fmd_list_prev(&sgp->sg_list);
	hrt = fmd_event_hrtime(sep->se_event) - sgp->sg_t;

	for (sep = fmd_list_next(&sgp->sg_list); sep != NULL; sep = nep) {
		if (fmd_event_hrtime(sep->se_event) >= hrt)
			break; /* sep and subsequent events are all within T */

		nep = fmd_list_next(sep);
		fmd_serd_eng_discard(sgp, sep);
		sgp->sg_flags |= FMD_SERD_DIRTY;
	}
}

void
fmd_serd_eng_commit(fmd_serd_eng_t *sgp, void *arg __unused)
{
	fmd_serd_elem_t *sep;

	if (!(sgp->sg_flags & FMD_SERD_DIRTY))
		return; /* engine has not changed since last commit */

	for (sep = fmd_list_next(&sgp->sg_list); sep != NULL;
	    sep = fmd_list_next(sep))
		fmd_event_commit(sep->se_event);

	sgp->sg_flags &= ~FMD_SERD_DIRTY;
}

void
fmd_serd_eng_clrdirty(fmd_serd_eng_t *sgp, void *arg __unused)
{
	sgp->sg_flags &= ~FMD_SERD_DIRTY;
}
