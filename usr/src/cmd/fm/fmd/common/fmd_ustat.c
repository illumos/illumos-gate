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

#include <fmd_ustat.h>
#include <fmd_alloc.h>
#include <fmd_subr.h>
#include <fmd_string.h>
#include <fmd_error.h>
#include <fmd.h>

static fmd_ustat_chunk_t *
fmd_ustat_chunk_init(fmd_ustat_t *usp, fmd_stat_t *base, uint_t len)
{
	fmd_ustat_chunk_t *cp;

	cp = fmd_zalloc(sizeof (fmd_ustat_chunk_t), FMD_SLEEP);
	cp->usc_base = base;
	cp->usc_len = len;
	cp->usc_refs = 1;

	ASSERT(RW_WRITE_HELD(&usp->us_lock));
	fmd_list_append(&usp->us_chunks, cp);

	return (cp);
}

static void
fmd_ustat_chunk_hold(fmd_ustat_t *usp, fmd_ustat_chunk_t *cp)
{
	ASSERT(RW_WRITE_HELD(&usp->us_lock));
	cp->usc_refs++;
	ASSERT(cp->usc_refs != 0);
}

static void
fmd_ustat_chunk_rele(fmd_ustat_t *usp, fmd_ustat_chunk_t *cp)
{
	ASSERT(RW_WRITE_HELD(&usp->us_lock));
	ASSERT(cp->usc_refs != 0);

	if (--cp->usc_refs == 0) {
		/*
		 * Note that any strings pointed to by FMD_TYPE_STRING stats
		 * are freed one-by-one before releasing the chunk.  So here
		 * we can just free the chunk and not worry about its content.
		 */
		fmd_free(cp->usc_base, sizeof (fmd_stat_t) * cp->usc_len);
		fmd_list_delete(&usp->us_chunks, cp);
		fmd_free(cp, sizeof (fmd_ustat_chunk_t));
	}
}

fmd_ustat_t *
fmd_ustat_create(void)
{
	fmd_ustat_t *usp = fmd_zalloc(sizeof (fmd_ustat_t), FMD_SLEEP);

	(void) pthread_rwlock_init(&usp->us_lock, NULL);
	usp->us_hashlen = fmd.d_str_buckets;
	usp->us_hash = fmd_zalloc(sizeof (void *) * usp->us_hashlen, FMD_SLEEP);

	return (usp);
}

void
fmd_ustat_destroy(fmd_ustat_t *usp)
{
	fmd_ustat_elem_t *ep, *np;
	uint_t i;

	(void) pthread_rwlock_wrlock(&usp->us_lock);

	for (i = 0; i < usp->us_hashlen; i++) {
		for (ep = usp->us_hash[i]; ep != NULL; ep = np) {
			if (ep->use_stat->fmds_type == FMD_TYPE_STRING)
				fmd_strfree(ep->use_stat->fmds_value.str);

			if (ep->use_chunk != NULL)
				fmd_ustat_chunk_rele(usp, ep->use_chunk);

			np = ep->use_next;
			fmd_free(ep, sizeof (fmd_ustat_elem_t));
		}
	}

	ASSERT(usp->us_chunks.l_next == NULL);
	ASSERT(usp->us_chunks.l_prev == NULL);

	fmd_free(usp->us_hash, sizeof (void *) * usp->us_hashlen);
	fmd_free(usp, sizeof (fmd_ustat_t));
}

int
fmd_ustat_snapshot(fmd_ustat_t *usp, fmd_ustat_snap_t *uss)
{
	const fmd_ustat_elem_t *ep;
	fmd_stat_t *sp;
	uint_t i;

	(void) pthread_rwlock_wrlock(&usp->us_lock);

	uss->uss_buf = sp = malloc(sizeof (fmd_stat_t) * usp->us_nelems);
	uss->uss_len = usp->us_nelems;

	if (uss->uss_buf == NULL) {
		(void) pthread_rwlock_unlock(&usp->us_lock);
		return (fmd_set_errno(EFMD_STAT_NOMEM));
	}

	for (i = 0; i < usp->us_hashlen; i++) {
		for (ep = usp->us_hash[i]; ep != NULL; ep = ep->use_next) {
			bcopy(ep->use_stat, sp, sizeof (fmd_stat_t));
			if (sp->fmds_type == FMD_TYPE_STRING &&
			    sp->fmds_value.str != NULL)
				sp->fmds_value.str = strdup(sp->fmds_value.str);
			sp++;
		}
	}

	ASSERT(sp == uss->uss_buf + uss->uss_len);
	(void) pthread_rwlock_unlock(&usp->us_lock);
	return (0);
}

static void
fmd_ustat_delete_locked(fmd_ustat_t *usp, uint_t n, fmd_stat_t *sp, int strfree)
{
	ASSERT(RW_WRITE_HELD(&usp->us_lock));

	for (; n-- != 0; sp++) {
		uint_t h = fmd_strhash(sp->fmds_name) % usp->us_hashlen;
		fmd_ustat_elem_t *ep, **pp = &usp->us_hash[h];

		for (ep = *pp; ep != NULL; ep = ep->use_next) {
			if (strcmp(sp->fmds_name, ep->use_stat->fmds_name) != 0)
				pp = &ep->use_next;
			else
				break;
		}

		if (ep == NULL)
			continue; /* silently ignore unregistered entries */

		if (strfree && ep->use_stat->fmds_type == FMD_TYPE_STRING)
			fmd_strfree(ep->use_stat->fmds_value.str);

		if (ep->use_chunk != NULL)
			fmd_ustat_chunk_rele(usp, ep->use_chunk);

		*pp = ep->use_next;
		fmd_free(ep, sizeof (fmd_ustat_elem_t));
		usp->us_nelems--;
	}
}

fmd_stat_t *
fmd_ustat_insert(fmd_ustat_t *usp, uint_t flags,
    uint_t n, fmd_stat_t *template, fmd_stat_t **epp)
{
	fmd_stat_t *stats, *sp;
	fmd_ustat_chunk_t *cp;
	uint_t i;

	int checkid = flags & FMD_USTAT_VALIDATE;
	int has_str = 0;
	int err = 0;

	if (flags & FMD_USTAT_ALLOC) {
		sp = stats = fmd_alloc(sizeof (fmd_stat_t) * n, FMD_SLEEP);
		bcopy(template, stats, sizeof (fmd_stat_t) * n);
	} else
		sp = stats = template;

	(void) pthread_rwlock_wrlock(&usp->us_lock);

	if (flags & FMD_USTAT_ALLOC)
		cp = fmd_ustat_chunk_init(usp, stats, n);
	else
		cp = NULL;

	for (i = 0; i < n; i++, sp++) {
		char *p, *q = sp->fmds_name + sizeof (sp->fmds_name);
		fmd_ustat_elem_t *ep;
		uint_t h;

		/*
		 * Since a module may be passing in this statistic and our
		 * names are represented by a fixed-size array, scan fmds_name
		 * to ensure it has a \0 somewhere before we attempt strcmps.
		 */
		for (p = sp->fmds_name; p < q; p++) {
			if (*p == '\0')
				break;
		}

		if (p == q)
			q[-1] = '\0'; /* nul-terminate for subsequent message */

		if (p == q || fmd_strbadid(sp->fmds_name, checkid) != NULL) {
			fmd_error(EFMD_STAT_BADNAME, "'%s' does not conform to "
			    "statistic naming rules\n", sp->fmds_name);
			err = fmd_set_errno(EFMD_STAT_BADNAME);
			break;
		}

		if (sp->fmds_type > FMD_TYPE_SIZE) {
			fmd_error(EFMD_STAT_BADTYPE, "'%s' statistic type %u "
			    "is not valid\n", sp->fmds_name, sp->fmds_type);
			err = fmd_set_errno(EFMD_STAT_BADTYPE);
			break;
		}

		if (sp->fmds_type == FMD_TYPE_STRING)
			has_str++; /* flag for second pass; see below */

		h = fmd_strhash(sp->fmds_name) % usp->us_hashlen;

		for (ep = usp->us_hash[h]; ep != NULL; ep = ep->use_next) {
			if (strcmp(sp->fmds_name, ep->use_stat->fmds_name) == 0)
				break;
		}

		if (ep != NULL) {
			fmd_error(EFMD_STAT_DUPNAME, "'%s' is already defined "
			    "as a statistic name\n", sp->fmds_name);
			err = fmd_set_errno(EFMD_STAT_DUPNAME);
			break;
		}

		ep = fmd_alloc(sizeof (fmd_ustat_elem_t), FMD_SLEEP);

		ep->use_next = usp->us_hash[h];
		usp->us_hash[h] = ep;
		ep->use_stat = sp;
		ep->use_chunk = cp;

		if (cp != NULL)
			fmd_ustat_chunk_hold(usp, cp);

		usp->us_nelems++;
	}

	/*
	 * If an error occurred, delete all the stats inserted by successful
	 * iterations of the loop [0 .. i-1].  If 'epp' is non-NULL, store a
	 * copy of the input stat pointer that caused the error there.  When
	 * the delete is done, if we allocated a chunk, there should be only
	 * one reference remaining (from the initial fmd_ustat_chunk_init()).
	 */
	if (err != 0) {
		fmd_ustat_delete_locked(usp, i, stats, FMD_B_FALSE);
		ASSERT(cp == NULL || cp->usc_refs == 1);
		if (epp != NULL)
			*epp = template + i;

	} else if (has_str) {
		/*
		 * If no error occurred and one or more string stats are being
		 * inserted, make a second pass through 'stats' duplicating any
		 * initial strings so that fmd_stat_setstr() can alloc/free.
		 */
		for (sp = stats, i = 0; i < n; i++, sp++) {
			if (sp->fmds_type == FMD_TYPE_STRING &&
			    sp->fmds_value.str != NULL) {
				sp->fmds_value.str = fmd_strdup(
				    sp->fmds_value.str, FMD_SLEEP);
			}
		}
	}

	if (cp != NULL)
		fmd_ustat_chunk_rele(usp, cp);

	(void) pthread_rwlock_unlock(&usp->us_lock);
	return (err ? NULL : stats);
}

void
fmd_ustat_delete(fmd_ustat_t *usp, uint_t n, fmd_stat_t *sp)
{
	(void) pthread_rwlock_wrlock(&usp->us_lock);
	fmd_ustat_delete_locked(usp, n, sp, FMD_B_TRUE);
	(void) pthread_rwlock_unlock(&usp->us_lock);
}

/*
 * Delete all statistics that are references to external memory (that is, all
 * statistics inserted with FMD_STAT_NOALLOC), i.e. a NULL ep->use_chunk.
 */
void
fmd_ustat_delete_references(fmd_ustat_t *usp)
{
	fmd_ustat_elem_t *ep, **pp;
	uint_t i;

	(void) pthread_rwlock_wrlock(&usp->us_lock);

	for (i = 0; i < usp->us_hashlen; i++) {
		for (pp = &usp->us_hash[i], ep = *pp; ep != NULL; ep = *pp) {
			if (ep->use_chunk != NULL) {
				pp = &ep->use_next;
				continue;
			}

			if (ep->use_stat->fmds_type == FMD_TYPE_STRING)
				fmd_strfree(ep->use_stat->fmds_value.str);

			*pp = ep->use_next;
			fmd_free(ep, sizeof (fmd_ustat_elem_t));
			usp->us_nelems--;
		}
	}

	(void) pthread_rwlock_unlock(&usp->us_lock);
}
