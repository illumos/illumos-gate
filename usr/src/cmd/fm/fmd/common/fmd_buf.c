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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fmd_alloc.h>
#include <fmd_string.h>
#include <fmd_subr.h>
#include <fmd_buf.h>
#include <fmd.h>

static fmd_buf_t *
fmd_buf_alloc(const char *name, size_t size)
{
	fmd_buf_t *bp = fmd_alloc(sizeof (fmd_buf_t), FMD_SLEEP);

	bp->buf_name = fmd_strdup(name, FMD_SLEEP);
	bp->buf_next = NULL;
	bp->buf_data = fmd_zalloc(size, FMD_SLEEP);
	bp->buf_size = size;
	bp->buf_flags = FMD_BUF_DIRTY;

	return (bp);
}

static void
fmd_buf_free(fmd_buf_t *bp)
{
	fmd_strfree(bp->buf_name);
	fmd_free(bp->buf_data, bp->buf_size);
	fmd_free(bp, sizeof (fmd_buf_t));
}

void
fmd_buf_hash_create(fmd_buf_hash_t *bhp)
{
	bhp->bh_hashlen = fmd.d_str_buckets;
	bhp->bh_hash = fmd_zalloc(sizeof (void *) * bhp->bh_hashlen, FMD_SLEEP);
	bhp->bh_count = 0;
}

size_t
fmd_buf_hash_destroy(fmd_buf_hash_t *bhp)
{
	size_t total = 0;
	fmd_buf_t *bp, *np;
	uint_t i;

	for (i = 0; i < bhp->bh_hashlen; i++) {
		for (bp = bhp->bh_hash[i]; bp != NULL; bp = np) {
			np = bp->buf_next;
			total += bp->buf_size;
			fmd_buf_free(bp);
		}
	}

	fmd_free(bhp->bh_hash, sizeof (void *) * bhp->bh_hashlen);
	bzero(bhp, sizeof (fmd_buf_hash_t));
	return (total);
}

void
fmd_buf_hash_apply(fmd_buf_hash_t *bhp, fmd_buf_f *func, void *arg)
{
	fmd_buf_t *bp;
	uint_t i;

	for (i = 0; i < bhp->bh_hashlen; i++) {
		for (bp = bhp->bh_hash[i]; bp != NULL; bp = bp->buf_next)
			func(bp, arg);
	}
}

void
fmd_buf_hash_commit(fmd_buf_hash_t *bhp)
{
	fmd_buf_t *bp;
	uint_t i;

	for (i = 0; i < bhp->bh_hashlen; i++) {
		for (bp = bhp->bh_hash[i]; bp != NULL; bp = bp->buf_next)
			bp->buf_flags &= ~FMD_BUF_DIRTY;
	}
}

uint_t
fmd_buf_hash_count(fmd_buf_hash_t *bhp)
{
	return (bhp->bh_count);
}

fmd_buf_t *
fmd_buf_insert(fmd_buf_hash_t *bhp, const char *name, size_t size)
{
	uint_t h = fmd_strhash(name) % bhp->bh_hashlen;
	fmd_buf_t *bp = fmd_buf_alloc(name, size);

	bp->buf_next = bhp->bh_hash[h];
	bhp->bh_hash[h] = bp;
	bhp->bh_count++;

	return (bp);
}

fmd_buf_t *
fmd_buf_lookup(fmd_buf_hash_t *bhp, const char *name)
{
	uint_t h = fmd_strhash(name) % bhp->bh_hashlen;
	fmd_buf_t *bp;

	for (bp = bhp->bh_hash[h]; bp != NULL; bp = bp->buf_next) {
		if (strcmp(name, bp->buf_name) == 0)
			return (bp);
	}

	return (NULL);
}

void
fmd_buf_delete(fmd_buf_hash_t *bhp, const char *name)
{
	uint_t h = fmd_strhash(name) % bhp->bh_hashlen;
	fmd_buf_t *bp, **pp = &bhp->bh_hash[h];

	for (bp = *pp; bp != NULL; bp = bp->buf_next) {
		if (strcmp(bp->buf_name, name) != 0)
			pp = &bp->buf_next;
		else
			break;
	}

	if (bp != NULL) {
		*pp = bp->buf_next;
		fmd_buf_free(bp);
		ASSERT(bhp->bh_count != 0);
		bhp->bh_count--;
	}
}
