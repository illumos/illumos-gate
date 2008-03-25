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
 *
 * stable.c -- string table module
 *
 * simple string table module.  all read-only strings are entered in
 * this table, allowing us to compare pointers rather than characters
 * to see if two strings are equal.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include "alloc.h"
#include "out.h"
#include "stats.h"
#include "stable.h"

#define	MINPTR_ALIGN	sizeof (char *)	/* alignment boundary for pointers */
#define	DEF_HASH_SIZE	11113	/* default hash table size */
#define	CHUNK_SIZE	8192	/* grab more memory with this chunk size */

static char **Stable;	/* the hash table */
static unsigned Stablesz;
static char *Stableblock;
static char *Stablenext;

static struct stats *Stablecount;
static struct stats *Blockcount;
static struct stats *Add0;
static struct stats *Add1;
static struct stats *Add2;
static struct stats *Add3;
static struct stats *Addn;

struct chunklst {
	struct chunklst *next;
	char *chunkp;
};

struct chunklst *Stablechunks;

/*
 * stable_init -- initialize the stable module
 *
 * hash table is sized according to sz.  sz of zero means pick
 * reasonable default size.
 */

void
stable_init(unsigned sz)
{
	/* allocate hash table */
	if (sz == 0)
		Stablesz = DEF_HASH_SIZE;
	else
		Stablesz = sz;

	Stable = MALLOC(Stablesz * sizeof (*Stable));
	bzero((void *)Stable, Stablesz * sizeof (*Stable));

	Stablecount = stats_new_counter("stable.size", "hash table size", 1);
	Blockcount = stats_new_counter("stable.blocks", "blocks allocated", 1);
	Add0 = stats_new_counter("stable.add0", "adds to empty buckets", 1);
	Add1 = stats_new_counter("stable.add1", "adds to 1-entry buckets", 1);
	Add2 = stats_new_counter("stable.add2", "adds to 2-entry buckets", 1);
	Add3 = stats_new_counter("stable.add3", "adds to 3-entry buckets", 1);
	Addn = stats_new_counter("stable.addn", "adds to n-entry buckets", 1);

	stats_counter_add(Stablecount, Stablesz);
}

void
stable_fini(void)
{
	struct chunklst *cp, *nc;

	stats_delete(Stablecount);
	stats_delete(Blockcount);
	stats_delete(Add0);
	stats_delete(Add1);
	stats_delete(Add2);
	stats_delete(Add3);
	stats_delete(Addn);

	FREE(Stable);
	cp = Stablechunks;
	nc = NULL;
	while (cp != NULL) {
		nc = cp->next;
		FREE(cp->chunkp);
		FREE(cp);
		cp = nc;
	}
	Stablechunks = NULL;
}

static char *
stable_newchunk(void)
{
	struct chunklst *save = Stablechunks;
	char *n;

	n = MALLOC(CHUNK_SIZE);
	bzero((void *)n, CHUNK_SIZE);
	stats_counter_bump(Blockcount);

	Stablechunks = MALLOC(sizeof (struct chunklst));
	Stablechunks->next = save;
	Stablechunks->chunkp = n;
	return (n);
}

/*
 * stable -- create/lookup a string table entry
 */

const char *
stable(const char *s)
{
	unsigned slen = 0;
	unsigned hash = DEF_HASH_SIZE ^ ((unsigned)*s << 2);
	char **ptrp;
	char *ptr;
	char *eptr;
	const char *sptr;
	int collisions = 0;

	if (Stablesz == 0)
		out(O_DIE, "internal error: Stablesz not set");

	for (sptr = &s[1]; *sptr; sptr++) {
		slen++;
		hash ^= (((unsigned)*sptr) << (slen % 3)) +
		    ((unsigned)*(sptr - 1) << ((slen % 3 + 7)));
	}
	hash ^= slen;
	if (slen > CHUNK_SIZE - sizeof (char *) - 1 - 4)
		out(O_DIE, "too big for string table %.20s...", s);
	hash %= Stablesz;

	ptrp = &Stable[hash];
	ptr = *ptrp;
	while (ptr) {
		/* hash brought us to something, see if it is the string */
		sptr = s;
		eptr = ptr;
		while (*sptr && *eptr && *sptr++ == *eptr++)
			;
		if (*sptr == '\0' && *eptr == '\0')
			return (ptr);	/* found it */
		/* strings didn't match, advance eptr to end of string */
		while (*eptr)
			eptr++;
		eptr++;		/* move past '\0' */
		while ((uintptr_t)eptr % MINPTR_ALIGN)
			eptr++;
		/* pull in next pointer in bucket */
		ptrp = (char **)(void *)eptr;
		ptr = *ptrp;
		collisions++;
	}

	/* string wasn't in table, add it and point ptr to it */
	if (Stablenext == NULL || (&Stableblock[CHUNK_SIZE] - Stablenext) <
	    (slen + sizeof (char *) + MINPTR_ALIGN + 4)) {
		/* need more room */
		Stablenext = Stableblock = stable_newchunk();
	}
	/* current chunk has room in it */
	ptr = *ptrp = Stablenext;
	sptr = s;
	while (*Stablenext++ = *sptr++)
		;
	while ((uintptr_t)Stablenext % MINPTR_ALIGN)
		Stablenext++;
	ptrp = (char **)(void *)Stablenext;
	Stablenext += sizeof (char *);
	*ptrp = NULL;

	/* just did an add, update stats */
	if (collisions == 0)
		stats_counter_bump(Add0);
	else if (collisions == 1)
		stats_counter_bump(Add1);
	else if (collisions == 2)
		stats_counter_bump(Add2);
	else if (collisions == 3)
		stats_counter_bump(Add3);
	else
		stats_counter_bump(Addn);

	return (ptr);
}
