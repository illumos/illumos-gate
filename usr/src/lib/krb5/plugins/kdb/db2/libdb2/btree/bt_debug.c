/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*-
 * Copyright (c) 1990, 1993, 1994, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Olson.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)bt_debug.c	8.6 (Berkeley) 1/9/95";
#endif /* LIBC_SCCS and not lint */

#include <sys/param.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db-int.h"
#include "btree.h"

#if defined(DEBUG) || defined(STATISTICS)

static FILE *tracefp;

/*
 * __bt_dinit --
 *	initialize debugging.
 */
static void
__bt_dinit()
{
	static int first = 1;
	char buf[1024];

	if (!first)
		return;
	first = 0;

#ifndef TRACE_TO_STDERR
	if ((tracefp = fopen("/tmp/__bt_debug", "wF")) != NULL)
		return;
#endif
	tracefp = stderr;
}
#endif

#ifdef DEBUG
/*
 * __bt_dump --
 *	dump the tree
 *
 * Parameters:
 *	dbp:	pointer to the DB
 */
int
__bt_dump(dbp)
	DB *dbp;
{
	BTREE *t;
	PAGE *h;
	db_pgno_t i;
	char *sep;

	__bt_dinit();

	t = dbp->internal;
	(void)fprintf(tracefp, "%s: pgsz %d",
	    F_ISSET(t, B_INMEM) ? "memory" : "disk", t->bt_psize);
	if (F_ISSET(t, R_RECNO))
		(void)fprintf(tracefp, " keys %lu", t->bt_nrecs);
#undef X
#define	X(flag, name) \
	if (F_ISSET(t, flag)) { \
		(void)fprintf(tracefp, "%s%s", sep, name); \
		sep = ", "; \
	}
	if (t->flags != 0) {
		sep = " flags (";
		X(R_FIXLEN,	"FIXLEN");
		X(B_INMEM,	"INMEM");
		X(B_NODUPS,	"NODUPS");
		X(B_RDONLY,	"RDONLY");
		X(R_RECNO,	"RECNO");
		X(B_METADIRTY,"METADIRTY");
		(void)fprintf(tracefp, ")\n");
	}
#undef X
	for (i = P_ROOT; i < t->bt_mp->npages &&
	    (h = mpool_get(t->bt_mp, i, MPOOL_IGNOREPIN)) != NULL; ++i)
		__bt_dpage(dbp, h);
	(void)fflush(tracefp);
	return (0);
}

/*
 * BT_DMPAGE -- Dump the meta page
 *
 * Parameters:
 *	h:	pointer to the PAGE
 */
int
__bt_dmpage(h)
	PAGE *h;
{
	BTMETA *m;
	char *sep;

	__bt_dinit();

	m = (BTMETA *)h;
	(void)fprintf(tracefp, "magic %lx\n", m->magic);
	(void)fprintf(tracefp, "version %lu\n", m->version);
	(void)fprintf(tracefp, "psize %lu\n", m->psize);
	(void)fprintf(tracefp, "free %lu\n", m->free);
	(void)fprintf(tracefp, "nrecs %lu\n", m->nrecs);
	(void)fprintf(tracefp, "flags %lu", m->flags);
#undef X
#define	X(flag, name) \
	if (m->flags & flag) { \
		(void)fprintf(tracefp, "%s%s", sep, name); \
		sep = ", "; \
	}
	if (m->flags) {
		sep = " (";
		X(B_NODUPS,	"NODUPS");
		X(R_RECNO,	"RECNO");
		(void)fprintf(tracefp, ")");
	}
	(void)fprintf(tracefp, "\n");
	(void)fflush(tracefp);
	return (0);
}

/*
 * BT_DNPAGE -- Dump the page
 *
 * Parameters:
 *	n:	page number to dump.
 */
int
__bt_dnpage(dbp, pgno)
	DB *dbp;
	db_pgno_t pgno;
{
	BTREE *t;
	PAGE *h;

	__bt_dinit();

	t = dbp->internal;
	if ((h = mpool_get(t->bt_mp, pgno, MPOOL_IGNOREPIN)) != NULL)
		__bt_dpage(dbp, h);
	(void)fflush(tracefp);
	return (0);
}

/*
 * BT_DPAGE -- Dump the page
 *
 * Parameters:
 *	h:	pointer to the PAGE
 */
void
__bt_dpage(dbp, h)
	DB *dbp;
	PAGE *h;
{
	BINTERNAL *bi;
	BLEAF *bl;
	RINTERNAL *ri;
	RLEAF *rl;
	u_long pgsize;
	indx_t cur, top, lim;
	char *sep;

	__bt_dinit();

	(void)fprintf(tracefp, "    page %d: (", h->pgno);
#undef X
#define	X(flag, name)							\
	if (h->flags & flag) {						\
		(void)fprintf(tracefp, "%s%s", sep, name);		\
		sep = ", ";						\
	}
	sep = "";
	X(P_BINTERNAL,	"BINTERNAL")		/* types */
	X(P_BLEAF,	"BLEAF")
	X(P_RINTERNAL,	"RINTERNAL")		/* types */
	X(P_RLEAF,	"RLEAF")
	X(P_OVERFLOW,	"OVERFLOW")
	X(P_PRESERVE,	"PRESERVE");
	(void)fprintf(tracefp, ")\n");
#undef X

	(void)fprintf(tracefp, "\tprev %2d next %2d", h->prevpg, h->nextpg);
	if (h->flags & P_OVERFLOW)
		return;

	pgsize = ((BTREE *)dbp->internal)->bt_mp->pagesize;
	lim = (pgsize - BTDATAOFF) / sizeof(indx_t);
	top = NEXTINDEX(h);
	lim = top > lim ? lim : top;
	(void)fprintf(tracefp, " lower %3d upper %3d nextind %d\n",
	    h->lower, h->upper, top);
	for (cur = 0; cur < lim; cur++) {
		(void)fprintf(tracefp, "\t[%03d] %4d ", cur, h->linp[cur]);
		switch (h->flags & P_TYPE) {
		case P_BINTERNAL:
			bi = GETBINTERNAL(h, cur);
			(void)fprintf(tracefp,
			    "size %03d pgno %03d", bi->ksize, bi->pgno);
			if (bi->flags & P_BIGKEY)
				(void)fprintf(tracefp, " (indirect)");
			else if (bi->ksize)
				(void)fprintf(tracefp,
				    " {%.*s}", (int)bi->ksize, bi->bytes);
			break;
		case P_RINTERNAL:
			ri = GETRINTERNAL(h, cur);
			(void)fprintf(tracefp, "entries %03d pgno %03d",
				ri->nrecs, ri->pgno);
			break;
		case P_BLEAF:
			bl = GETBLEAF(h, cur);
			if (bl->flags & P_BIGKEY)
				(void)fprintf(tracefp,
				    "big key page %lu size %u/",
				    *(db_pgno_t *)bl->bytes,
				    *(u_int32_t *)(bl->bytes + sizeof(db_pgno_t)));
			else if (bl->ksize)
				(void)fprintf(tracefp, "%s/", bl->bytes);
			if (bl->flags & P_BIGDATA)
				(void)fprintf(tracefp,
				    "big data page %lu size %u",
				    *(db_pgno_t *)(bl->bytes + bl->ksize),
				    *(u_int32_t *)(bl->bytes + bl->ksize +
				    sizeof(db_pgno_t)));
			else if (bl->dsize)
				(void)fprintf(tracefp, "%.*s",
				    (int)bl->dsize, bl->bytes + bl->ksize);
			break;
		case P_RLEAF:
			rl = GETRLEAF(h, cur);
			if (rl->flags & P_BIGDATA)
				(void)fprintf(tracefp,
				    "big data page %lu size %u",
				    *(db_pgno_t *)rl->bytes,
				    *(u_int32_t *)(rl->bytes + sizeof(db_pgno_t)));
			else if (rl->dsize)
				(void)fprintf(tracefp,
				    "%.*s", (int)rl->dsize, rl->bytes);
			break;
		}
		(void)fprintf(tracefp, "\n");
	}
	(void)fflush(tracefp);
	return;
}
#endif

#ifdef STATISTICS
/*
 * bt_stat --
 *	Gather/print the tree statistics
 *
 * Parameters:
 *	dbp:	pointer to the DB
 */
int
__bt_stat(dbp)
	DB *dbp;
{
	extern u_long bt_cache_hit, bt_cache_miss, bt_pfxsaved, bt_rootsplit;
	extern u_long bt_sortsplit, bt_split;
	BTREE *t;
	PAGE *h;
	db_pgno_t i, pcont, pinternal, pleaf;
	u_long ifree, lfree, nkeys;
	int levels;

	__bt_dinit();

	t = dbp->internal;
	pcont = pinternal = pleaf = 0;
	nkeys = ifree = lfree = 0;
	for (i = P_ROOT; i < t->bt_mp->npages &&
	    (h = mpool_get(t->bt_mp, i, MPOOL_IGNOREPIN)) != NULL; ++i)
		switch (h->flags & P_TYPE) {
		case P_BINTERNAL:
		case P_RINTERNAL:
			++pinternal;
			ifree += h->upper - h->lower;
			break;
		case P_BLEAF:
		case P_RLEAF:
			++pleaf;
			lfree += h->upper - h->lower;
			nkeys += NEXTINDEX(h);
			break;
		case P_OVERFLOW:
			++pcont;
			break;
		}

	/* Count the levels of the tree. */
	for (i = P_ROOT, levels = 0 ;; ++levels) {
		h = mpool_get(t->bt_mp, i, MPOOL_IGNOREPIN);
		if (h->flags & (P_BLEAF|P_RLEAF)) {
			if (levels == 0)
				levels = 1;
			break;
		}
		i = F_ISSET(t, R_RECNO) ?
		    GETRINTERNAL(h, 0)->pgno :
		    GETBINTERNAL(h, 0)->pgno;
	}

	(void)fprintf(tracefp, "%d level%s with %ld keys",
	    levels, levels == 1 ? "" : "s", nkeys);
	if (F_ISSET(t, R_RECNO))
		(void)fprintf(tracefp, " (%ld header count)", t->bt_nrecs);
	(void)fprintf(tracefp,
	    "\n%lu pages (leaf %ld, internal %ld, overflow %ld)\n",
	    pinternal + pleaf + pcont, pleaf, pinternal, pcont);
	(void)fprintf(tracefp, "%ld cache hits, %ld cache misses\n",
	    bt_cache_hit, bt_cache_miss);
	(void)fprintf(tracefp,
	    "%ld splits (%ld root splits, %ld sort splits)\n",
	    bt_split, bt_rootsplit, bt_sortsplit);
	pleaf *= t->bt_psize - BTDATAOFF;
	if (pleaf)
		(void)fprintf(tracefp,
		    "%.0f%% leaf fill (%ld bytes used, %ld bytes free)\n",
		    ((double)(pleaf - lfree) / pleaf) * 100,
		    pleaf - lfree, lfree);
	pinternal *= t->bt_psize - BTDATAOFF;
	if (pinternal)
		(void)fprintf(tracefp,
		    "%.0f%% internal fill (%ld bytes used, %ld bytes free\n",
		    ((double)(pinternal - ifree) / pinternal) * 100,
		    pinternal - ifree, ifree);
	if (bt_pfxsaved)
		(void)fprintf(tracefp, "prefix checking removed %lu bytes.\n",
		    bt_pfxsaved);
	(void)fflush(tracefp);
	return (0);
}
#endif
