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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * alloc.c -- memory allocation wrapper functions, for eft.so FMD module
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fm/fmd_api.h>

#include "alloc.h"
#include "out.h"
#include "stats.h"

extern fmd_hdl_t *Hdl;		/* handle from eft.c */

/* room to store size, possibly more to maintain alignment for long longs */
#define	HDRSIZ	sizeof (long long)

static struct stats *Malloctotal;
static struct stats *Freetotal;
static struct stats *Malloccount;
static struct stats *Freecount;

static int totalcount;

void
alloc_init(void)
{
	Malloctotal = stats_new_counter("alloc.total", "bytes allocated", 1);
	Freetotal = stats_new_counter("free.total", "bytes freed", 1);
	Malloccount = stats_new_counter("alloc.calls", "alloc calls", 1);
	Freecount = stats_new_counter("free.calls", "free calls", 1);
}

void
alloc_fini(void)
{
	struct stats *mt, *ft, *mc, *fc;

	mt = Malloctotal;
	ft = Freetotal;
	mc = Malloccount;
	fc = Freecount;

	Malloctotal = NULL;
	Freetotal = NULL;
	Malloccount = NULL;
	Freecount = NULL;

	stats_delete(mt);
	stats_delete(ft);
	stats_delete(mc);
	stats_delete(fc);
}

/*
 * alloc_malloc -- a malloc() with checks
 *
 * this routine is typically called via the MALLOC() macro in alloc.h
 */
/*ARGSUSED*/
void *
alloc_malloc(size_t nbytes, const char *fname, int line)
{
	char *retval;

	ASSERT(nbytes > 0);

	retval = fmd_hdl_alloc(Hdl, nbytes + HDRSIZ, FMD_SLEEP);

	/* retval can't be NULL since fmd_hdl_alloc() sleeps for memory */

	bcopy((void *)&nbytes, (void *)retval, sizeof (nbytes));
	retval += HDRSIZ;

	if (Malloctotal)
		stats_counter_add(Malloctotal, nbytes);

	if (Malloccount)
		stats_counter_bump(Malloccount);

	totalcount += nbytes + HDRSIZ;
	return ((void *)retval);
}

/*
 * alloc_realloc -- a realloc() with checks
 *
 * this routine is typically called via the REALLOC() macro in alloc.h
 */
void *
alloc_realloc(void *ptr, size_t nbytes, const char *fname, int line)
{
	void *retval = alloc_malloc(nbytes, fname, line);

	if (ptr != NULL) {
		size_t osize;

		bcopy((void *)((char *)ptr - HDRSIZ), (void *)&osize,
		    sizeof (osize));
		/* now we have the new memory, copy in the old contents */
		bcopy(ptr, retval, (osize < nbytes) ? osize : nbytes);

		/* don't need the old memory anymore */
		alloc_free((char *)ptr, fname, line);
	}

	return (retval);
}

/*
 * alloc_strdup -- a strdup() with checks
 *
 * this routine is typically called via the STRDUP() macro in alloc.h
 */
char *
alloc_strdup(const char *ptr, const char *fname, int line)
{
	char *retval = alloc_malloc(strlen(ptr) + 1, fname, line);

	(void) strcpy(retval, ptr);

	return (retval);
}

/*
 * alloc_free -- a free() with checks
 *
 * this routine is typically called via the FREE() macro in alloc.h
 */
/*ARGSUSED*/
void
alloc_free(void *ptr, const char *fname, int line)
{
	size_t osize;

	ASSERT(ptr != NULL);

	bcopy((void *)((char *)ptr - HDRSIZ), (void *)&osize, sizeof (osize));

	/* nothing to check in this version */

	fmd_hdl_free(Hdl, (char *)ptr - HDRSIZ, osize + HDRSIZ);

	if (Freetotal)
		stats_counter_add(Freetotal, osize);

	if (Freecount)
		stats_counter_bump(Freecount);
	totalcount -= osize + HDRSIZ;
}

int
alloc_total()
{
	return (totalcount);
}

/*
 * variants that don't maintain size in header - saves space
 */
void *
alloc_xmalloc(size_t nbytes)
{
	char *retval;

	ASSERT(nbytes > 0);
	retval = fmd_hdl_alloc(Hdl, nbytes, FMD_SLEEP);
	if (Malloctotal)
		stats_counter_add(Malloctotal, nbytes);
	if (Malloccount)
		stats_counter_bump(Malloccount);
	totalcount += nbytes;
	return ((void *)retval);
}

void
alloc_xfree(void *ptr, size_t size)
{
	ASSERT(ptr != NULL);

	fmd_hdl_free(Hdl, (char *)ptr, size);
	if (Freetotal)
		stats_counter_add(Freetotal, size);
	if (Freecount)
		stats_counter_bump(Freecount);
	totalcount -= size;
}
