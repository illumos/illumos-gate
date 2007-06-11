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
 * alloc.c -- memory allocation wrapper functions, replacable in more
 * constrained environments, such as within a DE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <string.h>

#include "alloc.h"
#include "out.h"
#include "stats.h"

static struct stats *Malloctotal;
static struct stats *Malloccount;

void
alloc_init(void)
{
	Malloctotal = stats_new_counter("alloc.total", "bytes allocated", 1);
	Malloccount = stats_new_counter("alloc.calls", "total calls", 1);
}

void
alloc_fini(void)
{
	struct stats *mt, *mc;

	mt = Malloctotal;
	mc = Malloccount;

	Malloctotal = NULL;
	Malloccount = NULL;

	stats_delete(mt);
	stats_delete(mc);
}

/*
 * alloc_malloc -- a malloc() with checks
 *
 * this routine is typically called via the MALLOC() macro in alloc.h
 */

void *
alloc_malloc(size_t nbytes, const char *fname, int line)
{
	void *retval = malloc(nbytes);

	if (retval == NULL)
		outfl(O_DIE, fname, line, "malloc: out of memory");

	if (Malloctotal)
		stats_counter_add(Malloctotal, nbytes);

	if (Malloccount)
		stats_counter_bump(Malloccount);

	return (retval);
}

/*
 * alloc_realloc -- a realloc() with checks
 *
 * this routine is typically called via the REALLOC() macro in alloc.h
 */
void *
alloc_realloc(void *ptr, size_t nbytes, const char *fname, int line)
{
	void *retval = realloc(ptr, nbytes);

	if (retval == NULL)
		out(O_DIE, fname, line, "realloc: out of memory");

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
	char *retval = strdup(ptr);

	if (retval == NULL)
		outfl(O_DIE, fname, line, "strdup: out of memory");

	return (retval);
}

/*
 * alloc_free -- a free() with checks
 *
 * this routine is typically called via the FREE() macro in alloc.h
 */
/*ARGSUSED1*/
void
alloc_free(void *ptr, const char *fname, int line)
{
	/* nothing to check in this version */
	free(ptr);
}

/*
 * variants that don't maintain size in header - saves space
 */
void *
alloc_xmalloc(size_t nbytes)
{
	void *retval;

	retval = malloc(nbytes);
	if (retval == NULL)
		out(O_DIE, "malloc: out of memory");
	if (Malloctotal)
		stats_counter_add(Malloctotal, nbytes);
	if (Malloccount)
		stats_counter_bump(Malloccount);
	return (retval);
}

/*ARGSUSED*/
void
alloc_xfree(void *ptr, size_t size)
{
	free(ptr);
}
