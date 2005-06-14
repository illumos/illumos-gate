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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <libnvpair.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include "topo_impl.h"
#include "libtopo.h"

static void * (*Topo_zalloc_sleep)(size_t);
static void (*Topo_free)(void *);

static void *
_topo_zalloc_sleep(size_t bytes)
{
	void *r;

	while ((r = malloc(bytes)) == NULL)
		topo_out(TOPO_INFO, "_topo_zalloc_sleep: "
		    "Must wait for %llu bytes memory...\n",
		    (unsigned long long)bytes);
	(void) memset(r, 0, bytes);
	return (r);
}

static void
_topo_free(void *p)
{
	free(p);
}

/*ARGSUSED*/
static void *
Topo_nv_alloc(nv_alloc_t *nva, size_t size)
{
	return (Topo_zalloc_sleep(size));
}

/*ARGSUSED*/
static void
Topo_nv_free(nv_alloc_t *nva, void *p, size_t sz)
{
	Topo_free(p);
}

const nv_alloc_ops_t Topo_nv_alloc_ops = {
	NULL,		/* nv_ao_init() */
	NULL,		/* nv_ao_fini() */
	Topo_nv_alloc,	/* nv_ao_alloc() */
	Topo_nv_free,	/* nv_ao_free() */
	NULL		/* nv_ao_reset() */
};

nv_alloc_t Topo_nv_alloc_hdl;

void
topo_mem_init()
{
	if (Topo_zalloc_sleep == NULL)
		Topo_zalloc_sleep = _topo_zalloc_sleep;
	if (Topo_free == NULL)
		Topo_free = _topo_free;
	(void) nv_alloc_init(&Topo_nv_alloc_hdl, &Topo_nv_alloc_ops);
}

void
topo_mem_fini(void)
{
	(void) nv_alloc_fini(&Topo_nv_alloc_hdl);
}

void *
topo_zalloc(size_t bytes)
{
	return (Topo_zalloc_sleep(bytes));
}

char *
topo_strdup(const char *str)
{
	char *r;

	r = Topo_zalloc_sleep(strlen(str) + 1);
	(void) strcpy(r, str);
	return (r);
}

void
topo_free(void *ptr)
{
	Topo_free(ptr);
}

void
topo_free_path(char *path)
{
	topo_free(path);
}

void
topo_free_fmri(nvlist_t *fmri)
{
	nvlist_free(fmri);
}

void
topo_set_mem_methods(void * (*zallocfn)(size_t), void (*freefn)(void *))
{
	if (zallocfn == NULL || freefn == NULL)
		return;
	Topo_zalloc_sleep = zallocfn;
	Topo_free = freefn;
}
