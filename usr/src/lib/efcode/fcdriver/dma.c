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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>


static void
do_dma_alloc(fcode_env_t *env)
{
	size_t size;
	void *p;

	CHECK_DEPTH(env, 1, "dma-alloc");
	size = (size_t) POP(DS);
	p = valloc(size);
	debug_msg(DEBUG_REG_ACCESS, "dma-alloc ( %x ) -> %p\n", (int)size, p);
	throw_from_fclib(env, (p == 0), "dma-alloc failed");
	PUSH(DS, (fstack_t) p);
}

static void
do_dma_free(fcode_env_t *env)
{
	void *p;
	size_t size;

	CHECK_DEPTH(env, 2, "dma-free");
	size = POP(DS);
	p = (void *) POP(DS);
	debug_msg(DEBUG_REG_ACCESS, "dma-free ( %p %x )\n", p, (int)size);

	free(p);
}

static void
do_dma_map_in(fcode_env_t *env)
{
	fc_cell_t data;
	fstack_t va, len, cacheable;
	private_data_t *pd = DEVICE_PRIVATE(env);
	int error;

	CHECK_DEPTH(env, 3, "dma-map-in");
	cacheable = POP(DS);
	len = POP(DS);
	va = POP(DS);

	error = fc_run_priv(pd->common, "dma-map-in", 3, 1,
	    fc_int2cell(cacheable), fc_size2cell(len), fc_ptr2cell(va),
	    &data);

	throw_from_fclib(env, error, "dma-map-in failed");

	PUSH(DS, (fstack_t)data);
}

static void
do_dma_map_out(fcode_env_t *env)
{
	fstack_t va, dva, len;
	private_data_t *pd = DEVICE_PRIVATE(env);
	int error;

	CHECK_DEPTH(env, 3, "dma-map-out");
	len = POP(DS);
	dva = POP(DS);
	va = POP(DS);

	error = fc_run_priv(pd->common, "dma-map-out", 3, 0, fc_size2cell(len),
	    fc_ptr2cell(dva), fc_ptr2cell(va));

	throw_from_fclib(env, error, "dma-map-out failed");
}

static void
do_dma_sync(fcode_env_t *env)
{
	CHECK_DEPTH(env, 3, "dma-sync");
	/* 3drop */
	DS -= 3;
}

void
install_dma_methods(fcode_env_t *env)
{
	FORTH(0,	"dma-alloc",		do_dma_alloc);
	FORTH(0,	"dma-free",		do_dma_free);
	FORTH(0,	"dma-map-in",		do_dma_map_in);
	FORTH(0,	"dma-map-out",		do_dma_map_out);
	FORTH(0,	"dma-sync",		do_dma_sync);

}
