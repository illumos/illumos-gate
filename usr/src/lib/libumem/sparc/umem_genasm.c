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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Don't Panic! If you wonder why this seemingly empty file exists, it's because
 * there is no sparc implementation for ptcumem. Go read libumem's big theory
 * statement in lib/libumem/common/umem.c, particularly section eight.
 */

#include <inttypes.h>
#include <strings.h>
#include <umem_impl.h>
#include "umem_base.h"

const int umem_genasm_supported = 0;

/*ARGSUSED*/
int
umem_genasm(int *alloc_sizes, umem_cache_t **caches, int ncaches)
{
	return (1);
}
