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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <amd64/boothooks.h>
#include <amd64/alloc.h>
#include <amd64/amd64_page.h>
#include <amd64/cpu.h>
#include <amd64/print.h>

void *
amd64_alloc_identity(size_t size)
{
	void *addr;

	if (addr = (void *)idmap_mem((uint32_t)0, size, AMD64_PAGESIZE))
		return (addr);

	amd64_panic("amd64_alloc_identity: boot failed to identity map 0x%lx "
	    "bytes\n", size);

	/*NOTREACHED*/
}

void *
amd64_zalloc_identity(size_t size)
{
	void *p;

	if (p = amd64_alloc_identity(size))
		bzero(p, size);

	return (p);
}
