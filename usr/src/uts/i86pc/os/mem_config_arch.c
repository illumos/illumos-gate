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
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <vm/page.h>
#include <sys/mem_config.h>

/*ARGSUSED*/
int
arch_kphysm_del_span_ok(pfn_t base, pgcnt_t npgs)
{
	ASSERT(npgs != 0);
	return (0);
}

/*ARGSUSED*/
int
arch_kphysm_relocate(pfn_t base, pgcnt_t npgs)
{
	ASSERT(npgs != 0);
	return (ENOTSUP);
}

int
arch_kphysm_del_supported(void)
{
	return (0);
}
