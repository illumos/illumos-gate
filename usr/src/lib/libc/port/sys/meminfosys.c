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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _meminfo = meminfo

#include "lint.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mman.h>

/*
 * meminfo() function call
 */
int
meminfo(const uint64_t *inaddr, int addr_count, const uint_t *info_req,
    int info_count, uint64_t *outdata, uint_t *validity)
{
	struct meminfo minfo;

	minfo.mi_inaddr = inaddr;
	minfo.mi_info_req = info_req;
	minfo.mi_info_count = info_count;
	minfo.mi_outdata = outdata;
	minfo.mi_validity = validity;

	return (syscall(SYS_meminfosys, MISYS_MEMINFO, addr_count, &minfo));
}
