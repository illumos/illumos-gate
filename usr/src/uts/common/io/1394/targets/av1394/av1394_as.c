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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * av1394 address space for mmap(2)
 */
#include <sys/1394/targets/av1394/av1394_impl.h>

void
av1394_as_init(av1394_as_t *as)
{
	as->as_end = 0;
}

void
av1394_as_fini(av1394_as_t *as)
{
	as->as_end = 0;
}

/*
 * XXX implement a better allocation algorithm
 */
off_t
av1394_as_alloc(av1394_as_t *as, size_t size)
{
	off_t	addr;

	addr = as->as_end;
	as->as_end += size;
	return (addr);
}

/*ARGSUSED*/
void
av1394_as_free(av1394_as_t *as, off_t addr)
{
}
