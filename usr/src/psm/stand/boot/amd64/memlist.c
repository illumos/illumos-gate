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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <amd64/boothooks.h>
#include <amd64/print.h>
#include <amd64/types.h>
#include <amd64/bootops64.h>
#include <amd64/memlist64.h>
#include <amd64/amd64_page.h>

struct memlist64 *
amd64_convert_memlist(struct memlist *ml, struct memlist64 *ml64)
{
	extern struct memlist64 *amd64_memlistpage;

	ml64->prev = (caddr64_t)0;

	while (ml) {
		ml64->address = ml->address;
		ml64->size = ml->size;
		ml = ml->next;

		if (ml) {
			struct memlist64 *next_ml = ml64 + 1;

			ml64->next = (caddr64_t)(uintptr_t)next_ml;
			next_ml->prev = (caddr64_t)(uintptr_t)ml64;
			ml64++;

			/*
			 * This may end up being shortsighted, but currently
			 * boot will panic if the memlists don't all fit on
			 * one page so we may as well make the same assumption.
			 */
			if ((uint64_t)(uintptr_t)ml64 > ((uint64_t)(uintptr_t)
			    amd64_memlistpage + AMD64_PAGESIZE))
				amd64_panic("Memory space for 64-bit memlists "
				    "exhausted when converting memlist @ 0x%x.",
				    (uint32_t)ml->prev);
		}
	}

	ml64->next = (caddr64_t)0;
	return (ml64 + 1);
}
