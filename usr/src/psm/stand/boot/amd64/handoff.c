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

#include <amd64/amd64.h>
#include <amd64/print.h>
#include <amd64/amd64_page.h>
#include <amd64/cpu.h>
#include <amd64/debug.h>
#include <amd64/alloc.h>
#include <amd64/msr.h>
#include <amd64/auxv64.h>

#ifdef DEBUG
int amd64_debug = 1;
#else
int amd64_debug = 0;
#endif

/*ARGSUSED*/
void
amd64_handoff(uint64_t entry)
{
	uint64_t va, pa;
	void *rp;

	va = UINT64_FROMPTR32(amd64_handoff);
	pa = amd64_legacy_lookup_physaddr(va, amd64_get_cr3());

	if (va != pa)
		amd64_panic("amd64 booter text not identity mapped (va 0x%llx "
		    "!= pa 0x%llx)\nCannot continue boot.\n", va, pa);

	rp = amd64_makectx64(entry);
#if defined(DEBUG)
	amd64_dump_amd64_machregs(rp);
#endif

	/*
	 * XX64:  Any other post-ELF load, pre-exitto() initialization required
	 *	  for AMD64 goes here.
	 */

	amd64_exitto(rp);
	/*NOTREACHED*/
}

/*
 * The kernel is linked against a module whose
 * name includes $MMU, thus krtld requires that
 * boot supplies an mmu module list.
 *
 * For now, there's only one kind of mmu module for
 * 64-bit systems
 *
 * XX64	So do we need this -- could we just link
 *	the kernel explicitly with mmu64?  Are there
 *	any interesting MMU reworks in the future that
 *	might make this modularity more useful?
 */

/*ARGSUSED*/
const char *
amd64_getmmulist(void)
{
	return ("mmu64");
}
