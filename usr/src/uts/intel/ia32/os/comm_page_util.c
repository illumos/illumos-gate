/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */


#include <sys/types.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/mman.h>
#include <sys/vmsystm.h>
#include <vm/as.h>
#include <vm/seg_umap.h>

#if !defined(__xpv)
#include <sys/comm_page.h>
#endif /* !defined(__xpv) */

/*
 * Map in the comm page.
 *
 * The contents of the comm page are only defined on non-xpv x86 at this time.
 * Furthermore, the data is only valid in userspace (32-bit or 64-bit) when
 * mapped from a 64-bit kernel.
 * See: "uts/i86pc/sys/comm_page.h"
 */
caddr_t
comm_page_mapin()
{
#if defined(__amd64) && !defined(__xpv)
	proc_t *p = curproc;
	caddr_t addr = NULL;
	size_t len = COMM_PAGE_SIZE;
	uint_t prot = PROT_USER | PROT_READ;
	segumap_crargs_t suarg;

	map_addr(&addr, len, (offset_t)0, 1, 0);
	if (addr == NULL || valid_usr_range(addr, len, prot, p->p_as,
	    p->p_as->a_userlimit) != RANGE_OKAY) {
		return (NULL);
	}

	suarg.kaddr = (caddr_t)&comm_page;
	suarg.prot = suarg.maxprot = prot;
	if (as_map(p->p_as, addr, len, segumap_create, &suarg) != 0) {
		return (NULL);
	}
	return (addr);
#else /* defined(__amd64) && !defined(__xpv) */
	return (NULL);
#endif /* defined(__amd64) && !defined(__xpv) */
}
