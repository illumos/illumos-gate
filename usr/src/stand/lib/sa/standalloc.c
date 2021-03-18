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

#include <sys/types.h>
#include <sys/saio.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/salib.h>

#ifdef DEBUG
static int	resalloc_debug = 1;
#else /* DEBUG */
static int	resalloc_debug = 0;
#endif /* DEBUG */
#define	dprintf	if (resalloc_debug) printf

extern	caddr_t		resalloc(enum RESOURCES type,
				size_t bytes, caddr_t virthint, int align);
extern	void		resfree(enum RESOURCES type,
				caddr_t virtaddr, size_t bytes);

extern int	pagesize;

/*
 *  This routine should be called get_a_page().
 *  It allocates from the appropriate entity one or
 *  more pages and maps them in.
 */

caddr_t
kern_resalloc(caddr_t virthint, size_t size, int align)
{
	if (virthint != 0)
		return (resalloc(RES_CHILDVIRT, size, virthint, align));
	else {
		return (resalloc(RES_BOOTSCRATCH, size, NULL, NULL));
	}
}

/*
 * This is called only on sparcv9 for freeing scratch memory.
 * The standalone allocator cannot free other types of memory.
 */
void
kern_resfree(caddr_t virtaddr, size_t size)
{
	resfree(RES_BOOTSCRATCH, virtaddr, size);
}

int
get_progmemory(caddr_t vaddr, size_t size, int align)
{
	uintptr_t n;

	/*
	 * if the vaddr given is not a mult of PAGESIZE,
	 * then we rounddown to a page, but keep the same
	 * ending addr.
	 */
	n = (uintptr_t)vaddr & (pagesize - 1);
	if (n) {
		vaddr -= n;
		size += n;
	}

	dprintf("get_progmemory: requesting %lx bytes at %p\n", size,
	    (void *)vaddr);
	if (resalloc(RES_CHILDVIRT, size, vaddr, align) != vaddr)
		return (-1);
	return (0);
}
