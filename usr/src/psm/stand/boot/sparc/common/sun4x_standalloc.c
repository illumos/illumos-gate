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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/saio.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/salib.h>

#define	NIL		0

#ifdef DEBUG
static int	resalloc_debug = 1;
#else /* DEBUG */
static int	resalloc_debug = 0;
#endif /* DEBUG */
#define	dprintf	if (resalloc_debug) printf

extern struct memlist	*vfreelistp, *pfreelistp;
extern	void		reset_alloc(void);
extern	void		alloc_segment(caddr_t);

caddr_t		memlistpage;
caddr_t		le_page;
caddr_t		ie_page;
caddr_t 	scratchmemp;
extern int	pagesize;

#define	N_FREELIST	20	/* keep the largest 20 free regions */
static size_t	free_size[N_FREELIST];
static caddr_t	free_addr[N_FREELIST];

/*
 * OBP sets up a 1:1 mapping of virtual to physical in the range 8KB-10MB.  The
 * standalone is free to use any or all of this during its lifetime.
 * Unfortunately, some platforms (Serengeti and LW8) can't use the full range.
 * See 4799331 for more details.  Limited platforms can use up to
 * MAPPEDMEM_MINTOP; everyone else can use up to MAPPEDMEM_FULLTOP.
 * resalloc_init makes the determination as to how much the machine being booted
 * can use.
 *
 * But wait!  There's more!  resalloc handles three types of allocations: Two
 * flavors of RES_BOOTSCRATCH (RES_BOOTSCRATCH and RES_BOOTSCRATCH_NOFAIL), and
 * one of RES_CHILDVIRT.  RES_CHILDVIRT is handled by prom_alloc, and is boring.
 * We handle RES_BOOTSCRATCH allocations ourselves using the portion of the 1:1
 * range not consumed by boot.  The unconsumed range is subdivided into two
 * portions - the general area from top_resvmem to top_bootmem and the reserved
 * area from above memlistpage to top_resvmem.  Both RES_BOOTSCRATCH flavors are
 * satisfied by the general area until said area is exhausted, at which point
 * RES_BOOTSCRATCH allocations return failure.  RES_BOOTSCRATCH_NOFAIL
 * allocations can't fail, so we'll try to satisfy them from the reserved area
 * if the general area is full.  If we still can't satisfy the nofail
 * allocation, we'll call prom_panic.
 *
 * This whole boot memory allocation thing needs some serious rethinking.
 *
 * Memory layout:
 *
 *	|-------| top_bootmem
 *	|	| } MAPPEDMEM_FULLTOP (only on non-serengeti, lw8)
 *	|	| } MAPPEDMEM_MINTOP
 *	|-------| top_resvmem/scratchmemp
 *	|	| } MAPPEDMEM_RESERVE
 *	|-------| scratchresvp
 *	|	| } one page
 *	|-------| memlistpage (at roundup(_end, pagesize))
 *	|-------| _end
 *	| boot  |
 *	:	:
 *
 */

#define	MAPPEDMEM_RESERVE	(512*1024)	/* reserved for NOFAIL allocs */

#define	MAPPEDMEM_MINTOP	(caddr_t)(6*1024*1024)
#define	MAPPEDMEM_FULLTOP	(caddr_t)(10*1024*1024)

static caddr_t top_bootmem = MAPPEDMEM_MINTOP;
static caddr_t top_resvmem, scratchresvp;

/*
 * with newboot, boot goes away when it launches the client,
 * so we can safely extend bootmem on sg, and give it back
 * before we die.
 */
int is_sg;
caddr_t sg_addr;
size_t sg_len;

static int
impl_name(char *buf, size_t bufsz)
{
	pnode_t n = prom_rootnode();
	size_t len = prom_getproplen(n, "name");

	if (len == 0 || len >= bufsz)
		return (-1);

	(void) prom_getprop(n, "name", buf);
	buf[len] = '\0';

	return (0);
}

static caddr_t
vpage_from_freelist(size_t bytes)
{
	caddr_t v;
	int i;

	/* find first region which fits */
	for (i = 0; i < N_FREELIST && free_size[i] < bytes; i++)
		continue;

	if (i == N_FREELIST) {
		dprintf("boot: failed to allocate %lu bytes from scratch "
		    "memory\n", bytes);
		return (NULL);
	}

	v = free_addr[i];
	free_addr[i] += bytes;
	free_size[i] -= bytes;
	dprintf("reuse freed temp scratch:  bytes = %lu at %p\n", bytes,
	    (void *)v);
	return (v);
}

/*
 *	This routine will find the next PAGESIZE chunk in the
 *	low MAPPEDMEM_MINTOP.  It is analogous to valloc(). It is only for boot
 *	scratch memory, because child scratch memory goes up in
 *	the the high memory.  We just need to verify that the
 *	pages are on the list.  The calling routine will actually
 *	remove them.
 */
static caddr_t
get_low_vpage(size_t numpages, enum RESOURCES type)
{
	size_t bytes;
	caddr_t v;

	if (!numpages)
		return (0);

	/* We know the page is mapped because the 1st MAPPEDMEM_MINTOP is 1:1 */
	bytes = numpages * pagesize;
	if (scratchmemp + bytes <= top_bootmem) {
		v = scratchmemp;
		scratchmemp += bytes;
		return (v);
	}

	/*
	 * If we run out of scratch memory, look in the freelist
	 */
	if ((v = vpage_from_freelist(bytes)) != NULL)
		return (v);

	/*
	 * Try really hard for allocations that can't fail.  Look in the area
	 * that we've reserved for them.
	 */
	if (type == RES_BOOTSCRATCH_NOFAIL) {
		if (scratchresvp + bytes <= top_resvmem) {
			v = scratchresvp;
			scratchresvp += bytes;
			dprintf("using %lu bytes of reserved mem (%lu left)\n",
			    bytes, top_resvmem - scratchresvp);
			return (v);
		} else {
			printf("boot: failed to allocate %lu bytes from "
			    "reserved scratch memory\n", bytes);
			prom_panic("boot: scratch memory overflow.\n");
		}
	}

	return (NULL);
}

void
resalloc_init(void)
{
	char iarch[128];

	if (impl_name(iarch, sizeof (iarch)) < 0) {
		dprintf("boot: resalloc_init: failed to read iarch\n");
		return;
	}

	dprintf("boot: resalloc_init: got iarch %s\n", iarch);

	/*
	 * Some versions of SG/LW8 firmware can actually handle the entire 10MB,
	 * but we don't have the ability to check for the firmware version here.
	 */
	if (strcmp(iarch, "SUNW,Sun-Fire") == 0 ||
	    strcmp(iarch, "SUNW,Netra-T12") == 0) {
		is_sg = 1;
		sg_addr = MAPPEDMEM_MINTOP;
		sg_len = MAPPEDMEM_FULLTOP - MAPPEDMEM_MINTOP;
		if (prom_alloc(sg_addr, sg_len, 1) != sg_addr)
			prom_panic("can't extend sg bootmem");
	}

	top_bootmem = MAPPEDMEM_FULLTOP;

	dprintf("boot: resalloc_init: boosted top_bootmem to %p\n",
	    (void *)top_bootmem);
}

caddr_t
resalloc(enum RESOURCES type, size_t bytes, caddr_t virthint, int align)
{
	caddr_t	vaddr;
	long pmap = 0;

	if (memlistpage == (caddr_t)0)
		reset_alloc();

	if (bytes == 0)
		return ((caddr_t)0);

	/* extend request to fill a page */
	bytes = roundup(bytes, pagesize);

	dprintf("resalloc:  bytes = %lu\n", bytes);

	switch (type) {

	/*
	 * even V2 PROMs never bother to indicate whether the
	 * first MAPPEDMEM_MINTOP is taken or not.  So we do it all here.
	 * Smart PROM or no smart PROM.
	 */
	case RES_BOOTSCRATCH:
	case RES_BOOTSCRATCH_NOFAIL:
		vaddr = get_low_vpage((bytes/pagesize), type);

		if (resalloc_debug) {
			dprintf("vaddr = %p, paddr = %lx\n", (void *)vaddr,
			    ptob(pmap));
			print_memlist(vfreelistp);
			print_memlist(pfreelistp);
		}
		return (vaddr);
		/*NOTREACHED*/

	case RES_CHILDVIRT:
		vaddr = (caddr_t)prom_alloc(virthint, bytes, align);

		if (vaddr == (caddr_t)virthint)
			return (vaddr);
		printf("Alloc of 0x%lx bytes at 0x%p refused.\n",
		    bytes, (void *)virthint);
		return ((caddr_t)0);
		/*NOTREACHED*/

	default:
		printf("Bad resurce type\n");
		return ((caddr_t)0);
	}
}

#ifdef	lint
static char _end[1];	/* defined by the linker! */
#endif	/* lint */

void
reset_alloc(void)
{
	extern char _end[];

	/* Cannot be called multiple times */
	if (memlistpage != (caddr_t)0)
		return;

	/*
	 *  Due to kernel history and ease of programming, we
	 *  want to keep everything private to /boot BELOW MAPPEDMEM_MINTOP.
	 *  In this way, the kernel can just snarf it all when
	 *  when it is ready, and not worry about snarfing lists.
	 */
	memlistpage = (caddr_t)roundup((uintptr_t)_end, pagesize);

	/*
	 *  This next is for scratch memory only
	 *  We only need 1 page in memlistpage for now
	 */
	scratchresvp = (caddr_t)(memlistpage + pagesize);
	scratchmemp = top_resvmem = scratchresvp + MAPPEDMEM_RESERVE;
	le_page = (caddr_t)(scratchmemp + pagesize);
	ie_page = (caddr_t)(le_page + pagesize);

	bzero(memlistpage, pagesize);
	bzero(scratchmemp, pagesize);
	dprintf("memlistpage = %p\n", (void *)memlistpage);
	dprintf("le_page = %p\n", (void *)le_page);
}

void
resfree(enum RESOURCES type, caddr_t virtaddr, size_t size)
{
	int i;

	/* make sure this is boot scratch memory */
	switch (type) {
	case RES_BOOTSCRATCH:
		if (virtaddr + size > top_bootmem)
			return;
		break;
	default:
		return;
	}

	/*
	 * Add this to the end of the free list
	 * NOTE: This relies on the fact that KRTLD calls BOP_FREE
	 *	from largest to smallest chunks.
	 */
	for (i = 0; i < N_FREELIST && free_size[i]; i++)
		;
	if (i == N_FREELIST)
		return;
	free_size[i] = size;
	free_addr[i] = virtaddr;
}
