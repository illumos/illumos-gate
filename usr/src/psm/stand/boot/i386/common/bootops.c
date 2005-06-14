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

#include <sys/param.h>
#include <sys/promif.h>
#include <sys/bootconf.h>
#include <sys/bootvfs.h>
#include <sys/varargs.h>
#include "standalloc.h"
#include "bootprop.h"
#include "util.h"
#include "biosint.h"
#include "debug.h"

#define	dprintf	if (debug & D_BOP) printf

extern struct memlist *pinstalledp, *pfreelistp, *vfreelistp, *pbooterp;
extern struct memlist *ppcimemp, *pramdiskp;
extern struct bootops *bop;

/* Misc memlist stuff */
extern void	 update_memlist(char *, char *, struct memlist **);

/*ARGSUSED*/
static caddr_t
bkern_alloc(struct bootops *bop, caddr_t virt, size_t size, int align)
{
	if (size < PAGESIZE)
		return (bkmem_alloc(size));

	return (resalloc(((virt == 0) ? RES_BOOTSCRATCH : RES_CHILDVIRT),
		size, virt, align));
}

/*ARGSUSED*/
static caddr_t
bkern_ealloc(struct bootops *bop, caddr_t virt, size_t size, int align,
    int flags)
{
	uint_t delta;

	/* sanity check */
	if (size == 0)
		return ((caddr_t)0);

	if (flags == BOPF_X86_ALLOC_IDMAP ||
	    flags == BOPF_X86_ALLOC_PHYS) {

		/* align to PAGESIZE */
		delta = (uint_t)virt & (PAGESIZE - 1);
		size += delta;
		size = roundup(size, PAGESIZE);

		switch (flags) {
		case BOPF_X86_ALLOC_IDMAP:
			return ((caddr_t)idmap_mem(
			    (uint32_t)virt, size, align));
			/*NOTREACHED*/
		case BOPF_X86_ALLOC_PHYS:
			return ((caddr_t)phys_alloc_mem(size, align));
			/*NOTREACHED*/
		}
	}

	return (resalloc(((virt == 0) ? RES_BOOTSCRATCH : RES_CHILDVIRT),
		size, virt, align));
}

/*ARGSUSED*/
static void
bkern_free(struct bootops *bop, caddr_t virt, size_t size)
{
	resfree(virt, size);
}

void
install_memlistptrs(void)
{
	/* allocate boot_mem structure */
	bop->boot_mem->physinstalled = pinstalledp;
	bop->boot_mem->physavail = pfreelistp;
	bop->boot_mem->pcimem = ppcimemp;

	dprintf("physinstalledp = 0x%p\n",
	    (void *)bop->boot_mem->physinstalled);
	dprintf("pfreelistp = 0x%p\n",
	    (void *)bop->boot_mem->physavail);
	dprintf("ppcimemp = 0x%p\n",
	    (void *)bop->boot_mem->pcimem);
}

/*ARGSUSED*/
static void
bkern_printf(struct bootops *bop, char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	prom_vprintf(fmt, adx);
	va_end(adx);
}

/*
 * Translate register structure fit what /platform/i86pc/biosint expects.
 */
static void
bkern_doint(struct bootops *bop, int intnum, struct bop_regs *rp)
{
	struct int_pb ic;

	ic.ax = rp->eax.word.ax;
	ic.bx = rp->ebx.word.bx;
	ic.cx = rp->ecx.word.cx;
	ic.dx = rp->edx.word.dx;
	ic.bp = rp->ebp.word.bp;
	ic.si = rp->esi.word.si;
	ic.di = rp->edi.word.di;
	ic.ds = rp->ds;
	ic.es = rp->es;

	if (debug & D_BIOS)
		printf("bkern_doint: int = 0x%x, ax 0x%x, dx 0x%x\n",
		    intnum, ic.ax, ic.dx);
	rp->eflags = bios_doint(intnum, &ic);
	if (debug & D_BIOS)
		printf("bios_doint ret = %d, ax 0x%x, dx 0x%x\n",
		    rp->eflags, ic.ax, ic.dx);

	rp->eax.word.ax = ic.ax;
	rp->ebx.word.bx = ic.bx;
	rp->ecx.word.cx = ic.cx;
	rp->edx.word.dx = ic.dx;
	rp->ebp.word.bp = ic.bp;
	rp->esi.word.si = ic.si;
	rp->edi.word.di = ic.di;
	rp->ds = ic.ds;
	rp->es = ic.es;
}

bootops_t bootops =
{
	/* reduced bootops BO_VERSION == 11 ... */

	BO_VERSION,	/* "major" version number */
	0, 		/* memlist pointers */
	bkern_alloc,	/* G.P. memory allocator */
	bkern_free,	/* G.P. memory release */
	bgetproplen,	/* proplen */
	bgetprop,	/* getprop */
	bnextprop,	/* nextprop */
	bkern_printf,	/* limited printf for kobj */
	bkern_doint,	/* biosint */
	bkern_ealloc
};

void
setup_bootops(void)
{
	/*
	 *  Initialize the bootops struct and establish a pointer to it ("bop")
	 *  for use by standalone clients.
	 */
	bop = &bootops;
	bop->boot_mem = bkmem_zalloc(sizeof (struct bsys_mem));
	install_memlistptrs();
	if (verbosemode)
		printf("setup bootops\n");
}
