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

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/param.h>
#include <sys/obpdefs.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <sys/boot.h>
#include <stddef.h>
#include "boot_plat.h"

#ifdef DEBUG
extern int debug;
#else
static const int debug = 0;
#endif

#define	dprintf		if (debug) printf

extern void	closeall(int);

struct bootops bootops;

static void
boot_fail(void)
{
	prom_panic("bootops is gone, it should not be called");
}

void
setup_bootops(void)
{
	bootops.bsys_version = BO_VERSION;
	bootops.bsys_1275_call = (uint64_t)boot_fail;
	bootops.bsys_printf = (uint32_t)(uintptr_t)boot_fail;

	if (!memlistpage) /* paranoia runs rampant */
		prom_panic("\nMemlistpage not setup yet.");
	/*
	 * The memory list should always be updated last.  The prom
	 * calls which are made to update a memory list may have the
	 * undesirable affect of claiming physical memory.  This may
	 * happen after the kernel has created its page free list.
	 * The kernel deals with this by comparing the n and n-1
	 * snapshots of memory.  Updating the memory available list
	 * last guarantees we will have a current, accurate snapshot.
	 * See bug #1260786.
	 */
	update_memlist("virtual-memory", "available", &vfreelistp);
	update_memlist("memory", "available", &pfreelistp);

	dprintf("\nPhysinstalled: ");
	if (debug) print_memlist(pinstalledp);
	dprintf("\nPhysfree: ");
	if (debug) print_memlist(pfreelistp);
	dprintf("\nVirtfree: ");
	if (debug) print_memlist(vfreelistp);
}

void
install_memlistptrs(void)
{

	/* prob only need 1 page for now */
	memlistextent = tablep - memlistpage;

	dprintf("physinstalled = %p\n", (void *)pinstalledp);
	dprintf("physavail = %p\n", (void *)pfreelistp);
	dprintf("virtavail = %p\n", (void *)vfreelistp);
	dprintf("extent = 0x%lx\n", memlistextent);
}

/*
 *      A word of explanation is in order.
 *      This routine is meant to be called during
 *      boot_release(), when the kernel is trying
 *      to ascertain the current state of memory
 *      so that it can use a memlist to walk itself
 *      thru kvm_init().
 */

void
update_memlist(char *name, char *prop, struct memlist **list)
{
	/* Just take another prom snapshot */
	*list = fill_memlists(name, prop, *list);
	install_memlistptrs();
}

/*
 *  This routine is meant to be called by the
 *  kernel to shut down all boot and prom activity.
 *  After this routine is called, PROM or boot IO is no
 *  longer possible, nor is memory allocation.
 */
void
kern_killboot(void)
{
	if (verbosemode) {
		dprintf("Entering boot_release()\n");
		dprintf("\nPhysinstalled: ");
		if (debug) print_memlist(pinstalledp);
		dprintf("\nPhysfree: ");
		if (debug) print_memlist(pfreelistp);
		dprintf("\nVirtfree: ");
		if (debug) print_memlist(vfreelistp);
	}
	if (debug) {
		dprintf("Calling quiesce_io()\n");
		prom_enter_mon();
	}

	/* close all open devices */
	closeall(1);

	/*
	 *  Now we take YAPS (yet another Prom snapshot) of
	 *  memory, just for safety sake.
	 *
	 * The memory list should always be updated last.  The prom
	 * calls which are made to update a memory list may have the
	 * undesirable affect of claiming physical memory.  This may
	 * happen after the kernel has created its page free list.
	 * The kernel deals with this by comparing the n and n-1
	 * snapshots of memory.  Updating the memory available list
	 * last guarantees we will have a current, accurate snapshot.
	 * See bug #1260786.
	 */
	update_memlist("virtual-memory", "available", &vfreelistp);
	update_memlist("memory", "available", &pfreelistp);

	if (verbosemode) {
		dprintf("physinstalled = %p\n", (void *)pinstalledp);
		dprintf("physavail = %p\n", (void *)pfreelistp);
		dprintf("virtavail = %p\n", (void *)vfreelistp);
		dprintf("extent = 0x%lx\n", memlistextent);
		dprintf("Leaving boot_release()\n");

		dprintf("Physinstalled: \n");
		if (debug)
			print_memlist(pinstalledp);

		dprintf("Physfree:\n");
		if (debug)
			print_memlist(pfreelistp);

		dprintf("Virtfree: \n");
		if (debug)
			print_memlist(vfreelistp);
	}

#ifdef DEBUG_MMU
	dump_mmu();
	prom_enter_mon();
#endif
}
