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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sunndi.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/memlist.h>
#include <sys/bootconf.h>
#include <sys/psw.h>

/*
 * pci irq routing information table
 */
int				pci_irq_nroutes;
static pci_irq_route_t		*pci_irq_routes;


static int pci_bios_get_irq_routing(pci_irq_route_t *, int, int *);
static void pci_get_irq_routing_table(void);


/*
 * Retrieve information from the bios needed for system
 * configuration early during startup.
 */
void
startup_pci_bios(void)
{
	pci_get_irq_routing_table();
}


/*
 * Issue the bios get irq routing information table interrupt
 *
 * Despite the name, the information in the table is only
 * used to derive slot names for some named pci hot-plug slots.
 *
 * Returns the number of irq routing table entries returned
 * by the bios, or 0 and optionally, the number of entries required.
 */
static int
pci_bios_get_irq_routing(pci_irq_route_t *routes, int nroutes, int *nneededp)
{
	struct bop_regs regs;
	uchar_t		*hdrp;
	uchar_t		*bufp;
	int 		i, n;
	int		rval = 0;

	if (nneededp)
		*nneededp = 0;

	/* in UEFI system, there is no BIOS data */
	if (BOP_GETPROPLEN(bootops, "efi-systab") > 0)
		return (0);

	/*
	 * Set up irq routing header with the size and address
	 * of some useable low-memory data addresses.  Initalize
	 * data area to zero, avoiding memcpy/bzero.
	 */
	hdrp = (uchar_t *)BIOS_IRQ_ROUTING_HDR;
	bufp = (uchar_t *)BIOS_IRQ_ROUTING_DATA;

	n = nroutes * sizeof (pci_irq_route_t);
	for (i = 0; i < n; i++)
		bufp[i] = 0;
	((pci_irq_route_hdr_t *)hdrp)->pir_size = n;
	((pci_irq_route_hdr_t *)hdrp)->pir_addr = (uint32_t)(uintptr_t)bufp;

	bzero(&regs, sizeof (regs));
	regs.eax.word.ax = (PCI_FUNCTION_ID << 8) | PCI_GET_IRQ_ROUTING;

	regs.ds = 0xf000;
	regs.es = FP_SEG((uint_t)(uintptr_t)hdrp);
	regs.edi.word.di = FP_OFF((uint_t)(uintptr_t)hdrp);

	BOP_DOINT(bootops, 0x1a, &regs);

	n = (int)(((pci_irq_route_hdr_t *)hdrp)->pir_size /
	    sizeof (pci_irq_route_t));

	if ((regs.eflags & PS_C) != 0) {
		if (nneededp)
			*nneededp = n;
	} else {
		/*
		 * Copy resulting irq routing data from low memory up to
		 * the kernel address space, avoiding memcpy as usual.
		 */
		if (n <= nroutes) {
			for (i = 0; i < n * sizeof (pci_irq_route_t); i++)
				((uchar_t *)routes)[i] = bufp[i];
			rval = n;
		}
	}
	return (rval);
}

static void
pci_get_irq_routing_table(void)
{
	pci_irq_route_t	*routes;
	int		n = N_PCI_IRQ_ROUTES;
	int		nneeded = 0;
	int		nroutes;

	/*
	 * Get irq routing table information.
	 * Allocate a buffer for an initial default number of entries.
	 * If the bios indicates it needs a larger buffer, try it again.
	 * Drive on if it still won't cooperate and play nice after that.
	 */
	routes = kmem_zalloc(n * sizeof (pci_irq_route_t), KM_SLEEP);
	nroutes = pci_bios_get_irq_routing(routes, n, &nneeded);
	if (nroutes == 0 && nneeded > n) {
		kmem_free(routes, n * sizeof (pci_irq_route_t));
		if (nneeded > N_PCI_IRQ_ROUTES_MAX) {
			cmn_err(CE_CONT,
			    "pci: unable to get IRQ routing information, "
			    "required buffer space of %d entries exceeds max\n",
			    nneeded);
			return;
		}
		n = nneeded;
		routes = kmem_zalloc(n * sizeof (pci_irq_route_t), KM_SLEEP);
		nroutes = pci_bios_get_irq_routing(routes, n, NULL);
		if (nroutes == 0) {
			cmn_err(CE_CONT,
			    "pci: unable to get IRQ routing information, "
			    "required buffer space for %d entries\n", n);
			kmem_free(routes, n * sizeof (pci_irq_route_t));
		}
	}

	if (nroutes > 0) {
		pci_irq_routes = routes;
		pci_irq_nroutes = nroutes;
	}
}

/*
 * Use the results of the PCI BIOS call that returned the routing tables
 * to build the 1275 slot-names property for the indicated bus.
 * Results are returned in buf.  Length is return value, -1 is returned on
 * overflow and zero is returned if no data exists to build a property.
 */
int
pci_slot_names_prop(int bus, char *buf, int len)
{
	uchar_t		dev;
	uchar_t		slot[N_PCI_IRQ_ROUTES_MAX+1];
	uint32_t	 mask;
	int		i, nnames, plen;

	ASSERT(pci_irq_nroutes <= N_PCI_IRQ_ROUTES_MAX);

	if (pci_irq_nroutes == 0)
		return (0);
	nnames = 0;
	mask = 0;
	for (i = 0; i < pci_irq_nroutes; i++)
		slot[i] = 0xff;
	for (i = 0; i < pci_irq_nroutes; i++) {
		if (pci_irq_routes[i].pir_bus != bus)
			continue;
		if (pci_irq_routes[i].pir_slot != 0) {
			dev = (pci_irq_routes[i].pir_dev & 0xf8) >> 3;
			slot[dev] = pci_irq_routes[i].pir_slot;
			mask |= (1 << dev);
			nnames++;
		}
	}

	if (nnames == 0)
		return (0);

	if (len < (4 + nnames * 8))
		return (-1);
	*(uint32_t *)buf = mask;
	plen = 4;
	for (i = 0; i < pci_irq_nroutes; i++) {
		if (slot[i] == 0xff)
			continue;
		(void) sprintf(buf + plen, "Slot%d", slot[i]);
		plen += strlen(buf+plen) + 1;
		*(buf + plen) = 0;
	}
	for (; plen % 4; plen++)
		*(buf + plen) = 0;
	return (plen);
}
