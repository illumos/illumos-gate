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

/*
 * Determine the PCI configuration mechanism recommended by the BIOS.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/pci_impl.h>
#include <sys/ddi_subrdefs.h>
#include <sys/bootconf.h>
#include <sys/psw.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/pci.h>
#include <sys/pci_cfgspace.h>
#include <sys/reboot.h>
#include "pci_autoconfig.h"

extern int pci_boot_debug;

/*
 * Internal structures and functions
 */
int pci_bios_cfg_type = PCI_MECHANISM_UNKNOWN;
int pci_bios_nbus;
int pci_bios_mech;
int pci_bios_vers;
static  int pci_nounload = 0;

/*
 * These two variables can be used to force a configuration mechanism or
 * to force which function is used to probe for the presence of the PCI bus.
 */
int	PCI_CFG_TYPE = 0;
int	PCI_PROBE_TYPE = 0;

/*
 * These function pointers lead to the actual implementation routines
 * for configuration space access.  Normally they lead to either the
 * pci_mech1_* or pci_mech2_* routines, but they can also lead to
 * routines that work around chipset bugs.
 */
uint8_t (*pci_getb_func)(int bus, int dev, int func, int reg);
uint16_t (*pci_getw_func)(int bus, int dev, int func, int reg);
uint32_t (*pci_getl_func)(int bus, int dev, int func, int reg);
void (*pci_putb_func)(int bus, int dev, int func, int reg, uint8_t val);
void (*pci_putw_func)(int bus, int dev, int func, int reg, uint16_t val);
void (*pci_putl_func)(int bus, int dev, int func, int reg, uint32_t val);

/*
 * Internal routines
 */
static int pci_check_bios(void);
static int pci_get_cfg_type(void);
static void pci_get_irq_routing_table(void);

/*
 * Interface routines
 */
void pci_enumerate(int);
void pci_setup_tree(void);
void pci_reprogram(void);

static struct modlmisc modlmisc = {
	&mod_miscops, "PCI BIOS interface %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

/* all config-space access routines share this one... */
kmutex_t pcicfg_mutex;

/* ..except Orion and Neptune, which have to have their own */
kmutex_t pcicfg_chipset_mutex;

int
_init(void)
{
	int	err;

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);
	mutex_init(&pcicfg_mutex, NULL, MUTEX_DEFAULT, 0);
	mutex_init(&pcicfg_chipset_mutex, NULL, MUTEX_DEFAULT, 0);

	impl_bus_add_probe(pci_enumerate);
	return (0);
}

int
_fini(void)
{
	int	err;

	if (pci_nounload)
		return (EBUSY);

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	impl_bus_delete_probe(pci_enumerate);
	mutex_destroy(&pcicfg_chipset_mutex);
	mutex_destroy(&pcicfg_mutex);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * This code determines if this system supports PCI and which
 * type of configuration access method is used
 */

static int
pci_check(void)
{
	/*
	 * Only do this once.  NB:  If this is not a PCI system, and we
	 * get called twice, we can't detect it and will probably die
	 * horribly when we try to ask the BIOS whether PCI is present.
	 * This code is safe *ONLY* during system startup when the
	 * bootstrap is still available.
	 */
	if (pci_bios_cfg_type != PCI_MECHANISM_UNKNOWN)
		return (DDI_SUCCESS);

	pci_bios_cfg_type = pci_check_bios();

	if (pci_bios_cfg_type == PCI_MECHANISM_NONE)
		return (DDI_FAILURE);

	pci_nounload = 1;

	switch (pci_get_cfg_type()) {
	case PCI_MECHANISM_1:
		if (pci_is_broken_orion()) {
			pci_getb_func = pci_orion_getb;
			pci_getw_func = pci_orion_getw;
			pci_getl_func = pci_orion_getl;
			pci_putb_func = pci_orion_putb;
			pci_putw_func = pci_orion_putw;
			pci_putl_func = pci_orion_putl;
		} else {
			pci_getb_func = pci_mech1_getb;
			pci_getw_func = pci_mech1_getw;
			pci_getl_func = pci_mech1_getl;
			pci_putb_func = pci_mech1_putb;
			pci_putw_func = pci_mech1_putw;
			pci_putl_func = pci_mech1_putl;
		}
		break;

	case PCI_MECHANISM_2:
		if (pci_check_neptune()) {
			/*
			 * The BIOS for some systems with the Intel
			 * Neptune chipset seem to default to #2 even
			 * though the chipset can do #1.  Override
			 * the BIOS so that MP systems will work
			 * correctly.
			 */

			pci_getb_func = pci_neptune_getb;
			pci_getw_func = pci_neptune_getw;
			pci_getl_func = pci_neptune_getl;
			pci_putb_func = pci_neptune_putb;
			pci_putw_func = pci_neptune_putw;
			pci_putl_func = pci_neptune_putl;
		} else {
			pci_getb_func = pci_mech2_getb;
			pci_getw_func = pci_mech2_getw;
			pci_getl_func = pci_mech2_getl;
			pci_putb_func = pci_mech2_putb;
			pci_putw_func = pci_mech2_putw;
			pci_putl_func = pci_mech2_putl;
		}
		break;

	default:
		/* Not sure what to do here. */
		cmn_err(CE_WARN, "pci:  Unknown configuration type");
		return (DDI_FAILURE);
	}

	pci_get_irq_routing_table();

	return (DDI_SUCCESS);
}

#define	PCI_FUNCTION_ID		(0xb1)
#define	PCI_BIOS_PRESENT	(0x1)

static int
pci_check_bios(void)
{
	struct bop_regs regs;
	uint32_t	carryflag;
	uint16_t	ax, dx;

	bzero(&regs, sizeof (regs));
	regs.eax.word.ax = (PCI_FUNCTION_ID << 8) | PCI_BIOS_PRESENT;

	BOP_DOINT(bootops, 0x1a, &regs);
	carryflag = regs.eflags & PS_C;
	ax = regs.eax.word.ax;
	dx = regs.edx.word.dx;

	/* the carry flag must not be set */
	if (carryflag != 0)
		return (PCI_MECHANISM_NONE);

	if (dx != ('P' | 'C'<<8))
		return (PCI_MECHANISM_NONE);

	/* ah (the high byte of ax) must be zero */
	if ((ax & 0xff00) != 0)
		return (PCI_MECHANISM_NONE);

	pci_bios_mech = (ax & 0x3);
	pci_bios_vers = regs.ebx.word.bx;
	pci_bios_nbus = (regs.ecx.word.cx & 0xff);
	if (boothowto & RB_VERBOSE)
		cmn_err(CE_CONT, "PCI probe mech %x, version 0x%x, # busses %d",
		    pci_bios_mech, pci_bios_vers, pci_bios_nbus);

	switch (pci_bios_mech) {
	default:	/* ?!? */
	case 0:		/* supports neither? */
		return (PCI_MECHANISM_NONE);

	case 1:
	case 3:		/* supports both */
		return (PCI_MECHANISM_1);

	case 2:
		return (PCI_MECHANISM_2);
	}
}

static int
pci_get_cfg_type(void)
{
	/* Check to see if the config mechanism has been set in /etc/system */
	switch (PCI_CFG_TYPE) {
	default:
	case 0:
		break;
	case 1:
		return (PCI_MECHANISM_1);
	case 2:
		return (PCI_MECHANISM_2);
	case -1:
		return (PCI_MECHANISM_NONE);
	}

	/* call one of the PCI detection algorithms */
	switch (PCI_PROBE_TYPE) {
	default:
	case 0:
		/* This is determined by pci_autoconfig early in startup. */
		return (pci_bios_cfg_type);
	case -1:
		return (PCI_MECHANISM_NONE);
	}
}


/*
 * pci irq routing information table
 */
int			pci_irq_nroutes;
pci_irq_route_t		*pci_irq_routes;

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
		(void) sprintf(buf + plen, "Slot %d", slot[i]);
		plen += strlen(buf+plen) + 1;
		*(buf + plen) = 0;
	}
	for (; plen % 4; plen++)
		*(buf + plen) = 0;
	return (plen);
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
 * This functions is invoked twice, first time with reprogram=0 to
 * set up the PCI portion of the device tree. The second time is
 * for reprogramming devices not set up by the BIOS.
 */
void
pci_enumerate(int reprogram)
{
	if (reprogram) {
		pci_reprogram();
		return;
	}

	/* setup probe mechanism */
	if (pci_check() != DDI_SUCCESS) {
		cmn_err(CE_WARN, "cannot determine PCI probing mechanism\n");
		return;
	}

	/* setup device tree */
	pci_setup_tree();
}
