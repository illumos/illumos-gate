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
pci_get_cfg_type()
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
