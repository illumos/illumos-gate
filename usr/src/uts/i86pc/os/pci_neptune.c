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
 * Support for Intel "Neptune" PCI chip set
 */

#include <sys/types.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/sunddi.h>
#include <sys/pci_cfgspace_impl.h>

/*
 * This variable is a place holder for the initial value in PCI_PMC register
 * of neptune chipset.
 */
static unsigned char neptune_BIOS_cfg_method = 0;

/*
 * Special hack for Intel's Neptune chipset, 82433NX and 82434NX.
 *
 * The motherboards I've seen still use a version of the BIOS
 * that operates using Configuration Mechanism #2 like the older
 * Mercury BIOS and chipset (the 82433LX and 82434LX).
 *
 */
boolean_t
pci_check_neptune(void)
{
	uint8_t		oldstatus;
	uint32_t	tmp;

	/* enable the config address space, bus=0 function=0 */
	oldstatus = inb(PCI_CSE_PORT);
	outb(PCI_CSE_PORT, PCI_MECH2_CONFIG_ENABLE);
	outb(PCI_FORW_PORT, 0);

	/*
	 * First check the vendor and device ids of the Host to
	 * PCI bridge. But it isn't sufficient just to do this check
	 * because the same device ID can refer to either
	 * the Neptune or Mercury chipset.
	 */

	/* check the vendor id, the device id, and the revision id */
	/* the Neptune revision ID == 0x11, allow 0x1? */
	if ((inl(PCI_CADDR2(0, PCI_CONF_VENID)) != 0x04a38086) ||
		(inb(PCI_CADDR2(0, PCI_CONF_REVID)) & 0xf0) != 0x10) {
		/* disable mechanism #2 config address space */
		outb(PCI_CSE_PORT, oldstatus);
		return (B_FALSE);
	}

	/* disable mechanism #2 config address space */
	outb(PCI_CSE_PORT, oldstatus);

	/*
	 * Now I know that the bridge *might* be a Neptune (it could be
	 * a Mercury chip.) Try enabling mechanism #1 to differentiate
	 * between the two chipsets.
	 */

	/*
	 * save the old value in case it's not Neptune (the Mercury
	 * chip has the deturbo and reset bits in the 0xcf9 register
	 * and the forward register at 0xcfa)
	 */
	tmp = inl(PCI_CONFADD);

	/*
	 * The Intel Neptune chipset defines this extra register
	 * to enable Config Mechanism #1.
	 */
	neptune_BIOS_cfg_method = inb(PCI_PMC);
	outb(PCI_PMC, neptune_BIOS_cfg_method | 1);

	/* make certain mechanism #1 works correctly */
	/* check the vendor and device id's of the Host to PCI bridge */
	outl(PCI_CONFADD, PCI_CADDR1(0, 0, 0, PCI_CONF_VENID));
	if (inl(PCI_CONFDATA) != ((0x04a3 << 16) | 0x8086)) {
		outb(PCI_PMC, neptune_BIOS_cfg_method);
		outl(PCI_CONFADD, tmp);
		return (B_FALSE);
	}
	outb(PCI_PMC, neptune_BIOS_cfg_method);
	return (B_TRUE);
}

static void
pci_neptune_enable()
{
	/*
	 * Switch the chipset to use Mechanism 1.
	 */
	mutex_enter(&pcicfg_chipset_mutex);
	outb(PCI_PMC, neptune_BIOS_cfg_method | 1);
}

static void
pci_neptune_disable()
{
	/*
	 * The Neptune chipset has a bug that if you write the PMC,
	 * it erroneously looks at some of the bits in the latches for
	 * adjacent registers... like, say, the "reset" bit.  We zero
	 * out the config address register to work around this bug.
	 */
	outl(PCI_CONFADD, PCI_CADDR1(0, 0, 0, 0));
	outb(PCI_PMC, neptune_BIOS_cfg_method);
	mutex_exit(&pcicfg_chipset_mutex);
}

uint8_t
pci_neptune_getb(int bus, int device, int function, int reg)
{
	uint8_t	val;

	pci_neptune_enable();

	val = pci_mech1_getb(bus, device, function, reg);

	pci_neptune_disable();
	return (val);
}

uint16_t
pci_neptune_getw(int bus, int device, int function, int reg)
{
	uint16_t val;

	pci_neptune_enable();

	val = pci_mech1_getw(bus, device, function, reg);

	pci_neptune_disable();
	return (val);
}

uint32_t
pci_neptune_getl(int bus, int device, int function, int reg)
{
	uint32_t val;

	pci_neptune_enable();

	val = pci_mech1_getl(bus, device, function, reg);

	pci_neptune_disable();
	return (val);
}

void
pci_neptune_putb(int bus, int device, int function, int reg, uint8_t val)
{
	pci_neptune_enable();

	pci_mech1_putb(bus, device, function, reg, val);

	pci_neptune_disable();
}

void
pci_neptune_putw(int bus, int device, int function, int reg, uint16_t val)
{
	pci_neptune_enable();

	pci_mech1_putw(bus, device, function, reg, val);

	pci_neptune_disable();
}

void
pci_neptune_putl(int bus, int device, int function, int reg, uint32_t val)
{
	pci_neptune_enable();

	pci_mech1_putl(bus, device, function, reg, val);

	pci_neptune_disable();
}
