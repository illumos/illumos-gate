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
 * PCI Mechanism 2 primitives
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/pci_impl.h>
#include <sys/pci_cfgspace_impl.h>

/*
 * The "mechanism 2" interface only has 4 bits for device number.  To
 * hide this implementation detail, we return all ones for accesses to
 * devices 16..31.
 */
#define	PCI_MAX_DEVS_2	16

/*
 * the PCI LOCAL BUS SPECIFICATION 2.0 does not say that you need to
 * save the value of the register and restore them.  The Intel chip
 * set documentation indicates that you should.
 */
static uint8_t
pci_mech2_config_enable(uchar_t bus, uchar_t function)
{
	uint8_t	old;

	mutex_enter(&pcicfg_mutex);
	old = inb(PCI_CSE_PORT);

	outb(PCI_CSE_PORT,
		PCI_MECH2_CONFIG_ENABLE | ((function & PCI_FUNC_MASK) << 1));
	outb(PCI_FORW_PORT, bus);

	return (old);
}

static void
pci_mech2_config_restore(uint8_t oldstatus)
{
	outb(PCI_CSE_PORT, oldstatus);
	mutex_exit(&pcicfg_mutex);
}

uint8_t
pci_mech2_getb(int bus, int device, int function, int reg)
{
	uint8_t tmp;
	uint8_t val;

	if (device >= PCI_MAX_DEVS_2)
		return (0xff);

	tmp = pci_mech2_config_enable(bus, function);
	val = inb(PCI_CADDR2(device, reg));
	pci_mech2_config_restore(tmp);

	return (val);
}

uint16_t
pci_mech2_getw(int bus, int device, int function, int reg)
{
	uint8_t	tmp;
	uint16_t val;

	if (device >= PCI_MAX_DEVS_2)
		return (0xffff);

	tmp = pci_mech2_config_enable(bus, function);
	val = inw(PCI_CADDR2(device, reg));
	pci_mech2_config_restore(tmp);

	return (val);
}

uint32_t
pci_mech2_getl(int bus, int device, int function, int reg)
{
	uint8_t		tmp;
	uint32_t	val;

	if (device >= PCI_MAX_DEVS_2)
		return (0xffffffffu);

	tmp = pci_mech2_config_enable(bus, function);
	val = inl(PCI_CADDR2(device, reg));
	pci_mech2_config_restore(tmp);

	return (val);
}

void
pci_mech2_putb(int bus, int device, int function, int reg, uint8_t val)
{
	uint8_t	tmp;

	if (device >= PCI_MAX_DEVS_2)
		return;

	tmp = pci_mech2_config_enable(bus, function);
	outb(PCI_CADDR2(device, reg), val);
	pci_mech2_config_restore(tmp);
}

void
pci_mech2_putw(int bus, int device, int function, int reg, uint16_t val)
{
	uint8_t	tmp;

	if (device >= PCI_MAX_DEVS_2)
		return;

	tmp = pci_mech2_config_enable(bus, function);
	outw(PCI_CADDR2(device, reg), val);
	pci_mech2_config_restore(tmp);
}

void
pci_mech2_putl(int bus, int device, int function, int reg, uint32_t val)
{
	uint8_t	tmp;

	if (device >= PCI_MAX_DEVS_2)
		return;

	tmp = pci_mech2_config_enable(bus, function);
	outl(PCI_CADDR2(device, reg), val);
	pci_mech2_config_restore(tmp);
}
