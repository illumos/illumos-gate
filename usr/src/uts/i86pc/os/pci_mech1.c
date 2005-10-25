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
 * PCI Mechanism 1 low-level routines
 */

#include <sys/types.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/sunddi.h>
#include <sys/pci_cfgspace_impl.h>

/*
 * Per PCI 2.1 section 3.7.4.1 and PCI-PCI Bridge Architecture 1.0 section
 * 5.3.1.2:  dev=31 func=7 reg=0 means a special cycle.  We don't want to
 * trigger that by accident, so we pretend that dev 31, func 7 doesn't
 * exist.  If we ever want special cycle support, we'll add explicit
 * special cycle support.
 */

uint8_t
pci_mech1_getb(int bus, int device, int function, int reg)
{
	uint8_t val;
	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return (0xff);
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1(bus, device, function, reg));
	val = inb(PCI_CONFDATA | (reg & 0x3));
	mutex_exit(&pcicfg_mutex);
	return (val);
}

uint16_t
pci_mech1_getw(int bus, int device, int function, int reg)
{
	uint16_t val;

	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return (0xffff);
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1(bus, device, function, reg));
	val =  inw(PCI_CONFDATA | (reg & 0x2));
	mutex_exit(&pcicfg_mutex);
	return (val);
}

uint32_t
pci_mech1_getl(int bus, int device, int function, int reg)
{
	uint32_t val;

	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return (0xffffffffu);
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1(bus, device, function, reg));
	val = inl(PCI_CONFDATA);
	mutex_exit(&pcicfg_mutex);
	return (val);
}

void
pci_mech1_putb(int bus, int device, int function, int reg, uint8_t val)
{
	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return;
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1(bus, device, function, reg));
	outb(PCI_CONFDATA | (reg & 0x3), val);
	mutex_exit(&pcicfg_mutex);
}

void
pci_mech1_putw(int bus, int device, int function, int reg, uint16_t val)
{
	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return;
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1(bus, device, function, reg));
	outw(PCI_CONFDATA | (reg & 0x2), val);
	mutex_exit(&pcicfg_mutex);
}

void
pci_mech1_putl(int bus, int device, int function, int reg, uint32_t val)
{
	if (device == PCI_MECH1_SPEC_CYCLE_DEV &&
	    function == PCI_MECH1_SPEC_CYCLE_FUNC) {
		return;
	}

	mutex_enter(&pcicfg_mutex);
	outl(PCI_CONFADD, PCI_CADDR1(bus, device, function, reg));
	outl(PCI_CONFDATA, val);
	mutex_exit(&pcicfg_mutex);
}
