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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Interfaces internal to the i86pc PCI nexus driver.
 */

#ifndef	_SYS_PCI_AUTOCONFIG_H
#define	_SYS_PCI_AUTOCONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mutex.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Routines to support particular PCI chipsets
 */

/*
 * Generic Mechanism 1 routines
 * XX64 putb -> put8, putw -> put16 etc.
 */
extern uint8_t pci_mech1_getb(int bus, int dev, int func, int reg);
extern uint16_t pci_mech1_getw(int bus, int dev, int func, int reg);
extern uint32_t pci_mech1_getl(int bus, int dev, int func, int reg);
extern void pci_mech1_putb(int bus, int dev, int func, int reg, uint8_t val);
extern void pci_mech1_putw(int bus, int dev, int func, int reg, uint16_t val);
extern void pci_mech1_putl(int bus, int dev, int func, int reg, uint32_t val);

/*
 * Generic Mechanism 2 routines
 */
extern uint8_t pci_mech2_getb(int bus, int dev, int func, int reg);
extern uint16_t pci_mech2_getw(int bus, int dev, int func, int reg);
extern uint32_t pci_mech2_getl(int bus, int dev, int func, int reg);
extern void pci_mech2_putb(int bus, int dev, int func, int reg, uint8_t val);
extern void pci_mech2_putw(int bus, int dev, int func, int reg, uint16_t val);
extern void pci_mech2_putl(int bus, int dev, int func, int reg, uint32_t val);

/*
 * Intel Neptune routines.  Neptune is Mech 1, except that BIOSes
 * often initialize it into Mech 2 so we dynamically switch it to
 * Mech 1.  The chipset's buggy, so we have to do it carefully.
 */
extern boolean_t pci_check_neptune(void);
extern uint8_t pci_neptune_getb(int bus, int dev, int func, int reg);
extern uint16_t pci_neptune_getw(int bus, int dev, int func, int reg);
extern uint32_t pci_neptune_getl(int bus, int dev, int func, int reg);
extern void pci_neptune_putb(int bus, int dev, int func, int reg, uint8_t val);
extern void pci_neptune_putw(int bus, int dev, int func, int reg, uint16_t val);
extern void pci_neptune_putl(int bus, int dev, int func, int reg, uint32_t val);

/*
 * Intel Orion routines.  Orion is Mech 1, except that there's a bug
 * in the peer bridge that requires that it be tweaked specially
 * around accesses to config space.
 */
extern boolean_t pci_is_broken_orion(void);
extern uint8_t pci_orion_getb(int bus, int dev, int func, int reg);
extern uint16_t pci_orion_getw(int bus, int dev, int func, int reg);
extern uint32_t pci_orion_getl(int bus, int dev, int func, int reg);
extern void pci_orion_putb(int bus, int dev, int func, int reg, uint8_t val);
extern void pci_orion_putw(int bus, int dev, int func, int reg, uint16_t val);
extern void pci_orion_putl(int bus, int dev, int func, int reg, uint32_t val);

/*
 * Generic PCI constants.  Probably these should be in pci.h.
 */
#define	PCI_MAX_BUSSES		256
#define	PCI_MAX_DEVS		32
#define	PCI_MAX_FUNCS		8

/*
 * PCI access mechanism constants.  Probably these should be in pci_impl.h.
 */
#define	PCI_MECH2_CONFIG_ENABLE	0x10	/* any nonzero high nibble works */

#define	PCI_MECH1_SPEC_CYCLE_DEV	0x1f	/* dev to request spec cyc */
#define	PCI_MECH1_SPEC_CYCLE_FUNC	0x07	/* func to request spec cyc */

/*
 * Mutex for all pci config space routines to share
 */

extern kmutex_t pcicfg_mutex;

/*
 * Orion/Neptune cfg access wraps mech1 cfg access, so needs a separate mutex
 */

extern kmutex_t pcicfg_chipset_mutex;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_AUTOCONFIG_H */
