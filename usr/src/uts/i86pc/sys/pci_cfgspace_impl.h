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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_PCI_CFGSPACE_IMPL_H
#define	_SYS_PCI_CFGSPACE_IMPL_H

/*
 * Routines to support particular PCI chipsets
 */

#ifdef __cplusplus
extern "C" {
#endif

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
 * AMD family >= 0x10 Mechanism 1 routines with ECS support
 */
extern boolean_t pci_check_amd_ioecs(void);
extern uint8_t pci_mech1_amd_getb(int bus, int dev, int func, int reg);
extern uint16_t pci_mech1_amd_getw(int bus, int dev, int func, int reg);
extern uint32_t pci_mech1_amd_getl(int bus, int dev, int func, int reg);
extern void pci_mech1_amd_putb(int bus, int dev, int func, int reg,
    uint8_t val);
extern void pci_mech1_amd_putw(int bus, int dev, int func, int reg,
    uint16_t val);
extern void pci_mech1_amd_putl(int bus, int dev, int func, int reg,
    uint32_t val);

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

extern uint64_t mcfg_mem_base;
extern uint8_t mcfg_bus_start;
extern uint8_t mcfg_bus_end;

/*
 * Mutexes for pci config space routines
 */
extern kmutex_t pcicfg_mutex;
extern kmutex_t pcicfg_mmio_mutex;

/*
 * Orion/Neptune cfg access wraps mech1 cfg access, so needs a separate mutex
 */

extern kmutex_t pcicfg_chipset_mutex;

/*
 * pci get irq routing information support
 */
#define	PCI_GET_IRQ_ROUTING	0x0e

#define	PCI_FUNCTION_ID		(0xb1)
#define	PCI_BIOS_PRESENT	(0x1)

/*
 * low-mem addresses for irq routing bios operations
 * We set up the initial request for up to 32 table entries, and will
 * re-issue for up to 255 entries if the bios indicates it requires
 * a larger table.  255 entries plus the header would consume the
 * memory between 0x7000-0x7fff.
 */
#define	BIOS_IRQ_ROUTING_HDR	0x7000
#define	BIOS_IRQ_ROUTING_DATA	0x7010

#define	N_PCI_IRQ_ROUTES	32
#define	N_PCI_IRQ_ROUTES_MAX	255

#define	MCFG_PROPNAME		"ecfg"

#define	FP_OFF(fp)	(((uintptr_t)(fp)) & 0xFFFF)
#define	FP_SEG(fp)	((((uintptr_t)(fp)) >> 16) & 0xFFFF)

#pragma pack(1)
typedef struct pci_irq_route {
	uchar_t		pir_bus;
	uchar_t		pir_dev;
	uchar_t		pir_inta_link;
	uint16_t	pir_inta_irq_map;
	uchar_t		pir_intb_link;
	uint16_t	pir_intb_irq_map;
	uchar_t		pir_intc_link;
	uint16_t	pir_intc_irq_map;
	uchar_t		pir_intd_link;
	uint16_t	pir_intd_irq_map;
	uchar_t		pir_slot;
	uchar_t		pir_reserved;
} pci_irq_route_t;
#pragma pack()

#pragma pack(1)
typedef struct pci_irq_route_hdr {
	uint16_t	pir_size;
	uint32_t	pir_addr;
} pci_irq_route_hdr_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PCI_CFGSPACE_IMPL_H */
