/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _SYS_PLAT_PCI_PRD_H
#define	_SYS_PLAT_PCI_PRD_H

/*
 * PCI Platform Resource Discovery (PRD)
 *
 * This file forms the platform-specific interfaces that a given platform must
 * implement to support the discovery of PCI resources. In particular:
 *
 *  o Any root complexes that do not show up through the use of normal scanning
 *  o Available resources per root-port including:
 *	+ I/O ports
 *	+ Prefetchable Memory
 *	+ Normal Memory
 *	+ PCI buses
 *  o The naming of slots (the platform uses the PCIe default)
 *
 * These interfaces are all expected to be implemented by a platform's 'pci_prd'
 * module. This is left as a module and not a part of say, unix, so that it can
 * in turn depend on other modules that a platform might require, such as ACPI.
 *
 * In general, unless otherwise indicated, these interfaces will always be
 * called from kernel context, typically during boot. The interfaces will only
 * be called from a single thread at this time and any locking is managed at a
 * layer outside of the pci_prd interfaces. If the subsystem is using some other
 * interfaces that may be used by multiple consumers and needs locking (e.g.
 * ACPI), then that still must be considered in the design and implementation.
 */

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Resource types that can be asked after.
 */
typedef enum pci_prd_rsrc {
	PCI_PRD_R_IO,
	PCI_PRD_R_MMIO,
	PCI_PRD_R_PREFETCH,
	PCI_PRD_R_BUS
} pci_prd_rsrc_t;

typedef struct pci_prd_upcalls {
	/*
	 * Return a dev_info_t, if one exists, for this PCI bus.
	 */
	dev_info_t *(*pru_bus2dip_f)(uint32_t);
} pci_prd_upcalls_t;

/*
 * Initialization and teardown functions that will be used by the PCI
 * enumeration code when it attaches and detaches. If all work is done before
 * these come up, there is nothing to do; however, after a call to the _init()
 * function, it is expected that the platform module will be ready to respond to
 * all function calls.
 *
 * Note that the _fini function may never be called as on a typical system, as
 * any PCI(e) devices with attached drivers will result in the PRD consumer
 * remaining loaded.
 */
extern int pci_prd_init(pci_prd_upcalls_t *);
extern void pci_prd_fini(void);

/*
 * Return the maximum PCI bus on this platform that should be searched. This
 * number is the last bus number that should be scanned. e.g. a value of 0x10
 * indicates that we will search buses [0, 0x10]. In general, it is expected
 * that platforms will just return 0xff (PCI_MAX_BUS_NUM - 1) unless for some
 * reason it has other knowledge here.
 */
extern uint32_t pci_prd_max_bus(void);

/*
 * Look up a set of resources that should be assigned to the PCI bus. In
 * general, it is expected that these are only the buses that are assigned to
 * root complexes.
 */
extern struct memlist *pci_prd_find_resource(uint32_t, pci_prd_rsrc_t);

/*
 * Originally when only using BIOS-derived (pre-ACPI) sources on i86pc, the
 * ability to utilize data about multiple buses was considered suspect. As such,
 * this exists as a way to indicate that resources on each root complex are
 * actually valid.
 */
extern boolean_t pci_prd_multi_root_ok(void);

/*
 * This is used to allow the PCI enumeration code to ask the platform about any
 * PCI root complexes that it might know about which might not be discovered
 * through the normal scanning process. One callback will be emitted for each
 * PCI bus via a call to the callback function. The return value of the callback
 * function determines whether we should continue iterating (B_TRUE) or
 * terminate (B_FALSE).
 */
typedef boolean_t (*pci_prd_root_complex_f)(uint32_t, void *);
extern void pci_prd_root_complex_iter(pci_prd_root_complex_f, void *);

/*
 * Give the chance for a platform to go through and use knowledge that it
 * has (such as the traditional BIOS PCI IRQ routing table) to name the PCI(e)
 * slot.
 */
extern void pci_prd_slot_name(uint32_t, dev_info_t *);

/*
 * These are a series of flags that indicate how certain compatibility options
 * should be specified and handled throughout the generic PCI stack. Unless
 * there is history here (i.e. you are on some kind of x86 system), this should
 * probably just return PCI_PRD_COMPAT_NONE.
 */
typedef enum {
	PCI_PRD_COMPAT_NONE	= 0,
	/*
	 * Indicates that ISA is supported and ISA bridge nodes should be
	 * created.
	 */
	PCI_PRD_COMPAT_ISA		= 1 << 0,
	/*
	 * Indicates that the node name should only be "pci" and we should not
	 * entertain "pciex" for reasons of platform tradition. This also tells
	 * us that we should generate PCI alises for PCI Express devices.
	 */
	PCI_PRD_COMPAT_PCI_NODE_NAME	= 1 << 1,
	/*
	 * Indicates that we need subsystem compatibility. In particular this
	 * means that bridges will not use subsystem IDs for their node names
	 * and unqualified (',p' and ',s') aliases will be created for PCI.  See
	 * uts/common/io/pciex/pcie_props.c.
	 */
	PCI_PRD_COMPAT_SUBSYS		= 1 << 2
} pci_prd_compat_flags_t;

extern pci_prd_compat_flags_t pci_prd_compat_flags(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PLAT_PCI_PRD_H */
