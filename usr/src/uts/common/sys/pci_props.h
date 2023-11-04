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

#ifndef _SYS_PCI_PROPS_H
#define	_SYS_PCI_PROPS_H

/*
 * This contains common structures and functions that are used to initialize and
 * set up PCI related nodes. As we move further towards unifying the PCI boot
 * time and hotplug settings several of the functions here can be consolidated
 * into that single path.
 */

#include <sys/stdint.h>
#include <sys/dditypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	PCI_PROP_F_MULT_FUNC	= 1 << 0,
	PCI_PROP_F_PCIE		= 1 << 1,
	PCI_PROP_F_SLOT_VALID	= 1 << 2
} pci_prop_flags_t;

typedef struct pci_prop_data {
	pci_prop_flags_t ppd_flags;
	uint8_t ppd_bus;
	uint8_t ppd_dev;
	uint8_t ppd_func;
	uint8_t ppd_rev;
	uint8_t ppd_header;
	uint8_t ppd_class;
	uint8_t ppd_subclass;
	uint8_t ppd_pi;
	uint16_t ppd_vendid;
	uint16_t ppd_devid;
	uint16_t ppd_subvid;
	uint16_t ppd_subsys;
	uint16_t ppd_pcie_type;
	uint16_t ppd_slotno;
	uint8_t ppd_pcie_cap_off;
	uint8_t ppd_ipin;
	uint8_t ppd_mingrt;
	uint8_t ppd_maxlat;
	uint16_t ppd_status;
} pci_prop_data_t;

typedef enum {
	PCI_PROP_OK	= 0,
	/*
	 * Indicates that we could not successfully read a given field from the
	 * device (e.g. getting all 1s when reading the vendor ID).
	 */
	PCI_PROP_E_BAD_READ,
	/*
	 * Indicates that we encountered an unknown header type. The ppd_header
	 * field will be valid on this failure as will the basic device, vendor,
	 * revision, and class IDs.
	 */
	PCI_PROP_E_UNKNOWN_HEADER,
	/*
	 * Indicates that we found an unknown and unsupported PCIe capability
	 * structure.
	 */
	PCI_PROP_E_BAD_PCIE_CAP,
	/*
	 * Indicates that an NDI or DDI failure occurred respectively.
	 */
	PCI_PROP_E_NDI,
	PCI_PROP_E_DDI
} pci_prop_failure_t;

extern pci_prop_failure_t pci_prop_data_fill(ddi_acc_handle_t, uint8_t, uint8_t,
    uint8_t, pci_prop_data_t *);
extern pci_prop_failure_t pci_prop_name_node(dev_info_t *,
    const pci_prop_data_t *);
extern pci_prop_failure_t pci_prop_set_common_props(dev_info_t *,
    const pci_prop_data_t *);
extern pci_prop_failure_t pci_prop_set_compatible(dev_info_t *,
    const pci_prop_data_t *);

/*
 * This is currently exported so there is a single implementation of this logic.
 */
extern boolean_t pci_prop_class_is_vga(const pci_prop_data_t *);
extern boolean_t pci_prop_class_is_isa(const pci_prop_data_t *);
extern boolean_t pci_prop_class_is_ioapic(const pci_prop_data_t *);
extern boolean_t pci_prop_class_is_pcibridge(const pci_prop_data_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PCI_PROPS_H */
