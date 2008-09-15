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
 * Portions Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008, Intel Corporation.
 * All rights reserved.
 */

#ifndef _SYS_DMAR_ACPI_H
#define	_SYS_DMAR_ACPI_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	DMAR_TABLE_PROPNAME	"dmar-table"

#define	DMAR_UNIT_TYPE_DRHD	0
#define	DMAR_UNIT_TYPE_RMRR	1
#define	DMAR_UNIT_TYPE_ATSR	2

#define	DEV_SCOPE_ENDPOINT	1
#define	DEV_SCOPE_P2P		2
#define	DEV_SCOPE_IOAPIC	3
#define	DEV_SCOPE_HPET		4

#define	INCLUDE_PCI_ALL		0x01
#define	DMAR_MAX_SEGMENT	1

#define	IOMMU_PAGE_SIZE_4K	(1UL << 12)
#define	IOMMU_REG_SIZE		(1UL << 12)
#define	PARSE_DMAR_SUCCESS	1
#define	PARSE_DMAR_FAIL		0

#define	for_each_in_list(list, node) \
	for (node = list_head(list); node != NULL; \
	    node = list_next(list, node))

/*
 * The following structure describes the formate of
 * DMAR ACPI table format. They are used to parse
 * DMAR ACPI table.
 *
 * Read the spec for the meaning of each member.
 */

/* DMAR ACPI table header */
typedef struct dmar_acpi_head {
	char		dh_sig[4];
	uint32_t	dh_len;
	uint8_t		dh_rev;
	uint8_t		dh_checksum;
	char		dh_oemid[6];
	char		dh_oemtblid[8];
	uint32_t	dh_oemrev;
	char		dh_asl[4];
	uint32_t	dh_aslrev;
	uint8_t		dh_haw;
	uint8_t		dh_flags;
	uint8_t		dh_reserved[10];
} dmar_acpi_head_t;

/* Remapping structure header */
typedef struct dmar_acpi_unit_head {
	uint16_t	uh_type;
	uint16_t	uh_length;
} dmar_acpi_unit_head_t;

/* DRHD unit structure */
typedef struct dmar_acpi_drhd {
	dmar_acpi_unit_head_t	dr_header;
	uint8_t			dr_flags;
	uint8_t			dr_reserved;
	uint16_t		dr_segment;
	uint64_t		dr_baseaddr;
} dmar_acpi_drhd_t;

/* Device scope structure */
typedef struct dmar_acpi_dev_scope {
	uint8_t		ds_type;
	uint8_t		ds_length;
	uint8_t		ds_reserved[2];
	uint8_t		ds_enumid;
	uint8_t		ds_sbusnum;
} dmar_acpi_dev_scope_t;

/* RMRR unit structure */
typedef struct dmar_acpi_rmrr {
	dmar_acpi_unit_head_t	rm_header;
	uint8_t			rm_reserved[2];
	uint16_t		rm_segment;
	uint64_t		rm_baseaddr;
	uint64_t		rm_limiaddr;
} dmar_acpi_rmrr_t;

/*
 * The following structures describes kernel recorded
 * information about the DRHD and RMRR.
 */

/*
 * DRHD information structure
 *
 * node           - the drhd info structure is inserted in the
 *                  list embedded in the intel_dmar_info
 * di_segment     - the pci segment associated with this drhd
 * di_reg_base    - base address of the register set, the size
 *                  of this set is 4K
 * di_include_all - is it an include_all unit
 * di_dev_list    - the dev_info list get from the device scope,
 *                  the node of this list is pci_dev_info_t,
 *                  which present a single pci device
 * di_dip         - pointer to the dev_info for this drhd in the
 *                  device tree
 * di_iommu	  - link to the iommu state structure
 */
typedef struct drhd_info {
	list_node_t 	node;
	uint16_t 	di_segment;
	uint64_t 	di_reg_base;
	boolean_t	di_include_all;
	list_t 		di_dev_list;
	dev_info_t	*di_dip;
	void		*di_iommu;
} drhd_info_t;

/*
 * RMRR information structure
 *
 * node        - the rmrr info structure is inserted in the
 *               list embedded in the intel_dmar_info
 * ri_segment  - the pci segment associated with this rmrr
 * ri_baseaddr - the low address of the reserved range
 * ri_limiaddr - the high address of the reserved range
 * ri_dev_list - the dev_info list get from the device scope,
 *               the node of this list is pci_dev_info_t, w-
 *               hich present a single pci device
 */
typedef struct rmrr_info {
	list_node_t	node;
	uint16_t	ri_segment;
	uint64_t	ri_baseaddr;
	uint64_t	ri_limiaddr;
	list_t		ri_dev_list;
} rmrr_info_t;

/*
 * Intel IOMMU information structure
 *
 * dmari_haw        - haw (host address width) indicates the max-
 *                    imum DMA physical addressability by this
 *                    platform.
 * dmari_intr_remap - does this platform support intr remapping
 * dmari_drhd       - the list array of drhd units with the
 *                    segment number as the index into this array
 * dmari_rmrr       - list array for the rmrr
 */
typedef struct intel_dmar_info {
	uint8_t		dmari_haw;
	boolean_t	dmari_intr_remap;
	list_t		dmari_drhd[DMAR_MAX_SEGMENT];
	list_t		dmari_rmrr[DMAR_MAX_SEGMENT];
} intel_dmar_info_t;

/*
 * The pci device node in the dev_list of drhd_info and
 * rmrr_info
 *
 * node		  - list node
 * bus, dev, func - bus, device and function number of
 *		  - this pci device
 * pdi_type	  - type of this device, includes
 *		    0x01 : pci endpoint
 *		    0x02 : pci p2p bridge
 *		    0x03 : ioapci
 *		    0x04 : msi capable hpet
 * pdi_sec_bus	  - record the bus number of the PCI bus
 *		    segment to which the secondary interface
 *		    of the bridge is connected
 * pdi_sub_bus	  - record the bus number of the highest
 *		    numbered PCI bus segment which is behind
 *		    (or subordinate to) the bridge
 */
typedef struct pci_dev_scope {
	list_node_t node;
	uint8_t pds_bus;
	uint8_t pds_dev;
	uint8_t pds_func;
	uint8_t pds_type;
} pci_dev_scope_t;

extern boolean_t intel_iommu_support;
extern intel_dmar_info_t *dmar_info;
extern void intel_iommu_release_dmar_info(void);
extern void intel_iommu_probe_and_parse(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DMAR_ACPI_H */
