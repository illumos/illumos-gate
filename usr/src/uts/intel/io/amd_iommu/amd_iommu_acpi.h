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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AMD_IOMMU_ACPI_H
#define	_AMD_IOMMU_ACPI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/amd_iommu.h>
#include "amd_iommu_impl.h"

#ifdef _KERNEL

#define	IVRS_SIG	"IVRS"

/*
 * IVHD deventry extended data settings
 */
#define	AMD_IOMMU_ACPI_DEVENTRY_LEN	(7 << 16 | 6)

/*
 * IVHD deventry data settings
 */
#define	AMD_IOMMU_ACPI_LINT1PASS	(7 << 16 | 7)
#define	AMD_IOMMU_ACPI_LINT0PASS	(6 << 16 | 6)
#define	AMD_IOMMU_ACPI_SYSMGT		(5 << 16 | 4)
#define	AMD_IOMMU_ACPI_NMIPASS		(2 << 16 | 2)
#define	AMD_IOMMU_ACPI_EXTINTPASS	(1 << 16 | 1)
#define	AMD_IOMMU_ACPI_INITPASS		(0 << 16 | 0)

/*
 * IVHD deventry extended data settings
 */
#define	AMD_IOMMU_ACPI_ATSDISABLED	(31 << 16 | 31)

typedef enum {
	DEVENTRY_INVALID = 0,
	DEVENTRY_ALL = 1,
	DEVENTRY_SELECT,
	DEVENTRY_RANGE,
	DEVENTRY_RANGE_END,
	DEVENTRY_ALIAS_SELECT,
	DEVENTRY_ALIAS_RANGE,
	DEVENTRY_EXTENDED_SELECT,
	DEVENTRY_EXTENDED_RANGE
} ivhd_deventry_flags_t;

typedef struct ivhd_deventry {
	uint8_t idev_len;
	ivhd_deventry_flags_t  idev_flags;
	uint16_t idev_bdf;
	uint16_t idev_src_bdf;
	uint8_t idev_Lint1Pass;
	uint8_t idev_Lint0Pass;
	uint8_t idev_SysMgt;
	uint8_t idev_NMIPass;
	uint8_t idev_ExtIntPass;
	uint8_t idev_INITPass;
	uint8_t idev_AtsDisabled;
	struct ivhd_deventry *idev_next;
} ivhd_deventry_t;

typedef struct ivhd {
	uint8_t ivhd_type;
	uint8_t ivhd_flags;
	uint16_t ivhd_len;
	uint8_t ivhd_bus;
	uint8_t ivhd_devfn;
	uint16_t ivhd_cap_off;
	uint64_t ivhd_reg_base;
	uint16_t ivhd_pci_seg;
	uint8_t ivhd_msi_unitid;
	uint32_t ivhd_resv;
} ivhd_t;

typedef struct ivhd_container {
	ivhd_t *ivhdc_ivhd;
	ivhd_deventry_t *ivhdc_first_deventry;
	ivhd_deventry_t *ivhdc_last_deventry;
	struct ivhd_container *ivhdc_next;
} ivhd_container_t;

typedef struct ivmd {
	uint8_t ivmd_type;
	uint8_t ivmd_resv;
	uint16_t ivmd_len;
	uint16_t ivmd_devid;
	uint8_t ivmd_resv2;
	uint8_t ivmd_flags;
	uint64_t ivmd_resv3;
	uint64_t ivmd_phys_start;
	uint64_t ivmd_phys_len;
} ivmd_t;

typedef struct ivmd_container {
	ivmd_t *ivmdc_ivmd;
	struct ivmd_container *ivmdc_next;
} ivmd_container_t;

typedef struct ivrs {
	struct acpi_table_header ivrs_hdr;
	uint32_t ivrs_ivinfo;
	uint64_t ivrs_resv;
} ivrs_t;

typedef struct amd_iommu_acpi {
	struct ivrs *acp_ivrs;
	ivhd_container_t *acp_first_ivhdc;
	ivhd_container_t *acp_last_ivhdc;
	ivmd_container_t *acp_first_ivmdc;
	ivmd_container_t *acp_last_ivmdc;
} amd_iommu_acpi_t;

#pragma pack()

extern amd_iommu_acpi_t *amd_iommu_acpip;

int amd_iommu_acpi_init(amd_iommu_acpi_t **acpipp);
void amd_iommu_acpi_fini(amd_iommu_acpi_t **acpipp);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _AMD_IOMMU_ACPI_H */
