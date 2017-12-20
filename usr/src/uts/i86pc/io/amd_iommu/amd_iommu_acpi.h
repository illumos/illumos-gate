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
 * Copyright 2017 Gary Mills
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
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
 * IVINFO bit fields
 * Documented at: http://support.amd.com/TechDocs/48882_IOMMU.pdf
 */
#define	AMD_IOMMU_ACPI_IVINFO_RSV1	(31 << 16 | 23)
#define	AMD_IOMMU_ACPI_HT_ATSRSV	(22 << 16 | 22)
#define	AMD_IOMMU_ACPI_VA_SIZE		(21 << 16 | 15)
#define	AMD_IOMMU_ACPI_PA_SIZE		(14 << 16 | 8)
#define	AMD_IOMMU_ACPI_GVA_SIZE		(7 << 16 | 5)
#define	AMD_IOMMU_ACPI_IVINFO_RSV2	(4 << 16 | 1)
#define	AMD_IOMMU_ACPI_IVINFO_EFRSUP	(0 << 16 | 0)

/*
 * IVHD Device entry len field
 */
#define	AMD_IOMMU_ACPI_DEVENTRY_LEN	(7 << 16 | 6)

/*
 * IVHD flag fields definition
 */
#define	AMD_IOMMU_ACPI_IVHD_FLAGS_RSV		(7 << 16 | 5)
#define	AMD_IOMMU_ACPI_IVHD_FLAGS_IOTLBSUP	(4 << 16 | 4)
#define	AMD_IOMMU_ACPI_IVHD_FLAGS_ISOC		(3 << 16 | 3)
#define	AMD_IOMMU_ACPI_IVHD_FLAGS_RESPASSPW	(2 << 16 | 2)
#define	AMD_IOMMU_ACPI_IVHD_FLAGS_PASSPW	(1 << 16 | 1)
#define	AMD_IOMMU_ACPI_IVHD_FLAGS_HTTUNEN	(0 << 16 | 0)

/*
 * IVHD IOMMU info fields
 */
#define	AMD_IOMMU_ACPI_IOMMU_INFO_RSV1		(15 << 16 | 13)
#define	AMD_IOMMU_ACPI_IOMMU_INFO_UNITID	(12 << 16 | 8)
#define	AMD_IOMMU_ACPI_IOMMU_INFO_RSV2		(7 << 16 | 5)
#define	AMD_IOMMU_ACPI_IOMMU_INFO_MSINUM	(4 << 16 | 0)

/*
 * IVHD deventry data settings
 */
#define	AMD_IOMMU_ACPI_LINT1PASS	(7 << 16 | 7)
#define	AMD_IOMMU_ACPI_LINT0PASS	(6 << 16 | 6)
#define	AMD_IOMMU_ACPI_SYSMGT		(5 << 16 | 4)
#define	AMD_IOMMU_ACPI_DATRSV		(3 << 16 | 3)
#define	AMD_IOMMU_ACPI_NMIPASS		(2 << 16 | 2)
#define	AMD_IOMMU_ACPI_EXTINTPASS	(1 << 16 | 1)
#define	AMD_IOMMU_ACPI_INITPASS		(0 << 16 | 0)

/*
 * IVHD deventry extended data settings
 */
#define	AMD_IOMMU_ACPI_ATSDISABLED	(31 << 16 | 31)
#define	AMD_IOMMU_ACPI_EXTDATRSV	(30 << 16 | 0)

/*
 * IVMD flags fields settings
 */
#define	AMD_IOMMU_ACPI_IVMD_RSV		(7 << 16 | 4)
#define	AMD_IOMMU_ACPI_IVMD_EXCL_RANGE	(3 << 16 | 3)
#define	AMD_IOMMU_ACPI_IVMD_IW		(2 << 16 | 2)
#define	AMD_IOMMU_ACPI_IVMD_IR		(1 << 16 | 1)
#define	AMD_IOMMU_ACPI_IVMD_UNITY	(0 << 16 | 0)

#define	AMD_IOMMU_ACPI_INFO_HASH_SZ	(256)

/*
 * Deventry special device "variety"
 */
#define	AMD_IOMMU_ACPI_SPECIAL_APIC	0x1
#define	AMD_IOMMU_ACPI_SPECIAL_HPET	0x2

typedef enum {
	DEVENTRY_INVALID = 0,
	DEVENTRY_ALL = 1,
	DEVENTRY_SELECT,
	DEVENTRY_RANGE,
	DEVENTRY_RANGE_END,
	DEVENTRY_ALIAS_SELECT,
	DEVENTRY_ALIAS_RANGE,
	DEVENTRY_EXTENDED_SELECT,
	DEVENTRY_EXTENDED_RANGE,
	DEVENTRY_SPECIAL_DEVICE
} ivhd_deventry_type_t;

typedef enum {
	IVMD_DEVICE_INVALID = 0,
	IVMD_DEVICEID_ALL,
	IVMD_DEVICEID_SELECT,
	IVMD_DEVICEID_RANGE
} ivmd_deviceid_type_t;

typedef struct ivhd_deventry {
	uint8_t idev_len;
	ivhd_deventry_type_t  idev_type;
	int32_t idev_deviceid;
	int32_t idev_src_deviceid;
	uint8_t idev_handle;
	uint8_t idev_variety;
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
	uint16_t ivhd_deviceid;
	uint16_t ivhd_cap_off;
	uint64_t ivhd_reg_base;
	uint16_t ivhd_pci_seg;
	uint16_t ivhd_iommu_info;
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
	uint8_t ivmd_flags;
	uint16_t ivmd_len;
	uint16_t ivmd_deviceid;
	uint16_t ivmd_auxdata;
	uint64_t ivmd_resv;
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


/* Global IVINFo fields */
typedef struct amd_iommu_acpi_global {
	uint8_t acg_HtAtsResv;
	uint8_t acg_VAsize;
	uint8_t acg_PAsize;
} amd_iommu_acpi_global_t;

typedef struct amd_iommu_acpi_ivhd {
	int32_t ach_deviceid_start;
	int32_t ach_deviceid_end;

	/* IVHD deventry type */
	ivhd_deventry_type_t ach_dev_type;

	/* IVHD flag fields */
	uint8_t ach_IotlbSup;
	uint8_t ach_Isoc;
	uint8_t ach_ResPassPW;
	uint8_t ach_PassPW;
	uint8_t ach_HtTunEn;

	/* IVHD fields */
	uint16_t ach_IOMMU_deviceid;
	uint16_t ach_IOMMU_cap_off;
	uint64_t ach_IOMMU_reg_base;
	uint16_t ach_IOMMU_pci_seg;

	/* IVHD IOMMU info fields */
	uint8_t ach_IOMMU_UnitID;
	uint8_t ach_IOMMU_MSInum;

	/* IVHD deventry data settings */
	uint8_t ach_Lint1Pass;
	uint8_t ach_Lint0Pass;
	uint8_t ach_SysMgt;
	uint8_t ach_NMIPass;
	uint8_t ach_ExtIntPass;
	uint8_t ach_INITPass;

	/* alias */
	int32_t ach_src_deviceid;

	/* IVHD deventry extended data settings */
	uint8_t ach_AtsDisabled;

	/* IVHD deventry special device */
	uint8_t ach_special_handle;
	uint8_t ach_special_variety;

	struct amd_iommu_acpi_ivhd *ach_next;
} amd_iommu_acpi_ivhd_t;

typedef struct amd_iommu_acpi_ivmd {
	int32_t acm_deviceid_start;
	int32_t acm_deviceid_end;

	/* IVMD type */
	ivmd_deviceid_type_t acm_dev_type;

	/* IVMD flags */
	uint8_t acm_ExclRange;
	uint8_t acm_IW;
	uint8_t acm_IR;
	uint8_t acm_Unity;

	/* IVMD mem block */
	uint64_t acm_ivmd_phys_start;
	uint64_t acm_ivmd_phys_len;

	struct amd_iommu_acpi_ivmd *acm_next;
} amd_iommu_acpi_ivmd_t;

typedef union {
	uint16_t   ent16;
	uint8_t	   ent8[2];
} align_16_t;

typedef union {
	uint32_t   ent32;
	uint8_t	   ent8[4];
} align_32_t;

typedef union {
	ivhd_t *ivhdp;
	char   *cp;
} align_ivhd_t;

typedef union {
	ivmd_t *ivmdp;
	char   *cp;
} align_ivmd_t;

#pragma pack()

int amd_iommu_acpi_init(void);
void amd_iommu_acpi_fini(void);
amd_iommu_acpi_ivhd_t *amd_iommu_lookup_all_ivhd(void);
amd_iommu_acpi_ivmd_t *amd_iommu_lookup_all_ivmd(void);
amd_iommu_acpi_ivhd_t *amd_iommu_lookup_any_ivhd(amd_iommu_t *);
amd_iommu_acpi_ivmd_t *amd_iommu_lookup_any_ivmd(void);
amd_iommu_acpi_global_t *amd_iommu_lookup_acpi_global(void);
amd_iommu_acpi_ivhd_t *amd_iommu_lookup_ivhd(int32_t deviceid);
amd_iommu_acpi_ivmd_t *amd_iommu_lookup_ivmd(int32_t deviceid);
int amd_iommu_acpi_init_devtbl(amd_iommu_t *iommu);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _AMD_IOMMU_ACPI_H */
