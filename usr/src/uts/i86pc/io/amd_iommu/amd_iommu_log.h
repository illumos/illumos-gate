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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AMD_IOMMU_LOG_H
#define	_AMD_IOMMU_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/amd_iommu.h>

#ifdef _KERNEL

#define	EV2OFF(e)	((e) << 4)
#define	OFF2EV(o)	((o) >> 4)

typedef enum {
	AMD_IOMMU_EVENT_INVALID = 0,
	AMD_IOMMU_EVENT_DEVTAB_ILLEGAL_ENTRY = 1,
	AMD_IOMMU_EVENT_IO_PAGE_FAULT = 2,
	AMD_IOMMU_EVENT_DEVTAB_HW_ERROR = 3,
	AMD_IOMMU_EVENT_PGTABLE_HW_ERROR = 4,
	AMD_IOMMU_EVENT_CMDBUF_ILLEGAL_CMD = 5,
	AMD_IOMMU_EVENT_CMDBUF_HW_ERROR = 6,
	AMD_IOMMU_EVENT_IOTLB_INVAL_TO = 7,
	AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ = 8
} amd_iommu_event_t;

/* Common to all events */
#define	AMD_IOMMU_EVENT_TYPE			(31 << 16 | 28)

/* Illegal device Table Entry Event bits */
#define	AMD_IOMMU_EVENT_DEVTAB_ILL_DEVICEID	(15 << 16 | 0)
#define	AMD_IOMMU_EVENT_DEVTAB_ILL_TR		(24 << 16 | 24)
#define	AMD_IOMMU_EVENT_DEVTAB_ILL_RZ		(23 << 16 | 23)
#define	AMD_IOMMU_EVENT_DEVTAB_ILL_RW		(21 << 16 | 21)
#define	AMD_IOMMU_EVENT_DEVTAB_ILL_INTR		(19 << 16 | 19)
#define	AMD_IOMMU_EVENT_DEVTAB_ILL_VADDR_LO	(31 << 16 | 2)

/* IO Page Fault event bits */
#define	AMD_IOMMU_EVENT_IO_PGFAULT_DEVICEID	(15 << 16 | 0)
#define	AMD_IOMMU_EVENT_IO_PGFAULT_TR		(24 << 16 | 24)
#define	AMD_IOMMU_EVENT_IO_PGFAULT_RZ		(23 << 16 | 23)
#define	AMD_IOMMU_EVENT_IO_PGFAULT_PE		(22 << 16 | 22)
#define	AMD_IOMMU_EVENT_IO_PGFAULT_RW		(21 << 16 | 21)
#define	AMD_IOMMU_EVENT_IO_PGFAULT_PR		(20 << 16 | 20)
#define	AMD_IOMMU_EVENT_IO_PGFAULT_INTR		(19 << 16 | 19)
#define	AMD_IOMMU_EVENT_IO_PGFAULT_DOMAINID	(15 << 16 | 0)


/* Device Table HW Error event bits */
#define	AMD_IOMMU_EVENT_DEVTAB_HWERR_DEVICEID	(15 << 16 | 0)
#define	AMD_IOMMU_EVENT_DEVTAB_HWERR_TYPE	(26 << 16 | 25)
#define	AMD_IOMMU_EVENT_DEVTAB_HWERR_TR		(24 << 16 | 24)
#define	AMD_IOMMU_EVENT_DEVTAB_HWERR_RW		(21 << 16 | 21)
#define	AMD_IOMMU_EVENT_DEVTAB_HWERR_INTR	(19 << 16 | 19)
#define	AMD_IOMMU_EVENT_DEVTAB_HWERR_PHYSADDR_LO	(31 << 16 | 4)


/* Page Table HW Error event bits */
#define	AMD_IOMMU_EVENT_PGTABLE_HWERR_DEVICEID	(15 << 16 | 0)
#define	AMD_IOMMU_EVENT_DEVTAB_HWERR_TYPE	(26 << 16 | 25)
#define	AMD_IOMMU_EVENT_PGTABLE_HWERR_TR	(24 << 16 | 24)
#define	AMD_IOMMU_EVENT_PGTABLE_HWERR_RW	(21 << 16 | 21)
#define	AMD_IOMMU_EVENT_PGTABLE_HWERR_INTR	(19 << 16 | 19)
#define	AMD_IOMMU_EVENT_PGTABLE_HWERR_DOMAINID  (15 << 16 | 0)
#define	AMD_IOMMU_EVENT_PGTABLE_HWERR_PHYSADDR_LO	(31 << 16 | 3)

/* Illegal Command Error event bits */
#define	AMD_IOMMU_EVENT_CMDBUF_ILLEGAL_CMD_PHYS_LO	(31 << 16 | 4)

/* Command Buffer HW Error event bits */
#define	AMD_IOMMU_EVENT_CMDBUF_HWERR_TYPE	(26 << 16 | 25)
#define	AMD_IOMMU_EVENT_CMDBUF_HWERR_PHYS_LO	(31 << 16 | 4)


/* IOTLB Invalidation TO event bits */
#define	AMD_IOMMU_EVENT_IOTLB_INVAL_TO_DEVICEID	(15 << 16 | 0)
#define	AMD_IOMMU_EVENT_IOTLB_INVAL_TO_TYPE	(26 << 16 | 25)
#define	AMD_IOMMU_EVENT_IOTLB_INVAL_TO_PHYS_LO	(31 << 16 | 4)

/* Illegal Device request event bits */
#define	AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ_DEVICEID	(15 << 16 | 0)
#define	AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ_TYPE		(27 << 16 | 25)
#define	AMD_IOMMU_EVENT_DEVICE_ILLEGAL_REQ_TR		(24 << 16 | 24)

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _AMD_IOMMU_LOG_H */
