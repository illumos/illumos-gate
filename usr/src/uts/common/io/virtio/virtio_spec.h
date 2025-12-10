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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _VIRTIO_SPEC_H
#define	_VIRTIO_SPEC_H

/*
 * VIRTIO FRAMEWORK: DEFINITIONS from the VirtIO specification
 *
 * For design and usage documentation, see the comments in "virtio.h".
 *
 * NOTE: Client drivers should not use definitions from this file.
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/list.h>
#include <sys/ccompile.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct virtio_vq_desc virtio_vq_desc_t;
typedef struct virtio_vq_driver virtio_vq_driver_t;
typedef struct virtio_vq_device virtio_vq_device_t;
typedef struct virtio_vq_elem virtio_vq_elem_t;

#define	VIRTIO_MIN_MODERN_DEVID		0x1040

/*
 * PCI capability types as defined by the specification.
 */
typedef enum virtio_pci_cap_type {
	VPC_COMMON_CFG =		1,
	VPC_NOTIFY_CFG =		2,
	VPC_ISR_CFG =			3,
	VPC_DEVICE_CFG =		4,
	VPC_PCI_CFG =			5,
} virtio_pci_cap_type_t;

/*
 * PACKED STRUCTS FOR DEVICE ACCESS
 */

struct virtio_vq_desc {
	/*
	 * Buffer physical address and length.
	 */
	uint64_t			vqd_addr;
	uint32_t			vqd_len;

	/*
	 * Flags.  Use with the VIRTQ_DESC_F_* family of constants.  See below.
	 */
	uint16_t			vqd_flags;

	/*
	 * If VIRTQ_DESC_F_NEXT is set in flags, this refers to the next
	 * descriptor in the chain by table index.
	 */
	uint16_t			vqd_next;
} __packed;

/*
 * VIRTIO DESCRIPTOR FLAGS (vqd_flags)
 */

/*
 * NEXT:
 *	Signals that this descriptor (direct or indirect) is part of a chain.
 *	If populated, "vqd_next" names the next descriptor in the chain by its
 *	table index.
 */
#define	VIRTQ_DESC_F_NEXT		(1 << 0)

/*
 * WRITE:
 *	Determines whether this buffer is to be written by the device (WRITE is
 *	set) or by the driver (WRITE is not set).
 */
#define	VIRTQ_DESC_F_WRITE		(1 << 1)

/*
 * INDIRECT:
 *	This bit signals that a direct descriptor refers to an indirect
 *	descriptor list, rather than directly to a buffer.  This bit may only
 *	be used in a direct descriptor; indirect descriptors are not allowed to
 *	refer to additional layers of indirect tables.  If this bit is set,
 *	NEXT must be clear; indirect descriptors may not be chained.
 */
#define	VIRTQ_DESC_F_INDIRECT		(1 << 2)

/*
 * This structure is variously known as the "available" or "avail" ring, or the
 * driver-owned portion of the queue structure.  It is used by the driver to
 * submit descriptor chains to the device.
 */
struct virtio_vq_driver {
	uint16_t			vqdr_flags;
	uint16_t			vqdr_index;
	uint16_t			vqdr_ring[];
} __packed;

#define	VIRTQ_AVAIL_F_NO_INTERRUPT	(1 << 0)

/*
 * We use the sizeof operator on this packed struct to calculate the offset of
 * subsequent structs.  Ensure the compiler is not adding any padding to the
 * end of the struct.
 */
CTASSERT(sizeof (virtio_vq_driver_t) ==
    offsetof(virtio_vq_driver_t, vqdr_ring));

struct virtio_vq_elem {
	/*
	 * The device returns chains of descriptors by specifying the table
	 * index of the first descriptor in the chain.
	 */
	uint32_t			vqe_start;
	uint32_t			vqe_len;
} __packed;

/*
 * This structure is variously known as the "used" ring, or the device-owned
 * portion of the queue structure.  It is used by the device to return
 * completed descriptor chains to the driver.
 */
struct virtio_vq_device {
	uint16_t			vqde_flags;
	uint16_t			vqde_index;
	virtio_vq_elem_t		vqde_ring[];
} __packed;

#define	VIRTQ_USED_F_NO_NOTIFY		(1 << 0)

/*
 * BASIC CONFIGURATION
 *
 * Legacy devices expose both their generic and their device-specific
 * configuration through PCI BAR0.
 */
#define	VIRTIO_LEGACY_BAR		0

/*
 * These are offsets into the base configuration space available through the
 * virtio_lget*() and virtio_lput*() family of functions.  These offsets are for
 * what the specification describes as the "legacy" mode of device operation.
 */
#define	VIRTIO_LEGACY_FEATURES_DEVICE	0x00	/* 32 R   */
#define	VIRTIO_LEGACY_FEATURES_DRIVER	0x04	/* 32 R/W */
#define	VIRTIO_LEGACY_QUEUE_ADDRESS	0x08	/* 32 R/W */
#define	VIRTIO_LEGACY_QUEUE_SIZE	0x0C	/* 16 R   */
#define	VIRTIO_LEGACY_QUEUE_SELECT	0x0E	/* 16 R/W */
#define	VIRTIO_LEGACY_QUEUE_NOTIFY	0x10	/* 16 R/W */
#define	VIRTIO_LEGACY_DEVICE_STATUS	0x12	/* 8  R/W */
#define	VIRTIO_LEGACY_ISR_STATUS	0x13	/* 8  R   */

#define	VIRTIO_LEGACY_MSIX_CONFIG	0x14	/* 16 R/W */
#define	VIRTIO_LEGACY_MSIX_QUEUE	0x16	/* 16 R/W */

#define	VIRTIO_LEGACY_CFG_OFFSET	(VIRTIO_LEGACY_ISR_STATUS + 1)
#define	VIRTIO_LEGACY_CFG_OFFSET_MSIX	(VIRTIO_LEGACY_MSIX_QUEUE + 2)

#define	VIRTIO_LEGACY_MSI_NO_VECTOR	0xFFFF

/*
 * These are offsets into the common configuration space available through the
 * virtio_cmnget*() and virtio_cmnput*() family of functions. These offsets are
 * for what the specification describes as the "modern" mode of device
 * operation.
 */
#define	VIRTIO_MODERN_COMMON_DFSELECT		0x00	/* 32 R/W */
#define	VIRTIO_MODERN_COMMON_DF			0x04	/* 32 R   */
#define	VIRTIO_MODERN_COMMON_GFSELECT		0x08	/* 32 R/W */
#define	VIRTIO_MODERN_COMMON_GF			0x0C	/* 32 R/W */
#define	VIRTIO_MODERN_COMMON_MSIX		0x10	/* 16 R/W */
#define	VIRTIO_MODERN_COMMON_NUMQ		0x12	/* 16 R   */
#define	VIRTIO_MODERN_COMMON_STATUS		0x14	/* 8  R/W */
#define	VIRTIO_MODERN_COMMON_CFGGENERATION	0x15	/* 8  R   */
#define	VIRTIO_MODERN_COMMON_Q_SELECT		0x16	/* 16 R/W */
#define	VIRTIO_MODERN_COMMON_Q_SIZE		0x18	/* 16 R/W */
#define	VIRTIO_MODERN_COMMON_Q_MSIX		0x1a	/* 16 R/W */
#define	VIRTIO_MODERN_COMMON_Q_ENABLE		0x1c	/* 16 R/W */
#define	VIRTIO_MODERN_COMMON_Q_NOFF		0x1e	/* 16 R   */
#define	VIRTIO_MODERN_COMMON_Q_DESCLO		0x20	/* 32 R/W */
#define	VIRTIO_MODERN_COMMON_Q_DESCHI		0x24	/* 32 R/W */
#define	VIRTIO_MODERN_COMMON_Q_AVAILLO		0x28	/* 32 R/W */
#define	VIRTIO_MODERN_COMMON_Q_AVAILHI		0x2c	/* 32 R/W */
#define	VIRTIO_MODERN_COMMON_Q_USEDLO		0x30	/* 32 R/W */
#define	VIRTIO_MODERN_COMMON_Q_USEDHI		0x34	/* 32 R/W */

/*
 * Offsets into a VirtIO PCI capability:
 */
#define	VIRTIO_PCI_CAP_LEN		2	/* 8  R   */
#define	VIRTIO_PCI_CAP_TYPE		3	/* 8  R   */
#define	VIRTIO_PCI_CAP_BAR		4	/* 8  R   */
#define	VIRTIO_PCI_CAP_ID		5	/* 32 R   */
#define	VIRTIO_PCI_CAP_BAROFF		8	/* 32 R   */
#define	VIRTIO_PCI_CAP_BARLEN		12	/* 32 R   */
#define	VIRTIO_PCI_CAP_MULTIPLIER	16	/* 32 R  ; NOTIFY CFG ONLY */

/*
 * Bits in the Device Status byte:
 */
#define	VIRTIO_STATUS_RESET		0
#define	VIRTIO_STATUS_ACKNOWLEDGE	(1 << 0)
#define	VIRTIO_STATUS_DRIVER		(1 << 1)
#define	VIRTIO_STATUS_DRIVER_OK		(1 << 2)
#define	VIRTIO_STATUS_FEAT_OK		(1 << 3)
#define	VIRTIO_STATUS_DEV_NEEDS_RESET	(1 << 6)
#define	VIRTIO_STATUS_FAILED		(1 << 7)

/*
 * Bits in the Interrupt Service Routine Status byte:
 */
#define	VIRTIO_ISR_CHECK_QUEUES		(1 << 0)
#define	VIRTIO_ISR_CHECK_CONFIG		(1 << 1)

/*
 * Bits in the Features fields:
 */
#define	VIRTIO_F_ANY_LAYOUT		(1ULL << 27)	/* Legacy only */
#define	VIRTIO_F_RING_INDIRECT_DESC	(1ULL << 28)
#define	VIRTIO_F_VERSION_1		(1ULL << 32)

/*
 * For devices operating in the legacy mode, virtqueues must be aligned on a
 * "page size" of 4096 bytes; this is also called the "Queue Align" value in
 * newer versions of the specification.
 */
#define	VIRTIO_PAGE_SHIFT		12
#define	VIRTIO_PAGE_SIZE		(1 << VIRTIO_PAGE_SHIFT)
CTASSERT(VIRTIO_PAGE_SIZE == 4096);
CTASSERT(ISP2(VIRTIO_PAGE_SIZE));

/*
 * For devices operating via the modern interface, the virtqueue layout is more
 * flexible with each component having different alignment requirements.
 */
#define	MODERN_VQ_ALIGN_DESC		16
#define	MODERN_VQ_ALIGN_DRIVER		2
#define	MODERN_VQ_ALIGN_DEVICE		4

#ifdef __cplusplus
}
#endif

#endif /* _VIRTIO_SPEC_H */
