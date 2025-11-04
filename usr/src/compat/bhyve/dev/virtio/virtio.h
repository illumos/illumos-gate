/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2025 Oxide Computer Company
 */

#ifndef	_BHYVE_COMPAT_VIRTIO_H_
#define	_BHYVE_COMPAT_VIRTIO_H_

#include <stddef.h>

#define	VIRTIO_PCI_DEVICEID_MODERN_MIN	0x1040

#define VRING_DESC_F_NEXT	(1 << 0)
#define VRING_DESC_F_WRITE	(1 << 1)
#define VRING_DESC_F_INDIRECT	(1 << 2)

struct vring_desc {
	uint64_t	addr;		/* guest physical address */
	uint32_t	len;		/* length of scatter/gather seg */
	uint16_t	flags;		/* VRING_F_DESC_* */
	uint16_t	next;		/* next desc if F_NEXT */
} __packed;

struct vring_used_elem {
	uint32_t	id;		/* head of used descriptor chain */
	uint32_t	len;		/* length written-to */
} __packed;

#define VRING_AVAIL_F_NO_INTERRUPT   1

struct vring_avail {
	uint16_t	flags;		/* VRING_AVAIL_F_* */
	uint16_t	idx;		/* counts to 65535, then cycles */
	uint16_t	ring[];		/* size N, reported in QNUM value */
/*	uint16_t	used_event;	-- after N ring entries */
} __packed;

#define	VRING_USED_F_NO_NOTIFY		1
struct vring_used {
	uint16_t	flags;		/* VRING_USED_F_* */
	uint16_t	idx;		/* counts to 65535, then cycles */
	struct vring_used_elem ring[];	/* size N */
/*	uint16_t	avail_event;	-- after N ring entries */
} __packed;

/*
 * Virtio device types
 */
#define	VIRTIO_ID_NETWORK	1
#define	VIRTIO_ID_BLOCK		2
#define	VIRTIO_ID_CONSOLE	3
#define	VIRTIO_ID_ENTROPY	4
#define	VIRTIO_ID_BALLOON	5
#define	VIRTIO_ID_IOMEMORY	6
#define	VIRTIO_ID_RPMSG		7
#define	VIRTIO_ID_SCSI		8
#define	VIRTIO_ID_9P		9

/* experimental IDs start at 65535 and work down */

/*
 * PCI config space constants.
 *
 * If MSI-X is enabled, the ISR register is generally not used,
 * and the configuration vector and queue vector appear at offsets
 * 20 and 22 with the remaining configuration registers at 24.
 * If MSI-X is not enabled, those two registers disappear and
 * the remaining configuration registers start at offset 20.
 */
#define	VIRTIO_PCI_HOST_FEATURES		0
#define	VIRTIO_PCI_GUEST_FEATURES		4
#define	VIRTIO_PCI_QUEUE_PFN			8
#define	VIRTIO_PCI_QUEUE_NUM			12
#define	VIRTIO_PCI_QUEUE_SEL			14
#define	VIRTIO_PCI_QUEUE_NOTIFY			16
#define	VIRTIO_PCI_STATUS			18
#define	VIRTIO_PCI_ISR				19
#define	VIRTIO_MSI_CONFIG_VECTOR		20
#define	VIRTIO_MSI_QUEUE_VECTOR			22
#define	VIRTIO_PCI_CONFIG_OFF(msix_enabled)	((msix_enabled) ? 24 : 20)

/*
 * Bits in VTCFG_R_STATUS.  Guests need not actually set any of these,
 * but a guest writing 0 to this register means "please reset".
 */
#define	VTCFG_STATUS_ACK	0x01	/* guest OS has acknowledged dev */
#define	VTCFG_STATUS_DRIVER	0x02	/* guest OS driver is loaded */
#define	VTCFG_STATUS_DRIVER_OK	0x04	/* guest OS driver ready */
#define	VTCFG_STATUS_FEAT_OK	0x08	/* driver finished cfg features */
#define	VTCFG_STATUS_NEEDS_RST	0x40	/* device needs reset */
#define	VTCFG_STATUS_FAILED	0x80	/* guest has given up on this dev */

#define	VIRTIO_CONFIG_STATUS_DRIVER_OK	VTCFG_STATUS_DRIVER_OK
#define	VIRTIO_CONFIG_S_FEATURES_OK	VTCFG_STATUS_FEAT_OK

/*
 * Bits in VTCFG_R_ISR.  These apply only if not using MSI-X.
 */
/* The bit of the ISR which indicates a device has an interrupt. */
#define VIRTIO_PCI_ISR_INTR     0x01
/* The bit of the ISR which indicates a device configuration change. */
#define VIRTIO_PCI_ISR_CONFIG   0x02

#define	VIRTIO_MSI_NO_VECTOR	0xFFFF

/*
 * Feature flags.
 * Note: bits 0 through 23 are reserved to each device type.
 */
#define	VIRTIO_F_NOTIFY_ON_EMPTY	(1ULL << 24)
#define	VIRTIO_F_ANY_LAYOUT		(1ULL << 27)
#define	VIRTIO_RING_F_INDIRECT_DESC	(1ULL << 28)
#define	VIRTIO_RING_F_EVENT_IDX		(1ULL << 29)
#define	VIRTIO_F_BAD_FEATURE		(1ULL << 30)
#define	VIRTIO_F_VERSION_1		(1ULL << 32)

static inline int
vring_size(unsigned int num, unsigned long align)
{
        int size;

        size = num * sizeof(struct vring_desc);
        size += sizeof(struct vring_avail) + (num * sizeof(uint16_t)) +
            sizeof(uint16_t);
        size = (size + align - 1) & ~(align - 1);
        size += sizeof(struct vring_used) +
            (num * sizeof(struct vring_used_elem)) + sizeof(uint16_t);
        return (size);
}

#define VIRTIO_PCI_CAP_COMMON_CFG	1
#define VIRTIO_PCI_CAP_NOTIFY_CFG	2
#define VIRTIO_PCI_CAP_ISR_CFG		3
#define VIRTIO_PCI_CAP_DEVICE_CFG	4
#define VIRTIO_PCI_CAP_PCI_CFG		5
#define	VIRTIO_PCI_CAP_MAX		VIRTIO_PCI_CAP_PCI_CFG

/*
 * Alignment requirements for the BAR regions pointed to by each capability.
 * Note that some have multiple alignment requirements based on negotiated
 * features and for those we choose the larger value. There are no alignment
 * requirements for VIRTIO_PCI_CAP_PCI_CFG as it does not point to a fixed BAR
 * area.
 */
#define VIRTIO_PCI_CAP_COMMON_CFG_ALIGN		4
#define VIRTIO_PCI_CAP_NOTIFY_CFG_ALIGN		4
#define VIRTIO_PCI_CAP_ISR_CFG_ALIGN		1
#define VIRTIO_PCI_CAP_DEVICE_CFG_ALIGN		4


/* This is the PCI capability header: */
typedef struct virtio_pci_cap {
	uint8_t cap_vndr;
	uint8_t cap_next;
	uint8_t cap_len;
	uint8_t cfg_type;
	uint8_t bar;
	uint8_t id;
	uint8_t padding[2];
	uint32_t offset;
	uint32_t length;
} virtio_pci_cap_t;

typedef struct virtio_pci_notify_cap {
	struct virtio_pci_cap cap;
	uint32_t notify_off_multiplier;
} virtio_pci_notify_cap_t;

/* Fields in VIRTIO_PCI_CAP_COMMON_CFG: */
typedef struct virtio_pci_common_cfg {
	/* About the whole device. */
	uint32_t device_feature_select;	/* read-write */
	uint32_t device_feature;	/* read-only */
	uint32_t driver_feature_select;	/* read-write */
	uint32_t driver_feature;	/* read-write */
	uint16_t msix_config;		/* read-write */
	uint16_t num_queues;		/* read-only */
	uint8_t device_status;		/* read-write */
	uint8_t config_generation;	/* read-only */

	/* About a specific virtqueue. */
	uint16_t queue_select;		/* read-write */
	uint16_t queue_size;		/* read-write */
	uint16_t queue_msix_vector;	/* read-write */
	uint16_t queue_enable;		/* read-write */
	uint16_t queue_notify_off;	/* read-only */
	uint32_t queue_desc_lo;		/* read-write */
	uint32_t queue_desc_hi;		/* read-write */
	uint32_t queue_avail_lo;	/* read-write */
	uint32_t queue_avail_hi;	/* read-write */
	uint32_t queue_used_lo;		/* read-write */
	uint32_t queue_used_hi;		/* read-write */
} virtio_pci_common_cfg_t;

/* Fields in VIRTIO_PCI_CAP_PCI_CFG: */
typedef struct virtio_pci_cfg_cap {
	struct virtio_pci_cap cap;
	uint8_t pci_cfg_data[4]; /* Data for BAR access. */
} virtio_pci_cfg_cap_t;

/* Macro versions of offsets */

#define __VPCO(x) offsetof(virtio_pci_cap_t, x)
#define VIRTIO_PCI_CAP_VNDR		__VPCO(cap_vndr)
#define VIRTIO_PCI_CAP_NEXT		__VPCO(cap_next)
#define VIRTIO_PCI_CAP_LEN		__VPCO(cap_len)
#define VIRTIO_PCI_CAP_CFG_TYPE		__VPCO(cfg_type)
#define VIRTIO_PCI_CAP_BAR		__VPCO(bar)
#define VIRTIO_PCI_CAP_ID		__VPCO(id)
#define VIRTIO_PCI_CAP_OFFSET		__VPCO(offset)
#define VIRTIO_PCI_CAP_LENGTH		__VPCO(length)

#define V__VPNCO(x) offsetof(virtio_pci_notify_cap_t, x)
#define VIRTIO_PCI_NOTIFY_CAP_MULT	V__VPNCO(notify_off_multiplier)

#define __VPCCO(x) offsetof(virtio_pci_common_cfg_t, x)
#define VIRTIO_PCI_COMMON_DFSELECT	__VPCCO(device_feature_select)
#define VIRTIO_PCI_COMMON_DF		__VPCCO(device_feature)
#define VIRTIO_PCI_COMMON_GFSELECT	__VPCCO(driver_feature_select)
#define VIRTIO_PCI_COMMON_GF		__VPCCO(driver_feature)
#define VIRTIO_PCI_COMMON_MSIX		__VPCCO(msix_config)
#define VIRTIO_PCI_COMMON_NUMQ		__VPCCO(num_queues)
#define VIRTIO_PCI_COMMON_STATUS	__VPCCO(device_status)
#define VIRTIO_PCI_COMMON_CFGGENERATION	__VPCCO(config_generation)
#define VIRTIO_PCI_COMMON_Q_SELECT	__VPCCO(queue_select)
#define VIRTIO_PCI_COMMON_Q_SIZE	__VPCCO(queue_size)
#define VIRTIO_PCI_COMMON_Q_MSIX	__VPCCO(queue_msix_vector)
#define VIRTIO_PCI_COMMON_Q_ENABLE	__VPCCO(queue_enable)
#define VIRTIO_PCI_COMMON_Q_NOFF	__VPCCO(queue_notify_off)
#define VIRTIO_PCI_COMMON_Q_DESCLO	__VPCCO(queue_desc_lo)
#define VIRTIO_PCI_COMMON_Q_DESCHI	__VPCCO(queue_desc_hi)
#define VIRTIO_PCI_COMMON_Q_AVAILLO	__VPCCO(queue_avail_lo)
#define VIRTIO_PCI_COMMON_Q_AVAILHI	__VPCCO(queue_avail_hi)
#define VIRTIO_PCI_COMMON_Q_USEDLO	__VPCCO(queue_used_lo)
#define VIRTIO_PCI_COMMON_Q_USEDHI	__VPCCO(queue_used_hi)

#endif	/* _BHYVE_COMPAT_VIRTIO_H_ */
