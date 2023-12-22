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

#ifndef	_BHYVE_COMPAT_VIRTIO_H_
#define	_BHYVE_COMPAT_VIRTIO_H_

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
#define	VTCFG_STATUS_FAILED	0x80	/* guest has given up on this dev */

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
#define	VIRTIO_F_NOTIFY_ON_EMPTY	(1 << 24)
#define	VIRTIO_RING_F_INDIRECT_DESC	(1 << 28)
#define	VIRTIO_RING_F_EVENT_IDX		(1 << 29)

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

#endif	/* _BHYVE_COMPAT_VIRTIO_H_ */
