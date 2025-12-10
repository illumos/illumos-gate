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

#ifndef _VIRTIO_IMPL_H
#define	_VIRTIO_IMPL_H

/*
 * VIRTIO FRAMEWORK: FRAMEWORK-PRIVATE DEFINITIONS
 *
 * For design and usage documentation, see the comments in "virtio.h".
 *
 * NOTE: Client drivers should not use definitions from this file.
 */

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/list.h>
#include <sys/ccompile.h>
#include <sys/stdbool.h>

#include "virtio.h"
#include "virtio_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

extern ddi_device_acc_attr_t virtio_acc_attr;
extern ddi_dma_attr_t virtio_dma_attr;

extern void virtio_acquireq(virtio_t *, uint16_t);
extern void virtio_releaseq(virtio_t *);

int virtio_dma_init(virtio_t *, virtio_dma_t *, size_t, const ddi_dma_attr_t *,
    int, int);
void virtio_dma_fini(virtio_dma_t *);

typedef enum virtio_dma_level {
	VIRTIO_DMALEVEL_HANDLE_ALLOC =	(1ULL << 0),
	VIRTIO_DMALEVEL_MEMORY_ALLOC =	(1ULL << 1),
	VIRTIO_DMALEVEL_HANDLE_BOUND =	(1ULL << 2),
	VIRTIO_DMALEVEL_COOKIE_ARRAY =	(1ULL << 3),
} virtio_dma_level_t;

struct virtio_dma {
	virtio_dma_level_t		vidma_level;
	virtio_t			*vidma_virtio;
	caddr_t				vidma_va;
	size_t				vidma_size;
	size_t				vidma_real_size;
	ddi_dma_handle_t		vidma_dma_handle;
	ddi_acc_handle_t		vidma_acc_handle;
	uint_t				vidma_dma_ncookies;
	ddi_dma_cookie_t		*vidma_dma_cookies;
};

typedef enum virtio_initlevel {
	VIRTIO_INITLEVEL_REGS =		(1ULL << 0),
	VIRTIO_INITLEVEL_PROVIDER =	(1ULL << 1),
	VIRTIO_INITLEVEL_INT_ALLOC =	(1ULL << 2),
	VIRTIO_INITLEVEL_INT_ADDED =	(1ULL << 3),
	VIRTIO_INITLEVEL_INT_ENABLED =	(1ULL << 4),
	VIRTIO_INITLEVEL_SHUTDOWN =	(1ULL << 5),
} virtio_initlevel_t;

typedef struct virtio_pci_cap {
	virtio_pci_cap_type_t		vpc_type;
	uint8_t				vpc_baridx;
	uint64_t			vpc_offset;
	uint64_t			vpc_size;

	ddi_acc_handle_t		vpc_barh;
	caddr_t				vpc_bar;
} virtio_pci_cap_t;

typedef enum virtio_mode {
	VIRTIO_MODE_LEGACY		= 1,	/* A pure "legacy" device */
	VIRTIO_MODE_TRANSITIONAL	= 2,	/* A "transitional" device */
	VIRTIO_MODE_MODERN		= 3,	/* A pure "modern" device */
} virtio_mode_t;

typedef struct virtio_ops {
	uint64_t	(*vop_device_get_features)(virtio_t *);
	bool		(*vop_device_set_features)(virtio_t *, uint64_t);
	void		(*vop_set_status_locked)(virtio_t *, uint8_t);
	uint8_t		(*vop_get_status)(virtio_t *);
	void		(*vop_device_reset_locked)(virtio_t *);
	uint8_t		(*vop_isr_status)(virtio_t *);
	void		(*vop_msix_config_set)(virtio_t *, uint16_t);
	uint16_t	(*vop_msix_config_get)(virtio_t *);
	void		(*vop_queue_notify)(virtio_queue_t *);

	void		(*vop_queue_select)(virtio_t *, uint16_t);
	uint16_t	(*vop_queue_size_get)(virtio_t *, uint16_t);
	void		(*vop_queue_size_set)(virtio_t *, uint16_t, uint16_t);
	uint64_t	(*vop_queue_noff_get)(virtio_t *, uint16_t);
	bool		(*vop_queue_enable_get)(virtio_t *, uint16_t);
	void		(*vop_queue_enable_set)(virtio_t *, uint16_t, bool);
	void		(*vop_queue_addr_set)(virtio_t *, uint16_t, uint64_t,
			    uint64_t, uint64_t);
	void		(*vop_msix_queue_set)(virtio_t *, uint16_t, uint16_t);
	uint16_t	(*vop_msix_queue_get)(virtio_t *, uint16_t);

	uint8_t		(*vop_device_cfg_gen)(virtio_t *);
	uint8_t		(*vop_device_cfg_get8)(virtio_t *, uintptr_t);
	uint16_t	(*vop_device_cfg_get16)(virtio_t *, uintptr_t);
	uint32_t	(*vop_device_cfg_get32)(virtio_t *, uintptr_t);
	uint64_t	(*vop_device_cfg_get64)(virtio_t *, uintptr_t);
	void		(*vop_device_cfg_put8)(virtio_t *, uintptr_t, uint8_t);
	void		(*vop_device_cfg_put16)(virtio_t *, uintptr_t,
			    uint16_t);
	void		(*vop_device_cfg_put32)(virtio_t *, uintptr_t,
			    uint32_t);
} virtio_ops_t;

extern virtio_ops_t virtio_legacy_ops, virtio_modern_ops;

struct virtio {
	dev_info_t			*vio_dip;

	kmutex_t			vio_mutex;

	virtio_initlevel_t		vio_initlevel;

	virtio_mode_t			vio_mode;
	virtio_ops_t			*vio_ops;

	list_t				vio_queues;
	kmutex_t			vio_qlock;
	uint16_t			vio_qcur;

	virtio_pci_cap_t		vio_cap_common;
	virtio_pci_cap_t		vio_cap_notify;
	virtio_pci_cap_t		vio_cap_isr;
	virtio_pci_cap_t		vio_cap_device;

	/* Notification multiplier used with the modern interface */
	uint32_t			vio_multiplier;

	ddi_acc_handle_t		vio_barh;
	caddr_t				vio_bar;
	uint_t				vio_legacy_cfg_offset;

	uint64_t			vio_features;
	uint64_t			vio_features_device;

	ddi_intr_handle_t		*vio_interrupts;
	int				vio_ninterrupts;
	int				vio_interrupt_type;
	int				vio_interrupt_cap;
	uint_t				vio_interrupt_priority;

	ddi_intr_handler_t		*vio_cfgchange_handler;
	void				*vio_cfgchange_handlerarg;
	boolean_t			vio_cfgchange_handler_added;
	uint_t				vio_cfgchange_handler_index;
};

struct virtio_queue {
	virtio_t			*viq_virtio;
	kmutex_t			viq_mutex;
	const char			*viq_name;
	list_node_t			viq_link;

	boolean_t			viq_shutdown;
	boolean_t			viq_indirect;
	uint_t				viq_max_segs;

	/*
	 * Each Virtio device type has some set of queues for data transfer to
	 * and from the host.  This index is described in the specification for
	 * the particular device and queue type, and written to QUEUE_SELECT to
	 * allow interaction with the queue.  For example, a network device has
	 * at least a receive queue with index 0, and a transmit queue with
	 * index 1.
	 */
	uint16_t			viq_index;

	/*
	 * Modern devices use a BAR region for notifications with each queue
	 * potentially having its own offset within that region. We store the
	 * offset for this queue here.
	 */
	uint64_t			viq_noff;

	/*
	 * For legacy Virtio devices, the size and shape of the queue is
	 * determined entirely by the number of queue entries.
	 */
	uint16_t			viq_size;
	id_space_t			*viq_descmap;

	/*
	 * The memory shared between the device and the driver is allocated as
	 * a large phyisically contiguous chunk.  Access to this area is
	 * through three pointers to packed structures.
	 */
	virtio_dma_t			viq_dma;
	virtio_vq_desc_t		*viq_dma_descs;
	virtio_vq_driver_t		*viq_dma_driver;
	virtio_vq_device_t		*viq_dma_device;

	uint16_t			viq_device_index;
	uint16_t			viq_driver_index;

	/*
	 * Interrupt handler function, or NULL if not provided.
	 */
	ddi_intr_handler_t		*viq_func;
	void				*viq_funcarg;
	boolean_t			viq_handler_added;
	uint_t				viq_handler_index;

	/*
	 * When a chain is submitted to the queue, it is also stored in this
	 * AVL tree keyed by the index of the first descriptor in the chain.
	 */
	avl_tree_t			viq_inflight;
};

struct virtio_chain {
	virtio_queue_t			*vic_vq;
	avl_node_t			vic_node;

	void				*vic_data;

	uint16_t			vic_head;
	uint32_t			vic_received_length;

	virtio_dma_t			vic_indirect_dma;
	uint_t				vic_indirect_capacity;
	uint_t				vic_indirect_used;

	uint_t				vic_direct_capacity;
	uint_t				vic_direct_used;
	uint16_t			vic_direct[];
};

/*
 * When laying out queues for use over the modern interface we choose to align
 * all queue components using the most restrictive alignment requirement, that
 * of the descriptor part of the ring.
 */
#define	MODERN_VQ_ALIGN			MODERN_VQ_ALIGN_DESC

/*
 * DMA SYNCHRONISATION WRAPPERS
 */

/*
 * Synchronise the driver-owned portion of the queue so that the device can see
 * our writes.  This covers the memory accessed via the "viq_dma_descs" and
 * "viq_dma_driver" members.
 */
#define	VIRTQ_DMA_SYNC_FORDEV(viq)	VERIFY0(ddi_dma_sync( \
					    (viq)->viq_dma.vidma_dma_handle, \
					    0, \
					    (uintptr_t)(viq)->viq_dma_device - \
					    (uintptr_t)(viq)->viq_dma_descs, \
					    DDI_DMA_SYNC_FORDEV))

/*
 * Synchronise the device-owned portion of the queue so that we can see any
 * writes from the device.  This covers the memory accessed via the
 * "viq_dma_device" member.
 */
#define	VIRTQ_DMA_SYNC_FORKERNEL(viq)	VERIFY0(ddi_dma_sync( \
					    (viq)->viq_dma.vidma_dma_handle, \
					    (uintptr_t)(viq)->viq_dma_device - \
					    (uintptr_t)(viq)->viq_dma_descs, \
					    (viq)->viq_dma.vidma_size - \
					    (uintptr_t)(viq)->viq_dma_device - \
					    (uintptr_t)(viq)->viq_dma_descs, \
					    DDI_DMA_SYNC_FORKERNEL))

#ifdef __cplusplus
}
#endif

#endif /* _VIRTIO_IMPL_H */
