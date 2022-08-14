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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * VIRTIO 9P DRIVER
 */

#ifndef _VIO9P_IMPL_H
#define	_VIO9P_IMPL_H

#include "virtio.h"
#include <sys/vio9p.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * VIRTIO 9P CONFIGURATION REGISTERS
 *
 * These are offsets into the device-specific configuration space available
 * through the virtio_dev_*() family of functions.
 */
#define	VIRTIO_9P_CONFIG_TAG_SZ			0x00	/* 16 R   */
#define	VIRTIO_9P_CONFIG_TAG			0x02	/* SZ R   */

/*
 * VIRTIO 9P VIRTQUEUES
 *
 * Virtio 9P devices have just one queue which is used to make 9P requests.
 * Each submitted chain should include appropriately sized inbound and outbound
 * descriptors for the request and response messages.  The maximum size is
 * negotiated via the "msize" member of the 9P TVERSION request and RVERSION
 * response.  Some hypervisors may require the first 7 bytes (size, type, tag)
 * to be contiguous in the first descriptor.
 */
#define	VIRTIO_9P_VIRTQ_REQUESTS	0

/*
 * VIRTIO 9P FEATURE BITS
 */
#define	VIRTIO_9P_F_MOUNT_TAG		(1ULL << 0)

/*
 * These features are supported by the driver and we will request them from the
 * device.
 */
#define	VIRTIO_9P_WANTED_FEATURES	(VIRTIO_9P_F_MOUNT_TAG)

/*
 * DRIVER PARAMETERS
 */
#define	VIRTIO_9P_MAX_REQS		16
#define	VIRTIO_9P_REQ_SIZE		8192

/*
 * It is not clear that there is a well-defined number of cookies for this
 * interface; QEMU may support as many as there are direct descriptors in the
 * ring, and bhyve may support something like 128.  We'll use a conservative
 * number that's large enough to ensure we'll be able to allocate without
 * requiring contiguous pages.
 */
#define	VIRTIO_9P_MAX_SGL		8

/*
 * TYPE DEFINITIONS
 */

typedef enum vio9p_teardown_style {
	VIRTIO_9P_TEARDOWN_PRE_MUTEX,
	VIRTIO_9P_TEARDOWN_ATTACH,
	VIRTIO_9P_TEARDOWN_DETACH,
} vio9p_teardown_style_t;

typedef struct vio9p_req {
	virtio_dma_t			*vnr_dma_in;
	virtio_dma_t			*vnr_dma_out;
	virtio_chain_t			*vnr_chain;
	list_node_t			vnr_link;
	list_node_t			vnr_link_complete;
	list_node_t			vnr_link_free;
	uint64_t			vnr_generation;
} vio9p_req_t;

typedef struct vio9p {
	dev_info_t			*vin_dip;
	virtio_t			*vin_virtio;
	virtio_queue_t			*vin_vq;

	kmutex_t			vin_mutex;
	kcondvar_t			vin_cv;

	/*
	 * When the device is opened, select a generation number.  This will be
	 * used to discard completed responses that arrive after the device was
	 * closed and reopened.
	 */
	uint64_t			vin_generation;
	bool				vin_open;

	uint_t				vin_nreqs;
	list_t				vin_reqs;
	list_t				vin_completes;

	list_t				vin_req_freelist;

	char				vin_tag[VIO9P_MOUNT_TAG_SIZE];
} vio9p_t;

#ifdef __cplusplus
}
#endif

#endif /* _VIO9P_IMPL_H */
