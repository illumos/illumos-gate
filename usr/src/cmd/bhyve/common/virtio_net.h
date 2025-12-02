/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _VIRTIO_NET_H_
#define	_VIRTIO_NET_H_

#include "mevent.h"
#include "net_backends.h"

/*
 * This structure appears at the start of each control virtqueue request.
 */
typedef struct virtio_net_ctrl_hdr {
	uint8_t		vnch_class;
	uint8_t		vnch_command;
} __packed virtio_net_ctrl_hdr_t;

/*
 * This structure is used for the mac address tables associated with the
 * VIRTIO_NET_CTRL_MAC class.
 */
typedef struct virtio_net_ctrl_mac {
	uint32_t	vncm_entries;
	ether_addr_t	vncm_mac;
} __packed virtio_net_ctrl_mac_t;

/*
 * This structure is used to pass the number of queues.
 */
typedef struct virtio_net_ctrl_mq {
	uint16_t virtqueue_pairs;
} __packed virtio_net_ctrl_mq_t;

/*
 * Control Queue Classes
 */
#define	VIRTIO_NET_CTRL_RX		0
#define	VIRTIO_NET_CTRL_MAC		1
#define	VIRTIO_NET_CTRL_VLAN		2
#define	VIRTIO_NET_CTRL_ANNOUNCE	3
#define	VIRTIO_NET_CTRL_MQ		4

/*
 * CTRL_RX commands
 */
#define	VIRTIO_NET_CTRL_RX_PROMISC	0
#define	VIRTIO_NET_CTRL_RX_ALLMULTI	1
#define	VIRTIO_NET_CTRL_RX_ALLUNI	2
#define	VIRTIO_NET_CTRL_RX_NOMULTI	3
#define	VIRTIO_NET_CTRL_RX_NOUNI	4
#define	VIRTIO_NET_CTRL_RX_NOBCAST	5

/* CTRL_MAC commands */
#define	VIRTIO_NET_CTRL_MAC_TABLE_SET	0
#define	VIRTIO_NET_CTRL_MAC_ADDR_SET	1

/* CTRL_MQ commands */
#define	VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET	0
#define	VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN	1
#define	VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX	0x8000

/*
 * Control queue ack values
 */
#define	VIRTIO_NET_CQ_OK		0
#define	VIRTIO_NET_CQ_ERR		1

#endif /* _VIRTIO_NET_H_ */
