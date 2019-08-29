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
 */

/*
 * VIRTIO NETWORK DRIVER
 */

#ifndef _VIOIF_H
#define	_VIOIF_H

#include "virtio.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * VIRTIO NETWORK CONFIGURATION REGISTERS
 *
 * These are offsets into the device-specific configuration space available
 * through the virtio_dev_*() family of functions.
 */
#define	VIRTIO_NET_CONFIG_MAC		0x00	/* 48 R/W */
#define	VIRTIO_NET_CONFIG_STATUS	0x06	/* 16 R   */
#define	VIRTIO_NET_CONFIG_MAX_VQ_PAIRS	0x08	/* 16 R   */
#define	VIRTIO_NET_CONFIG_MTU		0x0A	/* 16 R   */

/*
 * VIRTIO NETWORK VIRTQUEUES
 *
 * Note that the control queue is only present if VIRTIO_NET_F_CTRL_VQ is
 * negotiated with the device.
 */
#define	VIRTIO_NET_VIRTQ_RX		0
#define	VIRTIO_NET_VIRTQ_TX		1
#define	VIRTIO_NET_VIRTQ_CONTROL	2

/*
 * VIRTIO NETWORK FEATURE BITS
 */

/*
 * CSUM, GUEST_CSUM:
 *	Partial checksum support.  These features signal that the device will
 *	accept packets with partial checksums (CSUM), and that the driver will
 *	accept packets with partial checksums (GUEST_CSUM).  These features
 *	combine the use of the VIRTIO_NET_HDR_F_NEEDS_CSUM flag, and the
 *	"csum_start" and "csum_offset" fields, in the virtio net header.
 */
#define	VIRTIO_NET_F_CSUM		(1ULL << 0)
#define	VIRTIO_NET_F_GUEST_CSUM		(1ULL << 1)

/*
 * MTU:
 *	The device offers a maximum MTU value at VIRTIO_NET_CONFIG_MTU.  If
 *	this is not negotiated, we allow the largest possible MTU that our
 *	buffer allocations support in case jumbo frames are tacitly supported
 *	by the device.  The default MTU is always 1500.
 */
#define	VIRTIO_NET_F_MTU		(1ULL << 3)

/*
 * MAC:
 *	The device has an assigned primary MAC address.  If this feature bit is
 *	not set, the driver must provide a locally assigned MAC address.  See
 *	IEEE 802, "48-bit universal LAN MAC addresses" for more details on
 *	assignment.
 */
#define	VIRTIO_NET_F_MAC		(1ULL << 5)

/*
 * GUEST_TSO4, GUEST_TSO6, GUEST_UFO:
 *	Inbound segmentation offload support.  These features depend on having
 *	VIRTIO_NET_F_GUEST_CSUM and signal that the driver can accept large
 *	combined TCP (v4 or v6) packets, or reassembled UDP fragments.
 */
#define	VIRTIO_NET_F_GUEST_TSO4		(1ULL << 7)
#define	VIRTIO_NET_F_GUEST_TSO6		(1ULL << 8)
#define	VIRTIO_NET_F_GUEST_UFO		(1ULL << 10)

/*
 * GUEST_ECN:
 *	Depends on either VIRTIO_NET_F_GUEST_TSO4 or VIRTIO_NET_F_GUEST_TSO6.
 *	This feature means the driver will look for the VIRTIO_NET_HDR_GSO_ECN
 *	bit in the "gso_type" of the virtio net header.  This bit tells the
 *	driver that the Explicit Congestion Notification (ECN) bit was set in
 *	the original TCP packets.
 */
#define	VIRTIO_NET_F_GUEST_ECN		(1ULL << 9)

/*
 * HOST_TSO4, HOST_TSO6, HOST_UFO:
 *	Outbound segmentation offload support.  These features depend on having
 *	VIRTIO_NET_F_CSUM and signal that the device will accept large combined
 *	TCP (v4 or v6) packets that require segmentation offload, or large
 *	combined UDP packets that require fragmentation offload.
 */
#define	VIRTIO_NET_F_HOST_TSO4		(1ULL << 11)
#define	VIRTIO_NET_F_HOST_TSO6		(1ULL << 12)
#define	VIRTIO_NET_F_HOST_UFO		(1ULL << 14)

/*
 * HOST_ECN:
 *	Depends on either VIRTIO_NET_F_HOST_TSO4 or VIRTIO_NET_F_HOST_TSO6.
 *	This features means the device will accept packets that both require
 *	segmentation offload and have the Explicit Congestion Notification
 *	(ECN) bit set.  If this feature is not present, the device must not
 *	send large segments that require ECN to be set.
 */
#define	VIRTIO_NET_F_HOST_ECN		(1ULL << 13)

/*
 * GSO:
 *	The GSO feature is, in theory, the combination of HOST_TSO4, HOST_TSO6,
 *	and HOST_ECN.  This is only useful for legacy devices; newer devices
 *	should be using the more specific bits above.
 */
#define	VIRTIO_NET_F_GSO		(1ULL << 6)

/*
 * MRG_RXBUF:
 *	This feature allows the receipt of large packets without needing to
 *	allocate large buffers.  The "virtio_net_hdr" will include an extra
 *	value: the number of buffers to gang together.
 */
#define	VIRTIO_NET_F_MRG_RXBUF		(1ULL << 15)

/*
 * STATUS:
 *	The VIRTIO_NET_CONFIG_STATUS configuration register is available, which
 *	allows the driver to read the link state from the device.
 */
#define	VIRTIO_NET_F_STATUS		(1ULL << 16)

/*
 * CTRL_VQ, CTRL_RX, CTRL_VLAN:
 *	These features signal that the device exposes the control queue
 *	(VIRTIO_NET_VIRTQ_CONTROL), in the case of CTRL_VQ; and that the
 *	control queue supports extra commands (CTRL_RX, CTRL_VLAN).
 */
#define	VIRTIO_NET_F_CTRL_VQ		(1ULL << 17)
#define	VIRTIO_NET_F_CTRL_RX		(1ULL << 18)
#define	VIRTIO_NET_F_CTRL_VLAN		(1ULL << 19)
#define	VIRTIO_NET_F_CTRL_RX_EXTRA	(1ULL << 20)

/*
 * These features are supported by the driver and we will request them from the
 * device.  Note that we do not currently request GUEST_CSUM, as the driver
 * does not presently support receiving frames with any offload features from
 * the device.
 */
#define	VIRTIO_NET_WANTED_FEATURES	(VIRTIO_NET_F_CSUM |		\
					VIRTIO_NET_F_GSO |		\
					VIRTIO_NET_F_HOST_TSO4 |	\
					VIRTIO_NET_F_HOST_ECN |		\
					VIRTIO_NET_F_MAC |		\
					VIRTIO_NET_F_MTU)

/*
 * VIRTIO NETWORK HEADER
 *
 * This structure appears at the start of each transmit or receive packet
 * buffer.
 */
struct virtio_net_hdr {
	uint8_t				vnh_flags;
	uint8_t				vnh_gso_type;
	uint16_t			vnh_hdr_len;
	uint16_t			vnh_gso_size;
	uint16_t			vnh_csum_start;
	uint16_t			vnh_csum_offset;
} __packed;

/*
 * VIRTIO NETWORK HEADER: FLAGS (vnh_flags)
 */
#define	VIRTIO_NET_HDR_F_NEEDS_CSUM	0x01

/*
 * VIRTIO NETWORK HEADER: OFFLOAD OPTIONS (vnh_gso_type)
 *
 * Each of these is an offload type, except for the ECN value which is
 * logically OR-ed with one of the other types.
 */
#define	VIRTIO_NET_HDR_GSO_NONE		0
#define	VIRTIO_NET_HDR_GSO_TCPV4	1
#define	VIRTIO_NET_HDR_GSO_UDP		3
#define	VIRTIO_NET_HDR_GSO_TCPV6	4
#define	VIRTIO_NET_HDR_GSO_ECN		0x80


/*
 * DRIVER PARAMETERS
 */

/*
 * At attach, we allocate a fixed pool of buffers for receipt and transmission
 * of frames.  The maximum number of buffers of each type that we will allocate
 * is specified here.  If the ring size is smaller than this number, we will
 * use the ring size instead.
 */
#define	VIRTIO_NET_TX_BUFS		256
#define	VIRTIO_NET_RX_BUFS		256

/*
 * The virtio net header and the first buffer segment share the same DMA
 * allocation.  We round up the virtio header size to a multiple of 4 and add 2
 * bytes so that the IP header, which starts immediately after the 14 or 18
 * byte Ethernet header, is then correctly aligned:
 *
 *   0                10      16   18                              32/36
 *   | virtio_net_hdr | %4==0 | +2 | Ethernet header (14/18 bytes) | IPv4 ...
 *
 * Note that for this to work correctly, the DMA allocation must also be 4 byte
 * aligned.
 */
#define	VIOIF_HEADER_ALIGN		4
#define	VIOIF_HEADER_SKIP		(P2ROUNDUP( \
					    sizeof (struct virtio_net_hdr), \
					    VIOIF_HEADER_ALIGN) + 2)

/*
 * Given we are not negotiating VIRTIO_NET_F_MRG_RXBUF, the specification says
 * we must be able to accept a 1514 byte packet, or if any segmentation offload
 * features have been negotiated a 65550 byte packet.  To keep things simple,
 * we'll assume segmentation offload is possible in most cases.  In addition to
 * the packet payload, we need to account for the Ethernet header and the
 * virtio_net_hdr.
 */
#define	VIOIF_RX_DATA_SIZE		65550
#define	VIOIF_RX_BUF_SIZE		(VIOIF_RX_DATA_SIZE + \
					    sizeof (struct ether_header) + \
					    VIOIF_HEADER_SKIP)

/*
 * If we assume that a large allocation will probably have mostly 4K page sized
 * cookies, 64 segments allows us 256KB for a single frame.  We're in control
 * of the allocation we use for receive buffers, so this value only has an
 * impact on the length of chain we're able to create for external transmit
 * buffer mappings.
 */
#define	VIOIF_MAX_SEGS			64

/*
 * We pre-allocate a reasonably large buffer to copy small packets
 * there. Bigger packets are mapped, packets with multiple
 * cookies are mapped as indirect buffers.
 */
#define	VIOIF_TX_INLINE_SIZE		(2 * 1024)


/*
 * TYPE DEFINITIONS
 */

typedef struct vioif vioif_t;

/*
 * Receive buffers are allocated in advance as a combination of DMA memory and
 * a descriptor chain.  Receive buffers can be loaned to the networking stack
 * to avoid copying, and this object contains the free routine to pass to
 * desballoc().
 *
 * When receive buffers are not in use, they are linked into the per-instance
 * free list, "vif_rxbufs" via "rb_link".  Under normal conditions, we expect
 * the free list to be empty much of the time; most buffers will be in the ring
 * or on loan.
 */
typedef struct vioif_rxbuf {
	vioif_t				*rb_vioif;
	frtn_t				rb_frtn;

	virtio_dma_t			*rb_dma;
	virtio_chain_t			*rb_chain;

	list_node_t			rb_link;
} vioif_rxbuf_t;

/*
 * Transmit buffers are also allocated in advance.  DMA memory is allocated for
 * the virtio net header, and to hold small packets.  Larger packets are mapped
 * from storage loaned to the driver by the network stack.
 *
 * When transmit buffers are not in use, they are linked into the per-instance
 * free list, "vif_txbufs" via "tb_link".
 */
typedef struct vioif_txbuf {
	mblk_t				*tb_mp;

	/*
	 * Inline buffer space (VIOIF_TX_INLINE_SIZE) for storage of the virtio
	 * net header, and to hold copied (rather than mapped) packet data.
	 */
	virtio_dma_t			*tb_dma;
	virtio_chain_t			*tb_chain;

	/*
	 * External buffer mapping.  The capacity is fixed at allocation time,
	 * and "tb_ndmaext" tracks the current number of mappings.
	 */
	virtio_dma_t			**tb_dmaext;
	uint_t				tb_dmaext_capacity;
	uint_t				tb_ndmaext;

	list_node_t			tb_link;
} vioif_txbuf_t;

typedef enum vioif_runstate {
	VIOIF_RUNSTATE_STOPPED = 1,
	VIOIF_RUNSTATE_STOPPING,
	VIOIF_RUNSTATE_RUNNING
} vioif_runstate_t;

/*
 * Per-instance driver object.
 */
struct vioif {
	dev_info_t			*vif_dip;
	virtio_t			*vif_virtio;

	kmutex_t			vif_mutex;

	/*
	 * The NIC is considered RUNNING between the mc_start(9E) and
	 * mc_stop(9E) calls.  Otherwise it is STOPPING (while draining
	 * resources) then STOPPED.  When not RUNNING, we will drop incoming
	 * frames and refuse to insert more receive buffers into the receive
	 * queue.
	 */
	vioif_runstate_t		vif_runstate;

	mac_handle_t			vif_mac_handle;

	virtio_queue_t			*vif_rx_vq;
	virtio_queue_t			*vif_tx_vq;

	/* TX virtqueue management resources */
	boolean_t			vif_tx_corked;
	boolean_t			vif_tx_drain;
	timeout_id_t			vif_tx_reclaim_tid;

	/*
	 * Configured offload features:
	 */
	unsigned int			vif_tx_csum:1;
	unsigned int			vif_tx_tso4:1;

	/*
	 * For debugging, it is useful to know whether the MAC address we
	 * are using came from the host (via VIRTIO_NET_CONFIG_MAC) or
	 * was otherwise generated or set from within the guest.
	 */
	unsigned int			vif_mac_from_host:1;

	uint_t				vif_mtu;
	uint_t				vif_mtu_max;
	uint8_t				vif_mac[ETHERADDRL];

	/*
	 * Receive buffer free list and accounting:
	 */
	list_t				vif_rxbufs;
	uint_t				vif_nrxbufs_alloc;
	uint_t				vif_nrxbufs_onloan;
	uint_t				vif_nrxbufs_onloan_max;
	uint_t				vif_rxbufs_capacity;
	vioif_rxbuf_t			*vif_rxbufs_mem;

	/*
	 * Transmit buffer free list and accounting:
	 */
	list_t				vif_txbufs;
	uint_t				vif_ntxbufs_alloc;
	uint_t				vif_txbufs_capacity;
	vioif_txbuf_t			*vif_txbufs_mem;

	/*
	 * These copy size thresholds are exposed as private MAC properties so
	 * that they can be tuned without rebooting.
	 */
	uint_t				vif_rxcopy_thresh;
	uint_t				vif_txcopy_thresh;

	/*
	 * Statistics visible through mac:
	 */
	uint64_t			vif_ipackets;
	uint64_t			vif_opackets;
	uint64_t			vif_rbytes;
	uint64_t			vif_obytes;
	uint64_t			vif_brdcstxmt;
	uint64_t			vif_brdcstrcv;
	uint64_t			vif_multixmt;
	uint64_t			vif_multircv;
	uint64_t			vif_norecvbuf;
	uint64_t			vif_notxbuf;
	uint64_t			vif_ierrors;
	uint64_t			vif_oerrors;

	/*
	 * Internal debugging statistics:
	 */
	uint64_t			vif_rxfail_dma_handle;
	uint64_t			vif_rxfail_dma_buffer;
	uint64_t			vif_rxfail_dma_bind;
	uint64_t			vif_rxfail_chain_undersize;
	uint64_t			vif_rxfail_no_descriptors;
	uint64_t			vif_txfail_dma_handle;
	uint64_t			vif_txfail_dma_bind;
	uint64_t			vif_txfail_indirect_limit;

	uint64_t			vif_stat_tx_reclaim;
};

#ifdef __cplusplus
}
#endif

#endif /* _VIOIF_H */
