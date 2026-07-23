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
 * Copyright 2021 Joyent, Inc.
 * Copyright 2026 Oxide Computer Company
 */

/*
 * VIRTIO NETWORK DRIVER
 */

#ifndef _VIOIF_H
#define	_VIOIF_H

#include <sys/stdbool.h>
#include <sys/taskq_impl.h>

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
#define	VIRTIO_NET_CONFIG_SPEED		0x0C	/* 32 R   */
#define	VIRTIO_NET_CONFIG_DUPLEX	0x10	/* 8  R   */

#define	VIRTIO_NET_CONFIG_STATUS_LINK_UP	1
#define	VIRTIO_NET_CONFIG_SPEED_UNKNOWN		UINT32_MAX
#define	VIRTIO_NET_CONFIG_DUPLEX_HALF		0
#define	VIRTIO_NET_CONFIG_DUPLEX_FULL		1
#define	VIRTIO_NET_CONFIG_DUPLEX_UNKNOWN	0xff

/*
 * VIRTIO NETWORK VIRTQUEUES
 *
 * The device provides at least one pair of virtqueues: receive at index 0 and
 * transmit at index 1. If VIRTIO_NET_F_MQ is negotiated, the device provides
 * "max_virtqueue_pairs" pairs, with the queues for pair "n" at the indices
 * given below. The control queue, present only if VIRTIO_NET_F_CTRL_VQ is
 * negotiated, follows all of the provided pairs; when VIRTIO_NET_F_MQ has not
 * been negotiated its index is found by passing 1 for "maxqpairs".
 */
#define	VIRTIO_NET_VIRTQ_RX(n)			(2 * (n))
#define	VIRTIO_NET_VIRTQ_TX(n)			(2 * (n) + 1)
#define	VIRTIO_NET_VIRTQ_CONTROL(maxqpairs)	(2 * (maxqpairs))

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
 * MQ:
 *	The device supports multiple pairs of receive and transmit virtqueues.
 *	The number of available pairs can be read from
 *	VIRTIO_NET_CONFIG_MAX_VQ_PAIRS. The driver selects the number of pairs
 *	that will be used by sending the VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET
 *	command on the control queue. Until it does so, the device only uses
 *	the first pair. This feature depends on VIRTIO_NET_F_CTRL_VQ.
 */
#define	VIRTIO_NET_F_MQ			(1ULL << 22)

/*
 * SPEED_DUPLEX:
 *	The VIRTIO_NET_CONFIG_SPEED and VIRTIO_NET_CONFIG_DUPLEX registers are
 *	available, which allows the driver to determine the link speed and
 *	duplex of the device.
 */
#define	VIRTIO_NET_F_SPEED_DUPLEX	(1ULL << 63)

/*
 * These features are supported by the driver and we will request them from the
 * device.  Note that we do not currently request GUEST_CSUM, as the driver
 * does not presently support receiving frames with any offload features from
 * the device.
 */
#define	VIRTIO_NET_WANTED_FEATURES	(VIRTIO_NET_F_CSUM |		\
					VIRTIO_NET_F_GSO |		\
					VIRTIO_NET_F_HOST_TSO4 |	\
					VIRTIO_NET_F_HOST_TSO6 |	\
					VIRTIO_NET_F_HOST_ECN |		\
					VIRTIO_NET_F_MAC |		\
					VIRTIO_NET_F_MTU |		\
					VIRTIO_NET_F_CTRL_VQ |		\
					VIRTIO_NET_F_CTRL_RX |		\
					VIRTIO_NET_F_MQ |		\
					VIRTIO_NET_F_STATUS)

/* The following features are only available with the modern interface. */
#define	VIRTIO_NET_WANTED_FEATURES_MODERN	\
					(VIRTIO_NET_F_SPEED_DUPLEX)

/*
 * VIRTIO NETWORK HEADER
 *
 * This structure appears at the start of each transmit or receive packet
 * buffer. When using the legacy interface, the `vnh_num_buffers` field only
 * appears when VIRTIO_NET_F_MRG_RXBUF is negotiated, whereas it is always
 * present with the modern interface. We use a common struct since it is always
 * constructed in a buffer of at least this size, and then only put the
 * requisite number of bytes (VIRTIO_NET_HDR_LEN()) into the descriptor.
 */
struct virtio_net_hdr {
	uint8_t				vnh_flags;
	uint8_t				vnh_gso_type;
	uint16_t			vnh_hdr_len;
	uint16_t			vnh_gso_size;
	uint16_t			vnh_csum_start;
	uint16_t			vnh_csum_offset;
	uint16_t			vnh_num_buffers;
} __packed;
#define	VIRTIO_NET_HDR_LEN(modern) \
	((modern) ? sizeof (struct virtio_net_hdr) : \
	offsetof(struct virtio_net_hdr, vnh_num_buffers))

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
 * VIRTIO CONTROL VIRTQUEUE HEADER
 *
 * This structure appears at the start of each control virtqueue request.
 */
struct virtio_net_ctrlq_hdr {
	uint8_t		vnch_class;
	uint8_t		vnch_command;
} __packed;

/*
 * Control Queue Classes
 */
#define	VIRTIO_NET_CTRL_RX		0
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

/*
 * CTRL_MQ commands
 */
#define	VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET	0

/*
 * The valid range for the "max_virtqueue_pairs" configuration field, and for
 * the argument to VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET.
 */
#define	VIRTIO_NET_CTRL_MQ_PAIRS_MIN	1
#define	VIRTIO_NET_CTRL_MQ_PAIRS_MAX	0x8000

/*
 * The body of a VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET request. The pair count is
 * little-endian.
 */
struct virtio_net_ctrl_mq {
	uint16_t	vncm_pairs;
} __packed;

/*
 * Control queue ack values
 */
#define	VIRTIO_NET_CQ_OK		0
#define	VIRTIO_NET_CQ_ERR		1


/*
 * DRIVER PARAMETERS
 */

/*
 * At attach, we allocate a fixed pool of buffers for receipt and transmission
 * of frames for each virtqueue pair. The maximum number of buffers of each
 * type that we will allocate is specified here. If the ring size is smaller
 * than this number, we will use the ring size instead.
 */
#define	VIRTIO_NET_TX_BUFS		256
#define	VIRTIO_NET_RX_BUFS		256

/*
 * The maximum number of virtqueue pairs we are prepared to use. Each
 * additional pair consumes two MSI-X vectors and its own pools of transmit
 * and receive buffers, of which the receive pool in particular is a
 * significant allocation (VIRTIO_NET_RX_BUFS buffers of VIOIF_RX_BUF_SIZE
 * bytes; around 16MB per pair). The number of pairs used is also limited by
 * the device, the number of CPUs and the number of available interrupt
 * vectors, and can be restricted with the "vioif_max_qpairs" tuneable.
 */
#define	VIOIF_MAX_QPAIRS		8

/*
 * The number of buffers allocated for control queue requests. Each request
 * occupies one buffer until its response arrives. Responses are routed back
 * to the buffer used to submit the request, so several requests may be
 * outstanding at once and responses may be collected in any order.
 */
#define	VIRTIO_NET_CTRL_BUFS		4

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
 * Control queue messages are very small. This is a rather arbitrary small
 * bufer size that should be sufficiently large for any control queue
 * messages we will send.
 */
#define	VIOIF_CTRL_SIZE			256

/*
 * TYPE DEFINITIONS
 */

typedef struct vioif vioif_t;
typedef struct vioif_rxq vioif_rxq_t;
typedef struct vioif_txq vioif_txq_t;

/*
 * Receive buffers are allocated in advance as a combination of DMA memory and
 * a descriptor chain.  Receive buffers can be loaned to the networking stack
 * to avoid copying, and this object contains the free routine to pass to
 * desballoc().
 *
 * When receive buffers are not in use, they are linked into the owning
 * receive queue's free list, "vrq_bufs", via "rb_link". Under normal
 * conditions, we expect the free list to be empty much of the time; most
 * buffers will be in the ring or on loan.
 */
typedef struct vioif_rxbuf {
	vioif_rxq_t			*rb_rxq;
	frtn_t				rb_frtn;

	virtio_dma_t			*rb_dma;
	virtio_chain_t			*rb_chain;

	list_node_t			rb_link;
} vioif_rxbuf_t;

/*
 * The stages of a control queue request's life, tracked in the buffer used
 * to submit it. A buffer moves from FREE to ACTIVE when it is allocated
 * for a request. Collecting its response from the device moves the buffer
 * to DONE, and the submitter then reads the result and frees it. A
 * submitter that gives up waiting for a response moves the buffer to
 * ABANDONED instead. Ownership of an abandoned buffer rests with the
 * device and is recovered when the response eventually arrives, or
 * once the device has been reset during teardown.
 */
typedef enum vioif_ctrlbuf_state {
	VIOIF_CTRLBUF_FREE = 1,
	VIOIF_CTRLBUF_ACTIVE,
	VIOIF_CTRLBUF_DONE,
	VIOIF_CTRLBUF_ABANDONED
} vioif_ctrlbuf_state_t;

typedef struct vioif_ctrlbuf {
	vioif_t				*cb_vioif;
	vioif_ctrlbuf_state_t		cb_state;

	virtio_dma_t			*cb_dma;
	virtio_chain_t			*cb_chain;

	uint8_t				*cb_ack;

	list_node_t			cb_link;
} vioif_ctrlbuf_t;

/*
 * Transmit buffers are also allocated in advance.  DMA memory is allocated for
 * the virtio net header, and to hold small packets.  Larger packets are mapped
 * from storage loaned to the driver by the network stack.
 *
 * When transmit buffers are not in use, they are linked into the owning
 * transmit queue's free list, "vtq_bufs", via "tb_link".
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
 * Buffer space for the longest virtqueue name, and its terminating NUL.
 */
#define	VIOIF_VQ_NAME_LEN		(sizeof ("rx32767"))

/*
 * Per-receive queue state. Each receive queue is presented to MAC as a
 * receive ring, and has its own pool of receive buffers.
 */
struct vioif_rxq {
	vioif_t				*vrq_vif;
	virtio_queue_t			*vrq_vq;
	char				vrq_name[VIOIF_VQ_NAME_LEN];

	kmutex_t			vrq_mutex;

	/*
	 * "vrq_running" is set while the ring is started. While it is clear
	 * we drop incoming frames and refuse to insert more receive buffers
	 * into the receive queue.
	 *
	 * "vrq_polling" is set while MAC has claimed the ring for polled
	 * receive. Virtqueue interrupt suppression is only advisory, so the
	 * interrupt handler uses this to avoid delivering frames that the
	 * poll thread is responsible for collecting.
	 */
	bool				vrq_running;
	bool				vrq_polling;

	/*
	 * Frames returned by the device while its interrupt was suppressed
	 * are collected from the driver task queue. "vrq_collect_queued" is
	 * set while the pre-allocated task entry is on the queue.
	 */
	taskq_ent_t			vrq_collect_tqent;
	bool				vrq_collect_queued;

	mac_ring_handle_t		vrq_ringh;
	uint64_t			vrq_gen;

	/*
	 * Receive buffer free list and accounting:
	 */
	list_t				vrq_bufs;
	uint_t				vrq_nbufs_alloc;
	uint_t				vrq_nbufs_onloan;
	uint_t				vrq_nbufs_onloan_max;
	uint_t				vrq_bufs_capacity;
	vioif_rxbuf_t			*vrq_bufs_mem;

	/*
	 * Per-ring statistics:
	 */
	uint64_t			vrq_ipackets;
	uint64_t			vrq_rbytes;
	uint64_t			vrq_brdcstrcv;
	uint64_t			vrq_multircv;
	uint64_t			vrq_norecvbuf;
	uint64_t			vrq_ierrors;

	uint64_t			vrq_rxfail_chain_undersize;
	uint64_t			vrq_rxfail_chain_oversize;
};

/*
 * Per-transmit queue state. Each transmit queue is presented to MAC as a
 * transmit ring, and has its own pool of transmit buffers.
 */
struct vioif_txq {
	vioif_t				*vtq_vif;
	virtio_queue_t			*vtq_vq;
	char				vtq_name[VIOIF_VQ_NAME_LEN];

	kmutex_t			vtq_mutex;

	/* TX virtqueue management resources */
	bool				vtq_corked;
	bool				vtq_drain;
	timeout_id_t			vtq_reclaim_tid;

	mac_ring_handle_t		vtq_ringh;

	/*
	 * Transmit buffer free list and accounting:
	 */
	list_t				vtq_bufs;
	uint_t				vtq_nbufs_alloc;
	uint_t				vtq_bufs_capacity;
	vioif_txbuf_t			*vtq_bufs_mem;

	/*
	 * Per-ring statistics:
	 */
	uint64_t			vtq_opackets;
	uint64_t			vtq_obytes;
	uint64_t			vtq_brdcstxmt;
	uint64_t			vtq_multixmt;
	uint64_t			vtq_notxbuf;
	uint64_t			vtq_oerrors;

	uint64_t			vtq_txfail_dma_bind;
	uint64_t			vtq_txfail_indirect_limit;

	uint64_t			vtq_stat_tx_reclaim;
};

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
	 * resources) then STOPPED.
	 */
	vioif_runstate_t		vif_runstate;

	mac_handle_t			vif_mac_handle;

	/*
	 * The receive group handle is not currently used, but is retained,
	 * as in other ring-capable drivers, for debugging and for future
	 * group operations.
	 */
	mac_group_handle_t		vif_rx_grouph;

	/*
	 * Used by the receive path to collect and deliver frames that were
	 * returned by the device while its interrupt was suppressed.
	 */
	taskq_t				*vif_taskq;

	/*
	 * "vif_nqpairs" is the number of receive and transmit virtqueue pairs
	 * in use, and is the number of rings of each type that we present to
	 * MAC. "vif_nqpairs_alloc" is the number of pairs for which we have
	 * allocated queues and buffers; the two only differ if the device
	 * refused our VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET request.
	 */
	uint_t				vif_nqpairs;
	uint_t				vif_nqpairs_alloc;
	vioif_rxq_t			*vif_rxqs;
	vioif_txq_t			*vif_txqs;

	virtio_queue_t			*vif_ctrl_vq;

	/*
	 * Configured offload features:
	 */
	unsigned int			vif_tx_csum:1;
	unsigned int			vif_tx_tso4:1;
	unsigned int			vif_tx_tso6:1;

	/*
	 * For debugging, it is useful to know whether the MAC address we
	 * are using came from the host (via VIRTIO_NET_CONFIG_MAC) or
	 * was otherwise generated or set from within the guest.
	 */
	unsigned int			vif_mac_from_host:1;

	unsigned int			vif_has_ctrlq:1;
	unsigned int			vif_has_ctrlq_rx:1;

	uint32_t			vif_speed;	/* Mb/s */
	uint16_t			vif_status;

	/*
	 * The link state most recently reported to MAC.
	 */
	link_state_t			vif_link_state;
	uint8_t				vif_duplex;
	uint_t				vif_mtu;
	uint_t				vif_mtu_max;
	uint8_t				vif_mac[ETHERADDRL];

	size_t				vif_rxbuf_hdrlen;

	/*
	 * These copy size thresholds are exposed as private MAC properties so
	 * that they can be tuned without rebooting.
	 */
	uint_t				vif_rxcopy_thresh;
	uint_t				vif_txcopy_thresh;

	list_t				vif_ctrlbufs;
	uint_t				vif_nctrlbufs_alloc;
	uint_t				vif_nctrlbufs_abandoned;
	uint_t				vif_ctrlbufs_capacity;
	vioif_ctrlbuf_t			*vif_ctrlbufs_mem;

	/*
	 * Signalled when a control queue response is collected and when a
	 * control buffer is returned to the free list. Since a single wakeup
	 * could be consumed by a waiter whose condition has not been met,
	 * wakeups must be broadcast. The pool size bounds the number of
	 * waiters.
	 */
	kcondvar_t			vif_ctrlq_cv;

	uint64_t			vif_noctrlbuf;
	uint64_t			vif_ctrlbuf_toosmall;
	uint64_t			vif_ctrlq_abandoned;
	uint64_t			vif_ctrlq_recovered;
};

/*
 * Data and functions shared between the source files which make up the
 * driver.
 */

/* vioif.c */
extern ddi_dma_attr_t vioif_dma_attr_bufs;
extern const uchar_t vioif_broadcast[ETHERADDRL];

/* vioif_rx.c */
extern void vioif_rxbuf_free(vioif_rxq_t *, vioif_rxbuf_t *);
extern int vioif_alloc_rxq_bufs(vioif_rxq_t *);
extern void vioif_free_rxq_bufs(vioif_rxq_t *);
extern bool vioif_rx_drain(vioif_t *);
extern uint_t vioif_rx_handler(caddr_t, caddr_t);
extern void vioif_fill_rx_ring(void *, mac_ring_type_t, const int, const int,
    mac_ring_info_t *, mac_ring_handle_t);

/* vioif_tx.c */
extern int vioif_alloc_txq_bufs(vioif_txq_t *);
extern void vioif_free_txq_bufs(vioif_txq_t *);
extern void vioif_tx_drain(vioif_txq_t *);
extern uint_t vioif_tx_handler(caddr_t, caddr_t);
extern void vioif_fill_tx_ring(void *, mac_ring_type_t, const int, const int,
    mac_ring_info_t *, mac_ring_handle_t);

#ifdef __cplusplus
}
#endif

#endif /* _VIOIF_H */
