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
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright (c) 2017, Joyent, Inc.
 * Copyright 2017 Tegile Systems, Inc.  All rights reserved.
 */

/*
 * Please see i40e_main.c for an introduction to the device driver, its layout,
 * and more.
 */

#ifndef	_I40E_SW_H
#define	_I40E_SW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/dlpi.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/sdt.h>
#include <sys/ethernet.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/netlb.h>
#include <sys/random.h>
#include <inet/common.h>
#include <inet/tcp.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <netinet/udp.h>
#include <netinet/sctp.h>
#include <sys/bitmap.h>
#include <sys/cpuvar.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/disp.h>
#include <sys/fm/io/ddi.h>
#include <sys/list.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include "i40e_type.h"
#include "i40e_osdep.h"
#include "i40e_prototype.h"
#include "i40e_xregs.h"

#define	I40E_MODULE_NAME "i40e"

#define	I40E_ADAPTER_REGSET	1

/*
 * Configuration constants. Note that the hardware defines a minimum bound of 32
 * descriptors and requires that the programming of the descriptor lengths be
 * aligned in units of 32 descriptors.
 */
#define	I40E_MIN_TX_RING_SIZE	64
#define	I40E_MAX_TX_RING_SIZE	4096
#define	I40E_DEF_TX_RING_SIZE	1024

#define	I40E_MIN_RX_RING_SIZE	64
#define	I40E_MAX_RX_RING_SIZE	4096
#define	I40E_DEF_RX_RING_SIZE	1024

#define	I40E_DESC_ALIGN		32

/*
 * Sizes used for asynchronous processing of the adminq. We allocate a fixed
 * size buffer for each instance of the device during attach time, rather than
 * allocating and freeing one during interrupt processing.
 *
 * We also define the descriptor size of the admin queue here.
 */
#define	I40E_ADMINQ_BUFSZ	4096
#define	I40E_MAX_ADMINQ_SIZE	1024
#define	I40E_DEF_ADMINQ_SIZE	256

/*
 * Note, while the min and maximum values are based upon the sizing of the ring
 * itself, the default is taken from ixgbe without much thought. It's basically
 * been cargo culted. See i40e_transceiver.c for a bit more information.
 */
#define	I40E_MIN_RX_LIMIT_PER_INTR	16
#define	I40E_MAX_RX_LIMIT_PER_INTR	4096
#define	I40E_DEF_RX_LIMIT_PER_INTR	256

/*
 * Valid MTU ranges. Note that the XL710's maximum payload is actually 9728.
 * However, we need to adjust for the ETHERFCSL (4 bytes) and the Ethernet VLAN
 * header size (18 bytes) to get the actual maximum frame we can use. If
 * different adapters end up with different sizes, we should make this value a
 * bit more dynamic.
 */
#define	I40E_MAX_MTU	9706
#define	I40E_MIN_MTU	ETHERMIN
#define	I40E_DEF_MTU	ETHERMTU

/*
 * Interrupt throttling related values. Interrupt throttling values are defined
 * in two microsecond increments. Note that a value of zero basically says do no
 * ITR activity. A helpful way to think about these is that setting the ITR to a
 * value will allow a certain number of interrupts per second.
 *
 * Our default values for RX allow 20k interrupts per second while our default
 * values for TX allow for 5k interrupts per second. For other class interrupts,
 * we limit ourselves to a rate of 2k/s.
 */
#define	I40E_MIN_ITR		0x0000
#define	I40E_MAX_ITR		0x0FF0
#define	I40E_DEF_RX_ITR		0x0019
#define	I40E_DEF_TX_ITR		0x0064
#define	I40E_DEF_OTHER_ITR	0x00FA

/*
 * Indexes into the three ITR registers that we have.
 */
typedef enum i40e_itr_index {
	I40E_ITR_INDEX_RX	= 0x0,
	I40E_ITR_INDEX_TX	= 0x1,
	I40E_ITR_INDEX_OTHER	= 0x2,
	I40E_ITR_INDEX_NONE 	= 0x3
} i40e_itr_index_t;

/*
 * Table 1-5 of the PRM notes that LSO supports up to 256 KB.
 */
#define	I40E_LSO_MAXLEN	(256 * 1024)

#define	I40E_CYCLIC_PERIOD NANOSEC	/* 1 second */
#define	I40E_DRAIN_RX_WAIT	(500 * MILLISEC)	/* In us */

/*
 * All the other queue types for are defined by the common code. However, this
 * is the constant to indicate that it's terminated.
 */
#define	I40E_QUEUE_TYPE_EOL	0x7FF

/*
 * See the comments in i40e_transceiver.c as to the purpose of this value and
 * how it's used to ensure that the IP header is eventually aligned when it's
 * received by the OS.
 */
#define	I40E_BUF_IPHDR_ALIGNMENT	2

/*
 * The XL710 controller has a limit of eight buffers being allowed to be used
 * for the transmission of a single frame. This is defined in 8.4.1 - Transmit
 * Packet in System Memory.
 */
#define	I40E_TX_MAX_COOKIE	8

/*
 * Sizing to determine the amount of available descriptors at which we'll
 * consider ourselves blocked. Also, when we have these available, we'll then
 * consider ourselves available to transmit to MAC again. Strictly speaking, the
 * MAX is based on the ring size. The default sizing is based on ixgbe.
 */
#define	I40E_MIN_TX_BLOCK_THRESH	I40E_TX_MAX_COOKIE
#define	I40E_DEF_TX_BLOCK_THRESH	I40E_MIN_TX_BLOCK_THRESH

/*
 * Sizing for DMA thresholds. These are used to indicate whether or not we
 * should perform a bcopy or a DMA binding of a given message block. The range
 * allows for setting things such that we'll always do a bcopy (a high value) or
 * always perform a DMA binding (a low value).
 */
#define	I40E_MIN_RX_DMA_THRESH		0
#define	I40E_DEF_RX_DMA_THRESH		256
#define	I40E_MAX_RX_DMA_THRESH		INT32_MAX

#define	I40E_MIN_TX_DMA_THRESH		0
#define	I40E_DEF_TX_DMA_THRESH		256
#define	I40E_MAX_TX_DMA_THRESH		INT32_MAX

/*
 * Resource sizing counts. There are various aspects of hardware where we may
 * have some variable number of elements that we need to handle. Such as the
 * hardware capabilities and switch capacities. We cannot know a priori how many
 * elements to do, so instead we take a starting guess and then will grow it up
 * to an upper bound on a number of elements, to limit memory consumption in
 * case of a hardware bug.
 */
#define	I40E_HW_CAP_DEFAULT	40
#define	I40E_SWITCH_CAP_DEFAULT	25

/*
 * Host Memory Context related constants.
 */
#define	I40E_HMC_RX_CTX_UNIT		128
#define	I40E_HMC_RX_DBUFF_MIN		1024
#define	I40E_HMC_RX_DBUFF_MAX		(16 * 1024 - 128)
#define	I40E_HMC_RX_DTYPE_NOSPLIT	0
#define	I40E_HMC_RX_DSIZE_32BYTE	1
#define	I40E_HMC_RX_CRCSTRIP_ENABLE	1
#define	I40E_HMC_RX_FC_DISABLE		0
#define	I40E_HMC_RX_L2TAGORDER		1
#define	I40E_HMC_RX_HDRSPLIT_DISABLE	0
#define	I40E_HMC_RX_INVLAN_DONTSTRIP	0
#define	I40E_HMC_RX_TPH_DISABLE		0
#define	I40E_HMC_RX_LOWRXQ_NOINTR	0
#define	I40E_HMC_RX_PREFENA		1

#define	I40E_HMC_TX_CTX_UNIT		128
#define	I40E_HMC_TX_NEW_CONTEXT		1
#define	I40E_HMC_TX_FC_DISABLE		0
#define	I40E_HMC_TX_TS_DISABLE		0
#define	I40E_HMC_TX_FD_DISABLE		0
#define	I40E_HMC_TX_ALT_VLAN_DISABLE	0
#define	I40E_HMC_TX_WB_ENABLE		1
#define	I40E_HMC_TX_TPH_DISABLE		0

/*
 * Whenever we establish and create a VSI, we need to assign some number of
 * queues that it's allowed to access from the PF. Because we only have a single
 * VSI per PF at this time, we assign it all the queues.
 *
 * Many of the devices support what's called Data-center Bridging. Which is a
 * feature that we don't have much use of at this time. However, we still need
 * to fill in this information. We follow the guidance of the note in Table 7-80
 * which talks about bytes 62-77. It says that if we don't want to assign
 * anything to traffic classes, we should set the field to zero. Effectively
 * this means that everything in the system is assigned to traffic class zero.
 */
#define	I40E_ASSIGN_ALL_QUEUES		0
#define	I40E_TRAFFIC_CLASS_NO_QUEUES	0

/*
 * This defines the error mask that we care about from rx descriptors. Currently
 * we're only concerned with the general errors and oversize errors.
 */
#define	I40E_RX_ERR_BITS	((1 << I40E_RX_DESC_ERROR_RXE_SHIFT) | \
	(1 << I40E_RX_DESC_ERROR_OVERSIZE_SHIFT))

/*
 * Property sizing macros for firmware versions, etc. They need to be large
 * enough to hold 32-bit quantities transformed to strings as %d.%d or %x.
 */
#define	I40E_DDI_PROP_LEN	64

/*
 * We currently consolidate some overrides that we use in the code here. These
 * will be gone in the fullness of time, but as we're bringing up the device,
 * this is what we use.
 */
#define	I40E_GROUP_MAX		1
#define	I40E_TRQPAIR_MAX	1

#define	I40E_GROUP_NOMSIX	1
#define	I40E_TRQPAIR_NOMSIX	1

/*
 * It seems reasonable to cast this to void because the only reason that we
 * should be getting a DDI_FAILURE is due to the fact that we specify addresses
 * out of range. Because we specify no offset or address, it shouldn't happen.
 */
#ifdef	DEBUG
#define	I40E_DMA_SYNC(handle, flag)	ASSERT0(ddi_dma_sync( \
					    (handle)->dmab_dma_handle, 0, 0, \
					    (flag)))
#else	/* !DEBUG */
#define	I40E_DMA_SYNC(handle, flag)	((void) ddi_dma_sync( \
					    (handle)->dmab_dma_handle, 0, 0, \
					    (flag)))
#endif	/* DEBUG */

/*
 * Constants related to ring startup and teardown. These refer to the amount of
 * time that we're willing to wait for a ring to spin up and spin down.
 */
#define	I40E_RING_WAIT_NTRIES	10
#define	I40E_RING_WAIT_PAUSE	10	/* ms */

/*
 * Printed Board Assembly (PBA) length. These are derived from Table 6-2.
 */
#define	I40E_PBANUM_LENGTH	12
#define	I40E_PBANUM_STRLEN	13

/*
 * Define the maximum number of queues for a traffic class. These values come
 * from the 'Number and offset of queue pairs per TCs' section of the 'Add VSI
 * Command Buffer' table. For the 710 controller family this is table 7-62
 * (r2.5) and for the 722 this is table 38-216 (r2.0).
 */
#define	I40E_710_MAX_TC_QUEUES	64
#define	I40E_722_MAX_TC_QUEUES	128

/*
 * Define the size of the HLUT table size. The HLUT table can either be 128 or
 * 512 bytes. We always set the table size to be 512 bytes in i40e_chip_start().
 * Note, this should not be confused with the common code's macro
 * I40E_HASH_LUT_SIZE_512 which is the bit pattern needed to tell the card to
 * use a 512 byte HLUT.
 */
#define	I40E_HLUT_TABLE_SIZE	512

/*
 * Bit flags for attach_progress
 */
typedef enum i40e_attach_state {
	I40E_ATTACH_PCI_CONFIG	= 0x0001,	/* PCI config setup */
	I40E_ATTACH_REGS_MAP	= 0x0002,	/* Registers mapped */
	I40E_ATTACH_PROPS	= 0x0004,	/* Properties initialized */
	I40E_ATTACH_ALLOC_INTR	= 0x0008,	/* Interrupts allocated */
	I40E_ATTACH_ALLOC_RINGSLOCKS	= 0x0010, /* Rings & locks allocated */
	I40E_ATTACH_ADD_INTR	= 0x0020,	/* Intr handlers added */
	I40E_ATTACH_COMMON_CODE	= 0x0040, 	/* Intel code initialized */
	I40E_ATTACH_INIT	= 0x0080,	/* Device initialized */
	I40E_ATTACH_STATS	= 0x0200,	/* Kstats created */
	I40E_ATTACH_MAC		= 0x0800,	/* MAC registered */
	I40E_ATTACH_ENABLE_INTR	= 0x1000,	/* DDI interrupts enabled */
	I40E_ATTACH_FM_INIT	= 0x2000,	/* FMA initialized */
	I40E_ATTACH_LINK_TIMER	= 0x4000,	/* link check timer */
} i40e_attach_state_t;


/*
 * State flags that what's going on in in the device. Some of these state flags
 * indicate some aspirational work that needs to happen in the driver.
 *
 * I40E_UNKNOWN:	The device has yet to be started.
 * I40E_INITIALIZED:	The device has been fully attached.
 * I40E_STARTED:	The device has come out of the GLDV3 start routine.
 * I40E_SUSPENDED:	The device is suspended and I/O among other things
 * 			should not occur. This happens because of an actual
 * 			DDI_SUSPEND or interrupt adjustments.
 * I40E_STALL:		The tx stall detection logic has found a stall.
 * I40E_OVERTEMP:	The device has encountered a temperature alarm.
 * I40E_INTR_ADJUST:	Our interrupts are being manipulated and therefore we
 * 			shouldn't be manipulating their state.
 * I40E_ERROR:		We've detected an FM error and degraded the device.
 */
typedef enum i40e_state {
	I40E_UNKNOWN		= 0x00,
	I40E_INITIALIZED	= 0x01,
	I40E_STARTED		= 0x02,
	I40E_SUSPENDED		= 0x04,
	I40E_STALL		= 0x08,
	I40E_OVERTEMP		= 0x20,
	I40E_INTR_ADJUST	= 0x40,
	I40E_ERROR		= 0x80
} i40e_state_t;


/*
 * Definitions for common Intel things that we use and some slightly more usable
 * names.
 */
typedef struct i40e_hw i40e_hw_t;
typedef struct i40e_aqc_switch_resource_alloc_element_resp i40e_switch_rsrc_t;

/*
 * Handles and addresses of DMA buffers.
 */
typedef struct i40e_dma_buffer {
	caddr_t		dmab_address;		/* Virtual address */
	uint64_t	dmab_dma_address;	/* DMA (Hardware) address */
	ddi_acc_handle_t dmab_acc_handle;	/* Data access handle */
	ddi_dma_handle_t dmab_dma_handle;	/* DMA handle */
	size_t		dmab_size;		/* Buffer size */
	size_t		dmab_len;		/* Data length in the buffer */
} i40e_dma_buffer_t;

/*
 * RX Control Block
 */
typedef struct i40e_rx_control_block {
	mblk_t			*rcb_mp;
	uint32_t		rcb_ref;
	i40e_dma_buffer_t	rcb_dma;
	frtn_t			rcb_free_rtn;
	struct i40e_rx_data	*rcb_rxd;
} i40e_rx_control_block_t;

typedef enum {
	I40E_TX_NONE,
	I40E_TX_COPY,
	I40E_TX_DMA
} i40e_tx_type_t;

typedef struct i40e_tx_desc i40e_tx_desc_t;
typedef union i40e_32byte_rx_desc i40e_rx_desc_t;

typedef struct i40e_tx_control_block {
	struct i40e_tx_control_block	*tcb_next;
	mblk_t				*tcb_mp;
	i40e_tx_type_t			tcb_type;
	ddi_dma_handle_t		tcb_dma_handle;
	i40e_dma_buffer_t		tcb_dma;
} i40e_tx_control_block_t;

/*
 * Receive ring data (used below).
 */
typedef struct i40e_rx_data {
	struct i40e	*rxd_i40e;

	/*
	 * RX descriptor ring definitions
	 */
	i40e_dma_buffer_t rxd_desc_area;	/* DMA buffer of rx desc ring */
	i40e_rx_desc_t *rxd_desc_ring;		/* Rx desc ring */
	uint32_t rxd_desc_next;			/* Index of next rx desc */

	/*
	 * RX control block list definitions
	 */
	kmutex_t		rxd_free_lock;	/* Lock to protect free data */
	i40e_rx_control_block_t	*rxd_rcb_area;	/* Array of control blocks */
	i40e_rx_control_block_t	**rxd_work_list; /* Work list of rcbs */
	i40e_rx_control_block_t	**rxd_free_list; /* Free list of rcbs */
	uint32_t		rxd_rcb_free;	/* Number of free rcbs */

	/*
	 * RX software ring settings
	 */
	uint32_t	rxd_ring_size;		/* Rx descriptor ring size */
	uint32_t	rxd_free_list_size;	/* Rx free list size */

	/*
	 * RX outstanding data. This is used to keep track of outstanding loaned
	 * descriptors after we've shut down receiving information. Note these
	 * are protected by the i40e_t`i40e_rx_pending_lock.
	 */
	uint32_t	rxd_rcb_pending;
	boolean_t	rxd_shutdown;
} i40e_rx_data_t;

/*
 * Structures for unicast and multicast addresses. Note that we keep the VSI id
 * around for unicast addresses, since they may belong to different VSIs.
 * However, since all multicast addresses belong to the default VSI, we don't
 * duplicate that information.
 */
typedef struct i40e_uaddr {
	uint8_t iua_mac[ETHERADDRL];
	int	iua_vsi;
} i40e_uaddr_t;

typedef struct i40e_maddr {
	uint8_t ima_mac[ETHERADDRL];
} i40e_maddr_t;

/*
 * Collection of RX statistics on a given queue.
 */
typedef struct i40e_rxq_stat {
	/*
	 * The i40e hardware does not maintain statistics on a per-ring basis,
	 * only on a per-PF and per-VSI level. As such, to satisfy the GLDv3, we
	 * need to maintain our own stats for packets and bytes.
	 */
	kstat_named_t	irxs_bytes;	/* Bytes in on queue */
	kstat_named_t	irxs_packets;	/* Packets in on queue */

	/*
	 * The following set of stats cover non-checksum data path issues.
	 */
	kstat_named_t	irxs_rx_desc_error;	/* Error bit set on desc */
	kstat_named_t	irxs_rx_copy_nomem;	/* allocb failure for copy */
	kstat_named_t	irxs_rx_intr_limit;	/* Hit i40e_rx_limit_per_intr */
	kstat_named_t	irxs_rx_bind_norcb;	/* No replacement rcb free */
	kstat_named_t	irxs_rx_bind_nomp;	/* No mblk_t in bind rcb */

	/*
	 * The following set of statistics covers rx checksum related activity.
	 * These are all primarily set in i40e_rx_hcksum. If rx checksum
	 * activity is disabled, then these should all be zero.
	 */
	kstat_named_t	irxs_hck_v4hdrok;	/* Valid IPv4 Header */
	kstat_named_t	irxs_hck_l4hdrok;	/* Valid L4 Header */
	kstat_named_t	irxs_hck_unknown;	/* !pinfo.known */
	kstat_named_t	irxs_hck_nol3l4p;	/* Missing L3L4P bit in desc */
	kstat_named_t	irxs_hck_iperr;		/* IPE error bit set */
	kstat_named_t	irxs_hck_eiperr;	/* EIPE error bit set */
	kstat_named_t	irxs_hck_l4err;		/* L4E error bit set */
	kstat_named_t	irxs_hck_v6skip;	/* IPv6 case hw fails on */
	kstat_named_t	irxs_hck_set;		/* Total times we set cksum */
	kstat_named_t	irxs_hck_miss;		/* Times with zero cksum bits */
} i40e_rxq_stat_t;

/*
 * Collection of TX Statistics on a given queue
 */
typedef struct i40e_txq_stat {
	kstat_named_t	itxs_bytes;		/* Bytes out on queue */
	kstat_named_t	itxs_packets;		/* Packets out on queue */
	kstat_named_t	itxs_descriptors;	/* Descriptors issued */
	kstat_named_t	itxs_recycled;		/* Descriptors reclaimed */
	/*
	 * Various failure conditions.
	 */
	kstat_named_t	itxs_hck_meoifail;	/* ether offload failures */
	kstat_named_t	itxs_hck_nol2info;	/* Missing l2 info */
	kstat_named_t	itxs_hck_nol3info;	/* Missing l3 info */
	kstat_named_t	itxs_hck_nol4info;	/* Missing l4 info */
	kstat_named_t	itxs_hck_badl3;		/* Not IPv4/IPv6 */
	kstat_named_t	itxs_hck_badl4;		/* Bad L4 Paylaod */

	kstat_named_t	itxs_err_notcb;		/* No tcb's available */
	kstat_named_t	itxs_err_nodescs;	/* No tcb's available */
	kstat_named_t	itxs_err_context;	/* Total context failures */

	kstat_named_t	itxs_num_unblocked;	/* Number of MAC unblocks */
} i40e_txq_stat_t;

/*
 * An instance of an XL710 transmit/receive queue pair. This currently
 * represents a combination of both a transmit and receive ring, though they
 * should really be split apart into separate logical structures. Unfortunately,
 * during initial work we mistakenly joined them together.
 */
typedef struct i40e_trqpair {
	struct i40e *itrq_i40e;

	/* Receive-side structures. */
	kmutex_t itrq_rx_lock;
	mac_ring_handle_t itrq_macrxring; /* Receive ring handle. */
	i40e_rx_data_t *itrq_rxdata;	/* Receive ring rx data. */
	uint64_t itrq_rxgen;		/* Generation number for mac/GLDv3. */
	uint32_t itrq_index;		/* Queue index in the PF */
	uint32_t itrq_rx_intrvec;	/* Receive interrupt vector. */
	boolean_t itrq_intr_poll;	/* True when polling */

	/* Receive-side stats. */
	i40e_rxq_stat_t	itrq_rxstat;
	kstat_t	*itrq_rxkstat;

	/* Transmit-side structures. */
	kmutex_t itrq_tx_lock;
	mac_ring_handle_t itrq_mactxring; /* Transmit ring handle. */
	uint32_t itrq_tx_intrvec;	/* Transmit interrupt vector. */
	boolean_t itrq_tx_blocked;	/* Does MAC think we're blocked? */

	/*
	 * TX data sizing
	 */
	uint32_t		itrq_tx_ring_size;
	uint32_t		itrq_tx_free_list_size;

	/*
	 * TX descriptor ring data
	 */
	i40e_dma_buffer_t	itrq_desc_area;	/* DMA buffer of tx desc ring */
	i40e_tx_desc_t		*itrq_desc_ring; /* TX Desc ring */
	volatile uint32_t 	*itrq_desc_wbhead; /* TX write-back index */
	uint32_t		itrq_desc_head;	/* Last index hw freed */
	uint32_t		itrq_desc_tail;	/* Index of next free desc */
	uint32_t		itrq_desc_free;	/* Number of free descriptors */

	/*
	 * TX control block (tcb) data
	 */
	kmutex_t		itrq_tcb_lock;
	i40e_tx_control_block_t	*itrq_tcb_area;	/* Array of control blocks */
	i40e_tx_control_block_t	**itrq_tcb_work_list;	/* In use tcb */
	i40e_tx_control_block_t	**itrq_tcb_free_list;	/* Available tcb */
	uint32_t		itrq_tcb_free;	/* Count of free tcb */

	/* Transmit-side stats. */
	i40e_txq_stat_t		itrq_txstat;
	kstat_t			*itrq_txkstat;

} i40e_trqpair_t;

/*
 * VSI statistics.
 *
 * This mirrors the i40e_eth_stats structure but transforms it into a kstat.
 * Note that the stock statistic structure also includes entries for tx
 * discards. However, this is not actually implemented for the VSI (see Table
 * 7-221), hence why we don't include the member which would always have a value
 * of zero. This choice was made to minimize confusion to someone looking at
 * these, as a value of zero does not necessarily equate to the fact that it's
 * not implemented.
 */
typedef struct i40e_vsi_stats {
	uint64_t ivs_rx_bytes;			/* gorc */
	uint64_t ivs_rx_unicast;		/* uprc */
	uint64_t ivs_rx_multicast;		/* mprc */
	uint64_t ivs_rx_broadcast;		/* bprc */
	uint64_t ivs_rx_discards;		/* rdpc */
	uint64_t ivs_rx_unknown_protocol;	/* rupp */
	uint64_t ivs_tx_bytes;			/* gotc */
	uint64_t ivs_tx_unicast;		/* uptc */
	uint64_t ivs_tx_multicast;		/* mptc */
	uint64_t ivs_tx_broadcast;		/* bptc */
	uint64_t ivs_tx_errors;			/* tepc */
} i40e_vsi_stats_t;

typedef struct i40e_vsi_kstats {
	kstat_named_t	ivk_rx_bytes;
	kstat_named_t	ivk_rx_unicast;
	kstat_named_t	ivk_rx_multicast;
	kstat_named_t	ivk_rx_broadcast;
	kstat_named_t	ivk_rx_discards;
	kstat_named_t	ivk_rx_unknown_protocol;
	kstat_named_t	ivk_tx_bytes;
	kstat_named_t	ivk_tx_unicast;
	kstat_named_t	ivk_tx_multicast;
	kstat_named_t	ivk_tx_broadcast;
	kstat_named_t	ivk_tx_errors;
} i40e_vsi_kstats_t;

/*
 * For pf statistics, we opt not to use the standard statistics as defined by
 * the Intel common code. This also currently combines statistics that are
 * global across the entire device.
 */
typedef struct i40e_pf_stats {
	uint64_t ips_rx_bytes;			/* gorc */
	uint64_t ips_rx_unicast;		/* uprc */
	uint64_t ips_rx_multicast;		/* mprc */
	uint64_t ips_rx_broadcast;		/* bprc */
	uint64_t ips_tx_bytes;			/* gotc */
	uint64_t ips_tx_unicast;		/* uptc */
	uint64_t ips_tx_multicast;		/* mptc */
	uint64_t ips_tx_broadcast;		/* bptc */

	uint64_t ips_rx_size_64;		/* prc64 */
	uint64_t ips_rx_size_127;		/* prc127 */
	uint64_t ips_rx_size_255;		/* prc255 */
	uint64_t ips_rx_size_511;		/* prc511 */
	uint64_t ips_rx_size_1023;		/* prc1023 */
	uint64_t ips_rx_size_1522;		/* prc1522 */
	uint64_t ips_rx_size_9522;		/* prc9522 */

	uint64_t ips_tx_size_64;		/* ptc64 */
	uint64_t ips_tx_size_127;		/* ptc127 */
	uint64_t ips_tx_size_255;		/* ptc255 */
	uint64_t ips_tx_size_511;		/* ptc511 */
	uint64_t ips_tx_size_1023;		/* ptc1023 */
	uint64_t ips_tx_size_1522;		/* ptc1522 */
	uint64_t ips_tx_size_9522;		/* ptc9522 */

	uint64_t ips_link_xon_rx;		/* lxonrxc */
	uint64_t ips_link_xoff_rx;		/* lxoffrxc */
	uint64_t ips_link_xon_tx;		/* lxontxc */
	uint64_t ips_link_xoff_tx;		/* lxofftxc */
	uint64_t ips_priority_xon_rx[8];	/* pxonrxc[8] */
	uint64_t ips_priority_xoff_rx[8];	/* pxoffrxc[8] */
	uint64_t ips_priority_xon_tx[8];	/* pxontxc[8] */
	uint64_t ips_priority_xoff_tx[8];	/* pxofftxc[8] */
	uint64_t ips_priority_xon_2_xoff[8];	/* rxon2offcnt[8] */

	uint64_t ips_crc_errors;		/* crcerrs */
	uint64_t ips_illegal_bytes;		/* illerrc */
	uint64_t ips_mac_local_faults;		/* mlfc */
	uint64_t ips_mac_remote_faults;		/* mrfc */
	uint64_t ips_rx_length_errors;		/* rlec */
	uint64_t ips_rx_undersize;		/* ruc */
	uint64_t ips_rx_fragments;		/* rfc */
	uint64_t ips_rx_oversize;		/* roc */
	uint64_t ips_rx_jabber;			/* rjc */
	uint64_t ips_rx_discards;		/* rdpc */
	uint64_t ips_rx_vm_discards;		/* ldpc */
	uint64_t ips_rx_short_discards;		/* mspdc */
	uint64_t ips_tx_dropped_link_down;	/* tdold */
	uint64_t ips_rx_unknown_protocol;	/* rupp */
	uint64_t ips_rx_err1;			/* rxerr1 */
	uint64_t ips_rx_err2;			/* rxerr2 */
} i40e_pf_stats_t;

typedef struct i40e_pf_kstats {
	kstat_named_t ipk_rx_bytes;		/* gorc */
	kstat_named_t ipk_rx_unicast;		/* uprc */
	kstat_named_t ipk_rx_multicast;		/* mprc */
	kstat_named_t ipk_rx_broadcast;		/* bprc */
	kstat_named_t ipk_tx_bytes;		/* gotc */
	kstat_named_t ipk_tx_unicast;		/* uptc */
	kstat_named_t ipk_tx_multicast;		/* mptc */
	kstat_named_t ipk_tx_broadcast;		/* bptc */

	kstat_named_t ipk_rx_size_64;		/* prc64 */
	kstat_named_t ipk_rx_size_127;		/* prc127 */
	kstat_named_t ipk_rx_size_255;		/* prc255 */
	kstat_named_t ipk_rx_size_511;		/* prc511 */
	kstat_named_t ipk_rx_size_1023;		/* prc1023 */
	kstat_named_t ipk_rx_size_1522;		/* prc1522 */
	kstat_named_t ipk_rx_size_9522;		/* prc9522 */

	kstat_named_t ipk_tx_size_64;		/* ptc64 */
	kstat_named_t ipk_tx_size_127;		/* ptc127 */
	kstat_named_t ipk_tx_size_255;		/* ptc255 */
	kstat_named_t ipk_tx_size_511;		/* ptc511 */
	kstat_named_t ipk_tx_size_1023;		/* ptc1023 */
	kstat_named_t ipk_tx_size_1522;		/* ptc1522 */
	kstat_named_t ipk_tx_size_9522;		/* ptc9522 */

	kstat_named_t ipk_link_xon_rx;		/* lxonrxc */
	kstat_named_t ipk_link_xoff_rx;		/* lxoffrxc */
	kstat_named_t ipk_link_xon_tx;		/* lxontxc */
	kstat_named_t ipk_link_xoff_tx;		/* lxofftxc */
	kstat_named_t ipk_priority_xon_rx[8];	/* pxonrxc[8] */
	kstat_named_t ipk_priority_xoff_rx[8];	/* pxoffrxc[8] */
	kstat_named_t ipk_priority_xon_tx[8];	/* pxontxc[8] */
	kstat_named_t ipk_priority_xoff_tx[8];	/* pxofftxc[8] */
	kstat_named_t ipk_priority_xon_2_xoff[8];	/* rxon2offcnt[8] */

	kstat_named_t ipk_crc_errors;		/* crcerrs */
	kstat_named_t ipk_illegal_bytes;	/* illerrc */
	kstat_named_t ipk_mac_local_faults;	/* mlfc */
	kstat_named_t ipk_mac_remote_faults;	/* mrfc */
	kstat_named_t ipk_rx_length_errors;	/* rlec */
	kstat_named_t ipk_rx_undersize;		/* ruc */
	kstat_named_t ipk_rx_fragments;		/* rfc */
	kstat_named_t ipk_rx_oversize;		/* roc */
	kstat_named_t ipk_rx_jabber;		/* rjc */
	kstat_named_t ipk_rx_discards;		/* rdpc */
	kstat_named_t ipk_rx_vm_discards;	/* ldpc */
	kstat_named_t ipk_rx_short_discards;	/* mspdc */
	kstat_named_t ipk_tx_dropped_link_down;	/* tdold */
	kstat_named_t ipk_rx_unknown_protocol;	/* rupp */
	kstat_named_t ipk_rx_err1;		/* rxerr1 */
	kstat_named_t ipk_rx_err2;		/* rxerr2 */
} i40e_pf_kstats_t;

/*
 * Resources that are pooled and specific to a given i40e_t.
 */
typedef struct i40e_func_rsrc {
	uint_t	ifr_nrx_queue;
	uint_t	ifr_nrx_queue_used;
	uint_t	ifr_ntx_queue;
	uint_t	ifr_trx_queue_used;
	uint_t	ifr_nvsis;
	uint_t	ifr_nvsis_used;
	uint_t	ifr_nmacfilt;
	uint_t	ifr_nmacfilt_used;
	uint_t	ifr_nmcastfilt;
	uint_t	ifr_nmcastfilt_used;
} i40e_func_rsrc_t;

/*
 * Main i40e per-instance state.
 */
typedef struct i40e {
	list_node_t	i40e_glink;		/* Global list link */
	list_node_t	i40e_dlink;		/* Device list link */
	kmutex_t	i40e_general_lock;	/* General device lock */

	/*
	 * General Data and management
	 */
	dev_info_t	*i40e_dip;
	int		i40e_instance;
	int		i40e_fm_capabilities;
	uint_t		i40e_state;
	i40e_attach_state_t i40e_attach_progress;
	mac_handle_t	i40e_mac_hdl;
	ddi_periodic_t	i40e_periodic_id;

	/*
	 * Pointers to common code data structures and memory for the common
	 * code.
	 */
	struct i40e_hw				i40e_hw_space;
	struct i40e_osdep			i40e_osdep_space;
	struct i40e_aq_get_phy_abilities_resp	i40e_phy;
	void 					*i40e_aqbuf;

	/*
	 * Device state, switch information, and resources.
	 */
	int			i40e_vsi_id;
	uint16_t		i40e_vsi_num;
	struct i40e_device	*i40e_device;
	i40e_func_rsrc_t	i40e_resources;
	uint16_t		i40e_switch_rsrc_alloc;
	uint16_t		i40e_switch_rsrc_actual;
	i40e_switch_rsrc_t	*i40e_switch_rsrcs;
	i40e_uaddr_t		*i40e_uaddrs;
	i40e_maddr_t		*i40e_maddrs;
	int			i40e_mcast_promisc_count;
	boolean_t		i40e_promisc_on;
	link_state_t		i40e_link_state;
	uint32_t		i40e_link_speed;	/* In Mbps */
	link_duplex_t		i40e_link_duplex;
	uint_t			i40e_sdu;
	uint_t			i40e_frame_max;

	/*
	 * Transmit and receive information, tunables, and MAC info.
	 */
	i40e_trqpair_t	*i40e_trqpairs;
	boolean_t 	i40e_mr_enable;
	int		i40e_num_trqpairs;
	uint_t		i40e_other_itr;

	int		i40e_num_rx_groups;
	int		i40e_num_rx_descs;
	mac_group_handle_t i40e_rx_group_handle;
	uint32_t	i40e_rx_ring_size;
	uint32_t	i40e_rx_buf_size;
	boolean_t	i40e_rx_hcksum_enable;
	uint32_t	i40e_rx_dma_min;
	uint32_t	i40e_rx_limit_per_intr;
	uint_t		i40e_rx_itr;

	int		i40e_num_tx_descs;
	uint32_t	i40e_tx_ring_size;
	uint32_t	i40e_tx_buf_size;
	uint32_t	i40e_tx_block_thresh;
	boolean_t	i40e_tx_hcksum_enable;
	uint32_t	i40e_tx_dma_min;
	uint_t		i40e_tx_itr;

	/*
	 * Interrupt state
	 */
	uint_t		i40e_intr_pri;
	uint_t		i40e_intr_force;
	uint_t		i40e_intr_type;
	int		i40e_intr_cap;
	uint32_t	i40e_intr_count;
	uint32_t	i40e_intr_count_max;
	uint32_t	i40e_intr_count_min;
	size_t		i40e_intr_size;
	ddi_intr_handle_t *i40e_intr_handles;
	ddi_cb_handle_t	i40e_callback_handle;

	/*
	 * DMA attributes. See i40e_transceiver.c for why we have copies of them
	 * in the i40e_t.
	 */
	ddi_dma_attr_t		i40e_static_dma_attr;
	ddi_dma_attr_t		i40e_txbind_dma_attr;
	ddi_device_acc_attr_t	i40e_desc_acc_attr;
	ddi_device_acc_attr_t	i40e_buf_acc_attr;

	/*
	 * The following two fields are used to protect and keep track of
	 * outstanding, loaned buffers to MAC. If we have these, we can't
	 * detach as we have active DMA memory outstanding.
	 */
	kmutex_t	i40e_rx_pending_lock;
	kcondvar_t	i40e_rx_pending_cv;
	uint32_t	i40e_rx_pending;

	/*
	 * PF statistics and VSI statistics.
	 */
	kmutex_t		i40e_stat_lock;
	kstat_t			*i40e_pf_kstat;
	kstat_t			*i40e_vsi_kstat;
	i40e_pf_stats_t		i40e_pf_stat;
	i40e_vsi_stats_t	i40e_vsi_stat;
	uint16_t		i40e_vsi_stat_id;

	/*
	 * Misc. stats and counters that should maybe one day be kstats.
	 */
	uint64_t	i40e_s_link_status_errs;
	uint32_t	i40e_s_link_status_lasterr;
} i40e_t;

/*
 * The i40e_device represents a PCI device which encapsulates multiple physical
 * functions which are represented as an i40e_t. This is used to track the use
 * of pooled resources throughout all of the various devices.
 */
typedef struct i40e_device {
	list_node_t	id_link;
	dev_info_t	*id_parent;
	uint_t		id_pci_bus;
	uint_t		id_pci_device;
	uint_t		id_nfuncs;	/* Total number of functions */
	uint_t		id_nreg;	/* Total number present */
	list_t		id_i40e_list;	/* List of i40e_t's registered */
	i40e_switch_rsrc_t	*id_rsrcs; /* Switch resources for this PF */
	uint_t		id_rsrcs_alloc;	/* Total allocated resources */
	uint_t		id_rsrcs_act;	/* Actual number of resources */
} i40e_device_t;

/* Values for the interrupt forcing on the NIC. */
#define	I40E_INTR_NONE			0
#define	I40E_INTR_MSIX			1
#define	I40E_INTR_MSI			2
#define	I40E_INTR_LEGACY		3

/* Hint that we don't want to do any polling... */
#define	I40E_POLL_NULL			-1

/*
 * Logging functions.
 */
/*PRINTFLIKE2*/
extern void i40e_error(i40e_t *, const char *, ...) __KPRINTFLIKE(2);
/*PRINTFLIKE2*/
extern void i40e_notice(i40e_t *, const char *, ...) __KPRINTFLIKE(2);
/*PRINTFLIKE2*/
extern void i40e_log(i40e_t *, const char *, ...) __KPRINTFLIKE(2);

/*
 * General link handling functions.
 */
extern void i40e_link_check(i40e_t *);
extern void i40e_update_mtu(i40e_t *);

/*
 * FMA functions.
 */
extern int i40e_check_acc_handle(ddi_acc_handle_t);
extern int i40e_check_dma_handle(ddi_dma_handle_t);
extern void i40e_fm_ereport(i40e_t *, char *);

/*
 * Interrupt handlers and interrupt handler setup.
 */
extern void i40e_intr_chip_init(i40e_t *);
extern void i40e_intr_chip_fini(i40e_t *);
extern uint_t i40e_intr_msix(void *, void *);
extern uint_t i40e_intr_msi(void *, void *);
extern uint_t i40e_intr_legacy(void *, void *);
extern void i40e_intr_io_enable_all(i40e_t *);
extern void i40e_intr_io_disable_all(i40e_t *);
extern void i40e_intr_io_clear_cause(i40e_t *);
extern void i40e_intr_rx_queue_disable(i40e_trqpair_t *);
extern void i40e_intr_rx_queue_enable(i40e_trqpair_t *);
extern void i40e_intr_set_itr(i40e_t *, i40e_itr_index_t, uint_t);

/*
 * Receive-side functions
 */
extern mblk_t *i40e_ring_rx(i40e_trqpair_t *, int);
extern mblk_t *i40e_ring_rx_poll(void *, int);
extern void i40e_rx_recycle(caddr_t);

/*
 * Transmit-side functions
 */
mblk_t *i40e_ring_tx(void *, mblk_t *);
extern void i40e_tx_recycle_ring(i40e_trqpair_t *);
extern void i40e_tx_cleanup_ring(i40e_trqpair_t *);

/*
 * Statistics functions.
 */
extern boolean_t i40e_stats_init(i40e_t *);
extern void i40e_stats_fini(i40e_t *);
extern boolean_t i40e_stat_vsi_init(i40e_t *);
extern void i40e_stat_vsi_fini(i40e_t *);
extern boolean_t i40e_stats_trqpair_init(i40e_trqpair_t *);
extern void i40e_stats_trqpair_fini(i40e_trqpair_t *);
extern int i40e_m_stat(void *, uint_t, uint64_t *);
extern int i40e_rx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);
extern int i40e_tx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);

/*
 * MAC/GLDv3 functions, and functions called by MAC/GLDv3 support code.
 */
extern boolean_t i40e_register_mac(i40e_t *);
extern boolean_t i40e_start(i40e_t *, boolean_t);
extern void i40e_stop(i40e_t *, boolean_t);

/*
 * DMA & buffer functions and attributes
 */
extern void i40e_init_dma_attrs(i40e_t *, boolean_t);
extern boolean_t i40e_alloc_ring_mem(i40e_t *);
extern void i40e_free_ring_mem(i40e_t *, boolean_t);

#ifdef __cplusplus
}
#endif

#endif /* _I40E_SW_H */
