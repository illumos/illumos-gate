/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2009 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 David Höppner. All rights reserved.
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _E1000G_SW_H
#define	_E1000G_SW_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * **********************************************************************
 * Module Name:								*
 *   e1000g_sw.h							*
 *									*
 * Abstract:								*
 *   This header file contains Software-related data structures		*
 *   definitions.							*
 *									*
 * **********************************************************************
 */

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
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/disp.h>
#include <sys/pci.h>
#include <sys/sdt.h>
#include <sys/ethernet.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/netlb.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>
#include "e1000_api.h"

/* Driver states */
#define	E1000G_UNKNOWN			0x00
#define	E1000G_INITIALIZED		0x01
#define	E1000G_STARTED			0x02
#define	E1000G_SUSPENDED		0x04
#define	E1000G_ERROR			0x80

#define	JUMBO_FRAG_LENGTH		4096

#define	LAST_RAR_ENTRY			(E1000_RAR_ENTRIES - 1)
#define	MAX_NUM_UNICAST_ADDRESSES	E1000_RAR_ENTRIES
#define	MCAST_ALLOC_SIZE		256

/*
 * MAX_COOKIES = max_LSO_packet_size(65535 + ethernet_header_len)/page_size
 *	+ one for cross page split
 * MAX_TX_DESC_PER_PACKET = MAX_COOKIES + one for the context descriptor +
 *	two for the workaround of the 82546 chip
 */
#define	MAX_COOKIES			18
#define	MAX_TX_DESC_PER_PACKET		21

/*
 * constants used in setting flow control thresholds
 */
#define	E1000_PBA_MASK		0xffff
#define	E1000_PBA_SHIFT		10
#define	E1000_FC_HIGH_DIFF	0x1638 /* High: 5688 bytes below Rx FIFO size */
#define	E1000_FC_LOW_DIFF	0x1640 /* Low: 5696 bytes below Rx FIFO size */
#define	E1000_FC_PAUSE_TIME	0x0680 /* 858 usec */

#define	MAX_NUM_TX_DESCRIPTOR		4096
#define	MAX_NUM_RX_DESCRIPTOR		4096
#define	MAX_NUM_RX_FREELIST		4096
#define	MAX_NUM_TX_FREELIST		4096
#define	MAX_RX_LIMIT_ON_INTR		4096
#define	MAX_RX_INTR_DELAY		65535
#define	MAX_RX_INTR_ABS_DELAY		65535
#define	MAX_TX_INTR_DELAY		65535
#define	MAX_TX_INTR_ABS_DELAY		65535
#define	MAX_INTR_THROTTLING		65535
#define	MAX_RX_BCOPY_THRESHOLD		E1000_RX_BUFFER_SIZE_2K
#define	MAX_TX_BCOPY_THRESHOLD		E1000_TX_BUFFER_SIZE_2K
#define	MAX_MCAST_NUM			8192

#define	MIN_NUM_TX_DESCRIPTOR		80
#define	MIN_NUM_RX_DESCRIPTOR		80
#define	MIN_NUM_RX_FREELIST		64
#define	MIN_NUM_TX_FREELIST		80
#define	MIN_RX_LIMIT_ON_INTR		16
#define	MIN_RX_INTR_DELAY		0
#define	MIN_RX_INTR_ABS_DELAY		0
#define	MIN_TX_INTR_DELAY		0
#define	MIN_TX_INTR_ABS_DELAY		0
#define	MIN_INTR_THROTTLING		0
#define	MIN_RX_BCOPY_THRESHOLD		0
#define	MIN_TX_BCOPY_THRESHOLD		ETHERMIN
#define	MIN_MCAST_NUM			8

#define	DEFAULT_NUM_RX_DESCRIPTOR	2048
#define	DEFAULT_NUM_TX_DESCRIPTOR	2048
#define	DEFAULT_NUM_RX_FREELIST		4096
#define	DEFAULT_NUM_TX_FREELIST		2304
#define	DEFAULT_JUMBO_NUM_RX_DESC	1024
#define	DEFAULT_JUMBO_NUM_TX_DESC	1024
#define	DEFAULT_JUMBO_NUM_RX_BUF	2048
#define	DEFAULT_JUMBO_NUM_TX_BUF	1152
#define	DEFAULT_RX_LIMIT_ON_INTR	128
#define	RX_FREELIST_INCREASE_SIZE	512

#ifdef __sparc
#define	MAX_INTR_PER_SEC		7100
#define	MIN_INTR_PER_SEC		3000
#define	DEFAULT_INTR_PACKET_LOW		5
#define	DEFAULT_INTR_PACKET_HIGH	128
#else
#define	MAX_INTR_PER_SEC		15000
#define	MIN_INTR_PER_SEC		4000
#define	DEFAULT_INTR_PACKET_LOW		10
#define	DEFAULT_INTR_PACKET_HIGH	48
#endif

#define	DEFAULT_RX_INTR_DELAY		0
#define	DEFAULT_RX_INTR_ABS_DELAY	64
#define	DEFAULT_TX_INTR_DELAY		64
#define	DEFAULT_TX_INTR_ABS_DELAY	64
#define	DEFAULT_INTR_THROTTLING_HIGH    1000000000/(MIN_INTR_PER_SEC*256)
#define	DEFAULT_INTR_THROTTLING_LOW	1000000000/(MAX_INTR_PER_SEC*256)
#define	DEFAULT_INTR_THROTTLING		DEFAULT_INTR_THROTTLING_LOW

#define	DEFAULT_RX_BCOPY_THRESHOLD	128
#define	DEFAULT_TX_BCOPY_THRESHOLD	512
#define	DEFAULT_TX_UPDATE_THRESHOLD	256
#define	DEFAULT_TX_NO_RESOURCE		MAX_TX_DESC_PER_PACKET

#define	DEFAULT_TX_INTR_ENABLE		1
#define	DEFAULT_FLOW_CONTROL		3
#define	DEFAULT_MASTER_LATENCY_TIMER	0	/* BIOS should decide */
						/* which is normally 0x040 */
#define	DEFAULT_TBI_COMPAT_ENABLE	1	/* Enable SBP workaround */
#define	DEFAULT_MSI_ENABLE		1	/* MSI Enable */
#define	DEFAULT_TX_HCKSUM_ENABLE	1	/* Hardware checksum enable */
#define	DEFAULT_LSO_ENABLE		1	/* LSO enable */
#define	DEFAULT_MEM_WORKAROUND_82546	1	/* 82546 memory workaround */

#define	TX_DRAIN_TIME		(200)	/* # milliseconds xmit drain */
#define	RX_DRAIN_TIME		(200)	/* # milliseconds recv drain */

#define	TX_STALL_TIME_2S		(200)	/* in unit of tick */
#define	TX_STALL_TIME_8S		(800)	/* in unit of tick */

/*
 * The size of the receive/transmite buffers
 */
#define	E1000_RX_BUFFER_SIZE_2K		(2048)
#define	E1000_RX_BUFFER_SIZE_4K		(4096)
#define	E1000_RX_BUFFER_SIZE_8K		(8192)
#define	E1000_RX_BUFFER_SIZE_16K	(16384)

#define	E1000_TX_BUFFER_SIZE_2K		(2048)
#define	E1000_TX_BUFFER_SIZE_4K		(4096)
#define	E1000_TX_BUFFER_SIZE_8K		(8192)
#define	E1000_TX_BUFFER_SIZE_16K	(16384)

#define	E1000_TX_BUFFER_OEVRRUN_THRESHOLD	(2015)

#define	E1000G_RX_NORMAL		0x0
#define	E1000G_RX_STOPPED		0x1

#define	E1000G_CHAIN_NO_LIMIT		0

/*
 * definitions for smartspeed workaround
 */
#define	  E1000_SMARTSPEED_MAX		30	/* 30 watchdog iterations */
						/* or 30 seconds */
#define	  E1000_SMARTSPEED_DOWNSHIFT	6	/* 6 watchdog iterations */
						/* or 6 seconds */

/*
 * Definitions for module_info.
 */
#define	 WSNAME			"e1000g"	/* module name */

/*
 * Defined for IP header alignment. We also need to preserve space for
 * VLAN tag (4 bytes)
 */
#define	E1000G_IPALIGNROOM		2

/*
 * bit flags for 'attach_progress' which is a member variable in struct e1000g
 */
#define	ATTACH_PROGRESS_PCI_CONFIG	0x0001	/* PCI config setup */
#define	ATTACH_PROGRESS_REGS_MAP	0x0002	/* Registers mapped */
#define	ATTACH_PROGRESS_SETUP		0x0004	/* Setup driver parameters */
#define	ATTACH_PROGRESS_ADD_INTR	0x0008	/* Interrupt added */
#define	ATTACH_PROGRESS_LOCKS		0x0010	/* Locks initialized */
#define	ATTACH_PROGRESS_SOFT_INTR	0x0020	/* Soft interrupt added */
#define	ATTACH_PROGRESS_KSTATS		0x0040	/* Kstats created */
#define	ATTACH_PROGRESS_ALLOC		0x0080	/* DMA resources allocated */
#define	ATTACH_PROGRESS_INIT		0x0100	/* Driver initialization */
/* 0200 used to be PROGRESS_NDD. Now unused */
#define	ATTACH_PROGRESS_MAC		0x0400	/* MAC registered */
#define	ATTACH_PROGRESS_ENABLE_INTR	0x0800	/* DDI interrupts enabled */
#define	ATTACH_PROGRESS_FMINIT		0x1000	/* FMA initiated */

/*
 * Speed and Duplex Settings
 */
#define	GDIAG_10_HALF		1
#define	GDIAG_10_FULL		2
#define	GDIAG_100_HALF		3
#define	GDIAG_100_FULL		4
#define	GDIAG_1000_FULL		6
#define	GDIAG_ANY		7

/*
 * Coexist Workaround RP: 07/04/03
 * 82544 Workaround : Co-existence
 */
#define	MAX_TX_BUF_SIZE		(8 * 1024)

/*
 * Defines for Jumbo Frame
 */
#define	FRAME_SIZE_UPTO_2K	2048
#define	FRAME_SIZE_UPTO_4K	4096
#define	FRAME_SIZE_UPTO_8K	8192
#define	FRAME_SIZE_UPTO_16K	16384
#define	FRAME_SIZE_UPTO_9K	9234

#define	DEFAULT_MTU		ETHERMTU
#define	MAXIMUM_MTU_4K		4096
#define	MAXIMUM_MTU_9K		9216

#define	DEFAULT_FRAME_SIZE	\
	(DEFAULT_MTU + sizeof (struct ether_vlan_header) + ETHERFCSL)
#define	MAXIMUM_FRAME_SIZE	\
	(MAXIMUM_MTU + sizeof (struct ether_vlan_header) + ETHERFCSL)

#define	E1000_LSO_MAXLEN				65535
#define	E1000_LSO_FIRST_DESC_ALIGNMENT_BOUNDARY_4K	4096
#define	E1000_LSO_FIRST_DESC_ALIGNMENT			128

/* Defines for Tx stall check */
#define	E1000G_STALL_WATCHDOG_COUNT	8

#define	MAX_TX_LINK_DOWN_TIMEOUT	8

/* Defines for DVMA */
#ifdef __sparc
#define	E1000G_DEFAULT_DVMA_PAGE_NUM	2
#endif

/*
 * Loopback definitions
 */
#define	E1000G_LB_NONE			0
#define	E1000G_LB_EXTERNAL_1000		1
#define	E1000G_LB_EXTERNAL_100		2
#define	E1000G_LB_EXTERNAL_10		3
#define	E1000G_LB_INTERNAL_PHY		4

/*
 * Private dip list definitions
 */
#define	E1000G_PRIV_DEVI_ATTACH	0x0
#define	E1000G_PRIV_DEVI_DETACH	0x1

/*
 * Tx descriptor LENGTH field mask
 */
#define	E1000G_TBD_LENGTH_MASK		0x000fffff

#define	E1000G_IS_VLAN_PACKET(ptr)				\
	((((struct ether_vlan_header *)(uintptr_t)ptr)->ether_tpid) ==	\
	htons(ETHERTYPE_VLAN))

/*
 * QUEUE_INIT_LIST -- Macro which will init ialize a queue to NULL.
 */
#define	QUEUE_INIT_LIST(_LH)	\
	(_LH)->Flink = (_LH)->Blink = (PSINGLE_LIST_LINK)0

/*
 * IS_QUEUE_EMPTY -- Macro which checks to see if a queue is empty.
 */
#define	IS_QUEUE_EMPTY(_LH)	\
	((_LH)->Flink == (PSINGLE_LIST_LINK)0)

/*
 * QUEUE_GET_HEAD -- Macro which returns the head of the queue, but does
 * not remove the head from the queue.
 */
#define	QUEUE_GET_HEAD(_LH)	((PSINGLE_LIST_LINK)((_LH)->Flink))

/*
 * QUEUE_REMOVE_HEAD -- Macro which removes the head of the head of a queue.
 */
#define	QUEUE_REMOVE_HEAD(_LH)	\
{ \
	PSINGLE_LIST_LINK ListElem; \
	if (ListElem = (_LH)->Flink) \
	{ \
		if (!((_LH)->Flink = ListElem->Flink)) \
			(_LH)->Blink = (PSINGLE_LIST_LINK) 0; \
	} \
}

/*
 * QUEUE_POP_HEAD -- Macro which  will pop the head off of a queue (list),
 *	and return it (this differs from QUEUE_REMOVE_HEAD only in
 *	the 1st line).
 */
#define	QUEUE_POP_HEAD(_LH)	\
	(PSINGLE_LIST_LINK)(_LH)->Flink; \
	{ \
		PSINGLE_LIST_LINK ListElem; \
		ListElem = (_LH)->Flink; \
		if (ListElem) \
		{ \
			(_LH)->Flink = ListElem->Flink; \
			if (!(_LH)->Flink) \
				(_LH)->Blink = (PSINGLE_LIST_LINK)0; \
		} \
	}

/*
 * QUEUE_GET_TAIL -- Macro which returns the tail of the queue, but does not
 *	remove the tail from the queue.
 */
#define	QUEUE_GET_TAIL(_LH)	((PSINGLE_LIST_LINK)((_LH)->Blink))

/*
 * QUEUE_PUSH_TAIL -- Macro which puts an element at the tail (end) of the queue
 */
#define	QUEUE_PUSH_TAIL(_LH, _E)	\
	if ((_LH)->Blink) \
	{ \
		((PSINGLE_LIST_LINK)(_LH)->Blink)->Flink = \
			(PSINGLE_LIST_LINK)(_E); \
		(_LH)->Blink = (PSINGLE_LIST_LINK)(_E); \
	} else { \
		(_LH)->Flink = \
			(_LH)->Blink = (PSINGLE_LIST_LINK)(_E); \
	} \
	(_E)->Flink = (PSINGLE_LIST_LINK)0;

/*
 * QUEUE_PUSH_HEAD -- Macro which puts an element at the head of the queue.
 */
#define	QUEUE_PUSH_HEAD(_LH, _E)	\
	if (!((_E)->Flink = (_LH)->Flink)) \
	{ \
		(_LH)->Blink = (PSINGLE_LIST_LINK)(_E); \
	} \
	(_LH)->Flink = (PSINGLE_LIST_LINK)(_E);

/*
 * QUEUE_GET_NEXT -- Macro which returns the next element linked to the
 *	current element.
 */
#define	QUEUE_GET_NEXT(_LH, _E)		\
	(PSINGLE_LIST_LINK)((((_LH)->Blink) == (_E)) ? \
	(0) : ((_E)->Flink))

/*
 * QUEUE_APPEND -- Macro which appends a queue to the tail of another queue
 */
#define	QUEUE_APPEND(_LH1, _LH2)	\
	if ((_LH2)->Flink) { \
		if ((_LH1)->Flink) { \
			((PSINGLE_LIST_LINK)(_LH1)->Blink)->Flink = \
				((PSINGLE_LIST_LINK)(_LH2)->Flink); \
		} else { \
			(_LH1)->Flink = \
				((PSINGLE_LIST_LINK)(_LH2)->Flink); \
		} \
		(_LH1)->Blink = ((PSINGLE_LIST_LINK)(_LH2)->Blink); \
	}


#define	QUEUE_SWITCH(_LH1, _LH2)					\
	if ((_LH2)->Flink) { 						\
		(_LH1)->Flink = (_LH2)->Flink;				\
		(_LH1)->Blink = (_LH2)->Blink;				\
		(_LH2)->Flink = (_LH2)->Blink = (PSINGLE_LIST_LINK)0;	\
	}

/*
 * Property lookups
 */
#define	E1000G_PROP_EXISTS(d, n)	ddi_prop_exists(DDI_DEV_T_ANY, (d), \
						DDI_PROP_DONTPASS, (n))
#define	E1000G_PROP_GET_INT(d, n)	ddi_prop_get_int(DDI_DEV_T_ANY, (d), \
						DDI_PROP_DONTPASS, (n), -1)

#ifdef E1000G_DEBUG
/*
 * E1000G-specific ioctls ...
 */
#define	E1000G_IOC		((((((('E' << 4) + '1') << 4) \
				+ 'K') << 4) + 'G') << 4)

/*
 * These diagnostic IOCTLS are enabled only in DEBUG drivers
 */
#define	E1000G_IOC_REG_PEEK	(E1000G_IOC | 1)
#define	E1000G_IOC_REG_POKE	(E1000G_IOC | 2)
#define	E1000G_IOC_CHIP_RESET	(E1000G_IOC | 3)

#define	E1000G_PP_SPACE_REG	0	/* PCI memory space	*/
#define	E1000G_PP_SPACE_E1000G	1	/* driver's soft state	*/

typedef struct {
	uint64_t pp_acc_size;	/* It's 1, 2, 4 or 8	*/
	uint64_t pp_acc_space;	/* See #defines below	*/
	uint64_t pp_acc_offset;	/* See regs definition	*/
	uint64_t pp_acc_data;	/* output for peek	*/
				/* input for poke	*/
} e1000g_peekpoke_t;
#endif	/* E1000G_DEBUG */

/*
 * (Internal) return values from ioctl subroutines
 */
enum ioc_reply {
	IOC_INVAL = -1,		/* bad, NAK with EINVAL	*/
	IOC_DONE,		/* OK, reply sent	*/
	IOC_ACK,		/* OK, just send ACK	*/
	IOC_REPLY		/* OK, just send reply	*/
};

/*
 * Named Data (ND) Parameter Management Structure
 */
typedef struct {
	uint32_t ndp_info;
	uint32_t ndp_min;
	uint32_t ndp_max;
	uint32_t ndp_val;
	struct e1000g *ndp_instance;
	char *ndp_name;
} nd_param_t;

/*
 * The entry of the private dip list
 */
typedef struct _private_devi_list {
	dev_info_t *priv_dip;
	uint32_t flag;
	uint32_t pending_rx_count;
	struct _private_devi_list *prev;
	struct _private_devi_list *next;
} private_devi_list_t;

/*
 * A structure that points to the next entry in the queue.
 */
typedef struct _SINGLE_LIST_LINK {
	struct _SINGLE_LIST_LINK *Flink;
} SINGLE_LIST_LINK, *PSINGLE_LIST_LINK;

/*
 * A "ListHead" structure that points to the head and tail of a queue
 */
typedef struct _LIST_DESCRIBER {
	struct _SINGLE_LIST_LINK *volatile Flink;
	struct _SINGLE_LIST_LINK *volatile Blink;
} LIST_DESCRIBER, *PLIST_DESCRIBER;

enum e1000g_bar_type {
	E1000G_BAR_CONFIG = 0,
	E1000G_BAR_IO,
	E1000G_BAR_MEM32,
	E1000G_BAR_MEM64
};

typedef struct {
	enum e1000g_bar_type type;
	int rnumber;
} bar_info_t;

/*
 * Address-Length pair structure that stores descriptor info
 */
typedef struct _sw_desc {
	uint64_t address;
	uint32_t length;
} sw_desc_t, *p_sw_desc_t;

typedef struct _desc_array {
	sw_desc_t descriptor[4];
	uint32_t elements;
} desc_array_t, *p_desc_array_t;

typedef enum {
	USE_NONE,
	USE_BCOPY,
	USE_DVMA,
	USE_DMA
} dma_type_t;

typedef struct _dma_buffer {
	caddr_t address;
	uint64_t dma_address;
	ddi_acc_handle_t acc_handle;
	ddi_dma_handle_t dma_handle;
	size_t size;
	size_t len;
} dma_buffer_t, *p_dma_buffer_t;

/*
 * Transmit Control Block (TCB), Ndis equiv of SWPacket This
 * structure stores the additional information that is
 * associated with every packet to be transmitted. It stores the
 * message block pointer and the TBD addresses associated with
 * the m_blk and also the link to the next tcb in the chain
 */
typedef struct _tx_sw_packet {
	/* Link to the next tx_sw_packet in the list */
	SINGLE_LIST_LINK Link;
	mblk_t *mp;
	uint32_t num_desc;
	uint32_t num_mblk_frag;
	dma_type_t dma_type;
	dma_type_t data_transfer_type;
	ddi_dma_handle_t tx_dma_handle;
	dma_buffer_t tx_buf[1];
	sw_desc_t desc[MAX_TX_DESC_PER_PACKET];
	int64_t tickstamp;
} tx_sw_packet_t, *p_tx_sw_packet_t;

/*
 * This structure is similar to the rx_sw_packet structure used
 * for Ndis. This structure stores information about the 2k
 * aligned receive buffer into which the FX1000 DMA's frames.
 * This structure is maintained as a linked list of many
 * receiver buffer pointers.
 */
typedef struct _rx_sw_packet {
	/* Link to the next rx_sw_packet_t in the list */
	SINGLE_LIST_LINK Link;
	struct _rx_sw_packet *next;
	uint32_t ref_cnt;
	mblk_t *mp;
	caddr_t rx_data;
	dma_type_t dma_type;
	frtn_t free_rtn;
	dma_buffer_t rx_buf[1];
} rx_sw_packet_t, *p_rx_sw_packet_t;

typedef struct _mblk_list {
	mblk_t *head;
	mblk_t *tail;
} mblk_list_t, *p_mblk_list_t;

typedef struct _context_data {
	uint32_t ether_header_size;
	uint32_t cksum_flags;
	uint32_t cksum_start;
	uint32_t cksum_stuff;
	uint16_t mss;
	uint8_t hdr_len;
	uint32_t pay_len;
	boolean_t lso_flag;
} context_data_t;

typedef union _e1000g_ether_addr {
	struct {
		uint32_t high;
		uint32_t low;
	} reg;
	struct {
		uint8_t set;
		uint8_t redundant;
		uint8_t addr[ETHERADDRL];
	} mac;
} e1000g_ether_addr_t;

typedef struct _e1000g_stat {
	kstat_named_t reset_count;	/* Reset Count */

	kstat_named_t rx_error;		/* Rx Error in Packet */
	kstat_named_t rx_allocb_fail;	/* Rx Allocb Failure */
	kstat_named_t rx_size_error;	/* Rx Size Error */

	kstat_named_t tx_no_desc;	/* Tx No Desc */
	kstat_named_t tx_no_swpkt;	/* Tx No Pkt Buffer */
	kstat_named_t tx_send_fail;	/* Tx SendPkt Failure */
	kstat_named_t tx_over_size;	/* Tx Pkt Too Long */
	kstat_named_t tx_reschedule;	/* Tx Reschedule */

#ifdef E1000G_DEBUG
	kstat_named_t rx_none;		/* Rx No Incoming Data */
	kstat_named_t rx_multi_desc;	/* Rx Multi Spanned Pkt */
	kstat_named_t rx_no_freepkt;	/* Rx No Free Pkt */
	kstat_named_t rx_avail_freepkt;	/* Rx Freelist Avail Buffers */

	kstat_named_t tx_under_size;	/* Tx Packet Under Size */
	kstat_named_t tx_empty_frags;	/* Tx Empty Frags */
	kstat_named_t tx_exceed_frags;	/* Tx Exceed Max Frags */
	kstat_named_t tx_recycle;	/* Tx Recycle */
	kstat_named_t tx_recycle_intr;	/* Tx Recycle in Intr */
	kstat_named_t tx_recycle_retry;	/* Tx Recycle Retry */
	kstat_named_t tx_recycle_none;	/* Tx No Desc Recycled */
	kstat_named_t tx_copy;		/* Tx Send Copy */
	kstat_named_t tx_bind;		/* Tx Send Bind */
	kstat_named_t tx_multi_copy;	/* Tx Copy Multi Fragments */
	kstat_named_t tx_multi_cookie;	/* Tx Pkt Span Multi Cookies */
	kstat_named_t tx_lack_desc;	/* Tx Lack of Desc */
#endif

	kstat_named_t Symerrs;	/* Symbol Error Count */
	kstat_named_t Mpc;	/* Missed Packet Count */
	kstat_named_t Rlec;	/* Receive Length Error Count */
	kstat_named_t Xonrxc;	/* XON Received Count */
	kstat_named_t Xontxc;	/* XON Xmitted Count */
	kstat_named_t Xoffrxc;	/* XOFF Received Count */
	kstat_named_t Xofftxc;	/* Xoff Xmitted Count */
	kstat_named_t Fcruc;	/* Unknown Flow Conrol Packet Rcvd Count */
#ifdef E1000G_DEBUG
	kstat_named_t Prc64;	/* Packets Received - 64b */
	kstat_named_t Prc127;	/* Packets Received - 65-127b */
	kstat_named_t Prc255;	/* Packets Received - 127-255b */
	kstat_named_t Prc511;	/* Packets Received - 256-511b */
	kstat_named_t Prc1023;	/* Packets Received - 511-1023b */
	kstat_named_t Prc1522;	/* Packets Received - 1024-1522b */
#endif
	kstat_named_t Gprc;	/* Good Packets Received Count */
	kstat_named_t Gptc;	/* Good Packets Xmitted Count */
	kstat_named_t Gorl;	/* Good Octets Recvd Lo Count */
	kstat_named_t Gorh;	/* Good Octets Recvd Hi Count */
	kstat_named_t Gotl;	/* Good Octets Xmitd Lo Count */
	kstat_named_t Goth;	/* Good Octets Xmitd Hi Count */
	kstat_named_t Rfc;	/* Receive Frag Count */
#ifdef E1000G_DEBUG
	kstat_named_t Ptc64;	/* Packets Xmitted (64b) */
	kstat_named_t Ptc127;	/* Packets Xmitted (64-127b) */
	kstat_named_t Ptc255;	/* Packets Xmitted (128-255b) */
	kstat_named_t Ptc511;	/* Packets Xmitted (255-511b) */
	kstat_named_t Ptc1023;	/* Packets Xmitted (512-1023b) */
	kstat_named_t Ptc1522;	/* Packets Xmitted (1024-1522b */
#endif
	kstat_named_t Tncrs;	/* Transmit with no CRS */
	kstat_named_t Tsctc;	/* TCP seg contexts xmit count */
	kstat_named_t Tsctfc;	/* TCP seg contexts xmit fail count */
} e1000g_stat_t, *p_e1000g_stat_t;

typedef struct _e1000g_tx_ring {
	kmutex_t tx_lock;
	kmutex_t freelist_lock;
	kmutex_t usedlist_lock;
	/*
	 * Descriptor queue definitions
	 */
	ddi_dma_handle_t tbd_dma_handle;
	ddi_acc_handle_t tbd_acc_handle;
	struct e1000_tx_desc *tbd_area;
	uint64_t tbd_dma_addr;
	struct e1000_tx_desc *tbd_first;
	struct e1000_tx_desc *tbd_last;
	struct e1000_tx_desc *tbd_oldest;
	struct e1000_tx_desc *tbd_next;
	uint32_t tbd_avail;
	/*
	 * Software packet structures definitions
	 */
	p_tx_sw_packet_t packet_area;
	LIST_DESCRIBER used_list;
	LIST_DESCRIBER free_list;
	/*
	 * TCP/UDP Context Data Information
	 */
	context_data_t pre_context;
	/*
	 * Timer definitions for 82547
	 */
	timeout_id_t timer_id_82547;
	boolean_t timer_enable_82547;
	/*
	 * reschedule when tx resource is available
	 */
	boolean_t resched_needed;
	clock_t resched_timestamp;
	mblk_list_t mblks;
	/*
	 * Statistics
	 */
	uint32_t stat_no_swpkt;
	uint32_t stat_no_desc;
	uint32_t stat_send_fail;
	uint32_t stat_reschedule;
	uint32_t stat_timer_reschedule;
	uint32_t stat_over_size;
#ifdef E1000G_DEBUG
	uint32_t stat_under_size;
	uint32_t stat_exceed_frags;
	uint32_t stat_empty_frags;
	uint32_t stat_recycle;
	uint32_t stat_recycle_intr;
	uint32_t stat_recycle_retry;
	uint32_t stat_recycle_none;
	uint32_t stat_copy;
	uint32_t stat_bind;
	uint32_t stat_multi_copy;
	uint32_t stat_multi_cookie;
	uint32_t stat_lack_desc;
	uint32_t stat_lso_header_fail;
#endif
	/*
	 * Pointer to the adapter
	 */
	struct e1000g *adapter;
} e1000g_tx_ring_t, *pe1000g_tx_ring_t;

typedef struct _e1000g_rx_data {
	kmutex_t freelist_lock;
	kmutex_t recycle_lock;
	/*
	 * Descriptor queue definitions
	 */
	ddi_dma_handle_t rbd_dma_handle;
	ddi_acc_handle_t rbd_acc_handle;
	struct e1000_rx_desc *rbd_area;
	uint64_t rbd_dma_addr;
	struct e1000_rx_desc *rbd_first;
	struct e1000_rx_desc *rbd_last;
	struct e1000_rx_desc *rbd_next;
	/*
	 * Software packet structures definitions
	 */
	p_rx_sw_packet_t packet_area;
	LIST_DESCRIBER recv_list;
	LIST_DESCRIBER free_list;
	LIST_DESCRIBER recycle_list;
	uint32_t flag;

	uint32_t pending_count;
	uint32_t avail_freepkt;
	uint32_t recycle_freepkt;
	uint32_t rx_mblk_len;
	mblk_t *rx_mblk;
	mblk_t *rx_mblk_tail;

	private_devi_list_t *priv_devi_node;
	struct _e1000g_rx_ring *rx_ring;
} e1000g_rx_data_t;

typedef struct _e1000g_rx_ring {
	e1000g_rx_data_t *rx_data;

	kmutex_t rx_lock;

	mac_ring_handle_t mrh;
	mac_ring_handle_t mrh_init;
	uint64_t ring_gen_num;
	boolean_t poll_flag;

	/*
	 * Statistics
	 */
	uint32_t stat_error;
	uint32_t stat_allocb_fail;
	uint32_t stat_exceed_pkt;
	uint32_t stat_size_error;
	uint32_t stat_crc_only_pkt;
#ifdef E1000G_DEBUG
	uint32_t stat_none;
	uint32_t stat_multi_desc;
	uint32_t stat_no_freepkt;
#endif
	/*
	 * Pointer to the adapter
	 */
	struct e1000g *adapter;
} e1000g_rx_ring_t, *pe1000g_rx_ring_t;

typedef struct e1000g {
	int instance;
	dev_info_t *dip;
	dev_info_t *priv_dip;
	private_devi_list_t *priv_devi_node;
	mac_handle_t mh;
	mac_resource_handle_t mrh;
	struct e1000_hw shared;
	struct e1000g_osdep osdep;

	uint32_t e1000g_state;
	boolean_t e1000g_promisc;
	boolean_t strip_crc;
	boolean_t rx_buffer_setup;
	boolean_t esb2_workaround;
	link_state_t link_state;
	uint64_t link_speed;
	uint32_t link_duplex;
	uint32_t master_latency_timer;
	uint32_t smartspeed;	/* smartspeed w/a counter */
	uint32_t init_count;
	uint32_t reset_count;
	boolean_t reset_flag;
	uint32_t stall_threshold;
	boolean_t stall_flag;
	uint32_t attach_progress;	/* attach tracking */
	uint32_t loopback_mode;
	uint32_t pending_rx_count;

	uint32_t align_errors;
	uint32_t brdcstrcv;
	uint32_t brdcstxmt;
	uint32_t carrier_errors;
	uint32_t collisions;
	uint32_t defer_xmts;
	uint32_t ex_collisions;
	uint32_t fcs_errors;
	uint32_t first_collisions;
	uint32_t ipackets;
	uint32_t jabber_errors;
	uint32_t macrcv_errors;
	uint32_t macxmt_errors;
	uint32_t multi_collisions;
	uint32_t multircv;
	uint32_t multixmt;
	uint32_t norcvbuf;
	uint32_t oerrors;
	uint32_t opackets;
	uint32_t sqe_errors;
	uint32_t toolong_errors;
	uint32_t tooshort_errors;
	uint32_t tx_late_collisions;
	uint64_t obytes;
	uint64_t rbytes;

	uint32_t tx_desc_num;
	uint32_t tx_freelist_num;
	uint32_t rx_desc_num;
	uint32_t rx_freelist_num;
	uint32_t rx_freelist_limit;
	uint32_t tx_buffer_size;
	uint32_t rx_buffer_size;

	uint32_t tx_link_down_timeout;
	uint32_t tx_bcopy_thresh;
	uint32_t rx_limit_onintr;
	uint32_t rx_bcopy_thresh;
	uint32_t rx_buf_align;
	uint32_t desc_align;

	boolean_t intr_adaptive;
	boolean_t tx_intr_enable;
	uint32_t tx_intr_delay;
	uint32_t tx_intr_abs_delay;
	uint32_t rx_intr_delay;
	uint32_t rx_intr_abs_delay;
	uint32_t intr_throttling_rate;

	uint32_t	tx_desc_num_flag:1,
			rx_desc_num_flag:1,
			tx_buf_num_flag:1,
			rx_buf_num_flag:1,
			pad_to_32:28;

	uint32_t default_mtu;
	uint32_t max_mtu;
	uint32_t max_frame_size;
	uint32_t min_frame_size;

	boolean_t watchdog_timer_enabled;
	boolean_t watchdog_timer_started;
	timeout_id_t watchdog_tid;
	boolean_t link_complete;
	timeout_id_t link_tid;

	e1000g_rx_ring_t rx_ring[1];
	e1000g_tx_ring_t tx_ring[1];
	mac_group_handle_t rx_group;

	/*
	 * Rx and Tx packet count for interrupt adaptive setting
	 */
	uint32_t rx_pkt_cnt;
	uint32_t tx_pkt_cnt;

	/*
	 * The watchdog_lock must be held when updateing the
	 * timeout fields in struct e1000g, that is,
	 * watchdog_tid, watchdog_timer_started.
	 */
	kmutex_t watchdog_lock;
	/*
	 * The link_lock protects the link_complete and link_tid
	 * fields in struct e1000g.
	 */
	kmutex_t link_lock;
	/*
	 * The chip_lock assures that the Rx/Tx process must be
	 * stopped while other functions change the hardware
	 * configuration of e1000g card, such as e1000g_reset(),
	 * e1000g_reset_hw() etc are executed.
	 */
	krwlock_t chip_lock;

	boolean_t unicst_init;
	uint32_t unicst_avail;
	uint32_t unicst_total;
	e1000g_ether_addr_t unicst_addr[MAX_NUM_UNICAST_ADDRESSES];

	uint32_t mcast_count;
	uint32_t mcast_max_num;
	uint32_t mcast_alloc_count;
	struct ether_addr *mcast_table;

	ulong_t sys_page_sz;
#ifdef __sparc
	uint_t dvma_page_num;
#endif

	boolean_t msi_enable;
	boolean_t tx_hcksum_enable;
	boolean_t lso_enable;
	boolean_t lso_premature_issue;
	boolean_t mem_workaround_82546;
	int intr_type;
	int intr_cnt;
	int intr_cap;
	size_t intr_size;
	uint_t intr_pri;
	ddi_intr_handle_t *htable;

	int tx_softint_pri;
	ddi_softint_handle_t tx_softint_handle;

	kstat_t *e1000g_ksp;

	boolean_t poll_mode;

	uint16_t phy_ctrl;		/* contents of PHY_CTRL */
	uint16_t phy_status;		/* contents of PHY_STATUS */
	uint16_t phy_an_adv;		/* contents of PHY_AUTONEG_ADV */
	uint16_t phy_an_exp;		/* contents of PHY_AUTONEG_EXP */
	uint16_t phy_ext_status;	/* contents of PHY_EXT_STATUS */
	uint16_t phy_1000t_ctrl;	/* contents of PHY_1000T_CTRL */
	uint16_t phy_1000t_status;	/* contents of PHY_1000T_STATUS */
	uint16_t phy_lp_able;		/* contents of PHY_LP_ABILITY */

	/*
	 * LED Controls
	 */
	kmutex_t e1000g_led_lock;
	boolean_t e1000g_led_setup;
	boolean_t e1000g_emul_blink;
	boolean_t e1000g_emul_state;
	ddi_periodic_t e1000g_blink;

	/*
	 * FMA capabilities
	 */
	int fm_capabilities;

	uint32_t	param_en_1000fdx:1,
			param_en_1000hdx:1,
			param_en_100fdx:1,
			param_en_100hdx:1,
			param_en_10fdx:1,
			param_en_10hdx:1,
			param_autoneg_cap:1,
			param_pause_cap:1,
			param_asym_pause_cap:1,
			param_1000fdx_cap:1,
			param_1000hdx_cap:1,
			param_100t4_cap:1,
			param_100fdx_cap:1,
			param_100hdx_cap:1,
			param_10fdx_cap:1,
			param_10hdx_cap:1,
			param_adv_autoneg:1,
			param_adv_pause:1,
			param_adv_asym_pause:1,
			param_adv_1000fdx:1,
			param_adv_1000hdx:1,
			param_adv_100t4:1,
			param_adv_100fdx:1,
			param_adv_100hdx:1,
			param_adv_10fdx:1,
			param_adv_10hdx:1,
			param_lp_autoneg:1,
			param_lp_pause:1,
			param_lp_asym_pause:1,
			param_lp_1000fdx:1,
			param_lp_1000hdx:1,
			param_lp_100t4:1;

	uint32_t	param_lp_100fdx:1,
			param_lp_100hdx:1,
			param_lp_10fdx:1,
			param_lp_10hdx:1,
			param_pad_to_32:28;

} e1000g_t;


/*
 * Function prototypes
 */
void e1000g_free_priv_devi_node(private_devi_list_t *devi_node);
void e1000g_free_rx_pending_buffers(e1000g_rx_data_t *rx_data);
void e1000g_free_rx_data(e1000g_rx_data_t *rx_data);
int e1000g_alloc_dma_resources(struct e1000g *Adapter);
void e1000g_release_dma_resources(struct e1000g *Adapter);
void e1000g_free_rx_sw_packet(p_rx_sw_packet_t packet, boolean_t full_release);
void e1000g_tx_setup(struct e1000g *Adapter);
void e1000g_rx_setup(struct e1000g *Adapter);
int e1000g_increase_rx_packets(e1000g_rx_data_t *rx_data);

int e1000g_recycle(e1000g_tx_ring_t *tx_ring);
void e1000g_free_tx_swpkt(p_tx_sw_packet_t packet);
void e1000g_tx_freemsg(e1000g_tx_ring_t *tx_ring);
uint_t e1000g_tx_softint_worker(caddr_t arg1, caddr_t arg2);
mblk_t *e1000g_m_tx(void *arg, mblk_t *mp);
mblk_t *e1000g_receive(e1000g_rx_ring_t *rx_ring, mblk_t **tail, uint_t sz);
void e1000g_rxfree_func(p_rx_sw_packet_t packet);

int e1000g_m_stat(void *arg, uint_t stat, uint64_t *val);
int e1000g_init_stats(struct e1000g *Adapter);
int e1000g_rx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);
void e1000_tbi_adjust_stats(struct e1000g *Adapter,
    uint32_t frame_len, uint8_t *mac_addr);

void e1000g_clear_interrupt(struct e1000g *Adapter);
void e1000g_mask_interrupt(struct e1000g *Adapter);
void e1000g_clear_all_interrupts(struct e1000g *Adapter);
void e1000g_clear_tx_interrupt(struct e1000g *Adapter);
void e1000g_mask_tx_interrupt(struct e1000g *Adapter);
void phy_spd_state(struct e1000_hw *hw, boolean_t enable);
void e1000_destroy_hw_mutex(struct e1000_hw *hw);
void e1000_enable_pciex_master(struct e1000_hw *hw);
int e1000g_check_acc_handle(ddi_acc_handle_t handle);
int e1000g_check_dma_handle(ddi_dma_handle_t handle);
void e1000g_fm_ereport(struct e1000g *Adapter, char *detail);
void e1000g_set_fma_flags(int dma_flag);
int e1000g_reset_link(struct e1000g *Adapter);

/*
 * Functions for working around various problems, these used to be from the
 * common code.
 */
s32 e1000_fifo_workaround_82547(struct e1000_hw *hw, u16 length);
void e1000_update_tx_fifo_head_82547(struct e1000_hw *hw, u32 length);
void e1000_set_ttl_workaround_state_82541(struct e1000_hw *hw, bool state);
bool e1000_ttl_workaround_enabled_82541(struct e1000_hw *hw);
s32 e1000_igp_ttl_workaround_82547(struct e1000_hw *hw);

/*
 * I219 specific workarounds
 */
#define	PCICFG_DESC_RING_STATUS	0xe4
#define	FLUSH_DESC_REQUIRED	0x100
extern void e1000g_flush_rx_ring(struct e1000g *);
extern void e1000g_flush_tx_ring(struct e1000g *);

/*
 * Global variables
 */
extern boolean_t e1000g_force_detach;
extern uint32_t e1000g_mblks_pending;
extern kmutex_t e1000g_rx_detach_lock;
extern private_devi_list_t *e1000g_private_devi_list;
extern int e1000g_poll_mode;

#ifdef __cplusplus
}
#endif

#endif	/* _E1000G_SW_H */
