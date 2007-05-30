/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#ifndef _E1000G_SW_H
#define	_E1000G_SW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 *   This driver runs on the following hardware:			*
 *   - Wisemane based PCI gigabit ethernet adapters			*
 *									*
 * Environment:								*
 *   Kernel Mode -							*
 *									*
 * **********************************************************************
 */

#ifdef DEBUG
#define	e1000g_DEBUG
#endif

/*
 *  Solaris Multithreaded GLD wiseman PCI Ethernet Driver
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
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/sdt.h>
#include <sys/ethernet.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/netlb.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include "e1000_hw.h"

/*
 * PCI Command Register Bit Definitions
 * Configuration Space Header
 */
#define	CMD_IO_SPACE			0x0001	/* BIT_0 */
#define	CMD_MEMORY_SPACE		0x0002	/* BIT_1 */
#define	CMD_BUS_MASTER			0x0004	/* BIT_2 */
#define	CMD_SPECIAL_CYCLES		0x0008	/* BIT_3 */

#define	CMD_VGA_PALLETTE_SNOOP		0x0020	/* BIT_5 */
#define	CMD_PARITY_RESPONSE		0x0040	/* BIT_6 */
#define	CMD_WAIT_CYCLE_CONTROL		0x0080	/* BIT_7 */
#define	CMD_SERR_ENABLE			0x0100	/* BIT_8 */
#define	CMD_BACK_TO_BACK		0x0200	/* BIT_9 */

#define	WSDRAINTIME		(200)	/* # milliseconds xmit drain */

#ifdef __sparc
#ifdef _LP64
#define	DWORD_SWAP(value)	(value)
#else
#define	DWORD_SWAP(value)	\
	(uint64_t)((((uint64_t)value & 0x00000000FFFFFFFF) << 32) | \
	(((uint64_t)value & 0xFFFFFFFF00000000) >> 32))
#endif
#else
#define	DWORD_SWAP(value)	(value)
#endif

#define	JUMBO_FRAG_LENGTH		4096

#define	LAST_RAR_ENTRY			(E1000_RAR_ENTRIES - 1)
#define	MAX_NUM_UNICAST_ADDRESSES	E1000_RAR_ENTRIES
#define	MAX_NUM_MULTICAST_ADDRESSES	256

#define	MAX_TX_DESC_PER_PACKET		16

/*
 * constants used in setting flow control thresholds
 */
#define	E1000_PBA_MASK		0xffff
#define	E1000_PBA_SHIFT		10
#define	E1000_FC_HIGH_DIFF	0x1638 /* High: 5688 bytes below Rx FIFO size */
#define	E1000_FC_LOW_DIFF	0x1640 /* Low: 5696 bytes below Rx FIFO size */
#define	E1000_FC_PAUSE_TIME	0x0680 /* 858 usec */

#define	MAXNUMTXDESCRIPTOR		4096
#define	MAXNUMRXDESCRIPTOR		4096
#define	MAXNUMRXFREELIST		4096
#define	MAXNUMTXSWPACKET		4096
#define	MAXNUMRCVPKTONINTR		4096
#define	MAXTXFRAGSLIMIT			1024
#define	MAXTXINTERRUPTDELAYVAL		65535
#define	MAXINTERRUPTTHROTTLINGVAL	65535
#define	MAXRXBCOPYTHRESHOLD		E1000_RX_BUFFER_SIZE_2K
#define	MAXTXBCOPYTHRESHOLD		E1000_TX_BUFFER_SIZE_2K
#define	MAXTXRECYCLELOWWATER		\
	(DEFAULTNUMTXDESCRIPTOR - MAX_TX_DESC_PER_PACKET)
#define	MAXTXRECYCLENUM			DEFAULTNUMTXDESCRIPTOR

#define	MINNUMTXDESCRIPTOR		80
#define	MINNUMRXDESCRIPTOR		80
#define	MINNUMRXFREELIST		64
#define	MINNUMTXSWPACKET		80
#define	MINNUMRCVPKTONINTR		16
#define	MINTXFRAGSLIMIT			2
#define	MINTXINTERRUPTDELAYVAL		0
#define	MININTERRUPTTHROTTLINGVAL	0
#define	MINRXBCOPYTHRESHOLD		0
#define	MINTXBCOPYTHRESHOLD		MINIMUM_ETHERNET_PACKET_SIZE
#define	MINTXRECYCLELOWWATER		MAX_TX_DESC_PER_PACKET
#define	MINTXRECYCLENUM			MAX_TX_DESC_PER_PACKET

#define	DEFAULTNUMTXDESCRIPTOR		2048
#define	DEFAULTNUMRXDESCRIPTOR		2048
#define	DEFAULTNUMRXFREELIST		4096
#define	DEFAULTNUMTXSWPACKET		2048
#define	DEFAULTMAXNUMRCVPKTONINTR	256
#define	DEFAULTTXFRAGSLIMIT		4
#define	DEFAULTFLOWCONTROLVAL		3
#define	DEFAULTTXINTERRUPTDELAYVAL	300
#define	DEFAULTINTERRUPTTHROTTLINGVAL	0x225
#define	DEFAULTMWIENABLEVAL		1	/* Only PCI 450NX chipset */
						/* needs this value to be 0 */
#define	DEFAULTMASTERLATENCYTIMERVAL	0	/* BIOS should decide */
						/* which is normally 0x040 */
#define	DEFAULTRXPCIPRIORITYVAL		1	/* Boolean value */
#define	DEFAULTPROFILEJUMBOTRAFFIC	1	/* Profile Jumbo Traffic */
#define	DEFAULTTBICOMPATIBILITYENABLE	1	/* Enable SBP workaround */
#define	DEFAULTMSIENABLE		1	/* MSI Enable */

#define	DEFAULTRXBCOPYTHRESHOLD		0
#define	DEFAULTTXBCOPYTHRESHOLD		512
#define	DEFAULTTXRECYCLELOWWATER	64
#define	DEFAULTTXRECYCLENUM		128

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

#define	FORCE_BCOPY_EXCEED_FRAGS	0x1
#define	FORCE_BCOPY_UNDER_SIZE		0x2

#define	E1000G_RX_SW_FREE		0x0
#define	E1000G_RX_SW_SENDUP		0x1
#define	E1000G_RX_SW_DETACHED		0x2

/*
 * By default it will print only to log
 */
#define	DEFAULTDEBUGLEVEL		0x004
#define	DEFAULTDISPLAYONLY		0
#define	DEFAULTPRINTONLY		1

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
#define	E1000G_IPALIGNROOM		6
#define	E1000G_IPALIGNPRESERVEROOM	64

#define	E1000G_IMS_TX_INTR	(E1000_IMS_TXDW | E1000_IMS_TXQE)
#define	E1000G_IMC_TX_INTR	(E1000_IMC_TXDW | E1000_IMC_TXQE)
#define	E1000G_ICR_TX_INTR	(E1000_ICR_TXDW | E1000_ICR_TXQE)

/*
 * bit flags for 'attach_progress' which is a member variable in struct e1000g
 */
#define	ATTACH_PROGRESS_SOFTINTR	0x0001	/* Soft interrupt added */
#define	ATTACH_PROGRESS_REGSMAPPED	0x0002	/* registers mapped */
#define	ATTACH_PROGRESS_LOCKS		0x0004	/* locks initialized */
#define	ATTACH_PROGRESS_PCICONFIG	0x0008	/* PCI config set up */
#define	ATTACH_PROGRESS_KSTATS		0x0010	/* kstats created */
#define	ATTACH_PROGRESS_INIT		0x0020	/* reset */
#define	ATTACH_PROGRESS_INTRADDED	0x0040	/* interrupts added */
#define	ATTACH_PROGRESS_MACREGISTERED	0x0080	/* MAC registered */
#define	ATTACH_PROGRESS_PROP		0x0100	/* properties initialized */
#define	ATTACH_PROGRESS_NDD		0x0200	/* NDD initialized */
#define	ATTACH_PROGRESS_INTRENABLED	0x0400	/* DDI interrupts enabled */
#define	ATTACH_PROGRESS_ALLOC		0x0800	/* DMA resources allocated */

/*
 * Speed and Duplex Settings
 */
#define	GDIAG_10_HALF		1
#define	GDIAG_10_FULL		2
#define	GDIAG_100_HALF		3
#define	GDIAG_100_FULL		4
#define	GDIAG_1000_FULL		6
#define	GDIAG_ANY		7
#define	MAX_DEVICES		256

/*
 * Coexist Workaround RP: 07/04/03
 * 82544 Workaround : Co-existence
 */
#define	MAX_TX_BUF_SIZE		(8 * 1024)

#define	ROUNDOFF		0x1000

/*
 * Defines for Jumbo Frame
 */
#define	FRAME_SIZE_UPTO_2K	2048
#define	FRAME_SIZE_UPTO_4K	4096
#define	FRAME_SIZE_UPTO_8K	8192
#define	FRAME_SIZE_UPTO_16K	16384
#define	FRAME_SIZE_UPTO_10K	10500

/*
 * Max microsecond for ITR (Interrupt Throttling Register)
 */
#define	E1000_ITR_MAX_MICROSECOND	0x3fff

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


#define	GET_ETHER_TYPE(ptr)	(\
	(((uint8_t *)&((struct ether_header *)ptr)->ether_type)[0] << 8) | \
	(((uint8_t *)&((struct ether_header *)ptr)->ether_type)[1]))

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

/*
 * Property lookups
 */
#define	E1000G_PROP_EXISTS(d, n)	ddi_prop_exists(DDI_DEV_T_ANY, (d), \
						DDI_PROP_DONTPASS, (n))
#define	E1000G_PROP_GET_INT(d, n)	ddi_prop_get_int(DDI_DEV_T_ANY, (d), \
						DDI_PROP_DONTPASS, (n), -1)

/*
 * Shorthand for the NDD parameters
 */
#define	param_adv_autoneg	nd_params[PARAM_ADV_AUTONEG_CAP].ndp_val
#define	param_adv_pause		nd_params[PARAM_ADV_PAUSE_CAP].ndp_val
#define	param_adv_asym_pause	nd_params[PARAM_ADV_ASYM_PAUSE_CAP].ndp_val
#define	param_adv_1000fdx	nd_params[PARAM_ADV_1000FDX_CAP].ndp_val
#define	param_adv_1000hdx	nd_params[PARAM_ADV_1000HDX_CAP].ndp_val
#define	param_adv_100fdx	nd_params[PARAM_ADV_100FDX_CAP].ndp_val
#define	param_adv_100hdx	nd_params[PARAM_ADV_100HDX_CAP].ndp_val
#define	param_adv_10fdx		nd_params[PARAM_ADV_10FDX_CAP].ndp_val
#define	param_adv_10hdx		nd_params[PARAM_ADV_10HDX_CAP].ndp_val

#define	param_force_speed_duplex nd_params[PARAM_FORCE_SPEED_DUPLEX].ndp_val

#define	param_link_up		nd_params[PARAM_LINK_STATUS].ndp_val
#define	param_link_speed	nd_params[PARAM_LINK_SPEED].ndp_val
#define	param_link_duplex	nd_params[PARAM_LINK_DUPLEX].ndp_val
#define	param_link_autoneg	nd_params[PARAM_LINK_AUTONEG].ndp_val

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
 * NDD parameter indexes, divided into:
 *
 *	read-only parameters describing the hardware's capabilities
 *	read-write parameters controlling the advertised capabilities
 *	read-only parameters describing the partner's capabilities
 *	read-write parameters controlling the force speed and duplex
 *	read-only parameters describing the link state
 *	read-only parameters describing the driver properties
 *	read-write parameters controlling the driver properties
 */
enum {
	PARAM_AUTONEG_CAP,
	PARAM_PAUSE_CAP,
	PARAM_ASYM_PAUSE_CAP,
	PARAM_1000FDX_CAP,
	PARAM_1000HDX_CAP,
	PARAM_100T4_CAP,
	PARAM_100FDX_CAP,
	PARAM_100HDX_CAP,
	PARAM_10FDX_CAP,
	PARAM_10HDX_CAP,

	PARAM_ADV_AUTONEG_CAP,
	PARAM_ADV_PAUSE_CAP,
	PARAM_ADV_ASYM_PAUSE_CAP,
	PARAM_ADV_1000FDX_CAP,
	PARAM_ADV_1000HDX_CAP,
	PARAM_ADV_100T4_CAP,
	PARAM_ADV_100FDX_CAP,
	PARAM_ADV_100HDX_CAP,
	PARAM_ADV_10FDX_CAP,
	PARAM_ADV_10HDX_CAP,

	PARAM_LP_AUTONEG_CAP,
	PARAM_LP_PAUSE_CAP,
	PARAM_LP_ASYM_PAUSE_CAP,
	PARAM_LP_1000FDX_CAP,
	PARAM_LP_1000HDX_CAP,
	PARAM_LP_100T4_CAP,
	PARAM_LP_100FDX_CAP,
	PARAM_LP_100HDX_CAP,
	PARAM_LP_10FDX_CAP,
	PARAM_LP_10HDX_CAP,

	PARAM_FORCE_SPEED_DUPLEX,

	PARAM_LINK_STATUS,
	PARAM_LINK_SPEED,
	PARAM_LINK_DUPLEX,
	PARAM_LINK_AUTONEG,

	PARAM_MAX_FRAME_SIZE,
	PARAM_LOOP_MODE,
	PARAM_INTR_TYPE,

	PARAM_TX_BCOPY_THRESHOLD,
	PARAM_TX_FRAGS_LIMIT,
	PARAM_TX_RECYCLE_LOW_WATER,
	PARAM_TX_RECYCLE_NUM,
	PARAM_TX_INTR_ENABLE,
	PARAM_TX_INTR_DELAY,
	PARAM_RX_BCOPY_THRESHOLD,
	PARAM_RX_PKT_ON_INTR,
	PARAM_RX_RDTR,
	PARAM_RX_RADV,

	PARAM_COUNT
};

static struct ether_addr etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * DMA access attributes <Little Endian Card>
 */
static ddi_device_acc_attr_t accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
};

/*
 * DMA access attributes for receive buffer <Big Endian> for Sparc
 */
#ifdef __sparc
static ddi_device_acc_attr_t accattr2 = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_BE_ACC,
	DDI_STRICTORDER_ACC,
};
#else
static ddi_device_acc_attr_t accattr2 = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
};
#endif

typedef struct _private_devi_list {
	dev_info_t *dip;
	dev_info_t *priv_dip;
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

/*
 * Address-Length pair structure that stores descriptor info
 */
typedef struct _ADDRESS_LENGTH_PAIR {
	uint64_t Address;
	uint32_t Length;
} ADDRESS_LENGTH_PAIR, *PADDRESS_LENGTH_PAIR;

typedef struct _DESCRIPTOR_PAIR {
	ADDRESS_LENGTH_PAIR Descriptor[4];
	uint32_t Elements;
} DESC_ARRAY, *PDESC_ARRAY;

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
} dma_buffer_t, *pdma_buffer_t;

/*
 * Transmit Control Block (TCB), Ndis equiv of SWPacket This
 * structure stores the additional information that is
 * associated with every packet to be transmitted. It stores the
 * message block pointer and the TBD addresses associated with
 * the m_blk and also the link to the next tcb in the chain
 */
typedef struct _TX_SW_PACKET_ {
	/* Link to the next TX_SW_PACKET in the list */
	SINGLE_LIST_LINK Link;
	mblk_t *mp;
	UINT num_desc;
	UINT num_mblk_frag;
	dma_type_t dma_type;
	dma_type_t data_transfer_type;
	ddi_dma_handle_t tx_dma_handle;
	dma_buffer_t tx_buf[1];
	ADDRESS_LENGTH_PAIR desc[MAX_TX_DESC_PER_PACKET + 1];
} TX_SW_PACKET, *PTX_SW_PACKET;

/*
 * This structure is similar to the RX_SW_PACKET structure used
 * for Ndis. This structure stores information about the 2k
 * aligned receive buffer into which the FX1000 DMA's frames.
 * This structure is maintained as a linked list of many
 * receiver buffer pointers.
 */
typedef struct _RX_SW_PACKET {
	/* Link to the next RX_SW_PACKET in the list */
	SINGLE_LIST_LINK Link;
	struct _RX_SW_PACKET *next;
	uint16_t flag;
	mblk_t *mp;
	caddr_t rx_ring;
	dma_type_t dma_type;
	frtn_t free_rtn;
	dma_buffer_t rx_buf[1];
} RX_SW_PACKET, *PRX_SW_PACKET;

typedef struct _e1000g_msg_chain {
	mblk_t *head;
	mblk_t *tail;
	kmutex_t lock;
} e1000g_msg_chain_t;

typedef struct _cksum_data {
	uint32_t ether_header_size;
	uint32_t cksum_flags;
	uint32_t cksum_start;
	uint32_t cksum_stuff;
} cksum_data_t;

/*
 * MultiCast Command Block (MULTICAST_CB) The multicast
 * structure contains an array of multicast addresses and
 * also a count of the total number of addresses.
 */
typedef struct _multicast_cb_t {
	ushort_t mc_count;	/* Number of multicast addresses */
	uchar_t MulticastBuffer[(ETH_LENGTH_OF_ADDRESS *
		MAX_NUM_MULTICAST_ADDRESSES)];
} mltcst_cb_t, *pmltcst_cb_t;

typedef union _e1000g_ether_addr {
	struct {
		uint32_t high;
		uint32_t low;
	} reg;
	struct {
		uint8_t set;
		uint8_t redundant;
		uint8_t addr[NODE_ADDRESS_SIZE];
	} mac;
} e1000g_ether_addr_t;

typedef struct _e1000gstat {

	kstat_named_t link_speed;	/* Link Speed */
	kstat_named_t rx_none;		/* Rx No Incoming Data */
	kstat_named_t rx_error;		/* Rx Error in Packet */
	kstat_named_t rx_exceed_pkt;	/* Rx Exceed Max Pkt Count */
	kstat_named_t rx_multi_desc;	/* Rx Multi Spanned Pkt */
	kstat_named_t rx_no_freepkt;	/* Rx No Free Pkt */
	kstat_named_t rx_avail_freepkt;	/* Rx Freelist Avail Buffers */
	kstat_named_t rx_esballoc_fail;	/* Rx Desballoc Failure */
	kstat_named_t rx_allocb_fail;	/* Rx Allocb Failure */
	kstat_named_t rx_seq_intr;	/* Rx Sequencing Errors Intr */
	kstat_named_t tx_lack_desc;	/* Tx Lack of Desc */
	kstat_named_t tx_no_desc;	/* Tx No Desc */
	kstat_named_t tx_no_swpkt;	/* Tx No Pkt Buffer */
	kstat_named_t tx_send_fail;	/* Tx SendPkt Failure */
	kstat_named_t tx_multi_cookie;	/* Tx Pkt Span Multi Cookies */
	kstat_named_t tx_over_size;	/* Tx Pkt Too Long */
	kstat_named_t tx_under_size;	/* Tx Allocb Failure */
	kstat_named_t tx_reschedule;	/* Tx Reschedule */
	kstat_named_t tx_empty_frags;	/* Tx Empty Frags */
	kstat_named_t tx_exceed_frags;	/* Tx Exceed Max Frags */
	kstat_named_t tx_recycle;	/* Tx Recycle */
	kstat_named_t tx_recycle_retry;	/* Tx Recycle Retry */
	kstat_named_t tx_recycle_intr;	/* Tx Recycle in Intr */
	kstat_named_t tx_recycle_none;	/* Tx No Desc Recycled */
	kstat_named_t tx_copy;		/* Tx Send Copy */
	kstat_named_t tx_bind;		/* Tx Send Bind */
	kstat_named_t tx_multi_copy;	/* Tx Copy Multi Fragments */
	kstat_named_t StallWatchdog;	/* Tx Stall Watchdog */
	kstat_named_t reset_count;	/* Reset Count */
	kstat_named_t intr_type;	/* Interrupt Type */
	kstat_named_t Crcerrs;	/* CRC Error Count */
	kstat_named_t Symerrs;	/* Symbol Error Count */
	kstat_named_t Mpc;	/* Missed Packet Count */
	kstat_named_t Scc;	/* Single Collision Count */
	kstat_named_t Ecol;	/* Excessive Collision Count */
	kstat_named_t Mcc;	/* Multiple Collision Count */
	kstat_named_t Latecol;	/* Late Collision Count */
	kstat_named_t Colc;	/* Collision Count */
	kstat_named_t Dc;	/* Defer Count */
	kstat_named_t Sec;	/* Sequence Error Count */
	kstat_named_t Rlec;	/* Receive Length Error Count */
	kstat_named_t Xonrxc;	/* XON Received Count */
	kstat_named_t Xontxc;	/* XON Xmitted Count */
	kstat_named_t Xoffrxc;	/* XOFF Received Count */
	kstat_named_t Xofftxc;	/* Xoff Xmitted Count */
	kstat_named_t Fcruc;	/* Unknown Flow Conrol Packet Rcvd Count */
	kstat_named_t Prc64;	/* Packets Received - 64b */
	kstat_named_t Prc127;	/* Packets Received - 65-127b */
	kstat_named_t Prc255;	/* Packets Received - 127-255b */
	kstat_named_t Prc511;	/* Packets Received - 256-511b */
	kstat_named_t Prc1023;	/* Packets Received - 511-1023b */
	kstat_named_t Prc1522;	/* Packets Received - 1024-1522b */
	kstat_named_t Gprc;	/* Good Packets Received Count */
	kstat_named_t Bprc;	/* Broadcasts Pkts Received Count */
	kstat_named_t Mprc;	/* Multicast Pkts Received Count */
	kstat_named_t Gptc;	/* Good Packets Xmitted Count */
	kstat_named_t Gorl;	/* Good Octets Recvd Lo Count */
	kstat_named_t Gorh;	/* Good Octets Recvd Hi Count */
	kstat_named_t Gotl;	/* Good Octets Xmitd Lo Count */
	kstat_named_t Goth;	/* Good Octets Xmitd Hi Count */
	kstat_named_t Rnbc;	/* Receive No Buffers Count */
	kstat_named_t Ruc;	/* Receive Undersize Count */
	kstat_named_t Rfc;	/* Receive Frag Count */
	kstat_named_t Roc;	/* Receive Oversize Count */
	kstat_named_t Rjc;	/* Receive Jabber Count */
	kstat_named_t Torl;	/* Total Octets Recvd Lo Count */
	kstat_named_t Torh;	/* Total Octets Recvd Hi Count */
	kstat_named_t Totl;	/* Total Octets Xmted Lo Count */
	kstat_named_t Toth;	/* Total Octets Xmted Hi Count */
	kstat_named_t Tpr;	/* Total Packets Received */
	kstat_named_t Tpt;	/* Total Packets Xmitted */
	kstat_named_t Ptc64;	/* Packets Xmitted (64b) */
	kstat_named_t Ptc127;	/* Packets Xmitted (64-127b) */
	kstat_named_t Ptc255;	/* Packets Xmitted (128-255b) */
	kstat_named_t Ptc511;	/* Packets Xmitted (255-511b) */
	kstat_named_t Ptc1023;	/* Packets Xmitted (512-1023b) */
	kstat_named_t Ptc1522;	/* Packets Xmitted (1024-1522b */
	kstat_named_t Mptc;	/* Multicast Packets Xmited Count */
	kstat_named_t Bptc;	/* Broadcast Packets Xmited Count */
	/*
	 * New Livengood Stat Counters
	 */
	kstat_named_t Algnerrc;	/* Alignment Error count */
	kstat_named_t Tuc;	/* Transmit Underrun count */
	kstat_named_t Rxerrc;	/* Rx Error Count */
	kstat_named_t Tncrs;	/* Transmit with no CRS */
	kstat_named_t Cexterr;	/* Carrier Extension Error count */
	kstat_named_t Rutec;	/* Receive DMA too Early count */
	kstat_named_t Tsctc;	/* TCP seg contexts xmit count */
	kstat_named_t Tsctfc;	/* TCP seg contexts xmit fail count */
	/*
	 * Jumbo Frame Counters
	 */
	kstat_named_t JumboTx_4K;	/* 4k Jumbo Frames Transmitted */
	kstat_named_t JumboRx_4K;	/* 4k Jumbo Frames Received */
	kstat_named_t JumboTx_8K;	/* 8k Jumbo Frames Transmitted */
	kstat_named_t JumboRx_8K;	/* 8k Jumbo Frames Received */
	kstat_named_t JumboTx_16K;	/* 16k Jumbo Frames Transmitted */
	kstat_named_t JumboRx_16K;	/* 16k Jumbo Frames Received */

} e1000gstat, *e1000gstatp;

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
	/*
	 * Software packet structures definitions
	 */
	PTX_SW_PACKET packet_area;
	LIST_DESCRIBER used_list;
	LIST_DESCRIBER free_list;
	/*
	 * TCP/UDP checksum offload
	 */
	cksum_data_t cksum_data;
	/*
	 * Timer definitions for 82547
	 */
	timeout_id_t timer_id_82547;
	boolean_t timer_enable_82547;
	/*
	 * Pointer to the adapter
	 */
	struct e1000g *adapter;
} e1000g_tx_ring_t, *pe1000g_tx_ring_t;

typedef struct _e1000g_rx_ring {
	kmutex_t rx_lock;
	kmutex_t freelist_lock;
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
	PRX_SW_PACKET packet_area;
	LIST_DESCRIBER recv_list;
	LIST_DESCRIBER free_list;
	/*
	 * Pointer to the adapter
	 */
	struct e1000g *adapter;
} e1000g_rx_ring_t, *pe1000g_rx_ring_t;

typedef struct e1000g {
	mac_handle_t mh;
	dev_info_t *dip;
	dev_info_t *priv_dip;
	ddi_acc_handle_t handle;
	ddi_acc_handle_t E1000_handle;		/* Ws-PCI handle to regs */
	int AdapterInstance;
	struct e1000_hw Shared;
	struct e1000g_osdep osdep;

	link_state_t link_state;
	UINT link_speed;
	UINT link_duplex;
	UINT NumRxDescriptors;
	UINT NumRxFreeList;
	UINT NumTxDescriptors;
	UINT NumTxSwPacket;
	UINT MaxNumReceivePackets;
	UINT bar64;
	USHORT TxInterruptDelay;
	USHORT MWIEnable;
	UINT MasterLatencyTimer;
#ifdef e1000g_DEBUG
	UINT DebugLevel;
	UINT DisplayOnly;
	UINT PrintOnly;
#endif
	UINT smartspeed;	/* smartspeed w/a counter */
	uint32_t init_count;
	size_t TxBufferSize;
	size_t RxBufferSize;
	boolean_t intr_adaptive;
	uint32_t intr_throttling_rate;
	timeout_id_t WatchDogTimer_id;
	timeout_id_t link_tid;
	boolean_t link_complete;

	/*
	 * The e1000g_timeout_lock must be held when updateing the
	 * timeout fields in struct e1000g, that is,
	 * WatchDogTimer_id, timeout_enabled, timeout_started.
	 */
	kmutex_t e1000g_timeout_lock;
	/*
	 * The e1000g_linklock protects the link fields in struct e1000g,
	 * such as link_state, link_speed, link_duplex, link_complete, and
	 * link_tid.
	 */
	kmutex_t e1000g_linklock;
	kmutex_t TbiCntrMutex;
	/*
	 * The chip_lock assures that the Rx/Tx process must be
	 * stopped while other functions change the hardware
	 * configuration of e1000g card, such as e1000g_reset(),
	 * e1000g_reset_hw() etc are executed.
	 */
	krwlock_t chip_lock;

	e1000g_rx_ring_t rx_ring[1];
	e1000g_tx_ring_t tx_ring[1];

	uint32_t rx_bcopy_thresh;
	uint32_t tx_bcopy_thresh;
	uint32_t tx_recycle_low_water;
	uint32_t tx_recycle_num;
	uint32_t tx_frags_limit;
	uint32_t tx_link_down_timeout;

	boolean_t tx_intr_enable;
	ddi_softint_handle_t tx_softint_handle;
	int tx_softint_pri;
	/*
	 * Message chain that needs to be freed
	 */
	e1000g_msg_chain_t tx_msg_chain[1];

	mblk_t *rx_mblk;
	mblk_t *rx_mblk_tail;
	USHORT rx_packet_len;

	kstat_t *e1000g_ksp;

	uint32_t rx_none;
	uint32_t rx_error;
	uint32_t rx_exceed_pkt;
	uint32_t rx_multi_desc;
	uint32_t rx_no_freepkt;
	uint32_t rx_esballoc_fail;
	uint32_t rx_avail_freepkt;
	uint32_t rx_allocb_fail;
	uint32_t rx_seq_intr;
	uint32_t tx_lack_desc;
	uint32_t tx_no_desc;
	uint32_t tx_no_swpkt;
	uint32_t tx_send_fail;
	uint32_t tx_multi_cookie;
	uint32_t tx_over_size;
	uint32_t tx_under_size;
	uint32_t tx_reschedule;
	uint32_t tx_empty_frags;
	uint32_t tx_exceed_frags;
	uint32_t tx_recycle;
	uint32_t tx_recycle_retry;
	uint32_t tx_recycle_intr;
	uint32_t tx_recycle_none;
	uint32_t tx_copy;
	uint32_t tx_bind;
	uint32_t tx_multi_copy;

	uint32_t JumboTx_4K;
	uint32_t JumboRx_4K;
	uint32_t JumboTx_8K;
	uint32_t JumboRx_8K;
	uint32_t JumboTx_16K;
	uint32_t JumboRx_16K;

	uint32_t StallWatchdog;
	uint32_t tx_recycle_fail;
	uint32_t reset_count;

	uint32_t unicst_avail;
	uint32_t unicst_total;
	e1000g_ether_addr_t unicst_addr[MAX_NUM_UNICAST_ADDRESSES];

	uint32_t mcast_count;
	struct ether_addr mcast_table[MAX_NUM_MULTICAST_ADDRESSES];

	uint32_t loopback_mode;

	UINT ProfileJumboTraffic;
	UINT RcvBufferAlignment;

	boolean_t timeout_enabled;
	boolean_t timeout_started;

	boolean_t e1000g_promisc;
	boolean_t started;
	mac_resource_handle_t mrh;

	uint32_t attach_progress;	/* attach tracking */
	/*
	 * reschedule when tx resource is available
	 */
	boolean_t resched_needed;

#ifdef __sparc
	ulong_t sys_page_sz;
	uint_t dvma_page_num;
#endif

	boolean_t msi_enabled;
	int intr_type;
	int intr_cnt;
	int intr_cap;
	size_t intr_size;
	uint_t intr_pri;
	ddi_intr_handle_t *htable;

	/*
	 * NDD parameters
	 */
	caddr_t nd_data;
	nd_param_t nd_params[PARAM_COUNT];

} e1000g, *Pe1000g, ADAPTER_STRUCT, *PADAPTER_STRUCT;


static ddi_dma_attr_t tx_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	16,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

static ddi_dma_attr_t buf_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	1,			/* alignment in bytes */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

static ddi_dma_attr_t tbd_dma_attr = {
	DMA_ATTR_V0,		/* version of this structure */
	0,			/* lowest usable address */
	0xffffffffffffffffULL,	/* highest usable address */
	0x7fffffff,		/* maximum DMAable byte count */
	E1000_MDALIGN,		/* alignment in bytes 4K! */
	0x7ff,			/* burst sizes (any?) */
	1,			/* minimum transfer */
	0xffffffffU,		/* maximum transfer */
	0xffffffffffffffffULL,	/* maximum segment length */
	1,			/* maximum number of segments */
	1,			/* granularity */
	0,			/* flags (reserved) */
};

/*
 * Function prototypes
 */
int e1000g_alloc_dma_resources(struct e1000g *Adapter);
void e1000g_release_dma_resources(struct e1000g *Adapter);
void e1000g_free_rx_sw_packet(PRX_SW_PACKET packet);
void SetupTransmitStructures(struct e1000g *Adapter);
void SetupReceiveStructures(struct e1000g *Adapter);
void SetupMulticastTable(struct e1000g *Adapter);
boolean_t e1000g_reset(struct e1000g *Adapter);

int e1000g_recycle(e1000g_tx_ring_t *tx_ring);
void FreeTxSwPacket(PTX_SW_PACKET packet);
uint_t e1000g_tx_freemsg(caddr_t arg1, caddr_t arg2);
mblk_t *e1000g_m_tx(void *arg, mblk_t *mp);
mblk_t *e1000g_receive(struct e1000g *Adapter);
void e1000g_rxfree_func(PRX_SW_PACKET packet);

int e1000g_m_stat(void *arg, uint_t stat, uint64_t *val);
int InitStatsCounters(struct e1000g *Adapter);
void AdjustTbiAcceptedStats(struct e1000g *Adapter, UINT32 FrameLength,
    PUCHAR MacAddress);
enum ioc_reply e1000g_nd_ioctl(struct e1000g *Adapter,
    queue_t *wq, mblk_t *mp, struct iocblk *iocp);
void e1000g_nd_cleanup(struct e1000g *Adapter);
int e1000g_nd_init(struct e1000g *Adapter);

void e1000g_DisableInterrupt(struct e1000g *Adapter);
void e1000g_EnableInterrupt(struct e1000g *Adapter);
void e1000g_DisableAllInterrupts(struct e1000g *Adapter);
void e1000g_DisableTxInterrupt(struct e1000g *Adapter);
void e1000g_EnableTxInterrupt(struct e1000g *Adapter);
void phy_spd_state(struct e1000_hw *hw, boolean_t enable);
void e1000_enable_pciex_master(struct e1000_hw *hw);

/*
 * Global variables
 */
extern boolean_t e1000g_force_detach;
extern uint32_t e1000g_mblks_pending;
extern krwlock_t e1000g_rx_detach_lock;


#ifdef __cplusplus
}
#endif

#endif	/* _E1000G_SW_H */
