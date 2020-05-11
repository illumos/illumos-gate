/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LDC_IMPL_H
#define	_LDC_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ioctl.h>

/* Memory map table entries */
#define	LDC_MTBL_ENTRIES	8192	/* 8 K */

/* Define LDC Queue info */
#define	LDC_PACKET_SHIFT	6
#define	LDC_QUEUE_ENTRIES	512
#define	LDC_MTU_MSGS		4
#define	LDC_QUEUE_SIZE		(LDC_QUEUE_ENTRIES << LDC_PACKET_SHIFT)
#define	LDC_DEFAULT_MTU		(LDC_QUEUE_SIZE / LDC_MTU_MSGS)
#define	LDC_RXDQ_MULTIPLIER	2

/*
 * LDC Reliable mode - initial packet seqid
 * - If peer initiated handshake, RDX should contain init_seqid + 1
 * - If this endpoint initiated handshake first data packet should
 *   contain the message init_seqid + 1
 */
#define	LDC_INIT_SEQID	0x0

/* LDC Message types */
#define	LDC_CTRL	0x01	/* Control Pkt */
#define	LDC_DATA	0x02	/* Data Pkt */
#define	LDC_ERR		0x10	/* Error Pkt */

/* LDC Message Subtypes */
#define	LDC_INFO	0x01	/* Control/Data/Error info pkt */
#define	LDC_ACK		0x02	/* Control/Data ACK */
#define	LDC_NACK	0x04	/* Control/Data NACK */

/* LDC Control Messages */
#define	LDC_VER		0x01	/* Version message */
#define	LDC_RTS		0x02	/* Request to Send */
#define	LDC_RTR		0x03	/* Ready To Receive */
#define	LDC_RDX		0x04	/* Ready for data exchange */

#define	LDC_CTRL_MASK	0x0f	/* Mask to read control bits */

/* LDC Channel Transport State (tstate) */
#define	TS_TXQ_RDY	0x01	/* allocated TX queue */
#define	TS_RXQ_RDY	0x02	/* allocated RX queue */
#define	TS_INIT		(TS_TXQ_RDY | TS_RXQ_RDY)
#define	TS_QCONF_RDY	0x04	/* registered queues with HV */
#define	TS_CNEX_RDY	0x08	/* registered channel with cnex */
#define	TS_OPEN		(TS_INIT | TS_QCONF_RDY | TS_CNEX_RDY)
#define	TS_LINK_READY	0x10	/* both endpts registered Rx queues */
#define	TS_READY	(TS_OPEN | TS_LINK_READY)
#define	TS_VER_DONE	0x20	/* negotiated version */
#define	TS_VREADY	(TS_READY | TS_VER_DONE)
#define	TS_HSHAKE_DONE	0x40	/* completed handshake */
#define	TS_UP		(TS_READY | TS_VER_DONE | TS_HSHAKE_DONE)

#define	TS_IN_RESET	0x100	/* channel is in reset state */

/*  LDC Channel Transport Handshake states */
#define	TS_SENT_VER	0x01	/* Sent version */
#define	TS_SENT_RTS	0x02	/* Sent RTS */
#define	TS_RCVD_RTR	0x04	/* Received RTR */
#define	TS_SENT_RDX	0x08	/* Sent RDX */
#define	TS_RCVD_VER	0x10	/* Received version */
#define	TS_RCVD_RTS	0x20	/* Received RTS */
#define	TS_SENT_RTR	0x40	/* Sent RTR */
#define	TS_RCVD_RDX	0x80	/* Received RDX */

/* LDC Interrupt State */
#define	LDC_INTR_NONE	0x00	/* No interrupts */
#define	LDC_INTR_ACTIVE	0x01	/* Interrupt being processed */
#define	LDC_INTR_PEND	0x02	/* Interrupt pending */

/* LDC MSG Envelope */
#define	LDC_LEN_MASK	0x3F
#define	LDC_FRAG_MASK	0xC0

#define	LDC_FRAG_START	0x40	/* frag_info = 0x01 */
#define	LDC_FRAG_STOP	0x80	/* frag_info = 0x02 */
#define	LDC_FRAG_CONT	0x00	/* frag_info = 0x00 */

/*
 * LDC will retry LDC_MAX_RETRIES times when sending or
 * receiving data or if the HV returns back EWOULDBLOCK.
 * Between each retry it will wait LDC_DELAY usecs.
 */
#define	LDC_MAX_RETRIES	1000
#define	LDC_DELAY	1

/* delay(usec) between channel unregister retries in ldc_close() */
#define	LDC_CLOSE_DELAY	1

/*
 * LDC Version information
 */
#define	LDC_PAYLOAD_VER_OFF	8	/* offset of version in payload */

typedef struct ldc_ver {
	uint16_t	major;
	uint16_t	minor;
} ldc_ver_t;

/*
 * Each guest consists of one or more LDC endpoints represented by a ldc_chan
 * structure. Each ldc_chan structure points to a ldc_mtbl structure that
 * contains information about the map table associated with this LDC endpoint.
 * The map table contains the list of pages being shared by this guest over
 * this endpoint with the guest at the other end of this endpoint. Each LDC
 * endpoint also points to a list of memory handles used to bind and export
 * memory segments from this guest. If a memory segment is bound, it points to
 * a memory segment structure, which inturn consists of an array of ldc_page
 * structure for all the pages within that segment. Each ldc_page structure
 * contains information about the shared page and also points to the
 * corresponding entry in the map table.
 *
 * Each LDC endpoint also points to a list of ldc_dring structures that refer
 * to both imported and exported descriptor rings. If it is a exported
 * descriptor ring, it then points to memory handle/memseg corresponding to
 * the region of memory associated with the descriptor ring.
 *
 *     +----------+   +----------+   +----------+
 *     | ldc_chan |-->| ldc_chan |-->| ldc_chan |-->....
 *     +----------+   +----------+   +----------+
 *       |  |  |
 *       |  |  |
 *       |  |  |      +-----------+     +-----------+
 *       |  |  +----->| ldc_dring |---->| ldc_dring |---->......
 *       |  |         +-----------+     +-----------+
 *       |  |               |
 *       |  |               +----------------------------+
 *       |  |                                            |
 *       |  |                                            v
 *       |  |      +----------+     +----------+     +----------+
 *       |  +----->| ldc_mhdl |---->| ldc_mhdl |---->| ldc_mhdl |---> ....
 *       |         +----------+     +----------+     +----------+
 *       v                 |                             |
 *  +----------+           |    +------------+           |    +------------+
 *  | ldc_mtbl |--+        +--->| ldc_memseg |-----+     +--->| ldc_memseg |
 *  +----------+  |             +------------+     |          +------------+
 *                |                   |            |            |       |
 *                v                   v            v            |       v
 *     +--------------+         +----------+  +--------+        |   +--------+
 *     | ldc_mte_slot |<--------| ldc_page |  | cookie |        |   | cookie |
 *     +--------------+         +----------+  +--------+        |   +--------+
 *     | ldc_mte_slot |<--------| ldc_page |  | cookie |        v
 *     +--------------+         +----------+  +--------+   +----------+
 *     | ldc_mte_slot |<-----------------------------------| ldc_page |
 *     +--------------+                                    +----------+
 *     | ldc_mte_slot |
 *     +--------------+
 *     |    ......    |/ +------------+
 *     +--------------+  |   entry    |
 *     | ldc_mte_slot |  +------------+
 *     +--------------+  | inv_cookie |
 *                     \ +------------+
 *
 */

/*
 * Message format of each packet sent over the LDC channel.
 * Each packet is 64-bytes long.
 *
 * Each packet that is sent over LDC can contain either data or acks.
 * The type will reflect the contents. The len will contain in bytes
 * the amount of data being sent. In the case of ACKs, the seqid and
 * data fields will contain the SEQIDs of messages for which ACKs are
 * being sent.
 *
 * Raw pkt format:
 *
 *          +------------------------------------------------------+
 *  0 - 7   |                 data payload                         |
 *          +------------------------------------------------------+
 *
 * Unreliable pkt format:
 *
 *          +------------------------------------------------------+
 *      0   |          seqid          | env  | ctrl | stype | type |
 *          +------------------------------------------------------+
 *  1 - 7   |                 data payload                         |
 *          +------------------------------------------------------+
 *
 * Reliable pkt format:
 *
 *          +------------------------------------------------------+
 *      0   |            seqid        | env  | ctrl | stype | type |
 *          +------------------------------------------------------+
 *      1   |          ackid          |         unused             |
 *          +------------------------------------------------------+
 *  2 - 7   |                 data payload                         |
 *          +------------------------------------------------------+
 */

typedef struct ldc_msg {
	union {
		struct {
			uint8_t		_type;	/* Message type */
			uint8_t		_stype;	/* Message subtype */
			uint8_t		_ctrl;	/* Control/Error Message */
			uint8_t		_env;	/* Message Envelope */
			uint32_t	_seqid;	/* Sequence ID */

			union {
				uint8_t	_ud[LDC_PAYLOAD_SIZE_UNRELIABLE];
						/* Unreliable data payload */
				struct {
					uint32_t _unused;	/* unused */
					uint32_t _ackid;	/* ACK ID */
					uint8_t	_rd[LDC_PAYLOAD_SIZE_RELIABLE];
						/* Reliable data payload */
				} _rl;
			} _data;
		} _tpkt;

		uint8_t		_raw[LDC_PAYLOAD_SIZE_RAW];
	} _pkt;

} ldc_msg_t;

#define	raw		_pkt._raw
#define	type		_pkt._tpkt._type
#define	stype		_pkt._tpkt._stype
#define	ctrl		_pkt._tpkt._ctrl
#define	env		_pkt._tpkt._env
#define	seqid		_pkt._tpkt._seqid
#define	udata		_pkt._tpkt._data._ud
#define	ackid		_pkt._tpkt._data._rl._ackid
#define	rdata		_pkt._tpkt._data._rl._rd

/*
 * LDC Map Table Entry (MTE)
 *
 *   6    6                               1    1  1
 *  |3    0|                       psz|   3|   1| 0| 9| 8| 7|6|5|4|      0|
 *  +------+--------------------------+----+----+--+--+--+--+-+-+-+-------+
 *  | rsvd |           PFN            | 0  | 0  |CW|CR|IW|IR|X|W|R| pgszc |
 *  +------+--------------------------+----+----+--+--+--+--+-+-+-+-------+
 *  |                       hv invalidation cookie                        |
 *  +---------------------------------------------------------------------+
 */
typedef union {
	struct {
		uint64_t	_rsvd2:8,	/* <63:56> reserved */
				rpfn:43,	/* <55:13> real pfn */
				_rsvd1:2,	/* <12:11> reserved */
				cw:1,		/* <10> copy write access */
				cr:1,		/* <9> copy read perm */
				iw:1,		/* <8> iommu write perm */
				ir:1,		/* <7> iommu read perm */
				x:1,		/* <6> execute perm */
				w:1,		/* <5> write perm */
				r:1,		/* <4> read perm */
				pgszc:4;	/* <3:0> pgsz code */
	} mte_bit;

	uint64_t		ll;

} ldc_mte_t;

#define	mte_rpfn	mte_bit.rpfn
#define	mte_cw		mte_bit.cw
#define	mte_cr		mte_bit.cr
#define	mte_iw		mte_bit.iw
#define	mte_ir		mte_bit.ir
#define	mte_x		mte_bit.x
#define	mte_w		mte_bit.w
#define	mte_r		mte_bit.r
#define	mte_pgszc	mte_bit.pgszc

#define	MTE_BSZS_SHIFT(sz)	((sz) * 3)
#define	MTEBYTES(sz)		(MMU_PAGESIZE << MTE_BSZS_SHIFT(sz))
#define	MTEPAGES(sz)		(1 << MTE_BSZS_SHIFT(sz))
#define	MTE_PAGE_SHIFT(sz)	(MMU_PAGESHIFT + MTE_BSZS_SHIFT(sz))
#define	MTE_PAGE_OFFSET(sz)	(MTEBYTES(sz) - 1)
#define	MTE_PAGEMASK(sz)	(~MTE_PAGE_OFFSET(sz))
#define	MTE_PFNMASK(sz)		(~(MTE_PAGE_OFFSET(sz) >> MMU_PAGESHIFT))

/*
 * LDC Map Table Slot
 */
typedef struct ldc_mte_slot {
	ldc_mte_t	entry;
	uint64_t	cookie;
} ldc_mte_slot_t;

/*
 * LDC Memory Map Table
 *
 * Each LDC has a memory map table it uses to list all the pages
 * it exporting to its peer over the channel. This structure
 * contains information about the map table and is pointed to
 * by the ldc_chan structure.
 */
typedef struct ldc_mtbl {
	kmutex_t		lock;		/* Table lock */
	size_t			size;		/* Table size (in bytes) */
	uint64_t		next_entry;	/* Next entry to use */
	uint64_t		num_entries;	/* Num entries in table */
	uint64_t		num_avail;	/* Num of available entries */
	boolean_t		contigmem;	/* TRUE=Contig mem alloc'd */
	ldc_mte_slot_t		*table;		/* The table itself */
} ldc_mtbl_t;

/*
 * LDC page and memory segment information
 */
typedef struct ldc_page {
	uintptr_t		raddr;		/* Exported page RA */
	uint64_t		index;		/* Index in map table */
	ldc_mte_slot_t		*mte;		/* Map table entry */
} ldc_page_t;

typedef struct ldc_memseg {
	caddr_t			vaddr;		/* Exported segment VA */
	uintptr_t		raddr;		/* Exported segment VA */
	size_t			size;		/* Exported segment size */
	uint64_t		npages;		/* Number of pages */
	ldc_page_t		*pages;		/* Array of exported pages */
	uint32_t		ncookies;	/* Number of cookies */
	ldc_mem_cookie_t	*cookies;
	uint64_t		next_cookie;	/* Index to next cookie */
} ldc_memseg_t;

/*
 * LDC Cookie address format
 *
 *   6       6          m+n
 *  |3|      0|          |                  m|                  0|
 *  +-+-------+----------+-------------------+-------------------+
 *  |X| pgszc |   rsvd   |      table_idx    |     page_offset   |
 *  +-+-------+----------+-------------------+-------------------+
 */
#define	LDC_COOKIE_PGSZC_MASK	0x7
#define	LDC_COOKIE_PGSZC_SHIFT	60

/*
 * LDC Memory handle
 */
typedef struct ldc_chan ldc_chan_t;

typedef struct ldc_mhdl {
	kmutex_t		lock;		/* Mutex for memory handle */
	ldc_mstatus_t		status;		/* Memory map status */

	uint8_t			mtype;		/* Type of sharing */
	uint8_t			perm;		/* Access permissions */
	boolean_t		myshadow;	/* TRUE=alloc'd shadow mem */

	ldc_chan_t		*ldcp;		/* Pointer to channel struct */
	ldc_memseg_t		*memseg;	/* Bound memory segment */
	struct ldc_mhdl		*next;		/* Next memory handle */
} ldc_mhdl_t;

/*
 * LDC Descriptor rings
 */

typedef struct ldc_dring {
	kmutex_t		lock;		/* Desc ring lock */
	ldc_mstatus_t		status;		/* Desc ring status */

	uint32_t		dsize;		/* Descriptor size */
	uint32_t		length;		/* Descriptor ring length */
	uint64_t		size;		/* Desc ring size (in bytes) */
	caddr_t			base;		/* Descriptor ring base addr */

	ldc_chan_t		*ldcp;		/* Pointer to bound channel */
	ldc_mem_handle_t	mhdl;		/* Mem handle to desc ring */

	struct ldc_dring	*ch_next;	/* Next dring in channel */
	struct ldc_dring	*next;		/* Next dring overall */

} ldc_dring_t;


/*
 * Channel specific information is kept in a separate
 * structure. These are then stored on a array indexed
 * by the channel number.
 */
struct ldc_chan {
	ldc_chan_t	*next;		/* Next channel */

	kmutex_t	lock;		/* Channel lock */
	uint64_t	id;		/* Channel ID */
	ldc_status_t	status;		/* Channel status */
	uint32_t	tstate;		/* Channel transport state */
	uint32_t	hstate;		/* Channel transport handshake state */

	ldc_dev_t	devclass;	/* Associated device class */
	uint64_t	devinst;	/* Associated device instance */
	ldc_mode_t	mode;		/* Channel mode */

	uint64_t	mtu;		/* Max TU size */

	ldc_ver_t	version;	/* Channel version */
	uint32_t	next_vidx;	/* Next version to match */

	uint_t		(*cb)(uint64_t event, caddr_t arg);
	caddr_t		cb_arg;		/* Channel callback and arg */
	boolean_t	cb_inprogress;	/* Channel callback in progress */
	boolean_t	cb_enabled;	/* Channel callbacks are enabled */

	uint8_t		tx_intr_state;	/* Tx interrupt state */
	uint8_t		rx_intr_state;	/* Rx interrupt state */

	kmutex_t	tx_lock;	/* Transmit lock */
	uint64_t	tx_q_entries;	/* Num entries in transmit queue */
	uint64_t	tx_q_va;	/* Virtual addr of transmit queue */
	uint64_t	tx_q_ra;	/* Real addr of transmit queue */
	uint64_t	tx_head;	/* Tx queue head */
	uint64_t	tx_ackd_head;	/* Tx queue ACKd head (Reliable) */
	uint64_t	tx_tail;	/* Tx queue tail */

	uint64_t	rx_q_entries;	/* Num entries in receive queue */
	uint64_t	rx_q_va;	/* Virtual addr of receive queue */
	uint64_t	rx_q_ra;	/* Real addr of receive queue */

	uint64_t	rx_dq_entries;	/* Num entries in the data queue */
	uint64_t	rx_dq_va;	/* Virtual addr of the data queue */
	uint64_t	rx_dq_head;	/* Receive data queue head */
	uint64_t	rx_dq_tail;	/* Receive data queue tail */
	uint64_t	rx_ack_head;	/* Receive data ACK peek head ptr */

	uint64_t	link_state;	/* Underlying HV channel state */

	ldc_mtbl_t	*mtbl;		/* Memory table used by channel */
	ldc_mhdl_t	*mhdl_list;	/* List of memory handles */
	kmutex_t	mlist_lock;	/* Mem handle list lock */

	ldc_dring_t	*exp_dring_list; /* Exported desc ring list */
	kmutex_t	exp_dlist_lock;	/* Lock for exported desc ring list */
	ldc_dring_t	*imp_dring_list; /* Imported desc ring list */
	kmutex_t	imp_dlist_lock;	/* Lock for imported desc ring list */

	uint8_t		pkt_payload;	/* Size of packet payload */

	uint32_t	last_msg_snt;	/* Seqid of last packet sent */
	uint32_t	last_ack_rcd;	/* Seqid of last ACK recd */
	uint32_t	last_msg_rcd;	/* Seqid of last packet received */

	uint32_t	stream_remains;	/* Number of bytes in stream */
					/* packet buffer */
	uint32_t	stream_offset;	/* Offset into packet buffer for */
					/* next read */
	uint8_t		*stream_bufferp; /* Stream packet buffer */

	int		(*read_p)(ldc_chan_t *ldcp, caddr_t bufferp,
				size_t *sizep);
	int		(*write_p)(ldc_chan_t *ldcp, caddr_t bufferp,
				size_t *sizep);

	uint64_t	(*readq_get_state)(ldc_chan_t *ldcp, uint64_t *head,
				uint64_t *tail, uint64_t *link_state);

	int		(*readq_set_head)(ldc_chan_t *ldcp, uint64_t head);
};


/*
 * LDC module soft state structure
 */
typedef struct ldc_soft_state {
	kmutex_t	lock;		/* Protects ldc_soft_state_t  */
	ldc_cnex_t	cinfo;		/* channel nexus info */
	uint64_t	channel_count;	/* Number of channels */
	uint64_t	channels_open;	/* Number of open channels */
	ldc_chan_t	*chan_list;	/* List of LDC endpoints */
	ldc_dring_t	*dring_list;	/* Descriptor rings (for export) */

	kmem_cache_t	*memhdl_cache;	/* Memory handle cache */
	kmem_cache_t	*memseg_cache;	/* Memory segment cache */

	uint64_t	mapin_size;		/* Total mapin sz per guest  */
} ldc_soft_state_t;


/*
 * Debugging Utilities
 */
#define	DBG_ALL_LDCS	-1
#ifdef	DEBUG
#define	D1		\
if (ldcdbg & 0x01)	\
	ldcdebug
#define	D2		\
if (ldcdbg & 0x02)	\
	ldcdebug
#define	DWARN		\
if (ldcdbg & 0x04)	\
	ldcdebug
#else
#define	D1(...)
#define	D2(...)
#define	DWARN(...)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LDC_IMPL_H */
