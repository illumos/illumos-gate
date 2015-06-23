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
 * Copyright (c) 2010-2013, by Broadcom, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */

#ifndef _BGE_IMPL_H
#define	_BGE_IMPL_H


#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/modctl.h>
#include <sys/crc32.h>
#ifdef	__sparcv9
#include <v9/sys/membar.h>
#endif	/* __sparcv9 */
#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <sys/errno.h>
#include <sys/dlpi.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/conf.h>

#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/pattr.h>

#include <sys/disp.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

#ifdef __amd64
#include <sys/x86_archext.h>
#endif

#ifndef VLAN_TAGSZ
#define VLAN_TAGSZ 4
#endif

#define BGE_STR_SIZE 32

#ifndef OFFSETOF
#define OFFSETOF(_s, _f) \
    ((uint32_t)((uint8_t *)(&((_s *)0)->_f) - \
                (uint8_t *)((uint8_t *) 0)))
#endif

/*
 * <sys/ethernet.h> *may* already have provided the typedef ether_addr_t;
 * but of course C doesn't provide a way to check this directly.  So here
 * we rely on the fact that the symbol ETHERTYPE_AT was added to the
 * header file (as a #define, which we *can* test for) at the same time
 * as the typedef for ether_addr_t ;-!
 */
#ifndef	ETHERTYPE_AT
typedef uchar_t ether_addr_t[ETHERADDRL];
#endif	/* ETHERTYPE_AT */

/*
 * Reconfiguring the network devices requires the net_config privilege
 * in Solaris 10+.
 */
extern int secpolicy_net_config(const cred_t *, boolean_t);

#include <sys/miiregs.h>		/* by fjlite out of intel 	*/

#include "bge.h"
#include "bge_hw.h"

/*
 * Compile-time feature switches ...
 */
#define	BGE_DO_PPIO		0	/* peek/poke ioctls		*/
#define	BGE_RX_SOFTINT		0	/* softint per receive ring	*/
#define	BGE_CHOOSE_SEND_METHOD	0	/* send by copying only		*/

/*
 * NOTES:
 *
 * #defines:
 *
 *	BGE_PCI_CONFIG_RNUMBER and BGE_PCI_OPREGS_RNUMBER are the
 *	register-set numbers to use for the config space registers
 *	and the operating registers respectively.  On an OBP-based
 *	machine, regset 0 refers to CONFIG space, and regset 1 will
 *	be the operating registers in MEMORY space.  If an expansion
 *	ROM is fitted, it may appear as a further register set.
 *
 *	BGE_DMA_MODE defines the mode (STREAMING/CONSISTENT) used
 *	for the data buffers.  The descriptors are always set up
 *	in CONSISTENT mode.
 *
 *	BGE_HEADROOM defines how much space we'll leave in allocated
 *	mblks before the first valid data byte.  This should be chosen
 *	to be 2 modulo 4, so that once the ethernet header (14 bytes)
 *	has been stripped off, the packet data will be 4-byte aligned.
 *	The remaining space can be used by upstream modules to prepend
 *	any headers required.
 */

#define	BGE_PCI_CONFIG_RNUMBER	0
#define	BGE_PCI_OPREGS_RNUMBER	1
#define	BGE_PCI_APEREGS_RNUMBER	2
#define	BGE_DMA_MODE		DDI_DMA_STREAMING
#define	BGE_HEADROOM		34

/*
 *	BGE_HALFTICK is half the period of the cyclic callback (in
 *	nanoseconds), chosen so that 0.5s <= cyclic period <= 1s.
 *	Other time values are derived as odd multiples of this value
 *	so that there's little chance of ambiguity w.r.t. which tick
 *	a timeout expires on.
 *
 *	BGE_PHY_STABLE_TIME is the period for which the contents of the
 *	PHY's status register must remain unchanging before we accept
 *	that the link has come up.  [Sometimes the link comes up, only
 *	to go down again within a short time as the autonegotiation
 *	process cycles through various options before finding the best
 *	compatible mode.  We don't want to report repeated link up/down
 *	cycles, so we wait until we think it's stable.]
 *
 *	BGE_SERDES_STABLE_TIME is the analogous value for the SerDes
 *	interface.  It's much shorter, 'cos the SerDes doesn't show
 *	these effects as much as the copper PHY.
 *
 *	BGE_LINK_SETTLE_TIME is the period during which we regard link
 *	up/down cycles as an normal event after resetting/reprogramming
 *	the PHY.  During this time, link up/down messages are sent to
 *	the log only, not the console.  At any other time, link change
 *	events are regarded as unexpected and sent to both console & log.
 *
 *	These latter two values have no theoretical justification, but
 *	are derived from observations and heuristics - the values below
 *	just seem to work quite well.
 */

#define	BGE_HALFTICK		268435456LL		/* 2**28 ns!	*/
#define	BGE_CYCLIC_PERIOD	(4*BGE_HALFTICK)	/*    ~1.0s	*/
#define	BGE_CYCLIC_TIMEOUT	(drv_usectohz(1000000))	/*    ~1.0s	*/
#define	BGE_SERDES_STABLE_TIME	(3*BGE_HALFTICK)	/*    ~0.8s	*/
#define	BGE_PHY_STABLE_TIME	(11*BGE_HALFTICK)	/*    ~3.0s	*/
#define	BGE_LINK_SETTLE_TIME	(111*BGE_HALFTICK)	/*   ~30.0s	*/

/*
 * Indices used to identify the different buffer rings internally
 */
#define	BGE_STD_BUFF_RING	0
#define	BGE_JUMBO_BUFF_RING	1
#define	BGE_MINI_BUFF_RING	2

/*
 * Current implementation limits
 */
#define	BGE_BUFF_RINGS_USED	2		/* std & jumbo ring	*/
						/* for now		*/
#define	BGE_RECV_RINGS_USED	16		/* up to 16 rtn rings	*/
						/* for now		*/
#define	BGE_SEND_RINGS_USED	4		/* up to 4 tx rings	*/
						/* for now		*/
#define	BGE_HASH_TABLE_SIZE	128		/* may be 256 later	*/

/*
 * Ring/buffer size parameters
 *
 * All of the (up to) 16 TX rings & and the corresponding buffers are the
 * same size.
 *
 * Each of the (up to) 3 receive producer (aka buffer) rings is a different
 * size and has different sized buffers associated with it too.
 *
 * The (up to) 16 receive return rings have no buffers associated with them.
 * The number of slots per receive return ring must be 2048 if the mini
 * ring is enabled, otherwise it may be 1024.  See Broadcom document
 * 570X-PG102-R page 56.
 *
 * Note: only the 5700 supported external memory (and therefore the mini
 * ring); the 5702/3/4 don't.  This driver doesn't support the original
 * 5700, so we won't ever use the mini ring capability.
 */

#define	BGE_SEND_RINGS_DEFAULT		1
#define	BGE_RECV_RINGS_DEFAULT		1

#define	BGE_SEND_BUFF_SIZE_DEFAULT	1536
#define	BGE_SEND_BUFF_SIZE_JUMBO	9022
#define	BGE_SEND_SLOTS_USED	512

#define	BGE_STD_BUFF_SIZE	1536		/* 0x600		*/
#define	BGE_STD_SLOTS_USED	512

#define	BGE_JUMBO_BUFF_SIZE	9022		/* 9k			*/
#define	BGE_JUMBO_SLOTS_USED	256

#define	BGE_MINI_BUFF_SIZE	128		/* 64? 256?		*/
#define	BGE_MINI_SLOTS_USED	0		/* must be 0; see above	*/

#define	BGE_RECV_BUFF_SIZE	0
#if	BGE_MINI_SLOTS_USED > 0
#define	BGE_RECV_SLOTS_USED	2048		/* required		*/
#else
#define	BGE_RECV_SLOTS_USED	1024		/* could be 2048 anyway	*/
#endif

#define	BGE_SEND_BUF_NUM	512
#define	BGE_SEND_BUF_ARRAY	16
#define	BGE_SEND_BUF_ARRAY_JUMBO	3
#define	BGE_SEND_BUF_MAX	(BGE_SEND_BUF_NUM*BGE_SEND_BUF_ARRAY)

/*
 * PCI type. PCI-Express or PCI/PCIX
 */
#define	BGE_PCI		0
#define	BGE_PCI_E	1
#define	BGE_PCI_X	2

/*
 * Statistic type. There are two type of statistic:
 * statistic block and statistic registers
 */
#define	BGE_STAT_BLK	1
#define	BGE_STAT_REG	2

/*
 * MTU.for all chipsets ,the default is 1500 ,and some chipsets
 * support 9k jumbo frames size
 */
#define	BGE_DEFAULT_MTU		1500
#define	BGE_MAXIMUM_MTU		9000

/*
 * Pad the h/w defined status block (which can be up to 80 bytes long)
 * to a power-of-two boundary
 */
#define	BGE_STATUS_PADDING	(128 - sizeof (bge_status_t))

/*
 * On platforms which support DVMA, we can simply allocate one big piece
 * of memory for all the Tx buffers and another for the Rx buffers, and
 * then carve them up as required.  It doesn't matter if they aren't just
 * one physically contiguous piece each, because both the CPU *and* the
 * I/O device can see them *as though they were*.
 *
 * However, if only physically-addressed DMA is possible, this doesn't
 * work; we can't expect to get enough contiguously-addressed memory for
 * all the buffers of each type, so in this case we request a number of
 * smaller pieces, each still large enough for several buffers but small
 * enough to fit within "an I/O page" (e.g. 64K).
 *
 * The #define below specifies how many pieces of memory are to be used;
 * 16 has been shown to work on an i86pc architecture but this could be
 * different on other non-DVMA platforms ...
 */
#ifdef	_DMA_USES_VIRTADDR
#define	BGE_SPLIT		1		/* no split required	*/
#else
#if ((BGE_BUFF_RINGS_USED > 1) || (BGE_SEND_RINGS_USED > 1) || \
	(BGE_RECV_RINGS_USED > 1))
#define	BGE_SPLIT		128		/* split 128 ways	*/
#else
#define	BGE_SPLIT		16		/* split 16 ways	*/
#endif
#endif	/* _DMA_USES_VIRTADDR */

#define	BGE_RECV_RINGS_SPLIT	(BGE_RECV_RINGS_MAX + 1)

/*
 * STREAMS parameters
 */
#define	BGE_IDNUM		0		/* zero seems to work	*/
#define	BGE_LOWAT		(256)
#define	BGE_HIWAT		(256*1024)

/*
 * Basic data types, for clarity in distinguishing 'numbers'
 * used for different purposes ...
 *
 * A <bge_regno_t> is a register 'address' (offset) in any one of
 * various address spaces (PCI config space, PCI memory-mapped I/O
 * register space, MII registers, etc).  None of these exceeds 64K,
 * so we could use a 16-bit representation but pointer-sized objects
 * are more "natural" in most architectures; they seem to be handled
 * more efficiently on SPARC and no worse on x86.
 *
 * BGE_REGNO_NONE represents the non-existent value in this space.
 */
typedef uintptr_t bge_regno_t;			/* register # (offset)	*/
#define	BGE_REGNO_NONE		(~(uintptr_t)0u)

/*
 * Describes one chunk of allocated DMA-able memory
 *
 * In some cases, this is a single chunk as allocated from the system;
 * but we also use this structure to represent slices carved off such
 * a chunk.  Even when we don't really need all the information, we
 * use this structure as a convenient way of correlating the various
 * ways of looking at a piece of memory (kernel VA, IO space DVMA,
 * handle+offset, etc).
 */
typedef struct {
	ddi_acc_handle_t	acc_hdl;	/* handle for memory	*/
	void			*mem_va;	/* CPU VA of memory	*/
	uint32_t		nslots;		/* number of slots	*/
	uint32_t		size;		/* size per slot	*/
	size_t			alength;	/* allocated size	*/
						/* >= product of above	*/

	ddi_dma_handle_t	dma_hdl;	/* DMA handle		*/
	offset_t		offset;		/* relative to handle	*/
	ddi_dma_cookie_t	cookie;		/* associated cookie	*/
	uint32_t		ncookies;	/* must be 1		*/
	uint32_t		token;		/* arbitrary identifier	*/
} dma_area_t;					/* 0x50 (80) bytes	*/

typedef struct bge_queue_item {
	struct bge_queue_item	*next;
	void			*item;
} bge_queue_item_t;

typedef struct bge_queue {
	bge_queue_item_t	*head;
	uint32_t		count;
	kmutex_t		*lock;
} bge_queue_t;
/*
 * Software version of the Receive Buffer Descriptor
 * There's one of these for each receive buffer (up to 256/512/1024 per ring).
 */
typedef struct sw_rbd {
	dma_area_t		pbuf;		/* (const) related	*/
						/* buffer area		*/
} sw_rbd_t;					/* 0x50 (80) bytes	*/

/*
 * Software Receive Buffer (Producer) Ring Control Block
 * There's one of these for each receiver producer ring (up to 3),
 * but each holds buffers of a different size.
 */
typedef struct buff_ring {
	dma_area_t		desc;		/* (const) related h/w	*/
						/* descriptor area	*/
	dma_area_t		buf[BGE_SPLIT];	/* (const) related	*/
						/* buffer area(s)	*/
	bge_rcb_t		hw_rcb;		/* (const) image of h/w	*/
						/* RCB, and used to	*/
	struct bge		*bgep;		/* (const) containing	*/
						/* driver soft state	*/
						/* initialise same	*/
	volatile uint16_t	*cons_index_p;	/* (const) ptr to h/w	*/
						/* "consumer index"	*/
						/* (in status block)	*/

	/*
	 * The rf_lock must be held when updating the h/w producer index
	 * mailbox register (*chip_mbox_reg), or the s/w producer index
	 * (rf_next).
	 */
	bge_regno_t		chip_mbx_reg;	/* (const) h/w producer	*/
						/* index mailbox offset	*/
	kmutex_t		rf_lock[1];	/* serialize refill	*/
	uint64_t		rf_next;	/* next slot to refill	*/
						/* ("producer index")	*/

	sw_rbd_t		*sw_rbds; 	/* software descriptors	*/
	void			*spare[4];	/* padding		*/
} buff_ring_t;					/* 0x100 (256) bytes	*/

typedef struct bge_multi_mac {
	int		naddr;		/* total supported addresses */
	int		naddrfree;	/* free addresses slots */
	ether_addr_t	mac_addr[MAC_ADDRESS_REGS_MAX];
	boolean_t	mac_addr_set[MAC_ADDRESS_REGS_MAX];
} bge_multi_mac_t;

/*
 * Software Receive (Return) Ring Control Block
 * There's one of these for each receiver return ring (up to 16).
 */
typedef struct recv_ring {
	/*
	 * The elements flagged (const) in the comments below are
	 * set up once during initialiation and thereafter unchanged.
	 */
	dma_area_t		desc;		/* (const) related h/w	*/
						/* descriptor area	*/
	bge_rcb_t		hw_rcb;		/* (const) image of h/w	*/
						/* RCB, and used to	*/
						/* initialise same	*/
	struct bge		*bgep;		/* (const) containing	*/
						/* driver soft state	*/
	ddi_softintr_t		rx_softint;	/* (const) per-ring	*/
						/* receive callback	*/
	volatile uint16_t	*prod_index_p;	/* (const) ptr to h/w	*/
						/* "producer index"	*/
						/* (in status block)	*/
	/*
	 * The rx_lock must be held when updating the h/w consumer index
	 * mailbox register (*chip_mbox_reg), or the s/w consumer index
	 * (rx_next).
	 */
	bge_regno_t		chip_mbx_reg;	/* (const) h/w consumer	*/
						/* index mailbox offset	*/
	kmutex_t		rx_lock[1];	/* serialize receive	*/
	uint64_t		rx_next;	/* next slot to examine	*/

	mac_ring_handle_t	ring_handle;
	mac_group_handle_t	ring_group_handle;
	uint64_t		ring_gen_num;
	bge_rule_info_t		*mac_addr_rule;
	uint8_t			mac_addr_val[ETHERADDRL];
	int			poll_flag;	/* Polling flag		*/

	/* Per-ring statistics */
	uint64_t		rx_pkts;	/* Received Packets Count */
	uint64_t		rx_bytes;	/* Received Bytes Count */
} recv_ring_t;


/*
 * Send packet structure
 */
typedef struct send_pkt {
	uint16_t		vlan_tci;
	uint32_t		pflags;
	boolean_t		tx_ready;
	bge_queue_item_t	*txbuf_item;
} send_pkt_t;

/*
 * Software version of tx buffer structure
 */
typedef struct sw_txbuf {
	dma_area_t		buf;
	uint32_t		copy_len;
} sw_txbuf_t;

/*
 * Software version of the Send Buffer Descriptor
 * There's one of these for each send buffer (up to 512 per ring)
 */
typedef struct sw_sbd {
	dma_area_t		desc;		/* (const) related h/w	*/
						/* descriptor area	*/
	bge_queue_item_t	*pbuf;		/* (const) related	*/
						/* buffer area		*/
} sw_sbd_t;

/*
 * Software Send Ring Control Block
 * There's one of these for each of (up to) 16 send rings
 */
typedef struct send_ring {
	/*
	 * The elements flagged (const) in the comments below are
	 * set up once during initialiation and thereafter unchanged.
	 */
	dma_area_t		desc;		/* (const) related h/w	*/
						/* descriptor area	*/
	dma_area_t		buf[BGE_SEND_BUF_ARRAY][BGE_SPLIT];
						/* buffer area(s)	*/
	bge_rcb_t		hw_rcb;		/* (const) image of h/w	*/
						/* RCB, and used to	*/
						/* initialise same	*/
	struct bge		*bgep;		/* (const) containing	*/
						/* driver soft state	*/
	volatile uint16_t	*cons_index_p;	/* (const) ptr to h/w	*/
						/* "consumer index"	*/
						/* (in status block)	*/

	bge_regno_t		chip_mbx_reg;	/* (const) h/w producer	*/
						/* index mailbox offset	*/
	/*
	 * Tx buffer queue
	 */
	bge_queue_t		txbuf_queue;
	bge_queue_t		freetxbuf_queue;
	bge_queue_t		*txbuf_push_queue;
	bge_queue_t		*txbuf_pop_queue;
	kmutex_t		txbuf_lock[1];
	kmutex_t		freetxbuf_lock[1];
	bge_queue_item_t	*txbuf_head;
	send_pkt_t		*pktp;
	uint64_t		txpkt_next;
	uint64_t		txfill_next;
	sw_txbuf_t		*txbuf;
	uint32_t		tx_buffers;
	uint32_t		tx_buffers_low;
	uint32_t		tx_array_max;
	uint32_t		tx_array;
	kmutex_t		tx_lock[1];	/* serialize h/w update	*/
						/* ("producer index")	*/
	uint64_t		tx_next;	/* next slot to use	*/
	uint64_t		tx_flow;	/* # concurrent sends	*/
	uint64_t		tx_block;
	uint64_t		tx_nobd;
	uint64_t		tx_nobuf;
	uint64_t		tx_alloc_fail;

	/*
	 * These counters/indexes are manipulated in the transmit
	 * path using atomics rather than mutexes for speed
	 */
	uint64_t		tx_free;	/* # of slots available	*/

	/*
	 * The tc_lock must be held while manipulating the s/w consumer
	 * index (tc_next).
	 */
	kmutex_t		tc_lock[1];	/* serialize recycle	*/
	uint64_t		tc_next;	/* next slot to recycle	*/
						/* ("consumer index")	*/

	sw_sbd_t		*sw_sbds; 	/* software descriptors	*/
	uint64_t		mac_resid;	/* special per resource id */
	uint64_t		pushed_bytes;
} send_ring_t;					/* 0x100 (256) bytes	*/

typedef struct {
	ether_addr_t		addr;		/* in canonical form	*/
	uint8_t			spare;
	boolean_t		set;		/* B_TRUE => valid	*/
} bge_mac_addr_t;

/*
 * The original 5700/01 supported only SEEPROMs.  Later chips (5702+)
 * support both SEEPROMs (using the same 2-wire CLK/DATA interface for
 * the hardware and a backwards-compatible software access method), and
 * buffered or unbuffered FLASH devices connected to the 4-wire SPI bus
 * and using a new software access method.
 *
 * The access methods for SEEPROM and Flash are generally similar, with
 * the chip handling the serialisation/deserialisation and handshaking,
 * but the registers used are different, as are a few details of the
 * protocol, and the timing, so we have to determine which (if any) is
 * fitted.
 *
 * The value UNKNOWN means just that; we haven't yet tried to determine
 * the device type.
 *
 * The value NONE can indicate either that a real and definite absence of
 * any NVmem has been detected, or that there may be NVmem but we can't
 * determine its type, perhaps because the NVconfig pins on the chip have
 * been wired up incorrectly.  In either case, access to the NVmem (if any)
 * is not supported.
 */
enum bge_nvmem_type {
	BGE_NVTYPE_NONE = -1,			/* (or indeterminable)	*/
	BGE_NVTYPE_UNKNOWN,			/* not yet checked	*/
	BGE_NVTYPE_SEEPROM,			/* BCM5700/5701 only	*/
	BGE_NVTYPE_LEGACY_SEEPROM,		/* 5702+		*/
	BGE_NVTYPE_UNBUFFERED_FLASH,		/* 5702+		*/
	BGE_NVTYPE_BUFFERED_FLASH		/* 5702+		*/
};

/*
 * Describes the characteristics of a specific chip
 *
 * Note: elements from <businfo> to <latency> are filled in by during
 * the first phase of chip initialisation (see bge_chip_cfg_init()).
 * The remaining ones are determined just after the first RESET, in
 * bge_poll_firmware().  Thereafter, the entire structure is readonly.
 */
typedef struct {
	uint32_t		asic_rev;	/* masked from MHCR	*/
	uint32_t		asic_rev_prod_id; /* new revision ID format */
	uint32_t		businfo;	/* from private reg	*/
	uint16_t		command;	/* saved during attach	*/

	uint16_t		vendor;		/* vendor-id		*/
	uint16_t		device;		/* device-id		*/
	uint16_t		subven;		/* subsystem-vendor-id	*/
	uint16_t		subdev;		/* subsystem-id		*/
	uint8_t			revision;	/* revision-id		*/
	uint8_t			clsize;		/* cache-line-size	*/
	uint8_t			latency;	/* latency-timer	*/

	uint8_t			flags;
	uint16_t		chip_label;	/* numeric part only	*/
						/* (e.g. 5703/5794/etc)	*/
	uint32_t		mbuf_base;	/* Mbuf pool parameters */
	uint32_t		mbuf_length;	/* depend on chiptype	*/
	uint32_t		pci_type;
	uint32_t		statistic_type;
	uint32_t		bge_dma_rwctrl;
	uint32_t		bge_mlcr_default;
	uint32_t		recv_slots;	/* receive ring size    */
	enum bge_nvmem_type	nvtype;		/* SEEPROM or Flash	*/

	uint16_t		jumbo_slots;
	uint16_t		ethmax_size;
	uint16_t		snd_buff_size;
	uint16_t		recv_jumbo_size;
	uint16_t		std_buf_size;
	uint32_t		mbuf_hi_water;
	uint32_t		mbuf_lo_water_rmac;
	uint32_t		mbuf_lo_water_rdma;

	uint32_t		rx_rings;	/* from bge.conf	*/
	uint32_t		tx_rings;	/* from bge.conf	*/
	uint32_t		eee;		/* from bge.conf	*/
	uint32_t		default_mtu;	/* from bge.conf	*/

	uint64_t		hw_mac_addr;	/* from chip register	*/
	bge_mac_addr_t		vendor_addr;	/* transform of same	*/
	boolean_t		msi_enabled;	/* default to true */

	uint32_t		rx_ticks_norm;
	uint32_t		rx_count_norm;
	uint32_t		tx_ticks_norm;
	uint32_t		tx_count_norm;
	uint32_t		mask_pci_int;
} chip_id_t;

#define	CHIP_FLAG_SUPPORTED	0x80
#define	CHIP_FLAG_SERDES	0x40
#define	CHIP_FLAG_PARTIAL_CSUM	0x20
#define	CHIP_FLAG_NO_JUMBO	0x1

/*
 * Collection of physical-layer functions to:
 *	(re)initialise the physical layer
 *	update it to match software settings
 *	check for link status change
 */
typedef struct {
	int			(*phys_restart)(struct bge *, boolean_t);
	int			(*phys_update)(struct bge *);
	boolean_t		(*phys_check)(struct bge *, boolean_t);
} phys_ops_t;


/*
 * Actual state of the BCM570x chip
 */
enum bge_chip_state {
	BGE_CHIP_FAULT = -2,			/* fault, need reset	*/
	BGE_CHIP_ERROR,				/* error, want reset	*/
	BGE_CHIP_INITIAL,			/* Initial state only	*/
	BGE_CHIP_RESET,				/* reset, need init	*/
	BGE_CHIP_STOPPED,			/* Tx/Rx stopped	*/
	BGE_CHIP_RUNNING			/* with interrupts	*/
};

enum bge_mac_state {
	BGE_MAC_STOPPED = 0,
	BGE_MAC_STARTED
};

/*
 * (Internal) return values from ioctl subroutines
 */
enum ioc_reply {
	IOC_INVAL = -1,				/* bad, NAK with EINVAL	*/
	IOC_DONE,				/* OK, reply sent	*/
	IOC_ACK,				/* OK, just send ACK	*/
	IOC_REPLY,				/* OK, just send reply	*/
	IOC_RESTART_ACK,			/* OK, restart & ACK	*/
	IOC_RESTART_REPLY			/* OK, restart & reply	*/
};

/*
 * (Internal) return values from send_msg subroutines
 */
enum send_status {
	SEND_FAIL = -1,				/* Not OK		*/
	SEND_KEEP,				/* OK, msg queued	*/
	SEND_FREE				/* OK, free msg		*/
};

/*
 * (Internal) enumeration of this driver's kstats
 */
enum {
	BGE_KSTAT_RAW = 0,
	BGE_KSTAT_STATS,
	BGE_KSTAT_CHIPID,
	BGE_KSTAT_DRIVER,
	BGE_KSTAT_PHYS,

	BGE_KSTAT_COUNT
};

#define	BGE_MAX_RESOURCES 255

/*
 * Per-instance soft-state structure
 */
typedef struct bge {
	/*
	 * These fields are set by attach() and unchanged thereafter ...
	 */
	char			version[BGE_STR_SIZE];
#define BGE_FW_VER_SIZE 32
	char			fw_version[BGE_FW_VER_SIZE];
	dev_info_t		*devinfo;	/* device instance	*/
	uint32_t		pci_bus;	/* from "regs" prop */
	uint32_t		pci_dev;	/* from "regs" prop */
	uint32_t		pci_func;	/* from "regs" prop */
	mac_handle_t		mh;		/* mac module handle	*/
	ddi_acc_handle_t	cfg_handle;	/* DDI I/O handle	*/
	ddi_acc_handle_t	io_handle;	/* DDI I/O handle	*/
	void			*io_regs;	/* mapped registers	*/
	ddi_acc_handle_t	ape_handle;	/* DDI I/O handle	*/
	void			*ape_regs;	/* mapped registers	*/
	boolean_t		ape_enabled;
	boolean_t		ape_has_ncsi;

	ddi_periodic_t		periodic_id;	/* periodical callback	*/
	ddi_softintr_t		factotum_id;	/* factotum callback	*/
	ddi_softintr_t		drain_id;	/* reschedule callback	*/

	ddi_intr_handle_t 	*htable;	/* For array of interrupts */
	int			intr_type;	/* What type of interrupt */
	int			intr_cnt;	/* # of intrs count returned */
	uint_t			intr_pri;	/* Interrupt priority	*/
	int			intr_cap;	/* Interrupt capabilities */
	uint32_t		progress;	/* attach tracking	*/
	uint32_t		debug;		/* per-instance debug	*/
	chip_id_t		chipid;
	const phys_ops_t	*physops;
	char			ifname[8];	/* "bge0" ... "bge999"	*/

	int			fm_capabilities;	/* FMA capabilities */

	/*
	 * These structures describe the blocks of memory allocated during
	 * attach().  They remain unchanged thereafter, although the memory
	 * they describe is carved up into various separate regions and may
	 * therefore be described by other structures as well.
	 */
	dma_area_t		tx_desc;	/* transmit descriptors	*/
	dma_area_t		rx_desc[BGE_RECV_RINGS_SPLIT];
						/* receive descriptors	*/
	dma_area_t		tx_buff[BGE_SPLIT];
	dma_area_t		rx_buff[BGE_SPLIT];

	/*
	 * The memory described by the <dma_area> structures above
	 * is carved up into various pieces, which are described by
	 * the structures below.
	 */
	dma_area_t		statistics;	/* describes hardware	*/
						/* statistics area	*/
	dma_area_t		status_block;	/* describes hardware	*/
						/* status block		*/
	/*
	 * For the BCM5705/5788/5721/5751/5752/5714 and 5715,
	 * the statistic block is not available,the statistic counter must
	 * be gotten from statistic registers.And bge_statistics_reg_t record
	 * the statistic registers value
	 */
	bge_statistics_reg_t	*pstats;

	/*
	 * Runtime read-write data starts here ...
	 *
	 * 3 Buffer Rings (std/jumbo/mini)
	 * 16 Receive (Return) Rings
	 * 16 Send Rings
	 *
	 * Note: they're not necessarily all used.
	 */
	buff_ring_t		buff[BGE_BUFF_RINGS_MAX]; /*  3*0x0100	*/

	/* may be obsoleted */
	recv_ring_t		recv[BGE_RECV_RINGS_MAX]; /* 16*0x0090	*/
	send_ring_t		send[BGE_SEND_RINGS_MAX]; /* 16*0x0100	*/

	mac_resource_handle_t macRxResourceHandles[BGE_RECV_RINGS_MAX];

	/*
	 * Locks:
	 *
	 * Each buffer ring contains its own <rf_lock> which regulates
	 *	ring refilling.
	 *
	 * Each receive (return) ring contains its own <rx_lock> which
	 *	protects the critical cyclic counters etc.
	 *
	 * Each send ring contains two locks: <tx_lock> for the send-path
	 * 	protocol data and <tc_lock> for send-buffer recycling.
	 *
	 * Finally <genlock> is a general lock, protecting most other
	 *	operational data in the state structure and chip register
	 *	accesses.  It is acquired by the interrupt handler and
	 *	most "mode-control" routines.
	 *
	 * Any of the locks can be acquired singly, but where multiple
	 * locks are acquired, they *must* be in the order:
	 *
	 *	genlock >>> rx_lock >>> rf_lock >>> tx_lock >>> tc_lock.
	 *
	 * and within any one class of lock the rings must be locked in
	 * ascending order (send[0].tc_lock >>> send[1].tc_lock), etc.
	 *
	 * Note: actually I don't believe there's any need to acquire
	 * locks on multiple rings, or even locks of all these classes
	 * concurrently; but I've set out the above order so there is a
	 * clear definition of lock hierarchy in case it's ever needed.
	 *
	 * Note: the combinations of locks that are actually held
	 * concurrently are:
	 *
	 *	genlock >>>			(bge_chip_interrupt())
	 *		rx_lock[i] >>>		(bge_receive())
	 *			rf_lock[n]	(bge_refill())
	 *		tc_lock[i]		(bge_recycle())
	 */
	kmutex_t		genlock[1];
	krwlock_t		errlock[1];
	kmutex_t		softintrlock[1];

	/*
	 * Current Ethernet addresses and multicast hash (bitmap) and
	 * refcount tables, protected by <genlock>
	 */
	bge_mac_addr_t		curr_addr[MAC_ADDRESS_REGS_MAX];
	uint32_t		mcast_hash[BGE_HASH_TABLE_SIZE/32];
	uint8_t			mcast_refs[BGE_HASH_TABLE_SIZE];
	uint32_t		unicst_addr_total; /* total unicst addresses */
	uint32_t		unicst_addr_avail;
					/* unused unicst addr slots */

	/*
	 * Link state data (protected by genlock)
	 */
	link_state_t		link_state;

	/*
	 * Physical layer: copper only
	 */
	bge_regno_t		phy_mii_addr;	/* should be (const) 1!	*/
	uint16_t		phy_gen_status;
	uint16_t		phy_aux_status;

	/*
	 * Physical layer: serdes only
	 */
	uint32_t		serdes_status;
	uint32_t		serdes_advert;
	uint32_t		serdes_lpadv;

	/*
	 * Driver kstats, protected by <genlock> where necessary
	 */
	kstat_t			*bge_kstats[BGE_KSTAT_COUNT];

	/*
	 * Miscellaneous operating variables (protected by genlock)
	 */
	uint64_t		chip_resets;	/* # of chip RESETs	*/
	uint64_t		missed_dmas;	/* # of missed DMAs	*/
	uint64_t		missed_updates;	/* # of missed updates	*/
	enum bge_mac_state	bge_mac_state;	/* definitions above	*/
	enum bge_chip_state	bge_chip_state;	/* definitions above	*/
	boolean_t		send_hw_tcp_csum;
	boolean_t		recv_hw_tcp_csum;
	boolean_t		promisc;
	boolean_t		manual_reset;

	/*
	 * Miscellaneous operating variables (not synchronised)
	 */
	uint32_t		watchdog;	/* watches for Tx stall	*/
	boolean_t		bge_intr_running;
	boolean_t		bge_dma_error;
	boolean_t		tx_resched_needed;
	uint64_t		tx_resched;
	uint32_t		factotum_flag;	/* softint pending	*/
	uintptr_t		pagemask;
	boolean_t		rdma_length_bug_on_5719;

	/*
	 * NDD parameters (protected by genlock)
	 */
	caddr_t			nd_data_p;

	/*
	 * A flag to prevent excessive config space accesses
	 * on platforms having BCM5714C/15C
	 */
	boolean_t		lastWriteZeroData;

	/*
	 * Spare space, plus guard element used to check data integrity
	 */
	uint64_t		spare[5];
	uint64_t		bge_guard;

	/*
	 * Receive rules configure
	 */
	bge_recv_rule_t	recv_rules[RECV_RULES_NUM_MAX];

#ifdef BGE_IPMI_ASF
	boolean_t		asf_enabled;
	boolean_t		asf_wordswapped;
	boolean_t		asf_newhandshake;
	boolean_t		asf_pseudostop;

	uint32_t		asf_status;
	timeout_id_t		asf_timeout_id;
#endif
	uint32_t		param_en_pause:1,
				param_en_asym_pause:1,
				param_en_1000hdx:1,
				param_en_1000fdx:1,
				param_en_100fdx:1,
				param_en_100hdx:1,
				param_en_10fdx:1,
				param_en_10hdx:1,
				param_adv_autoneg:1,
				param_adv_1000fdx:1,
				param_adv_1000hdx:1,
				param_adv_100fdx:1,
				param_adv_100hdx:1,
				param_adv_10fdx:1,
				param_adv_10hdx:1,
				param_lp_autoneg:1,
				param_lp_pause:1,
				param_lp_asym_pause:1,
				param_lp_1000fdx:1,
				param_lp_1000hdx:1,
				param_lp_100fdx:1,
				param_lp_100hdx:1,
				param_lp_10fdx:1,
				param_lp_10hdx:1,
				param_link_up:1,
				param_link_autoneg:1,
				param_adv_pause:1,
				param_adv_asym_pause:1,
				param_link_rx_pause:1,
				param_link_tx_pause:1,
				param_pad_to_32:2;

	uint32_t		param_loop_mode;
	uint32_t		param_msi_cnt;
	uint32_t 		param_drain_max;
	uint64_t		param_link_speed;
	link_duplex_t		param_link_duplex;
	uint32_t		eee_lpi_wait;

	uint64_t		timestamp;
} bge_t;

#define CATC_TRIGGER(bgep, data) bge_reg_put32(bgep, 0x0a00, (data))

/*
 * 'Progress' bit flags ...
 */
#define	PROGRESS_CFG		0x0001	/* config space mapped		*/
#define	PROGRESS_REGS		0x0002	/* registers mapped		*/
#define	PROGRESS_BUFS		0x0004	/* ring buffers allocated	*/
#define	PROGRESS_RESCHED	0x0010	/* resched softint registered	*/
#define	PROGRESS_FACTOTUM	0x0020	/* factotum softint registered	*/
#define	PROGRESS_HWINT		0x0040	/* h/w interrupt registered	*/
					/* and mutexen initialised	*/
#define	PROGRESS_INTR		0x0080	/* Intrs enabled		*/
#define	PROGRESS_PHY		0x0100	/* PHY initialised		*/
#define	PROGRESS_NDD		0x1000	/* NDD parameters set up	*/
#define	PROGRESS_KSTATS		0x2000	/* kstats created		*/
#define	PROGRESS_READY		0x8000	/* ready for work		*/


/*
 * Sync a DMA area described by a dma_area_t
 */
#define	DMA_SYNC(area, flag)	((void) ddi_dma_sync((area).dma_hdl,	\
				    (area).offset, (area).alength, (flag)))

/*
 * Find the (kernel virtual) address of block of memory
 * described by a dma_area_t
 */
#define	DMA_VPTR(area)		((area).mem_va)

/*
 * Zero a block of memory described by a dma_area_t
 */
#define	DMA_ZERO(area)		bzero(DMA_VPTR(area), (area).alength)

/*
 * Next value of a cyclic index
 */
#define	NEXT(index, limit)	((index)+1 < (limit) ? (index)+1 : 0)

/*
 * Property lookups
 */
#define	BGE_PROP_EXISTS(d, n)	ddi_prop_exists(DDI_DEV_T_ANY, (d),	\
					DDI_PROP_DONTPASS, (n))
#define	BGE_PROP_GET_INT(d, n)	ddi_prop_get_int(DDI_DEV_T_ANY, (d),	\
					DDI_PROP_DONTPASS, (n), -1)

/*
 * Copy an ethernet address
 */
#define	ethaddr_copy(src, dst)	bcopy((src), (dst), ETHERADDRL)

/*
 * Endian swap
 */
/* BEGIN CSTYLED */
#define BGE_BSWAP_32(x)		((((x) & 0xff000000) >> 24)  |		\
                                 (((x) & 0x00ff0000) >> 8)   |		\
                                 (((x) & 0x0000ff00) << 8)   |		\
                                 (((x) & 0x000000ff) << 24))
/* END CSTYLED */

/*
 * Marker value placed at the end of the driver's state
 */
#define	BGE_GUARD		0x1919306009031802

/*
 * Bit flags in the 'debug' word ...
 */
#define	BGE_DBG_STOP		0x00000001	/* early debug_enter()	*/
#define	BGE_DBG_TRACE		0x00000002	/* general flow tracing	*/
#define	BGE_DBG_APE		0x00000004	/* low-level APE access	*/
#define	BGE_DBG_HPSD		0x00000008	/* low-level HPSD access*/
#define	BGE_DBG_REGS		0x00000010	/* low-level accesses	*/
#define	BGE_DBG_MII		0x00000020	/* low-level MII access	*/
#define	BGE_DBG_SEEPROM		0x00000040	/* low-level SEEPROM IO	*/
#define	BGE_DBG_CHIP		0x00000080	/* low(ish)-level code	*/
#define	BGE_DBG_RECV		0x00000100	/* receive-side code	*/
#define	BGE_DBG_SEND		0x00000200	/* packet-send code	*/
#define	BGE_DBG_INT		0x00001000	/* interrupt handler	*/
#define	BGE_DBG_FACT		0x00002000	/* factotum (softint)	*/
#define	BGE_DBG_PHY		0x00010000	/* Copper PHY code	*/
#define	BGE_DBG_SERDES		0x00020000	/* SerDes code		*/
#define	BGE_DBG_PHYS		0x00040000	/* Physical layer code	*/
#define	BGE_DBG_LINK		0x00080000	/* Link status check	*/
#define	BGE_DBG_INIT		0x00100000	/* initialisation	*/
#define	BGE_DBG_NEMO		0x00200000	/* nemo interaction	*/
#define	BGE_DBG_ADDR		0x00400000	/* address-setting code	*/
#define	BGE_DBG_STATS		0x00800000	/* statistics		*/
#define	BGE_DBG_IOCTL		0x01000000	/* ioctl handling	*/
#define	BGE_DBG_LOOP		0x02000000	/* loopback ioctl code	*/
#define	BGE_DBG_PPIO		0x04000000	/* Peek/poke ioctls	*/
#define	BGE_DBG_BADIOC		0x08000000	/* unknown ioctls	*/
#define	BGE_DBG_MCTL		0x10000000	/* mctl (csum) code	*/
#define	BGE_DBG_NDD		0x20000000	/* NDD operations	*/
#define	BGE_DBG_MEM		0x40000000	/* memory allocations and chunking */

/*
 * Debugging ...
 */
#ifdef	DEBUG
#define	BGE_DEBUGGING		1
#else
#define	BGE_DEBUGGING		1
#endif	/* DEBUG */


/*
 * 'Do-if-debugging' macro.  The parameter <command> should be one or more
 * C statements (but without the *final* semicolon), which will either be
 * compiled inline or completely ignored, depending on the BGE_DEBUGGING
 * compile-time flag.
 *
 * You should get a compile-time error (at least on a DEBUG build) if
 * your statement isn't actually a statement, rather than unexpected
 * run-time behaviour caused by unintended matching of if-then-elses etc.
 *
 * Note that the BGE_DDB() macro itself can only be used as a statement,
 * not an expression, and should always be followed by a semicolon.
 */
#if	BGE_DEBUGGING
#define	BGE_DDB(command)	do {					\
					{ command; }			\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)
#else 	/* BGE_DEBUGGING */
#define	BGE_DDB(command)	do {					\
					{ _NOTE(EMPTY); }		\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)
#endif	/* BGE_DEBUGGING */

/*
 * 'Internal' macros used to construct the TRACE/DEBUG macros below.
 * These provide the primitive conditional-call capability required.
 * Note: the parameter <args> is a parenthesised list of the actual
 * printf-style arguments to be passed to the debug function ...
 */
#define	BGE_XDB(b, w, f, args)	BGE_DDB(if ((b) & (w)) f args)
#define	BGE_GDB(b, args)	BGE_XDB(b, bge_debug, (*bge_gdb()), args)
#define	BGE_LDB(b, args)	BGE_XDB(b, bgep->debug, (*bge_db(bgep)), args)
#define	BGE_CDB(f, args)	BGE_XDB(BGE_DBG, bgep->debug, f, args)

#define DEVNAME(_sc) ((_sc)->ifname)
#define DPRINTF(f, ...) do { cmn_err(CE_NOTE, (f), __VA_ARGS__); } while (0)

/*
 * Conditional-print macros.
 *
 * Define BGE_DBG to be the relevant member of the set of BGE_DBG_* values
 * above before using the BGE_GDEBUG() or BGE_DEBUG() macros.  The 'G'
 * versions look at the Global debug flag word (bge_debug); the non-G
 * versions look in the per-instance data (bgep->debug) and so require a
 * variable called 'bgep' to be in scope (and initialised!) before use.
 *
 * You could redefine BGE_TRC too if you really need two different
 * flavours of debugging output in the same area of code, but I don't
 * really recommend it.
 *
 * Note: the parameter <args> is a parenthesised list of the actual
 * arguments to be passed to the debug function, usually a printf-style
 * format string and corresponding values to be formatted.
 */

#define	BGE_TRC			BGE_DBG_TRACE	/* default 'trace' bit	*/
#define	BGE_GTRACE(args)	BGE_GDB(BGE_TRC, args)
#define	BGE_GDEBUG(args)	BGE_GDB(BGE_DBG, args)
#define	BGE_TRACE(args)		BGE_LDB(BGE_TRC, args)
#define	BGE_DEBUG(args)		BGE_LDB(BGE_DBG, args)

/*
 * Debug-only action macros
 */
#define	BGE_BRKPT(bgep, s)	BGE_DDB(bge_dbg_enter(bgep, s))
#define	BGE_MARK(bgep)		BGE_DDB(bge_led_mark(bgep))
#define	BGE_PCICHK(bgep)	BGE_DDB(bge_pci_check(bgep))
#define	BGE_PKTDUMP(args)	BGE_DDB(bge_pkt_dump args)
#define	BGE_REPORT(args)	BGE_DDB(bge_log args)

/*
 * Inter-source-file linkage ...
 */

/* bge_chip.c */
uint16_t bge_mii_get16(bge_t *bgep, bge_regno_t regno);
void bge_mii_put16(bge_t *bgep, bge_regno_t regno, uint16_t value);
uint16_t bge_phydsp_read(bge_t *bgep, bge_regno_t regno);
void bge_phydsp_write(bge_t *bgep, bge_regno_t regno, uint16_t value);
uint32_t bge_reg_get32(bge_t *bgep, bge_regno_t regno);
void bge_reg_put32(bge_t *bgep, bge_regno_t regno, uint32_t value);
void bge_reg_set32(bge_t *bgep, bge_regno_t regno, uint32_t bits);
void bge_reg_clr32(bge_t *bgep, bge_regno_t regno, uint32_t bits);
uint32_t bge_ape_get32(bge_t *bgep, bge_regno_t regno);
void bge_ape_put32(bge_t *bgep, bge_regno_t regno, uint32_t value);
void bge_mbx_put(bge_t *bgep, bge_regno_t regno, uint64_t value);
void bge_ape_lock_init(bge_t *bgep);
int bge_ape_scratchpad_read(bge_t *bgep, uint32_t *data, uint32_t base_off, uint32_t lenToRead);
int bge_ape_scratchpad_write(bge_t *bgep, uint32_t dstoff, uint32_t *data, uint32_t lenToWrite);
int bge_nvmem_read32(bge_t *bgep, bge_regno_t addr, uint32_t *dp);
int bge_nvmem_write32(bge_t *bgep, bge_regno_t addr, uint32_t *dp);
void bge_chip_cfg_init(bge_t *bgep, chip_id_t *cidp, boolean_t enable_dma);
int bge_chip_id_init(bge_t *bgep);
void bge_chip_coalesce_update(bge_t *bgep);
int bge_chip_start(bge_t *bgep, boolean_t reset_phy);
void bge_chip_stop(bge_t *bgep, boolean_t fault);
#ifndef __sparc
void bge_chip_stop_nonblocking(bge_t *bgep);
#endif
#ifdef BGE_IPMI_ASF
void bge_nic_put32(bge_t *bgep, bge_regno_t addr, uint32_t data);
#pragma	inline(bge_nic_put32)
uint32_t bge_nic_read32(bge_t *bgep, bge_regno_t addr);
void bge_ind_put32(bge_t *bgep, bge_regno_t regno, uint32_t val);
#pragma inline(bge_ind_put32)
uint32_t bge_ind_get32(bge_t *bgep, bge_regno_t regno);
#pragma inline(bge_ind_get32)
void bge_asf_update_status(bge_t *bgep);
void bge_asf_heartbeat(void *bgep);
void bge_asf_stop_timer(bge_t *bgep);
void bge_asf_get_config(bge_t *bgep);
void bge_asf_pre_reset_operations(bge_t *bgep, uint32_t mode);
void bge_asf_post_reset_old_mode(bge_t *bgep, uint32_t mode);
void bge_asf_post_reset_new_mode(bge_t *bgep, uint32_t mode);
int bge_chip_reset(bge_t *bgep, boolean_t enable_dma, uint_t asf_mode);
int bge_chip_sync(bge_t *bgep, boolean_t asf_keeplive);
#else
int bge_chip_reset(bge_t *bgep, boolean_t enable_dma);
int bge_chip_sync(bge_t *bgep);
#endif
void bge_chip_blank(void *arg, time_t ticks, uint_t count, int flag);
extern mblk_t *bge_poll_ring(void *, int);
uint_t bge_chip_factotum(caddr_t arg);
void bge_chip_cyclic(void *arg);
enum ioc_reply bge_chip_ioctl(bge_t *bgep, queue_t *wq, mblk_t *mp,
	struct iocblk *iocp);
uint_t bge_intr(caddr_t arg1, caddr_t arg2);
void bge_sync_mac_modes(bge_t *);
extern uint32_t bge_rx_ticks_norm;
extern uint32_t bge_tx_ticks_norm;
extern uint32_t bge_rx_count_norm;
extern uint32_t bge_tx_count_norm;
extern boolean_t bge_relaxed_ordering;

void   bge_chip_msi_trig(bge_t *bgep);

/* bge_kstats.c */
void bge_init_kstats(bge_t *bgep, int instance);
void bge_fini_kstats(bge_t *bgep);
int bge_m_stat(void *arg, uint_t stat, uint64_t *val);
int bge_rx_ring_stat(mac_ring_driver_t, uint_t, uint64_t *);

/* bge_log.c */
#if	BGE_DEBUGGING
void (*bge_db(bge_t *bgep))(const char *fmt, ...);
void (*bge_gdb(void))(const char *fmt, ...);
void bge_pkt_dump(bge_t *bgep, bge_rbd_t *hbp, sw_rbd_t *sdp, const char *msg);
void bge_dbg_enter(bge_t *bgep, const char *msg);
#endif	/* BGE_DEBUGGING */
void bge_problem(bge_t *bgep, const char *fmt, ...);
void bge_log(bge_t *bgep, const char *fmt, ...);
void bge_error(bge_t *bgep, const char *fmt, ...);
void bge_fm_ereport(bge_t *bgep, char *detail);
extern kmutex_t bge_log_mutex[1];
extern uint32_t bge_debug;

/* bge_main.c */
int bge_restart(bge_t *bgep, boolean_t reset_phy);
int bge_check_acc_handle(bge_t *bgep, ddi_acc_handle_t handle);
int bge_check_dma_handle(bge_t *bgep, ddi_dma_handle_t handle);
void bge_init_rings(bge_t *bgep);
void bge_fini_rings(bge_t *bgep);
bge_queue_item_t *bge_alloc_txbuf_array(bge_t *bgep, send_ring_t *srp);
void bge_free_txbuf_arrays(send_ring_t *srp);
int bge_alloc_bufs(bge_t *bgep);
void bge_free_bufs(bge_t *bgep);
void bge_intr_enable(bge_t *bgep);
void bge_intr_disable(bge_t *bgep);
int bge_reprogram(bge_t *);

/* bge_mii.c */
void bge_eee_init(bge_t *bgep);
void bge_eee_enable(bge_t * bgep);
int bge_phys_init(bge_t *bgep);
void bge_phys_reset(bge_t *bgep);
int bge_phys_idle(bge_t *bgep);
int bge_phys_update(bge_t *bgep);
boolean_t bge_phys_check(bge_t *bgep);

/* bge_ndd.c */
int bge_nd_init(bge_t *bgep);

/* bge_recv.c */
void bge_receive(bge_t *bgep, bge_status_t *bsp);

/* bge_send.c */
mblk_t *bge_m_tx(void *arg, mblk_t *mp);
mblk_t *bge_ring_tx(void *arg, mblk_t *mp);
boolean_t bge_recycle(bge_t *bgep, bge_status_t *bsp);
uint_t bge_send_drain(caddr_t arg);

/* bge_atomic.c */
uint64_t bge_atomic_reserve(uint64_t *count_p, uint64_t n);
void bge_atomic_renounce(uint64_t *count_p, uint64_t n);
uint64_t bge_atomic_claim(uint64_t *count_p, uint64_t limit);
uint64_t bge_atomic_next(uint64_t *sp, uint64_t limit);
void bge_atomic_sub64(uint64_t *count_p, uint64_t n);
uint64_t bge_atomic_clr64(uint64_t *sp, uint64_t bits);
uint32_t bge_atomic_shl32(uint32_t *sp, uint_t count);

/* bge_mii_5906.c */
void bge_adj_volt_5906(bge_t *bgep);

/*
 * Reset type
 */
#define	BGE_SHUTDOWN_RESET	0
#define	BGE_INIT_RESET		1
#define	BGE_SUSPEND_RESET	2

/* For asf_status */
#define	ASF_STAT_NONE		0
#define	ASF_STAT_STOP		1
#define	ASF_STAT_RUN		2
#define	ASF_STAT_RUN_INIT	3	/* attached but don't plumb */

/* ASF modes for bge_reset() and bge_chip_reset() */
#define	ASF_MODE_NONE		0	/* don't launch asf	 */
#define	ASF_MODE_SHUTDOWN	1	/* asf shutdown mode	 */
#define	ASF_MODE_INIT		2	/* asf init mode	 */
#define	ASF_MODE_POST_SHUTDOWN	3	/* only do post-shutdown */
#define	ASF_MODE_POST_INIT	4	/* only do post-init	 */

#define	BGE_ASF_HEARTBEAT_INTERVAL		1500000

#ifdef __cplusplus
}
#endif

#endif	/* _BGE_IMPL_H */
