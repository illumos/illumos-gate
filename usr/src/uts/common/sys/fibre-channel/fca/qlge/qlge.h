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
 * Copyright 2010 QLogic Corporation. All rights reserved.
 */

#ifndef _QLGE_H
#define	_QLGE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunmdi.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/dlpi.h>
#include <sys/sdt.h>
#include <sys/mac_provider.h>
#include <sys/mac.h>
#include <sys/mac_flow.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/netlb.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/callb.h>
#include <sys/disp.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/miiregs.h>
#include <sys/kstat.h>
#include <sys/byteorder.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

#include <qlge_hw.h>
#include <qlge_dbg.h>
#include <qlge_open.h>

#define	ADAPTER_NAME		"qlge"

/*
 * Local Macro Definitions.
 */
#ifdef  TRUE
#undef  TRUE
#endif
#define	TRUE	1

#ifdef  FALSE
#undef  FALSE
#endif
#define	FALSE	0

/* #define QLGE_TRACK_BUFFER_USAGE */
/*
 * byte order, sparc is big endian, x86 is little endian,
 * but PCI is little endian only
 */
#ifdef sparc
#define	cpu_to_le64(x)	BSWAP_64(x)
#define	cpu_to_le32(x)	BSWAP_32(x)
#define	cpu_to_le16(x)	BSWAP_16(x)
#define	le64_to_cpu(x)	cpu_to_le64(x)
#define	le32_to_cpu(x)	cpu_to_le32(x)
#define	le16_to_cpu(x)	cpu_to_le16(x)
#else
#define	cpu_to_le64(x)	(x)
#define	cpu_to_le32(x)	(x)
#define	cpu_to_le16(x)	(x)
#define	le64_to_cpu(x)	(x)
#define	le32_to_cpu(x)	(x)
#define	le16_to_cpu(x)	(x)
#endif

/*
 * Macros to help code, maintain, etc.
 */

#define	LSB(x)			(uint8_t)(x)
#define	MSB(x)			(uint8_t)((uint16_t)(x) >> 8)

#define	MSW(x)			(uint16_t)((uint32_t)(x) >> 16)
#define	LSW(x)			(uint16_t)(x)

#define	MS32(x)			(uint32_t)((uint32_t)(x) >> 32)
#define	LS32(x)			(uint32_t)(x)

#define	MSW_LSB(x)		(uint8_t)(LSB(MSW(x)))
#define	MSW_MSB(x)		(uint8_t)(MSB(MSW(x)))

#define	LSD(x)			(uint32_t)(x)
#define	MSD(x)			(uint32_t)((uint64_t)(x) >> 32)

#define	SHORT_TO_LONG(a, b)	(uint32_t)((uint16_t)b << 16 | (uint16_t)a)
#define	CHAR_TO_SHORT(a, b)	(uint16_t)((uint8_t)b << 8 | (uint8_t)a)

#define	SWAP_ENDIAN_16(x)	((LSB(x) << 8) | MSB(x))

#define	SWAP_ENDIAN_32(x)	((SWAP_ENDIAN_16(LSW(x)) << 16) | \
				    SWAP_ENDIAN_16(MSW(x)))

#define	SWAP_ENDIAN_64(x)	((SWAP_ENDIAN_32(LS32(x)) << 32) | \
				    SWAP_ENDIAN_32(MS32(x)))

#define	QL_MIN(x, y)		((x < y) ? x : y)

#define	CARRIER_ON(qlge)	mac_link_update((qlge)->mh, LINK_STATE_UP)
#define	CARRIER_OFF(qlge)	mac_link_update((qlge)->mh, LINK_STATE_DOWN)

/*
 * qlge local function return status codes
 */
#define	QL_ERROR		1
#define	QL_SUCCESS		0
/*
 * Solaris version compatibility definitions.
 */
#define	QL_GET_LBOLT(timer)	timer = ddi_get_lbolt()
#define	QL_DMA_XFER_COUNTER	(uint64_t)0xffffffff
#define	QL_DRIVER_NAME(dip)	ddi_driver_name(ddi_get_parent(dip))

#define	MINOR_NODE_FLAG		8

/*
 * Host adapter default definitions.
 */

/* Timeout timer counts in seconds (must greater than 1 second). */
#define	USEC_PER_TICK		drv_hztousec(1)
#define	TICKS_PER_SEC		drv_usectohz(1000000)
#define	QL_ONE_SEC_DELAY	1000000
#define	QL_ONE_MSEC_DELAY	1000
#define	TX_TIMEOUT		3*TICKS_PER_SEC
/*
 * DMA attributes definitions.
 */
#define	QL_DMA_LOW_ADDRESS		(uint64_t)0
#define	QL_DMA_HIGH_64BIT_ADDRESS	(uint64_t)0xffffffffffffffffull
#define	QL_DMA_HIGH_32BIT_ADDRESS	(uint64_t)0xffffffff
#define	QL_DMA_ADDRESS_ALIGNMENT	(uint64_t)8
#define	QL_DMA_ALIGN_8_BYTE_BOUNDARY	(uint64_t)BIT_3
#define	QL_DMA_RING_ADDRESS_ALIGNMENT	(uint64_t)64
#define	QL_DMA_ALIGN_64_BYTE_BOUNDARY	(uint64_t)BIT_6
#define	QL_DMA_BURSTSIZES		0xfff
#define	QL_DMA_MIN_XFER_SIZE		1
#define	QL_DMA_MAX_XFER_SIZE		(uint64_t)0xffffffff
#define	QL_DMA_SEGMENT_BOUNDARY		(uint64_t)0xffffffff
#define	QL_DMA_GRANULARITY		1
#define	QL_DMA_XFER_FLAGS		0
#define	QL_MAX_COOKIES			16

/*
 * ISP PCI Configuration.
 */
#define	QL_INTR_INTERVAL	128	/* default interrupt interval 128us */
#define	QL_INTR_PKTS		8	/* default packet count threshold 8us */

/* GLD */
#define	QL_STREAM_OPS(dev_ops, attach, detach)	\
	DDI_DEFINE_STREAM_OPS(dev_ops, nulldev, nulldev, attach, detach, \
	    nodev, NULL, D_MP, NULL, ql_quiesce)

#define	QL_GET_DEV(dip)		((qlge_t *)(ddi_get_driver_private(dip)))
#define	RESUME_TX(tx_ring)		mac_tx_update(tx_ring->qlge->mh);
#define	RX_UPSTREAM(rx_ring, mp)	mac_rx(rx_ring->qlge->mh, \
					    rx_ring->qlge->handle, mp);

/* GLD DMA */
extern ddi_device_acc_attr_t ql_dev_acc_attr;
extern ddi_device_acc_attr_t ql_desc_acc_attr;
extern ddi_device_acc_attr_t ql_buf_acc_attr;

struct dma_info {
	void		 *vaddr;
	ddi_dma_handle_t dma_handle;
	ddi_acc_handle_t acc_handle;
	uint64_t	 dma_addr;
	size_t		 mem_len; /* allocated size */
	offset_t	 offset;  /* relative to handle	*/
};

/*
 * Sync a DMA area described by a dma_info
 */
#define	DMA_SYNC(area, flag)	((void) ddi_dma_sync((area).dma_handle,	\
				    (area).offset, (area).mem_len, (flag)))

/*
 * Find the (kernel virtual) address of block of memory
 * described by a dma_info
 */
#define	DMA_VPTR(area)		((area).vaddr)

/*
 * Zero a block of memory described by a dma_info
 */
#define	DMA_ZERO(area)		bzero(DMA_VPTR(area), (area).mem_len)

#define	MAX_SG_ELEMENTS		16
#define	QL_MAX_TX_DMA_HANDLES	MAX_SG_ELEMENTS
#define	TOTAL_SG_ELEMENTS	(MAX_SG_ELEMENTS + TX_DESC_PER_IOCB)

/*
 * ISP PCI Configuration.
 */

/* Initialize steps */
#define	INIT_SOFTSTATE_ALLOC 		BIT_0
#define	INIT_REGS_SETUP			BIT_1
#define	INIT_DOORBELL_REGS_SETUP	BIT_2
#define	INIT_MAC_ALLOC			BIT_3
#define	INIT_PCI_CONFIG_SETUP   	BIT_4
#define	INIT_SETUP_RINGS		BIT_5
#define	INIT_MEMORY_ALLOC		BIT_6
#define	INIT_INTR_ALLOC			BIT_7
#define	INIT_ADD_INTERRUPT		BIT_8
#define	INIT_LOCKS_CREATED		BIT_9
#define	INIT_ADD_SOFT_INTERRUPT		BIT_10
#define	INIT_MUTEX			BIT_11
#define	ADAPTER_INIT			BIT_12
#define	INIT_MAC_REGISTERED		BIT_13
#define	INIT_KSTATS			BIT_14
#define	INIT_FM				BIT_15
#define	INIT_ADAPTER_UP			BIT_16
#define	INIT_ALLOC_RX_BUF		BIT_17
#define	INIT_INTR_ENABLED		BIT_18


#define	LS_64BITS(x)	(uint32_t)(0xffffffff & ((uint64_t)x))
#define	MS_64BITS(x)	(uint32_t)(0xffffffff & (((uint64_t)x)>>16>>16))

typedef uint64_t dma_addr_t;
extern int ql_quiesce(dev_info_t *dip);

/*
 * LSO can support up to 65535 bytes of data, but can not be sent in one IOCB
 * which only has 8 TX OALs, additional OALs must be applied separately.
 */
#define	QL_LSO_MAX		65535 /* Maximum supported LSO data Length */

enum tx_mode_t {
	USE_DMA,
	USE_COPY
};

#define	QL_MAX_COPY_LENGTH	256

#define	MAX_FRAGMENTS_IN_IOCB	7

#ifndef VLAN_ID_MASK
#define	VLAN_ID_MASK		0x0fffu
#endif
#ifndef VLAN_TAGSZ
#define	VLAN_TAGSZ		4
#endif

#ifndef	ETHERTYPE_VLAN
#define	ETHERTYPE_VLAN		0x8100
#endif

#ifndef	MBLKL
#define	MBLKL(mp)	((uintptr_t)(mp)->b_wptr - (uintptr_t)(mp)->b_rptr)
#endif
/*
 * Checksum Offload
 */
#define	TCP_CKSUM_OFFSET	16
#define	UDP_CKSUM_OFFSET	6
#define	IPPROTO_IPv6OVERv4	41

/*
 * Driver must be in one of these states
 */
enum mac_state {
	QL_MAC_INIT,		/* in the initialization stage */
	QL_MAC_ATTACHED,	/* driver attached */
	QL_MAC_STARTED,		/* interrupt enabled, driver is ready */
	QL_MAC_BRINGDOWN,	/* in the bring down process */
	QL_MAC_STOPPED,		/* stoped, no more interrupts */
	QL_MAC_DETACH,		/* to be detached */
	QL_MAC_SUSPENDED
};

/*
 * Soft Request Flag
 */
#define	NEED_HW_RESET	BIT_0	/* need hardware reset */
#define	NEED_MPI_RESET	BIT_1	/* need MPI RISC reset */

/*
 * (Internal) return values from ioctl subroutines
 */
enum ioc_reply {
	IOC_INVAL = -1,			/* bad, NAK with EINVAL	*/
	IOC_DONE,			/* OK, reply sent	*/
	IOC_ACK,			/* OK, just send ACK	*/
	IOC_REPLY,			/* OK, just send reply	*/
	IOC_RESTART_ACK,		/* OK, restart & ACK	*/
	IOC_RESTART_REPLY		/* OK, restart & reply	*/
};

/*
 * Link Speed,in Mbps
 */
#define	SPEED_10		10
#define	SPEED_100		100
#define	SPEED_1000		1000
#define	SPEED_10G		10000

/*
 * Multicast List
 */
typedef struct {
	struct ether_addr	addr;
	unsigned char		reserved[2];
} ql_multicast_addr;

#define	MAX_MULTICAST_LIST_SIZE	128

typedef struct {
	struct ether_addr	addr;		/* in canonical form	*/
	boolean_t		set;		/* B_TRUE => valid	*/
} qlge_mac_addr_t;

#define	MAX_UNICAST_LIST_SIZE	128

/*
 * Device kstate structure.
 */
enum {
	QL_KSTAT_CHIP = 0,
	QL_KSTAT_LINK,
	QL_KSTAT_REG,
	QL_KSTAT_COUNT
};

/*
 * Register Bit Set/Reset
 */
enum {
	BIT_SET = 0,
	BIT_RESET
};

/*
 * Flash Image Search State
 */
enum {	STOP_SEARCH,		/* Image address bad, no more search */
	CONTINUE_SEARCH,	/* Image address ok, continue search */
	LAST_IMAGE_FOUND	/* Found last image and FLTDS address */
};

/*
 * Loop Back Modes
 */
enum {	QLGE_LOOP_NONE,
	QLGE_LOOP_INTERNAL_PARALLEL,
	QLGE_LOOP_INTERNAL_SERIAL,
	QLGE_LOOP_EXTERNAL_PHY
};

/* for soft state routine */
typedef struct {
	offset_t	index;
	char		*name;
} ql_ksindex_t;

struct bq_desc {
	struct		dma_info bd_dma;
	struct		bq_desc *next;
	struct		rx_ring *rx_ring;
	mblk_t		*mp;
	frtn_t		rx_recycle;	/* recycle function - called after mp */
					/* is to be freed by OS */
	uint16_t	index;
	uint16_t	free_buf;	/* Set to indicate the buffer is */
					/* being freed, new one should not */
					/* be allocated */
	uint32_t	upl_inuse;	/* buffer in use by upper layers */
};

#define	VM_PAGE_SIZE		4096

#define	QLGE_POLL_ALL		-1

#define	SMALL_BUFFER_SIZE	512
#define	LARGE_BUFFER_SIZE	4096

#define	MAX_TX_WAIT_COUNT	1000
#define	MAX_RX_WAIT_COUNT	25	/* 25 second */

#define	MIN_BUFFERS_ARM_COUNT	16
#define	MIN_BUFFERS_FREE_COUNT	32	/* If free buffer count go over this */
					/* value, arm the chip */
/* if less than 16 free lrg buf nodes in the free list, then */
/* rx has to use copy method to send packets upstream */
#define	RX_COPY_MODE_THRESHOLD	(MIN_BUFFERS_ARM_COUNT/4)
/* if there are more than TX_STOP_THRESHOLD free tx buffers, try to send it */
#define	TX_STOP_THRESHOLD	16
#define	TX_RESUME_THRESHOLD	8

struct tx_ring_desc {
	struct ob_mac_iocb_req *queue_entry;	/* tx descriptor of this */
	struct dma_info		dma_mem_area;	/* tx buffer */
	ddi_dma_handle_t	tx_dma_handle[QL_MAX_TX_DMA_HANDLES];
	int			tx_dma_handle_used;
	enum tx_mode_t		tx_type;	/* map mode or copy mode */
	mblk_t			*mp;		/* requested sending packet */
	uint32_t		index;
	caddr_t			copy_buffer;
	uint64_t		copy_buffer_dma_addr;
	struct dma_info		oal_dma;	/* oal is premapped */
	uint64_t		oal_dma_addr;	/* oal dma address premapped */
	uint32_t		tx_bytes;
	void			*oal;
};

struct tx_ring {
	struct qlge		*qlge;
	struct dma_info		wqicb_dma;
	uint16_t		cq_id;		/* completion (rx) queue for */
						/* tx completions */
	uint8_t			wq_id;
	uint32_t		wq_size;
	uint32_t		wq_len;
	kmutex_t		tx_lock;
	struct dma_info		wq_dma;
	volatile uint32_t	tx_free_count;
	uint32_t		tx_mode;
	boolean_t		queue_stopped;	/* Tx no resource */
	uint32_t		*prod_idx_db_reg;
	uint16_t		prod_idx;
	uint32_t		*valid_db_reg;	/* PCI doorbell mem area + 4 */
	struct tx_ring_desc	*wq_desc;
				/* shadow copy of consumer idx */
	uint32_t		*cnsmr_idx_sh_reg;
				/* dma-shadow copy consumer */
	uint64_t		cnsmr_idx_sh_reg_dma;
	uint32_t		defer;	/* tx no resource */
	uint64_t		obytes;
	uint64_t		opackets;
	uint32_t		errxmt;
	uint64_t		brdcstxmt;
	uint64_t		multixmt;
	uint64_t		tx_fail_dma_bind;
	uint64_t		tx_no_dma_handle;
	uint64_t		tx_no_dma_cookie;

	enum mac_state		mac_flags;
};

struct bq_element {
uint32_t addr_lo;
uint32_t addr_hi;
};

/*
 * Type of inbound queue.
 */
enum {
	DEFAULT_Q = 2,		/* Handles slow queue and chip/MPI events. */
	TX_Q = 3,		/* Handles outbound completions. */
	RX_Q = 4,		/* Handles inbound completions. */
};

struct rx_ring {
	struct dma_info		cqicb_dma;

	/* GLD required flags */
	uint64_t		ring_gen_num;
	/* statistics */
	uint64_t		rx_packets;
	uint64_t		rx_bytes;
	uint32_t		frame_too_long;
	uint32_t		frame_too_short;
	uint32_t		fcs_err;
	uint32_t		rx_packets_dropped_no_buffer;
	uint32_t		rx_pkt_dropped_mac_unenabled;
	volatile uint32_t	rx_indicate;

	/* miscellaneous */
	int			type; /* DEFAULT_Q, TX_Q, RX_Q */
	kmutex_t		rx_lock;
	uint32_t		irq;
	struct qlge		*qlge;
	uint32_t		cpu;	/* Which CPU this should run on. */
	enum mac_state		mac_flags;
	/* completion queue */
	struct dma_info		cq_dma;	/* virtual addr and phy addr */
	uint32_t		cq_size;
	uint32_t		cq_len;
	uint16_t		cq_id;
	off_t			prod_idx_sh_reg_offset;
	volatile uint32_t	*prod_idx_sh_reg;	/* Shadowed prod reg */
	uint64_t		prod_idx_sh_reg_dma;	/* Physical address */
	uint32_t		*cnsmr_idx_db_reg;	/* PCI db mem area 0 */
	uint32_t		cnsmr_idx;		/* current sw idx */
	struct net_rsp_iocb	*curr_entry;	/* next entry on queue */
	uint32_t		*valid_db_reg;	/* PCI doorbell mem area + 4 */

	/* large buffer queue */
	uint32_t 		lbq_len;		/* entry count */
	uint32_t		lbq_size;		/* size in bytes */
	uint32_t		lbq_buf_size;
	struct dma_info		lbq_dma;		/* lbq dma info */
	uint64_t		*lbq_base_indirect;
	uint64_t		lbq_base_indirect_dma;
	kmutex_t 		lbq_lock;
	struct bq_desc		**lbuf_in_use;
	volatile uint32_t	lbuf_in_use_count;
	struct bq_desc		**lbuf_free;
	volatile uint32_t	lbuf_free_count;	/* free lbuf desc cnt */
	uint32_t		*lbq_prod_idx_db_reg; /* PCI db mem area+0x18 */
	uint32_t		lbq_prod_idx;	/* current sw prod idx */
	uint32_t		lbq_curr_idx;	/* next entry we expect */
	uint32_t		lbq_free_tail;	/* free tail */
	uint32_t		lbq_free_head;	/* free head */
	uint32_t		lbq_use_tail;	/* inuse tail */
	uint32_t		lbq_use_head;	/* inuse head */

	struct bq_desc		*lbq_desc;

	/* small buffer queue */
	uint32_t		sbq_len;		/* entry count */
	uint32_t		sbq_size;	/* size in bytes of queue */
	uint32_t		sbq_buf_size;
	struct dma_info		sbq_dma; 		/* sbq dma info */
	uint64_t		*sbq_base_indirect;
	uint64_t		sbq_base_indirect_dma;
	kmutex_t		sbq_lock;
	struct bq_desc		**sbuf_in_use;
	volatile uint32_t	sbuf_in_use_count;
	struct bq_desc		**sbuf_free;
	volatile uint32_t	sbuf_free_count; /* free buffer desc cnt */
	uint32_t		*sbq_prod_idx_db_reg; /* PCI db mem area+0x1c */
	uint32_t		sbq_prod_idx;	/* current sw prod idx */
	uint32_t		sbq_curr_idx;	/* next entry we expect */
	uint32_t		sbq_free_tail;	/* free tail */
	uint32_t		sbq_free_head;	/* free head */
	uint32_t		sbq_use_tail;	/* inuse tail */
	uint32_t		sbq_use_head;	/* inuse head */
	struct bq_desc		*sbq_desc;
	/* for test purpose */
	uint32_t		rx_failed_sbq_allocs;
	uint32_t		rx_failed_lbq_allocs;
	uint32_t		sbuf_copy_count;
	uint32_t		lbuf_copy_count;

#ifdef QLGE_PERFORMANCE
	uint32_t		hist[8];
#endif
};

struct intr_ctx {
	struct	qlge		*qlge;
	uint32_t		intr;
	uint32_t		hooked;
	uint32_t		intr_en_mask;
	uint32_t		intr_dis_mask;
	uint32_t		intr_read_mask;
				/*
				 * It's incremented for
				 * each irq handler that is scheduled.
				 * When each handler finishes it
				 * decrements irq_cnt and enables
				 * interrupts if it's zero.
				 */
	uint32_t		irq_cnt;
	uint_t			(*handler)(caddr_t, caddr_t);
};

struct tx_buf_desc {
	uint64_t		addr;
	uint32_t		len;
#define	TX_DESC_LEN_MASK	0x000fffff
#define	TX_DESC_C		0x40000000
#define	TX_DESC_E		0x80000000
};

typedef struct qlge {
	/*
	 * Solaris adapter configuration data
	 */
	dev_info_t		*dip;
	int			instance;
	ddi_acc_handle_t	dev_handle;
	caddr_t			iobase;
	ddi_acc_handle_t	dev_doorbell_reg_handle;
	caddr_t			doorbell_reg_iobase;
	pci_cfg_t		pci_cfg;
	ddi_acc_handle_t	pci_handle;
	uint32_t		page_size;
	uint32_t		sequence;
	struct intr_ctx		intr_ctx[MAX_RX_RINGS];
	struct dma_info		ricb_dma;
	/* fault management capabilities */
	int			fm_capabilities;
	boolean_t		fm_enable;
	enum mac_state		mac_flags;

	volatile uint32_t	cfg_flags;

#define	CFG_JUMBLE_PACKET		BIT_1
#define	CFG_RX_COPY_MODE		BIT_2
#define	CFG_SUPPORT_MULTICAST		BIT_3
#define	CFG_HW_UNABLE_PSEUDO_HDR_CKSUM	BIT_4
#define	CFG_CKSUM_HEADER_IPv4		BIT_5
#define	CFG_CKSUM_PARTIAL		BIT_6
#define	CFG_CKSUM_FULL_IPv4		BIT_7
#define	CFG_CKSUM_FULL_IPv6		BIT_8
#define	CFG_LSO				BIT_9
#define	CFG_SUPPORT_SCATTER_GATHER	BIT_10
#define	CFG_ENABLE_SPLIT_HEADER		BIT_11
#define	CFG_ENABLE_EXTENDED_LOGGING	BIT_15
	uint32_t			chksum_cap;
	volatile uint32_t		flags;
#define	CFG_CHIP_8100			BIT_16

#define	CFG_IST(qlge, cfgflags)		(qlge->cfg_flags & cfgflags)

	/* For Shadow Registers, used by adapter to write to host memory */
	struct dma_info		host_copy_shadow_dma_attr;
	/*
	 * Extra 2x8 bytes memory saving large/small buf queue base address
	 * for each CQICB and read by chip, new request since 8100
	 */
	struct dma_info		buf_q_ptr_base_addr_dma_attr;
	/*
	 * Debugging
	 */
	uint32_t		ql_dbgprnt;
	/*
	 * GLD
	 */
	mac_handle_t		mh;
	mac_resource_handle_t	handle;
	ql_stats_t		stats;
	kstat_t			*ql_kstats[QL_KSTAT_COUNT];
	/*
	 * mutex
	 */
	kmutex_t		gen_mutex;	/* general adapter mutex */
	kmutex_t		hw_mutex;	/* common hw(nvram)access */

	/*
	 * Generic timer
	 */
	timeout_id_t		ql_timer_timeout_id;
	clock_t			ql_timer_ticks;

	/*
	 * Interrupt
	 */
	int			intr_type;
	/* for legacy interrupt */
	ddi_iblock_cookie_t	iblock_cookie;
	/* for MSI and Fixed interrupts */
	ddi_intr_handle_t	*htable;	/* For array of interrupts */
	int			intr_cnt; /* # of intrs actually allocated */
	uint_t			intr_pri;	/* Interrupt priority */
	int			intr_cap;	/* Interrupt capabilities */
	size_t			intr_size;	/* size of the allocated  */
						/* interrupt handlers */
	/* Power management context. */
	uint8_t			power_level;
#define	LOW_POWER_LEVEL		(BIT_1 | BIT_0)
#define	MAX_POWER_LEVEL		0

	/*
	 * General NIC
	 */
	uint32_t		xgmac_sem_mask;
	uint32_t		xgmac_sem_bits;
	uint32_t		func_number;
	uint32_t		fn0_net;	/* network function 0 port */
	uint32_t		fn1_net;	/* network function 1 port */

	uint32_t		mtu;
	uint32_t		max_frame_size;
	uint32_t		port_link_state;
	uint32_t		speed;
	uint16_t		link_type;
	uint32_t		duplex;
	uint32_t		pause;	/* flow-control mode */
	uint32_t		loop_back_mode;
	uint32_t		lso_enable;
	uint32_t		dcbx_enable;	/* dcbx mode */
	/*
	 * PCI status
	 */
	uint16_t		vendor_id;
	uint16_t		device_id;

	/*
	 * Multicast list
	 */
	uint32_t		multicast_list_count;
	ql_multicast_addr	multicast_list[MAX_MULTICAST_LIST_SIZE];
	boolean_t		multicast_promisc;
	/*
	 * MAC address information
	 */
	struct ether_addr	dev_addr; /* ethernet address read from nvram */
	qlge_mac_addr_t		unicst_addr[MAX_UNICAST_LIST_SIZE];
	uint32_t		unicst_total; /* total unicst addresses */
	uint32_t		unicst_avail;
	/*
	 * Soft Interrupt handlers
	 */
	/* soft interrupt handle for MPI interrupt */
	ddi_softint_handle_t	mpi_event_intr_hdl;
	/* soft interrupt handle for asic reset */
	ddi_softint_handle_t	asic_reset_intr_hdl;
	/* soft interrupt handle for mpi reset */
	ddi_softint_handle_t	mpi_reset_intr_hdl;
	/*
	 * IOCTL
	 */
	/* new ioctl admin flags to work around the 1024 max data copy in&out */
	caddr_t			ioctl_buf_ptr;
	uint32_t		ioctl_buf_lenth;
	uint16_t		expected_trans_times;
	uint32_t		ioctl_total_length;
	uint32_t		ioctl_transferred_bytes;
	ql_mpi_coredump_t	ql_mpi_coredump;
	/*
	 * Mailbox lock and flags
	 */
	boolean_t		fw_init_complete;
	kmutex_t		mbx_mutex;
	boolean_t		mbx_wait_completion;
	kcondvar_t		cv_mbx_intr;
	mbx_data_t 		received_mbx_cmds;
	uint_t			max_read_mbx;
	firmware_version_info_t		fw_version_info;
	phy_firmware_version_info_t	phy_version_info;
	port_cfg_info_t			port_cfg_info;
	struct dma_info			ioctl_buf_dma_attr;

	/*
	 * Flash
	 */
	uint32_t		flash_fltds_addr;
	uint32_t		flash_flt_fdt_index;
	uint32_t		flash_fdt_addr;
	uint32_t		flash_fdt_size;
	uint32_t		flash_flt_nic_config_table_index;
	uint32_t		flash_nic_config_table_addr;
	uint32_t		flash_nic_config_table_size;
	uint32_t		flash_vpd_addr;
	ql_flash_info_t		flash_info;
	ql_fltds_t		fltds;
	ql_flt_t		flt;
	uint16_t		flash_len;	/* size of Flash memory */
	ql_nic_config_t		nic_config;
	flash_desc_t		fdesc;
	/*
	 * TX / RX
	 */
	clock_t			last_tx_time;
	boolean_t		rx_copy;
	uint16_t		rx_coalesce_usecs;
	uint16_t		rx_max_coalesced_frames;
	uint16_t		tx_coalesce_usecs;
	uint16_t		tx_max_coalesced_frames;
	uint32_t		payload_copy_thresh;

	uint32_t		xg_sem_mask;

	uint32_t		ip_hdr_offset;
	uint32_t		selected_tx_ring;

	struct rx_ring		rx_ring[MAX_RX_RINGS];
	struct tx_ring		tx_ring[MAX_TX_RINGS];
	uint32_t		rx_polls[MAX_RX_RINGS];
	uint32_t		rx_interrupts[MAX_RX_RINGS];

	int 			tx_ring_size;
	int 			rx_ring_size;
	uint32_t		rx_copy_threshold;
	uint32_t		rx_ring_count;
	uint32_t		rss_ring_count;
	uint32_t		tx_ring_first_cq_id;
	uint32_t		tx_ring_count;
	uint32_t		isr_stride;
#ifdef QLGE_TRACK_BUFFER_USAGE
	/* Count no of times the buffers fell below 32 */
	uint32_t		rx_sb_low_count[MAX_RX_RINGS];
	uint32_t		rx_lb_low_count[MAX_RX_RINGS];
	uint32_t		cq_low_count[MAX_RX_RINGS];
#endif
} qlge_t;


/*
 * Reconfiguring the network devices requires the net_config privilege
 * in Solaris 10+.
 */
extern int secpolicy_net_config(const cred_t *, boolean_t);

/*
 * Global Function Prototypes in qlge_dbg.c source file.
 */
extern int ql_fw_dump(qlge_t *);
extern uint8_t ql_get8(qlge_t *, uint32_t);
extern uint16_t ql_get16(qlge_t *, uint32_t);
extern uint32_t ql_get32(qlge_t *, uint32_t);
extern void ql_put8(qlge_t *, uint32_t, uint8_t);
extern void ql_put16(qlge_t *, uint32_t, uint16_t);
extern void ql_put32(qlge_t *, uint32_t, uint32_t);
extern uint32_t ql_read_reg(qlge_t *, uint32_t);
extern void ql_write_reg(qlge_t *, uint32_t, uint32_t);
extern void ql_dump_all_contrl_regs(qlge_t *);
extern int ql_wait_reg_bit(qlge_t *, uint32_t, uint32_t, int, uint32_t);
extern void ql_dump_pci_config(qlge_t *);
extern void ql_dump_host_pci_regs(qlge_t *);
extern void ql_dump_req_pkt(qlge_t *, struct ob_mac_iocb_req *, void *, int);
extern void ql_dump_cqicb(qlge_t *, struct cqicb_t *);
extern void ql_dump_wqicb(qlge_t *, struct wqicb_t *);
extern void ql_gld3_init(qlge_t *, mac_register_t *);
enum ioc_reply ql_chip_ioctl(qlge_t *, queue_t *, mblk_t *);
enum ioc_reply ql_loop_ioctl(qlge_t *, queue_t *, mblk_t *, struct iocblk *);
extern int ql_8xxx_binary_core_dump(qlge_t *, ql_mpi_coredump_t *);
/*
 * Global Data in qlge.c source file.
 */
extern void qlge_delay(clock_t usecs);
extern int ql_sem_spinlock(qlge_t *, uint32_t);
extern void ql_sem_unlock(qlge_t *, uint32_t);
extern int ql_sem_lock(qlge_t *, uint32_t, uint32_t);
extern int ql_init_misc_registers(qlge_t *);
extern int ql_init_mem_resources(qlge_t *);
extern int ql_do_start(qlge_t *);
extern int ql_do_stop(qlge_t *);
extern int ql_add_to_multicast_list(qlge_t *, uint8_t *ep);
extern int ql_remove_from_multicast_list(qlge_t *, uint8_t *);
extern void ql_set_promiscuous(qlge_t *, int);
extern void ql_get_hw_stats(qlge_t *);
extern int ql_send_common(struct tx_ring *, mblk_t *);
extern void ql_wake_asic_reset_soft_intr(qlge_t *);
extern void ql_write_doorbell_reg(qlge_t *, uint32_t *, uint32_t);
extern uint32_t ql_read_doorbell_reg(qlge_t *, uint32_t *);
extern int ql_set_mac_addr_reg(qlge_t *, uint8_t *, uint32_t, uint16_t);
extern int ql_read_xgmac_reg(qlge_t *, uint32_t, uint32_t *);
extern void ql_enable_completion_interrupt(qlge_t *, uint32_t);
extern mblk_t *ql_ring_rx_poll(void *, int);
extern void ql_disable_completion_interrupt(qlge_t *qlge, uint32_t intr);
extern mblk_t *ql_ring_tx(void *arg, mblk_t *mp);
extern uint8_t ql_tx_hashing(qlge_t *qlge, caddr_t bp);
extern void ql_atomic_set_32(volatile uint32_t *target, uint32_t newval);
extern uint32_t ql_atomic_read_32(volatile uint32_t *target);
extern void ql_restart_timer(qlge_t *qlge);
extern int ql_route_initialize(qlge_t *);
/*
 * Global Function Prototypes in qlge_flash.c source file.
 */
extern int ql_sem_flash_lock(qlge_t *);
extern void ql_sem_flash_unlock(qlge_t *);
extern int qlge_load_flash(qlge_t *, uint8_t *, uint32_t, uint32_t);
extern int qlge_dump_fcode(qlge_t *, uint8_t *, uint32_t, uint32_t);
extern int ql_flash_vpd(qlge_t *qlge, uint8_t *buf);
extern int ql_get_flash_params(qlge_t *qlge);
/*
 * Global Function Prototypes in qlge_mpi.c source file.
 */
extern void ql_do_mpi_intr(qlge_t *qlge);
extern int ql_reset_mpi_risc(qlge_t *);
extern int ql_get_fw_state(qlge_t *, uint32_t *);
extern int qlge_get_link_status(qlge_t *, struct qlnic_link_status_info *);
extern int ql_mbx_test(qlge_t *qlge);
extern int ql_mbx_test2(qlge_t *qlge);
extern int ql_get_port_cfg(qlge_t *qlge);
extern int ql_set_mpi_port_config(qlge_t *qlge, port_cfg_info_t new_cfg);
extern int ql_set_loop_back_mode(qlge_t *qlge);
extern int ql_set_pause_mode(qlge_t *qlge);
extern int ql_get_LED_config(qlge_t *);
extern int ql_dump_sfp(qlge_t *, void *bp, int mode);
extern int ql_set_IDC_Req(qlge_t *, uint8_t dest_functions, uint8_t timeout);
extern void ql_write_flash_test(qlge_t *qlge, uint32_t testAddr);
extern void ql_write_flash_test2(qlge_t *qlge, uint32_t testAddr);
extern int ql_get_firmware_version(qlge_t *,
    struct qlnic_mpi_version_info *);
extern int ql_read_processor_data(qlge_t *, uint32_t, uint32_t *);
extern int ql_write_processor_data(qlge_t *, uint32_t, uint32_t);
extern int ql_read_risc_ram(qlge_t *, uint32_t, uint64_t, uint32_t);
extern int ql_trigger_system_error_event(qlge_t *qlge);

extern void ql_core_dump(qlge_t *);
extern void ql_dump_crash_record(qlge_t *);
extern void ql_dump_buf(char *, uint8_t *, uint8_t, uint32_t);
extern void ql_printf(const char *, ...);

/*
 * Global Function Prototypes in qlge_gld.c source file.
 */
extern int ql_unicst_set(qlge_t *qlge, const uint8_t *macaddr, int slot);

/*
 * Global Function Prototypes in qlge_fm.c source file.
 */
extern void ql_fm_ereport(qlge_t *qlge, char *detail);
extern int ql_fm_check_acc_handle(ddi_acc_handle_t handle);
extern int ql_fm_check_dma_handle(ddi_dma_handle_t handle);


#ifdef __cplusplus
}
#endif

#endif /* _QLGE_H */
