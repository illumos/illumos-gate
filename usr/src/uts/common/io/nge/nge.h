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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NGE_H
#define	_SYS_NGE_H

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
#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <sys/pattr.h>
#include <sys/errno.h>
#include <sys/dlpi.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/conf.h>
#include <sys/callb.h>

#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <netinet/udp.h>
#include <inet/mi.h>
#include <inet/nd.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/mac_provider.h>
#include <sys/mac_ether.h>

/*
 * Reconfiguring the network devices requires the net_config privilege
 * in Solaris 10+.
 */
extern int secpolicy_net_config(const cred_t *, boolean_t);

#include <sys/netlb.h>
#include <sys/miiregs.h>

#include "nge_chip.h"

#define	PIO_ADDR(ngep, offset)	((void *)((caddr_t)(ngep)->io_regs+(offset)))
/*
 * Copy an ethernet address
 */
#define	ethaddr_copy(src, dst)	bcopy((src), (dst), ETHERADDRL)
#define	ether_eq(a, b) (bcmp((caddr_t)(a), (caddr_t)(b), (ETHERADDRL)) == 0)

#define	BIS(w, b)	(((w) & (b)) ? B_TRUE : B_FALSE)
#define	BIC(w, b)	(((w) & (b)) ? B_FALSE : B_TRUE)
#define	UPORDOWN(x)	((x) ? "up" : "down")

#define	NGE_DRIVER_NAME		"nge"

/*
 * 'Progress' bit flags ...
 */
#define	PROGRESS_CFG		0x0001	/* config space mapped		*/
#define	PROGRESS_REGS		0x0002	/* registers mapped		*/
#define	PROGRESS_BUFS		0x0004	/* registers mapped		*/
#define	PROGRESS_RESCHED	0x0008	/* resched softint registered	*/
#define	PROGRESS_FACTOTUM	0x0010	/* factotum softint registered	*/
#define	PROGRESS_SWINT		0x0020	/* s/w interrupt registered	*/
#define	PROGRESS_INTR		0x0040	/* h/w interrupt registered	*/
					/* and mutexen initialised	*/
#define	PROGRESS_HWINT		0x0080
#define	PROGRESS_PHY		0x0100	/* PHY initialised		*/
#define	PROGRESS_NDD		0x0200	/* NDD parameters set up	*/
#define	PROGRESS_KSTATS		0x0400	/* kstats created		*/
#define	PROGRESS_READY		0x0800	/* ready for work		*/

#define	NGE_HW_ERR		0x00
#define	NGE_HW_LINK		0x01
#define	NGE_HW_BM		0x02
#define	NGE_HW_RCHAN		0x03
#define	NGE_HW_TCHAN		0x04
#define	NGE_HW_ROM		0x05
#define	NGE_SW_PROBLEM_ID	0x06


/*
 * NOTES:
 *
 * #defines:
 *
 *	NGE_PCI_CONFIG_RNUMBER and NGE_PCI_OPREGS_RNUMBER are the
 *	register-set numbers to use for the config space registers
 *	and the operating registers respectively.  On an OBP-based
 *	machine, regset 0 refers to CONFIG space, and regset 1 will
 *	be the operating registers in MEMORY space.  If an expansion
 *	ROM is fitted, it may appear as a further register set.
 *
 *	NGE_DMA_MODE defines the mode (STREAMING/CONSISTENT) used
 *	for the data buffers.  The descriptors are always set up
 *	in CONSISTENT mode.
 *
 *	NGE_HEADROOM defines how much space we'll leave in allocated
 *	mblks before the first valid data byte.  This should be chosen
 *	to be 2 modulo 4, so that once the ethernet header (14 bytes)
 *	has been stripped off, the packet data will be 4-byte aligned.
 *	The remaining space can be used by upstream modules to prepend
 *	any headers required.
 */


#define	NGE_PCI_OPREGS_RNUMBER	1
#define	NGE_DMA_MODE		DDI_DMA_STREAMING
#define	NGE_HEADROOM		6
#define	ETHER_HEAD_LEN		14
#ifndef	VTAG_SIZE
#define	VTAG_SIZE		4
#endif

#define	NGE_CYCLIC_PERIOD	(1000000000)

#define	NGE_DEFAULT_MTU		1500
#define	NGE_DEFAULT_SDU		1518
#define	NGE_MTU_2500		2500
#define	NGE_MTU_4500		4500
#define	NGE_MAX_MTU		9000
#define	NGE_MAX_SDU		9018

#define	NGE_DESC_MIN		0x200

#define	NGE_STD_BUFSZ		1792
#define	NGE_JB2500_BUFSZ	(3*1024)
#define	NGE_JB4500_BUFSZ	(5*1024)
#define	NGE_JB9000_BUFSZ	(9*1024)

#define	NGE_SEND_SLOTS_DESC_1024	1024
#define	NGE_SEND_SLOTS_DESC_3072	3072
#define	NGE_SEND_JB2500_SLOTS_DESC	3072
#define	NGE_SEND_JB4500_SLOTS_DESC	2048
#define	NGE_SEND_JB9000_SLOTS_DESC	1024
#define	NGE_SEND_LOWMEM_SLOTS_DESC	1024
#define	NGE_SEND_SLOTS_BUF		3072

#define	NGE_RECV_SLOTS_DESC_1024	1024
#define	NGE_RECV_SLOTS_DESC_3072	3072
#define	NGE_RECV_JB2500_SLOTS_DESC	3072
#define	NGE_RECV_JB4500_SLOTS_DESC	2048
#define	NGE_RECV_JB9000_SLOTS_DESC	1024
#define	NGE_RECV_LOWMEM_SLOTS_DESC	1024
#define	NGE_RECV_SLOTS_BUF		6144

#define	NGE_SPLIT_32		32
#define	NGE_SPLIT_96		96
#define	NGE_SPLIT_256		256

#define	NGE_RX_COPY_SIZE	512
#define	NGE_TX_COPY_SIZE	512
#define	NGE_MAP_FRAGS		3
#define	NGE_MAX_COOKIES		3
#define	NGE_MAX_DMA_HDR		(4*1024)

/* Used by interrupt moderation */
#define	NGE_TFINT_DEFAULT	32
#define	NGE_POLL_TUNE		80000
#define	NGE_POLL_ENTER		10000
#define	NGE_POLL_MAX		1280000
#define	NGE_POLL_QUIET_TIME	100
#define	NGE_POLL_BUSY_TIME	2

/*
 * NGE-specific ioctls ...
 */
#define	NGE_IOC			((((('N' << 8) + 'G') << 8) + 'E') << 8)

/*
 * PHY register read/write ioctls, used by cable test software
 */
#define	NGE_MII_READ		(NGE_IOC|1)
#define	NGE_MII_WRITE		(NGE_IOC|2)

/*
 * SEEPROM read/write ioctls, for use by SEEPROM upgrade utility
 *
 * Note: SEEPROMs can only be accessed as 32-bit words, so <see_addr>
 * must be a multiple of 4.  Not all systems have a SEEPROM fitted!
 */
#define	NGE_SEE_READ		(NGE_IOC|3)
#define	NGE_SEE_WRITE		(NGE_IOC|4)


/*
 * These diagnostic IOCTLS are enabled only in DEBUG drivers
 */
#define	NGE_DIAG		(NGE_IOC|5)	/* currently a no-op	*/
#define	NGE_PEEK		(NGE_IOC|6)
#define	NGE_POKE		(NGE_IOC|7)
#define	NGE_PHY_RESET		(NGE_IOC|8)
#define	NGE_SOFT_RESET		(NGE_IOC|9)
#define	NGE_HARD_RESET		(NGE_IOC|10)


enum NGE_HW_OP {
	NGE_CLEAR = 0,
	NGE_SET
};

/*
 * Required state according to GLD
 */
enum nge_mac_state {
	NGE_MAC_UNKNOWN,
	NGE_MAC_RESET,
	NGE_MAC_STOPPED,
	NGE_MAC_STARTED,
	NGE_MAC_UNATTACH
};
enum loop_type {
	NGE_LOOP_NONE = 0,
	NGE_LOOP_EXTERNAL_100,
	NGE_LOOP_EXTERNAL_10,
	NGE_LOOP_INTERNAL_PHY,
};

/*
 * (Internal) return values from send_msg subroutines
 */
enum send_status {
	SEND_COPY_FAIL = -1,		/* => GLD_NORESOURCES	*/
	SEND_MAP_FAIL,			/* => GLD_NORESOURCES	*/
	SEND_COPY_SUCESS,		/* OK, msg queued	*/
	SEND_MAP_SUCCESS		/* OK, free msg		*/
};

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

enum nge_pp_type {
	NGE_PP_SPACE_CFG = 0,
	NGE_PP_SPACE_REG,
	NGE_PP_SPACE_NIC,
	NGE_PP_SPACE_MII,
	NGE_PP_SPACE_NGE,
	NGE_PP_SPACE_TXDESC,
	NGE_PP_SPACE_TXBUFF,
	NGE_PP_SPACE_RXDESC,
	NGE_PP_SPACE_RXBUFF,
	NGE_PP_SPACE_STATISTICS,
	NGE_PP_SPACE_SEEPROM,
	NGE_PP_SPACE_FLASH
};

/*
 * Flag to kstat type
 */
enum nge_kstat_type {
	NGE_KSTAT_RAW = 0,
	NGE_KSTAT_STATS,
	NGE_KSTAT_CHIPID,
	NGE_KSTAT_DEBUG,
	NGE_KSTAT_COUNT
};


/*
 * Actual state of the nvidia's chip
 */
enum nge_chip_state {
	NGE_CHIP_FAULT = -2,		/* fault, need reset	*/
	NGE_CHIP_ERROR,			/* error, want reset	*/
	NGE_CHIP_INITIAL,		/* Initial state only	*/
	NGE_CHIP_RESET,			/* reset, need init	*/
	NGE_CHIP_STOPPED,		/* Tx/Rx stopped	*/
	NGE_CHIP_RUNNING		/* with interrupts	*/
};

enum nge_eeprom_size {
	EEPROM_1K = 0,
	EEPROM_2K,
	EEPROM_4K,
	EEPROM_8K,
	EEPROM_16K,
	EEPROM_32K,
	EEPROM_64K
};

enum nge_eeprom_access_wid {
	ACCESS_8BIT = 0,
	ACCESS_16BIT
};

/*
 * MDIO operation
 */
enum nge_mdio_operation {
	NGE_MDIO_READ = 0,
	NGE_MDIO_WRITE
};

/*
 * Speed selection
 */
enum nge_speed {
	UNKOWN_SPEED = 0,
	NGE_10M,
	NGE_100M,
	NGE_1000M
};

/*
 * Duplex selection
 */
enum nge_duplex {
	UNKOWN_DUPLEX = 0,
	NGE_HD,
	NGE_FD
};

typedef struct {
	ether_addr_t		addr;		/* in canonical form	*/
	uint8_t			spare;
	uint8_t			set;		/* nonzero => valid	*/
} nge_mac_addr_t;

struct nge;


#define	CHIP_FLAG_COPPER	0x40

/*
 * Collection of physical-layer functions to:
 *	(re)initialise the physical layer
 *	update it to match software settings
 *	check for link status change
 */
typedef struct {
	boolean_t	(*phys_restart)(struct nge *);
	void		(*phys_update)(struct nge *);
	boolean_t	(*phys_check)(struct nge *);
} phys_ops_t;

struct nge_see_rw {
	uint32_t	see_addr;	/* Byte offset within SEEPROM	*/
	uint32_t	see_data;	/* Data read/data to write	*/
};

typedef struct {
	uint64_t	pp_acc_size;	/* in bytes: 1,2,4,8	*/
	uint64_t	pp_acc_space;	/* See #defines below	*/
	uint64_t	pp_acc_offset;
	uint64_t	pp_acc_data;	/* output for peek	*/
					/* input for poke	*/
} nge_peekpoke_t;

typedef uintptr_t 	nge_regno_t;	/* register # (offset)	*/

typedef struct _mul_list {
	struct _mul_list *next;
	uint32_t ref_cnt;
	ether_addr_t mul_addr;
}mul_item, *pmul_item;

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
typedef struct dma_area
{

	caddr_t			private;	/* pointer to nge */
	frtn_t			rx_recycle;	/* recycle function */
	mblk_t			*mp;
	ddi_acc_handle_t	acc_hdl;	/* handle for memory	*/
	void			*mem_va;	/* CPU VA of memory	*/
	uint32_t		nslots;		/* number of slots	*/
	uint32_t		size;		/* size per slot	*/
	size_t			alength;	/* allocated size	*/
						/* >= product of above	*/
	ddi_dma_handle_t	dma_hdl;	/* DMA handle		*/
	offset_t		offset;		/* relative to handle	*/
	ddi_dma_cookie_t	cookie;		/* associated cookie	*/
	uint32_t		ncookies;
	uint32_t		signature;	/* buffer signature	*/
						/* for deciding to free */
						/* or to reuse buffers	*/
	boolean_t		rx_delivered;	/* hold by upper layer	*/
	struct dma_area		*next;
} dma_area_t;

#define	HOST_OWN	0x00000000
#define	CONTROLER_OWN	0x00000001
#define	NGE_END_PACKET	0x00000002


typedef struct nge_dmah_node
{
	struct nge_dmah_node	*next;
	ddi_dma_handle_t	hndl;
} nge_dmah_node_t;

typedef struct nge_dmah_list
{
	nge_dmah_node_t	*head;
	nge_dmah_node_t	*tail;
} nge_dmah_list_t;

/*
 * Software version of the Recv Descriptor
 * There's one of these for each recv buffer (up to 512 per ring)
 */
typedef struct sw_rx_sbd {

	dma_area_t		desc;		/* (const) related h/w	*/
						/* descriptor area	*/
	dma_area_t		*bufp;		/* (const) related	*/
						/* buffer area		*/
	uint8_t			flags;
} sw_rx_sbd_t;

/*
 * Software version of the send Buffer Descriptor
 * There's one of these for each send buffer (up to 512 per ring)
 */
typedef struct sw_tx_sbd {

	dma_area_t		desc;		/* (const) related h/w	*/
						/* descriptor area	*/
	dma_area_t		pbuf;		/* (const) related	*/
						/* buffer area		*/
	void			(*tx_recycle)(struct sw_tx_sbd *);
	uint32_t		flags;
	mblk_t			*mp;		/* related mblk, if any	*/
	nge_dmah_list_t		mp_hndl;
	uint32_t		frags;
	uint32_t		ncookies;	/* dma cookie number */

} sw_tx_sbd_t;

/*
 * Software Receive Buffer (Producer) Ring Control Block
 * There's one of these for each receiver producer ring (up to 3),
 * but each holds buffers of a different size.
 */
typedef struct buff_ring {

	uint64_t		nslots;		/* descriptor area	*/
	struct nge		*ngep;		/* (const) containing	*/
						/* driver soft state	*/
						/* initialise same	*/
	uint64_t		rx_hold;
	sw_rx_sbd_t		*sw_rbds; 	/* software descriptors	*/
	sw_rx_sbd_t		*free_rbds;	/* free ring */
	dma_area_t		*free_list;	/* available buffer queue */
	dma_area_t		*recycle_list;	/* recycling buffer queue */
	kmutex_t		recycle_lock[1];
	uint32_t		buf_sign;	/* buffer ring signature */
						/* for deciding to free  */
						/* or to reuse buffers   */
	boolean_t		rx_bcopy;
} buff_ring_t;

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
	struct nge		*ngep;		/* (const) containing	*/
						/* driver soft state	*/
	uint16_t		prod_index;	/* (const) ptr to h/w	*/
						/* "producer index"	*/
	mac_resource_handle_t	handle;
} recv_ring_t;



/*
 * Software Send Ring Control Block
 * There's one of these for each of (up to) 1 send rings
 */
typedef struct send_ring {
	/*
	 * The elements flagged (const) in the comments below are
	 * set up once during initialiation and thereafter unchanged.
	 */
	dma_area_t		desc;		/* (const) related h/w	*/
						/* descriptor area	*/
	dma_area_t		buf[NGE_SEND_SLOTS_BUF];
						/* buffer area(s)	*/
	struct nge		*ngep;		/* (const) containing	*/
						/* driver soft state	*/

	uint32_t		tx_hwmark;
	uint32_t		tx_lwmark;

	/*
	 * The tx_lock must be held when updating
	 * the s/w producer index
	 * (tx_next)
	 */
	kmutex_t		tx_lock[1];	/* serialize h/w update	*/
	uint32_t		tx_next;	/* next slot to use	*/
	uint32_t		tx_flow;

	/*
	 * These counters/indexes are manipulated in the transmit
	 * path using atomics rather than mutexes for speed
	 */
	uint32_t		tx_free;	/* # of slots available	*/

	/*
	 * index (tc_next).
	 */
	kmutex_t		tc_lock[1];
	uint32_t		tc_next;	/* next slot to recycle	*/
						/* ("consumer index")	*/

	sw_tx_sbd_t		*sw_sbds; 	/* software descriptors	*/

	kmutex_t		dmah_lock;
	nge_dmah_list_t		dmah_free;
	nge_dmah_node_t		dmahndl[NGE_MAX_DMA_HDR];

} send_ring_t;


typedef struct {
	uint32_t		businfo;	/* from private reg	*/
	uint16_t		command;	/* saved during attach	*/

	uint16_t		vendor;		/* vendor-id		*/
	uint16_t		device;		/* device-id		*/
	uint16_t		subven;		/* subsystem-vendor-id	*/
	uint16_t		subdev;		/* subsystem-id		*/
	uint8_t			class_code;
	uint8_t			revision;	/* revision-id		*/
	uint8_t			clsize;		/* cache-line-size	*/
	uint8_t			latency;	/* latency-timer	*/
	uint8_t			flags;

	uint16_t		phy_type;	/* Fiber module type 	*/
	uint64_t		hw_mac_addr;	/* from chip register	*/
	nge_mac_addr_t		vendor_addr;	/* transform of same	*/
} chip_info_t;


typedef struct {
	offset_t	index;
	char		*name;
} nge_ksindex_t;

typedef struct {
	uint64_t tso_err_mss;
	uint64_t tso_dis;
	uint64_t tso_err_nosum;
	uint64_t tso_err_hov;
	uint64_t tso_err_huf;
	uint64_t tso_err_l2;
	uint64_t tso_err_ip;
	uint64_t tso_err_l4;
	uint64_t tso_err_tcp;
	uint64_t hsum_err_ip;
	uint64_t hsum_err_l4;
}fe_statistics_t;

/*
 * statistics parameters to tune the driver
 */
typedef struct {
	uint64_t		intr_count;
	uint64_t		intr_lval;
	uint64_t		recv_realloc;
	uint64_t		poll_time;
	uint64_t		recy_free;
	uint64_t		recv_count;
	uint64_t		xmit_count;
	uint64_t		obytes;
	uint64_t		rbytes;
	uint64_t		mp_alloc_err;
	uint64_t		dma_alloc_err;
	uint64_t		kmem_alloc_err;
	uint64_t		load_context;
	uint64_t		ip_hwsum_err;
	uint64_t		tcp_hwsum_err;
	uint64_t		rx_nobuffer;
	uint64_t		rx_err;
	uint64_t		tx_stop_err;
	uint64_t		tx_stall;
	uint64_t		tx_rsrv_fail;
	uint64_t		tx_resched;
	fe_statistics_t	fe_err;
}nge_sw_statistics_t;

typedef struct {
	nge_hw_statistics_t	hw_statistics;
	nge_sw_statistics_t	sw_statistics;
}nge_statistics_t;

struct nge_desc_attr	{

	size_t	rxd_size;
	size_t	txd_size;

	ddi_dma_attr_t	*dma_attr;
	ddi_dma_attr_t	*tx_dma_attr;

	void (*rxd_fill)(void *, const ddi_dma_cookie_t *, size_t);
	uint32_t (*rxd_check)(const void *, size_t *);

	void (*txd_fill)(void *, const ddi_dma_cookie_t *, size_t,
			uint32_t, boolean_t, boolean_t);

	uint32_t (*txd_check)(const void *);
};

typedef struct nge_desc_attr nge_desc_attr_t;

/*
 * Structure used to hold the device-specific config parameters.
 * The setting of such parameters may not consistent with the
 * hardware feature of the device. It's used for software purpose.
 */
typedef struct nge_dev_spec_param {
	boolean_t	msi;		/* specifies msi support */
	boolean_t	msi_x;		/* specifies msi_x support */
	boolean_t	vlan;		/* specifies vlan support */
	boolean_t	advanced_pm;	/* advanced power management support */
	boolean_t	mac_addr_order; /* mac address order */
	boolean_t	tx_pause_frame;	/* specifies tx pause frame support */
	boolean_t	rx_pause_frame;	/* specifies rx pause frame support */
	boolean_t	jumbo;		/* jumbo frame support */
	boolean_t	tx_rx_64byte;	/* set the max tx/rx prd fetch size */
	boolean_t	rx_hw_checksum;	/* specifies tx hw checksum feature */
	uint32_t	tx_hw_checksum;	/* specifies rx hw checksum feature */
	uint32_t	desc_type;	/* specifies descriptor type */
	uint32_t	rx_desc_num;	/* specifies rx descriptor number */
	uint32_t	tx_desc_num;	/* specifies tx descriptor number */
	uint32_t	nge_split;	/* specifies the split number */
} nge_dev_spec_param_t;

typedef struct nge {
	/*
	 * These fields are set by attach() and unchanged thereafter ...
	 */
	dev_info_t		*devinfo;	/* device instance	*/
	mac_handle_t		mh;		/* mac module handle    */
	chip_info_t		chipinfo;
	ddi_acc_handle_t	cfg_handle;	/* DDI I/O handle	*/
	ddi_acc_handle_t	io_handle;	/* DDI I/O handle	*/
	void			*io_regs;	/* mapped registers	*/

	ddi_periodic_t		periodic_id;	/* periodical callback	*/
	uint32_t		factotum_flag;
	ddi_softint_handle_t	factotum_hdl;	/* factotum callback	*/
	ddi_softint_handle_t	resched_hdl;	/* reschedule callback	*/
	uint_t			soft_pri;

	ddi_intr_handle_t 	*htable;	/* for array of interrupts */
	int			intr_type;	/* type of interrupt */
	int			intr_actual_cnt; /* alloc intrs count */
	int			intr_req_cnt;	/* request intrs count */
	uint_t			intr_pri;	/* interrupt priority	*/
	int			intr_cap;	/* interrupt capabilities */

	uint32_t		progress;	/* attach tracking	*/
	uint32_t		debug;		/* flag to debug function */

	char			ifname[8];	/* "nge0" ... "nge999" */


	enum nge_mac_state	nge_mac_state;	/* definitions above	*/
	enum nge_chip_state	nge_chip_state; /* definitions above	*/
	boolean_t		promisc;
	boolean_t		record_promisc;
	boolean_t		suspended;

	int			resched_needed;
	uint32_t		default_mtu;
	uint32_t		max_sdu;
	uint32_t		buf_size;
	uint32_t		rx_desc;
	uint32_t		tx_desc;
	uint32_t		rx_buf;
	uint32_t		nge_split;
	uint32_t		watchdog;
	uint32_t		lowmem_mode;


	/*
	 * Runtime read-write data starts here ...
	 * 1 Receive Rings
	 * 1 Send Rings
	 *
	 * Note: they're not necessarily all used.
	 */
	struct buff_ring	buff[1];
	struct recv_ring	recv[1];
	struct send_ring	send[1];


	kmutex_t		genlock[1];
	krwlock_t		rwlock[1];
	kmutex_t		softlock[1];
	uint32_t		intr_masks;
	boolean_t		poll;
	boolean_t		ch_intr_mode;
	boolean_t		intr_moderation;
	uint32_t		recv_count;
	uint32_t		quiet_time;
	uint32_t		busy_time;
	uint64_t		tpkts_last;
	uint32_t		tfint_threshold;
	uint32_t		sw_intr_intv;
	nge_mac_addr_t		cur_uni_addr;
	uint32_t		rx_datahwm;
	uint32_t		rx_prdlwm;
	uint32_t		rx_prdhwm;
	uint32_t		rx_def;
	uint32_t		desc_mode;

	mul_item		*pcur_mulist;
	nge_mac_addr_t		cur_mul_addr;
	nge_mac_addr_t		cur_mul_mask;

	nge_desc_attr_t		desc_attr;

	/*
	 * Link state data (protected by genlock)
	 */
	int32_t			link_state;	/* See GLD #defines	*/
	uint32_t		stall_cknum;	/* Stall check number */

	uint32_t		phy_xmii_addr;
	uint32_t		phy_id;
	uint32_t		phy_mode;
	const phys_ops_t	*physops;
	uint16_t		phy_gen_status;

	uint32_t		param_loop_mode;

	kstat_t			*nge_kstats[NGE_KSTAT_COUNT];
	nge_statistics_t	statistics;

	nge_dev_spec_param_t	dev_spec_param;

	uint32_t		param_en_pause:1,
				param_en_asym_pause:1,
				param_en_1000hdx:1,
				param_en_1000fdx:1,
				param_en_100fdx:1,
				param_en_100hdx:1,
				param_en_10fdx:1,
				param_en_10hdx:1,
				param_adv_autoneg:1,
				param_adv_pause:1,
				param_adv_asym_pause:1,
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
				param_link_rx_pause:1,
				param_link_tx_pause:1,
				param_pad_to_32:2;
	uint64_t		param_link_speed;
	link_duplex_t		param_link_duplex;
	int			param_txbcopy_threshold;
	int			param_rxbcopy_threshold;
	int			param_recv_max_packet;
	int			param_poll_quiet_time;
	int			param_poll_busy_time;
	int			param_rx_intr_hwater;
	int			param_rx_intr_lwater;
} nge_t;

extern const nge_ksindex_t nge_statistics[];

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
 * Next/Prev value of a cyclic index
 */
#define	NEXT(index, limit)	((index) + 1 < (limit) ? (index) + 1 : 0)
#define	PREV(index, limit)	(0 == (index) ? (limit - 1) : (index) - 1)

#define	NEXT_INDEX(ndx, num, lim)\
	(((ndx) + (num) < (lim)) ? ((ndx) + (num)) : ((ndx) + (num) - (lim)))


/*
 * Property lookups
 */
#define	NGE_PROP_EXISTS(d, n)	ddi_prop_exists(DDI_DEV_T_ANY, (d),	\
					DDI_PROP_DONTPASS, (n))
#define	NGE_PROP_GET_INT(d, n)	ddi_prop_get_int(DDI_DEV_T_ANY, (d),	\
					DDI_PROP_DONTPASS, (n), -1)


/*
 * Debugging ...
 */
#ifdef	DEBUG
#define	NGE_DEBUGGING		1
#else
#define	NGE_DEBUGGING		0
#endif	/* DEBUG */

/*
 * Bit flags in the 'debug' word ...
 */
#define	NGE_DBG_STOP		0x00000001	/* early debug_enter()	*/
#define	NGE_DBG_TRACE		0x00000002	/* general flow tracing	*/

#define	NGE_DBG_MII		0x00000010	/* low-level MII access	*/
#define	NGE_DBG_CHIP		0x00000020	/* low(ish)-level code	*/

#define	NGE_DBG_RECV		0x00000100	/* receive-side code	*/
#define	NGE_DBG_SEND		0x00000200	/* packet-send code	*/

#define	NGE_DBG_INIT		0x00100000	/* initialisation	*/
#define	NGE_DBG_NEMO		0x00200000	/* MAC layer entry points */
#define	NGE_DBG_STATS		0x00400000	/* statistics		*/

#define	NGE_DBG_BADIOC		0x01000000	/* unknown ioctls	*/

#define	NGE_DBG_NDD		0x10000000	/* NDD operations	*/



/*
 * 'Do-if-debugging' macro.  The parameter <command> should be one or more
 * C statements (but without the *final* semicolon), which will either be
 * compiled inline or completely ignored, depending on the NGE_DEBUGGING
 * compile-time flag.
 *
 * You should get a compile-time error (at least on a DEBUG build) if
 * your statement isn't actually a statement, rather than unexpected
 * run-time behaviour caused by unintended matching of if-then-elses etc.
 *
 * Note that the NGE_DDB() macro itself can only be used as a statement,
 * not an expression, and should always be followed by a semicolon.
 */
#if NGE_DEBUGGING
#define	NGE_DDB(command)	do {					\
					{ command; }			\
					_NOTE(CONSTANTCONDITION)	\
				} while (0)
#else 	/* NGE_DEBUGGING */
#define	NGE_DDB(command)
/*
 * Old way of debugging.  This is a poor way, as it leeaves empty
 * statements that cause lint to croak.
 * #define	NGE_DDB(command)	do {				\
 * 					{ _NOTE(EMPTY); }		\
 * 					_NOTE(CONSTANTCONDITION)	\
 * 				} while (0)
 */
#endif	/* NGE_DEBUGGING */

/*
 * 'Internal' macros used to construct the TRACE/DEBUG macros below.
 * These provide the primitive conditional-call capability required.
 * Note: the parameter <args> is a parenthesised list of the actual
 * printf-style arguments to be passed to the debug function ...
 */
#define	NGE_XDB(b, w, f, args)	NGE_DDB(if ((b) & (w)) f args)
#define	NGE_GDB(b, args)	NGE_XDB(b, nge_debug, (*nge_gdb()), args)
#define	NGE_LDB(b, args)	NGE_XDB(b, ngep->debug, \
				    (*nge_db(ngep)), args)
#define	NGE_CDB(f, args)	NGE_XDB(NGE_DBG, ngep->debug, f, args)

/*
 * Conditional-print macros.
 *
 * Define NGE_DBG to be the relevant member of the set of NGE_DBG_* values
 * above before using the NGE_GDEBUG() or NGE_DEBUG() macros.  The 'G'
 * versions look at the Global debug flag word (nge_debug); the non-G
 * versions look in the per-instance data (ngep->debug) and so require a
 * variable called 'ngep' to be in scope (and initialised!) before use.
 *
 * You could redefine NGE_TRC too if you really need two different
 * flavours of debugging output in the same area of code, but I don't
 * really recommend it.
 *
 * Note: the parameter <args> is a parenthesised list of the actual
 * arguments to be passed to the debug function, usually a printf-style
 * format string and corresponding values to be formatted.
 */

#define	NGE_TRC	NGE_DBG_TRACE

#define	NGE_GTRACE(args)	NGE_GDB(NGE_TRC, args)
#define	NGE_GDEBUG(args)	NGE_GDB(NGE_DBG, args)
#define	NGE_TRACE(args)		NGE_LDB(NGE_TRC, args)
#define	NGE_DEBUG(args)		NGE_LDB(NGE_DBG, args)

/*
 * Debug-only action macros
 */


#define	NGE_REPORT(args)	NGE_DDB(nge_log args)

boolean_t nge_atomic_decrease(uint64_t *count_p, uint64_t n);
void nge_atomic_increase(uint64_t *count_p, uint64_t n);

int nge_alloc_dma_mem(nge_t *ngep, size_t memsize,
    ddi_device_acc_attr_t *attr_p, uint_t dma_flags, dma_area_t *dma_p);
void nge_free_dma_mem(dma_area_t *dma_p);
int nge_restart(nge_t *ngep);
void nge_wake_factotum(nge_t *ngep);

uint8_t nge_reg_get8(nge_t *ngep, nge_regno_t regno);
void nge_reg_put8(nge_t *ngep, nge_regno_t regno, uint8_t data);
uint16_t nge_reg_get16(nge_t *ngep, nge_regno_t regno);
void nge_reg_put16(nge_t *ngep, nge_regno_t regno, uint16_t data);
uint32_t nge_reg_get32(nge_t *ngep, nge_regno_t regno);
void nge_reg_put32(nge_t *ngep, nge_regno_t regno, uint32_t data);
uint_t nge_chip_factotum(caddr_t args1, caddr_t args2);
void nge_chip_cfg_init(nge_t *ngep, chip_info_t *infop, boolean_t reset);
void nge_init_dev_spec_param(nge_t *ngep);
int nge_chip_stop(nge_t *ngep, boolean_t fault);
void nge_restore_mac_addr(nge_t *ngep);
int nge_chip_reset(nge_t *ngep);
int nge_chip_start(nge_t *ngep);
void nge_chip_sync(nge_t *ngep);

uint_t nge_chip_intr(caddr_t arg1, caddr_t arg2);
enum ioc_reply nge_chip_ioctl(nge_t *ngep, mblk_t *mp, struct iocblk *iocp);

void nge_phys_init(nge_t *ngep);
boolean_t nge_phy_reset(nge_t *ngep);
uint16_t nge_mii_get16(nge_t *ngep, nge_regno_t regno);
void nge_mii_put16(nge_t *ngep, nge_regno_t regno, uint16_t data);

void nge_recv_recycle(caddr_t arg);
void nge_receive(nge_t *ngep);

uint_t nge_reschedule(caddr_t args1, caddr_t args2);
mblk_t *nge_m_tx(void *arg, mblk_t *mp);

void nge_tx_recycle(nge_t *ngep, boolean_t is_intr);
void nge_tx_recycle_all(nge_t *ngep);

int nge_nd_init(nge_t *ngep);
void nge_nd_cleanup(nge_t *ngep);


void nge_init_kstats(nge_t *ngep, int instance);
void nge_fini_kstats(nge_t *ngep);
int nge_m_stat(void *arg, uint_t stat, uint64_t *val);

uint32_t nge_atomic_shl32(uint32_t *sp, uint_t count);

void nge_log(nge_t *ngep, const char *fmt, ...);
void nge_problem(nge_t *ngep, const char *fmt, ...);
void nge_error(nge_t *ngep, const char *fmt, ...);
void
nge_report(nge_t *ngep, uint8_t error_id);

void (*nge_db(nge_t *ngep))(const char *fmt, ...);
void (*nge_gdb(void))(const char *fmt, ...);
extern	uint32_t nge_debug;

/*
 * DESC MODE 2
 */

extern void nge_sum_rxd_fill(void *, const ddi_dma_cookie_t *, size_t);
extern uint32_t nge_sum_rxd_check(const void *, size_t *);

extern void nge_sum_txd_fill(void *, const ddi_dma_cookie_t *,
				size_t, uint32_t, boolean_t, boolean_t);
extern uint32_t nge_sum_txd_check(const void *);

/*
 * DESC MODE 3
 */

extern void nge_hot_rxd_fill(void *, const ddi_dma_cookie_t *, size_t);
extern uint32_t nge_hot_rxd_check(const void *, size_t *);

extern void nge_hot_txd_fill(void *, const ddi_dma_cookie_t *,
				size_t, uint32_t, boolean_t, boolean_t);
extern uint32_t nge_hot_txd_check(const void *);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_NGE_H */
