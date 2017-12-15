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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UNM_NIC_
#define	_UNM_NIC_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/inttypes.h>
#include <sys/rwlock.h>
#include <sys/mutex.h>
#include <sys/ddi.h>

#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/devops.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/note.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/ethernet.h>
#include <sys/errno.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <sys/pattr.h>
#include <inet/mi.h>
#include <inet/nd.h>

#ifdef SOLARIS11
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#else
#include "mac.h"
#include "mac_ether.h"
#endif
#include <sys/miiregs.h> /* by fjlite out of intel */

#include "unm_nic_hw.h"
#include "nic_cmn.h"
#include "unm_inc.h" /* For MAX_RCV_CTX */
#include "unm_brdcfg.h"
#include "unm_version.h"
#include "nic_phan_reg.h"
#include "unm_nic_ioctl.h"

#define	MAX_ADDR_LEN	 6

#define	ADDR_IN_WINDOW1(off)	\
	((off > UNM_CRB_PCIX_HOST2) && (off < UNM_CRB_MAX)) ? 1 : 0

typedef unsigned long uptr_t;

#define	FIRST_PAGE_GROUP_START	0
#define	FIRST_PAGE_GROUP_END	0x100000

#define	SECOND_PAGE_GROUP_START	0x6000000
#define	SECOND_PAGE_GROUP_END	0x68BC000

#define	THIRD_PAGE_GROUP_START	0x70E4000
#define	THIRD_PAGE_GROUP_END	0x8000000

#define	FIRST_PAGE_GROUP_SIZE	FIRST_PAGE_GROUP_END - FIRST_PAGE_GROUP_START
#define	SECOND_PAGE_GROUP_SIZE	SECOND_PAGE_GROUP_END - SECOND_PAGE_GROUP_START
#define	THIRD_PAGE_GROUP_SIZE	THIRD_PAGE_GROUP_END - THIRD_PAGE_GROUP_START

/*
 * normalize a 64MB crb address to 32MB PCI window
 * To use CRB_NORMALIZE, window _must_ be set to 1
 */
#define	CRB_NORMAL(reg)	\
	(reg) - UNM_CRB_PCIX_HOST2 + UNM_CRB_PCIX_HOST
#define	CRB_NORMALIZE(adapter, reg) \
	(void *)(unsigned long)(pci_base_offset(adapter, CRB_NORMAL(reg)))

#define	DB_NORMALIZE(adapter, off) \
	(void *)((unsigned long)adapter->ahw.db_base + (off))

#define	find_diff_among(a, b, range) \
	((a) < (b)?((b)-(a)):((b)+(range)-(a)))

#define	__FUNCTION__		__func__
#define	nx_msleep(_msecs_)	delay(drv_usectohz(_msecs_ * 1000))

#define	HOST_TO_LE_64			LE_64
#define	HOST_TO_LE_32			LE_32
#define	LE_TO_HOST_32			LE_32
#define	HOST_TO_LE_16			LE_16
#define	LE_TO_HOST_16			LE_16

#define	dbwritel(DATA, ADDRESS) \
	ddi_put32(adapter->db_handle, (uint32_t *)(ADDRESS), (DATA))

/*
 * Following macros require the mapped addresses to access
 * the Phantom memory.
 */
#define	UNM_NIC_PCI_READ_8(ADDRESS) \
	ddi_get8(adapter->regs_handle, (uint8_t *)(ADDRESS))
#define	UNM_NIC_PCI_READ_16(ADDRESS) \
	ddi_get16(adapter->regs_handle, (uint16_t *)(ADDRESS))
#define	UNM_NIC_PCI_READ_32(ADDRESS) \
	ddi_get32(adapter->regs_handle, (uint32_t *)(ADDRESS))
#define	UNM_NIC_PCI_READ_64(ADDRESS) \
	ddi_get64(adapter->regs_handle, (uint64_t *)(ADDRESS))

#define	UNM_NIC_PCI_WRITE_8(DATA, ADDRESS) \
	ddi_put8(adapter->regs_handle, (uint8_t *)(ADDRESS), (DATA))
#define	UNM_NIC_PCI_WRITE_16(DATA, ADDRESS) \
	ddi_put16(adapter->regs_handle, (uint16_t *)(ADDRESS), (DATA))
#define	UNM_NIC_PCI_WRITE_32(DATA, ADDRESS) \
	ddi_put32(adapter->regs_handle, (uint32_t *)(ADDRESS), (DATA))
#define	UNM_NIC_PCI_WRITE_64(DATA, ADDRESS) \
	ddi_put64(adapter->regs_handle, (uint64_t *)(ADDRESS), (DATA))

#ifdef DEBUG_LEVEL
#define	DPRINTF(n, args)	if (DEBUG_LEVEL > (n)) cmn_err args;
#else
#define	DPRINTF(n, args)
#endif

#define	UNM_SPIN_LOCK(_lp_)			mutex_enter((_lp_))
#define	UNM_SPIN_UNLOCK(_lp_)			mutex_exit((_lp_))
#define	UNM_SPIN_LOCK_ISR(_lp_)			mutex_enter((_lp_))
#define	UNM_SPIN_UNLOCK_ISR(_lp_)		mutex_exit((_lp_))

#define	UNM_WRITE_LOCK(_lp_)			rw_enter((_lp_), RW_WRITER)
#define	UNM_WRITE_UNLOCK(_lp_)			rw_exit((_lp_))
#define	UNM_READ_LOCK(_lp_)			rw_enter((_lp_), RW_READER)
#define	UNM_READ_UNLOCK(_lp_)			rw_exit((_lp_))
#define	UNM_WRITE_LOCK_IRQS(_lp_, _fl_)		rw_enter((_lp_), RW_WRITER)
#define	UNM_WRITE_UNLOCK_IRQR(_lp_, _fl_)	rw_exit((_lp_))

extern char unm_nic_driver_name[];
extern int verbmsg;

typedef struct unm_dmah_node {
	struct unm_dmah_node *next;
	ddi_dma_handle_t dmahdl;
}unm_dmah_node_t;

typedef struct dma_area {
	ddi_acc_handle_t	acc_hdl;	/* handle for memory	*/
	ddi_dma_handle_t	dma_hdl;	/* DMA handle		*/
	uint32_t		ncookies;
	u64			dma_addr;
	void			*vaddr;
} dma_area_t;

struct unm_cmd_buffer {
	dma_area_t	dma_area;
	mblk_t		*msg;
	unm_dmah_node_t	*head, *tail;
};

typedef struct pkt_info {
	uint32_t	total_len;
	uint16_t	mblk_no;
	uint16_t	etype;
	uint16_t	mac_hlen;
	uint16_t	ip_hlen;
	uint16_t	l4_proto;
} pktinfo_t;

typedef struct unm_rcv_desc_context_s unm_rcv_desc_ctx_t;
typedef struct unm_adapter_s unm_adapter;

typedef struct unm_rx_buffer {
	struct unm_rx_buffer	*next;
	dma_area_t		dma_info;
	frtn_t			rx_recycle;	/* recycle function */
	mblk_t			*mp;
	unm_rcv_desc_ctx_t	*rcv_desc;
	unm_adapter		*adapter;
}unm_rx_buffer_t;

/* Board types */
#define	UNM_NIC_GBE		0x01
#define	UNM_NIC_XGBE    0x02

/*
 * One hardware_context{} per adapter
 * contains interrupt info as well shared hardware info.
 */
typedef	struct _hardware_context {
	unsigned long	pci_base0;
	unsigned long	pci_len0;
	unsigned long	pci_base1;
	unsigned long	pci_len1;
	unsigned long	pci_base2;
	unsigned long	pci_len2;
	unsigned long	first_page_group_end;
	unsigned long	first_page_group_start;
	uint8_t			revision_id;
	uint8_t			cut_through;
	uint16_t		board_type;
	int				pci_func;
	uint16_t		max_ports;
	unm_board_info_t	boardcfg;
	uint32_t		linkup;

	struct unm_adapter_s	*adapter;
	cmdDescType0_t			*cmdDescHead;

	uint32_t		cmdProducer;
	uint32_t		cmdConsumer;
	uint32_t		rcvFlag;
	uint32_t		crb_base;
	unsigned long	db_base;    /* base of mapped db memory */
	unsigned long	db_len;    /* length of mapped db memory */


	uint64_t		cmdDesc_physAddr;
	int				qdr_sn_window, ddr_mn_window;
	unsigned long	mn_win_crb, ms_win_crb;
	ddi_dma_handle_t cmd_desc_dma_handle;
	ddi_acc_handle_t cmd_desc_acc_handle;
	ddi_dma_cookie_t cmd_desc_dma_cookie;
} hardware_context, *phardware_context;

#define	NX_CT_DEFAULT_RX_BUF_LEN	2048
#define	MTU_SIZE			1500
#define	MAX_COOKIES_PER_CMD		15
#define	UNM_DB_MAPSIZE_BYTES		0x1000
#define	EXTRA_HANDLES			512
#define	UNM_TX_BCOPY_THRESHOLD		128
#define	UNM_RX_BCOPY_THRESHOLD		128
#define	NX_MIN_DRIVER_RDS_SIZE		64

typedef struct unm_pauseparam {
	uint16_t rx_pause;
	uint16_t tx_pause;
} unm_pauseparam_t;

/*
 * The driver supports the NDD ioctls ND_GET/ND_SET, and the loopback
 * ioctls LB_GET_INFO_SIZE/LB_GET_INFO/LB_GET_MODE/LB_SET_MODE
 *
 * These are the values to use with LD_SET_MODE.
 */
#define	UNM_LOOP_NONE	   0
#define	UNM_LOOP_INTERNAL_PHY   1
#define	UNM_LOOP_INTERNAL_MAC   2

/*
 * Named Data (ND) Parameter Management Structure
 */
typedef	struct {
	int			ndp_info;
	int			ndp_min;
	int			ndp_max;
	int			ndp_val;
	char		*ndp_name;
} nd_param_t; /* 0x18 (24) bytes  */

/*
 * NDD parameter indexes, divided into:
 *
 *      read-only parameters describing the hardware's capabilities
 *      read-write parameters controlling the advertised capabilities
 *      read-only parameters describing the partner's capabilities
 *      read-only parameters describing the link state
 */
enum {
	PARAM_AUTONEG_CAP = 0,
	PARAM_PAUSE_CAP,
	PARAM_ASYM_PAUSE_CAP,
	PARAM_10000FDX_CAP,
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
	PARAM_ADV_10000FDX_CAP,
	PARAM_ADV_1000FDX_CAP,
	PARAM_ADV_1000HDX_CAP,
	PARAM_ADV_100T4_CAP,
	PARAM_ADV_100FDX_CAP,
	PARAM_ADV_100HDX_CAP,
	PARAM_ADV_10FDX_CAP,
	PARAM_ADV_10HDX_CAP,

	PARAM_LINK_STATUS,
	PARAM_LINK_SPEED,
	PARAM_LINK_DUPLEX,

	PARAM_LOOP_MODE,

	PARAM_COUNT
};

struct unm_adapter_stats {
	uint64_t  rcvdbadmsg;
	uint64_t  xmitcalled;
	uint64_t  xmitedframes;
	uint64_t  xmitfinished;
	uint64_t  badmsglen;
	uint64_t  nocmddescriptor;
	uint64_t  polled;
	uint64_t  uphappy;
	uint64_t  updropped;
	uint64_t  uplcong;
	uint64_t  uphcong;
	uint64_t  upmcong;
	uint64_t  updunno;
	uint64_t  msgfreed;
	uint64_t  txdropped;
	uint64_t  txnullmsg;
	uint64_t  csummed;
	uint64_t  no_rcv;
	uint64_t  rxbytes;
	uint64_t  txbytes;
	uint64_t  ints;
	uint64_t  desballocfailed;
	uint64_t  txcopyed;
	uint64_t  txmapped;
	uint64_t  outoftxdmahdl;
	uint64_t  outofcmddesc;
	uint64_t  rxcopyed;
	uint64_t  rxmapped;
	uint64_t  outofrxbuf;
	uint64_t  promiscmode;
	uint64_t  rxbufshort;
	uint64_t  allocbfailed;
};

/* descriptor types */
#define	RCV_RING_STD		RCV_DESC_NORMAL
#define	RCV_RING_JUMBO		RCV_DESC_JUMBO
#define	RCV_RING_LRO		RCV_DESC_LRO

/*
 * Rcv Descriptor Context. One such per Rcv Descriptor. There may
 * be one Rcv Descriptor for normal packets, one for jumbo,
 * one for LRO and may be expanded.
 */
struct unm_rcv_desc_context_s {
	uint32_t	producer;

	uint64_t	phys_addr;
	dev_info_t	*phys_pdev;
	/* address of rx ring in Phantom */
	rcvDesc_t	*desc_head;

	uint32_t	MaxRxDescCount;
	uint32_t	rx_desc_handled;
	uint32_t	rx_buf_card;
	uint32_t	rx_buf_total;
	uint32_t	rx_buf_free;
	uint32_t	rx_buf_recycle;
	unm_rx_buffer_t *rx_buf_pool;
	unm_rx_buffer_t *pool_list;
	unm_rx_buffer_t *recycle_list;
	kmutex_t	pool_lock[1];	/* buffer pool lock */
	kmutex_t	recycle_lock[1]; /* buffer recycle lock */
	/* size of the receive buf */
	uint32_t	buf_size;
	/* rx buffers for receive   */

	ddi_dma_handle_t	rx_desc_dma_handle;
	ddi_acc_handle_t 	rx_desc_acc_handle;
	ddi_dma_cookie_t	rx_desc_dma_cookie;
	uint32_t		host_rx_producer;
	uint32_t		dma_size;
};

/*
 * Receive context. There is one such structure per instance of the
 * receive processing. Any state information that is relevant to
 * the receive, and is must be in this structure. The global data may be
 * present elsewhere.
 */
typedef struct unm_recv_context_s {
	unm_rcv_desc_ctx_t 	rcv_desc[NUM_RCV_DESC_RINGS];

	uint32_t			statusRxConsumer;

	uint64_t			rcvStatusDesc_physAddr;
	statusDesc_t 		*rcvStatusDescHead;

	ddi_dma_handle_t	status_desc_dma_handle;
	ddi_acc_handle_t	status_desc_acc_handle;
	ddi_dma_cookie_t	status_desc_dma_cookie;

	uint32_t		state, host_sds_consumer;
	uint16_t		context_id, virt_port;
} unm_recv_context_t;

#define	UNM_NIC_MSI_ENABLED	0x02
#define	UNM_NIC_MSIX_ENABLED	0x04
#define	UNM_IS_MSI_FAMILY(ADAPTER)	\
	((ADAPTER)->flags & (UNM_NIC_MSI_ENABLED | UNM_NIC_MSIX_ENABLED))

#define	NX_USE_MSIX

/* msix defines */
#define	MSIX_ENTRIES_PER_ADAPTER	8
#define	UNM_MSIX_TBL_SPACE		8192
#define	UNM_PCI_REG_MSIX_TBL		0x44

/*
 * Bug: word or char write on MSI-X capcabilities register (0x40) in PCI config
 * space has no effect on register values. Need to write dword.
 */
#define	UNM_HWBUG_8_WORKAROUND

/*
 * Bug: Can not reset bit 32 (msix enable bit) on MSI-X capcabilities
 * register (0x40) independently.
 * Need to write 0x0 (zero) to MSI-X capcabilities register in order to reset
 * msix enable bit. On writing zero rest of the bits are not touched.
 */
#define	UNM_HWBUG_9_WORKAROUND

#define	UNM_MC_COUNT    38	/* == ((UNM_ADDR_L2LU_COUNT-1)/4) -2 */

/* Following structure is for specific port information */
struct unm_adapter_s {
	hardware_context	ahw;
	uint8_t			id[32];
	uint16_t		portnum;
	uint16_t		physical_port;
	uint16_t		link_speed;
	uint16_t		link_duplex;

	struct unm_adapter_stats stats;
	int			rx_csum;
	int			status;
	kmutex_t    		stats_lock;
	unsigned char		mac_addr[MAX_ADDR_LEN];
	int			mtu;		/* active mtu */
	int			maxmtu;		/* max possible mtu value */
	uint32_t		promisc;

	mac_resource_handle_t   mac_rx_ring_ha;
	mac_handle_t	mach;
	int				flags;

	int		  instance;
	dev_info_t	  *dip;
	ddi_acc_handle_t  pci_cfg_handle;
	ddi_acc_handle_t  regs_handle;
	ddi_dma_attr_t    gc_dma_attr_desc;

	struct ddi_device_acc_attr  gc_attr_desc;
	ddi_iblock_cookie_t iblock_cookie;
	const char *name;
	ddi_acc_handle_t  db_handle;

	ddi_intr_handle_t	intr_handle;
	int			intr_type;
	uint_t		intr_pri;
	unm_dmah_node_t		*dmahdl_pool;
	unm_dmah_node_t		tx_dma_hdls[MAX_CMD_DESCRIPTORS+EXTRA_HANDLES];
	uint64_t		freehdls;
	uint64_t		freecmds;
	int			tx_bcopy_threshold;
	kmutex_t		tx_lock;
	krwlock_t		adapter_lock;
	kmutex_t		lock;
	struct nx_legacy_intr_set	legacy_intr;
	timeout_id_t		watchdog_timer;
	kstat_t			*kstats[1];

	uint32_t		curr_window;
	uint32_t		crb_win;
	uint32_t		cmdProducer;
	uint32_t		*cmdConsumer;

	uint32_t		interrupt_crb;
	uint32_t		fw_major;
	uint32_t		crb_addr_cmd_producer;
	uint32_t		crb_addr_cmd_consumer;
	uint16_t		tx_context_id;
	short			context_alloced;
	int			max_rds_rings;

	uint32_t		lastCmdConsumer;
	/* Num of bufs posted in phantom */
	uint32_t	pendingCmdCount;
	uint32_t	MaxTxDescCount;
	uint32_t	MaxRxDescCount;
	uint32_t	MaxJumboRxDescCount;
	uint32_t	MaxLroRxDescCount;
	/* Num of instances active on cmd buffer ring */
	int		resched_needed;

	int			driver_mismatch;
	uint32_t	temp;

	struct unm_cmd_buffer *cmd_buf_arr;  /* Command buffers for xmit */
	int		rx_bcopy_threshold;

	/*
	 * Receive instances. These can be either one per port,
	 * or one per peg, etc.
	 */
	unm_recv_context_t	recv_ctx[MAX_RCV_CTX];
	int		is_up;

	/* context interface shared between card and host */
	RingContext		*ctxDesc;
	uint64_t		ctxDesc_physAddr;
	ddi_dma_handle_t 	ctxDesc_dma_handle;
	ddi_acc_handle_t 	ctxDesc_acc_handle;

	struct {
		void			*addr;
		uint64_t		phys_addr;
		ddi_dma_handle_t	dma_handle;
		ddi_acc_handle_t	acc_handle;
	} dummy_dma;

	void	(*unm_nic_pci_change_crbwindow)(struct unm_adapter_s *,
		    uint32_t);
	int	(*unm_crb_writelit_adapter)(struct unm_adapter_s *,
		    unsigned long, int);
	unsigned long long
		(*unm_nic_pci_set_window)(struct unm_adapter_s *,
		    unsigned long long);
	int	(*unm_nic_fill_statistics)(struct unm_adapter_s *,
		    struct unm_statistics *);
	int	(*unm_nic_clear_statistics)(struct unm_adapter_s *);
	int	(*unm_nic_hw_write_wx)(struct unm_adapter_s *, u64,
	    void *, int);
	int	(*unm_nic_hw_read_wx)(struct unm_adapter_s *, u64, void *, int);
	int	(*unm_nic_hw_write_ioctl)(struct unm_adapter_s *, u64, void *,
		    int);
	int	(*unm_nic_hw_read_ioctl)(struct unm_adapter_s *, u64, void *,
		    int);
	int	(*unm_nic_pci_mem_write)(struct unm_adapter_s *, u64, void *,
		    int);
	int	(*unm_nic_pci_mem_read)(struct unm_adapter_s *, u64, void *,
		    int);
	int	(*unm_nic_pci_write_immediate)(struct unm_adapter_s *, u64,
		    u32 *);
	int	(*unm_nic_pci_read_immediate)(struct unm_adapter_s *, u64,
		    u32 *);
	void	(*unm_nic_pci_write_normalize)(struct unm_adapter_s *, u64,
		    u32);
	u32	(*unm_nic_pci_read_normalize)(struct unm_adapter_s *, u64);

	caddr_t			nd_data_p;
	nd_param_t		nd_params[PARAM_COUNT];
};  /* unm_adapter structure */

#define	UNM_HOST_DUMMY_DMA_SIZE	 1024

/* Following structure is for specific port information    */

#define	PCI_OFFSET_FIRST_RANGE(adapter, off)	\
	((adapter)->ahw.pci_base0 + off)
#define	PCI_OFFSET_SECOND_RANGE(adapter, off)	\
	((adapter)->ahw.pci_base1 + off - SECOND_PAGE_GROUP_START)
#define	PCI_OFFSET_THIRD_RANGE(adapter, off)	\
	((adapter)->ahw.pci_base2 + off - THIRD_PAGE_GROUP_START)

#define	pci_base_offset(adapter, off)	\
	((((off) < ((adapter)->ahw.first_page_group_end)) &&	\
	    ((off) >= ((adapter)->ahw.first_page_group_start))) ?	\
	    ((adapter)->ahw.pci_base0 + (off)) :	\
	    ((((off) < SECOND_PAGE_GROUP_END) &&	\
	    ((off) >= SECOND_PAGE_GROUP_START)) ?	\
	    ((adapter)->ahw.pci_base1 +		\
	    (off) - SECOND_PAGE_GROUP_START) :	\
		((((off) < THIRD_PAGE_GROUP_END) &&	\
	    ((off) >= THIRD_PAGE_GROUP_START)) ?	\
	    ((adapter)->ahw.pci_base2 + (off) -	\
	    THIRD_PAGE_GROUP_START) :		\
	    0)))
#define	unm_nic_reg_write(_adp_, _off_, _val_)			\
	{							\
		__uint32_t	_v1_ = (_val_);			\
		((_adp_)->unm_nic_hw_write_wx((_adp_), (_off_),	\
		    &_v1_, 4));					\
	}

#define	unm_nic_reg_read(_adp_, _off_, _ptr_)			\
	((_adp_)->unm_nic_hw_read_wx((_adp_), (_off_), (_ptr_), 4))


#define	unm_nic_write_w0(_adp_, _idx_, _val_)			\
	((_adp_)->unm_nic_hw_write_wx((_adp_), (_idx_), &(_val_), 4))

#define	unm_nic_read_w0(_adp_, _idx_, _val_)			\
	((_adp_)->unm_nic_hw_read_wx((_adp_), (_idx_), (_val_), 4))

/* Functions available from unm_nic_hw.c */
int unm_nic_get_board_info(struct unm_adapter_s *adapter);
void _unm_nic_write_crb(struct unm_adapter_s *adapter, uint32_t index,
				uint32_t value);
void  unm_nic_write_crb(struct unm_adapter_s *adapter, uint32_t index,
				uint32_t value);
void _unm_nic_read_crb(struct unm_adapter_s *adapter, uint32_t index,
				uint32_t *value);
void  unm_nic_read_crb(struct unm_adapter_s *adapter, uint32_t index,
				uint32_t *value);
// int   unm_nic_reg_read (unm_adapter *adapter, u64 off);
int _unm_nic_hw_write(struct unm_adapter_s *adapter,
				u64 off, void *data, int len);
int  unm_nic_hw_write(struct unm_adapter_s *adapter,
				u64 off, void *data, int len);
int _unm_nic_hw_read(struct unm_adapter_s *adapter,
				u64 off, void *data, int len);
int  unm_nic_hw_read(struct unm_adapter_s *adapter,
				u64 off, void *data, int len);
void _unm_nic_hw_block_read(struct unm_adapter_s *adapter,
				u64 off, void *data, int num_words);
void  unm_nic_hw_block_read(struct unm_adapter_s *adapter,
				u64 off, void *data, int num_words);
void _unm_nic_hw_block_write(struct unm_adapter_s *adapter,
				u64 off, void *data, int num_words);
void unm_nic_hw_block_write(struct unm_adapter_s *adapter,
				u64 off, void *data, int num_words);
int  unm_nic_pci_mem_write(struct unm_adapter_s *adapter,
				u64 off, void *data, int size);
void unm_nic_mem_block_read(struct unm_adapter_s *adapter, u64 off,
				void *data, int num_words);
void unm_nic_mem_block_write(struct unm_adapter_s *adapter, u64 off,
				void *data, int num_words);
int unm_nic_hw_read_ioctl(unm_adapter *adapter, u64 off, void *data, int len);
int unm_nic_hw_write_ioctl(unm_adapter *adapter, u64 off, void *data, int len);
int  unm_nic_macaddr_set(struct unm_adapter_s *, __uint8_t *addr);
void unm_tcl_resetall(struct unm_adapter_s *adapter);
void unm_tcl_phaninit(struct unm_adapter_s *adapter);
void unm_tcl_postimage(struct unm_adapter_s *adapter);
int unm_nic_set_mtu(struct unm_adapter_s *adapter, int new_mtu);
long unm_nic_phy_read(unm_adapter *adapter, long reg, __uint32_t *);
long unm_nic_init_port(struct unm_adapter_s *adapter);
void unm_crb_write_adapter(unsigned long off, void *data,
		struct unm_adapter_s *adapter);
int unm_crb_read_adapter(unsigned long off, void *data,
		struct unm_adapter_s *adapter);
int unm_crb_read_val_adapter(unsigned long off,
		struct unm_adapter_s *adapter);
void unm_nic_stop_port(struct unm_adapter_s *adapter);
int unm_nic_set_promisc_mode(struct unm_adapter_s *adapter);
int unm_nic_unset_promisc_mode(struct unm_adapter_s *adapter);

/* unm_nic_hw.c */
void unm_nic_pci_change_crbwindow_128M(unm_adapter *adapter, uint32_t wndw);
int unm_crb_writelit_adapter_128M(struct unm_adapter_s *, unsigned long, int);
int unm_nic_hw_write_wx_128M(unm_adapter *adapter, u64 off, void *data,
    int len);
int unm_nic_hw_read_wx_128M(unm_adapter *adapter, u64 off, void *data, int len);
int unm_nic_hw_write_ioctl_128M(unm_adapter *adapter, u64 off, void *data,
    int len);
int unm_nic_hw_read_ioctl_128M(unm_adapter *adapter, u64 off, void *data,
    int len);
int unm_nic_pci_mem_write_128M(struct unm_adapter_s *adapter, u64 off,
    void *data, int size);
int unm_nic_pci_mem_read_128M(struct unm_adapter_s *adapter, u64 off,
    void *data, int size);
void unm_nic_pci_write_normalize_128M(unm_adapter *adapter, u64 off, u32 data);
u32 unm_nic_pci_read_normalize_128M(unm_adapter *adapter, u64 off);
int unm_nic_pci_write_immediate_128M(unm_adapter *adapter, u64 off, u32 *data);
int unm_nic_pci_read_immediate_128M(unm_adapter *adapter, u64 off, u32 *data);
unsigned long long unm_nic_pci_set_window_128M(unm_adapter *adapter,
    unsigned long long addr);
int unm_nic_clear_statistics_128M(struct unm_adapter_s *adapter);
int unm_nic_fill_statistics_128M(struct unm_adapter_s *adapter,
    struct unm_statistics *unm_stats);

void unm_nic_pci_change_crbwindow_2M(unm_adapter *adapter, uint32_t wndw);
int unm_crb_writelit_adapter_2M(struct unm_adapter_s *, unsigned long, int);
int unm_nic_hw_write_wx_2M(unm_adapter *adapter, u64 off, void *data, int len);
int unm_nic_pci_mem_write_2M(struct unm_adapter_s *adapter, u64 off,
    void *data, int size);
int unm_nic_pci_mem_read_2M(struct unm_adapter_s *adapter, u64 off,
    void *data, int size);
int unm_nic_hw_read_wx_2M(unm_adapter *adapter, u64 off, void *data, int len);
void unm_nic_pci_write_normalize_2M(unm_adapter *adapter, u64 off, u32 data);
u32 unm_nic_pci_read_normalize_2M(unm_adapter *adapter, u64 off);
int unm_nic_pci_write_immediate_2M(unm_adapter *adapter, u64 off, u32 *data);
int unm_nic_pci_read_immediate_2M(unm_adapter *adapter, u64 off, u32 *data);
unsigned long long unm_nic_pci_set_window_2M(unm_adapter *adapter,
    unsigned long long addr);
int unm_nic_clear_statistics_2M(struct unm_adapter_s *adapter);
int unm_nic_fill_statistics_2M(struct unm_adapter_s *adapter,
    struct unm_statistics *unm_stats);
void nx_p3_nic_set_multi(unm_adapter *adapter);

/* unm_nic_init.c */
int phantom_init(struct unm_adapter_s *adapter, int first_time);
int load_from_flash(struct unm_adapter_s *adapter);
int  pinit_from_rom(unm_adapter *adapter, int verbose);
int  rom_fast_read(struct unm_adapter_s *adapter, int addr, int *valp);

/* unm_nic_isr.c */
void unm_nic_handle_phy_intr(unm_adapter *adapter);

/* niu.c */
native_t unm_niu_set_promiscuous_mode(struct unm_adapter_s *adapter,
		unm_niu_prom_mode_t mode);
native_t unm_niu_xg_set_promiscuous_mode(struct unm_adapter_s *adapter,
		unm_niu_prom_mode_t mode);

int unm_niu_xg_macaddr_set(struct unm_adapter_s *adapter,
		unm_ethernet_macaddr_t addr);
native_t unm_niu_disable_xg_port(struct unm_adapter_s *adapter);

long unm_niu_gbe_init_port(long port);
native_t unm_niu_enable_gbe_port(struct unm_adapter_s *adapter);
native_t unm_niu_disable_gbe_port(struct unm_adapter_s *adapter);

int unm_niu_macaddr_get(struct unm_adapter_s *adapter, unsigned char *addr);
int unm_niu_macaddr_set(struct unm_adapter_s *adapter,
		unm_ethernet_macaddr_t addr);

int unm_niu_xg_set_tx_flow_ctl(struct unm_adapter_s *adapter, int enable);
int unm_niu_gbe_set_rx_flow_ctl(struct unm_adapter_s *adapter, int enable);
int unm_niu_gbe_set_tx_flow_ctl(struct unm_adapter_s *adapter, int enable);
long unm_niu_gbe_disable_phy_interrupts(struct unm_adapter_s *);
long unm_niu_gbe_phy_read(struct unm_adapter_s *,
		long reg, unm_crbword_t *readval);

/* unm_nic_ctx.c */
int netxen_create_rxtx(struct unm_adapter_s *adapter);
void netxen_destroy_rxtx(struct unm_adapter_s *adapter);
int nx_fw_cmd_set_mtu(struct unm_adapter_s *adapter, int mtu);

/* unm_nic_main.c */
int receive_peg_ready(struct unm_adapter_s *adapter);
void unm_nic_update_cmd_producer(struct unm_adapter_s *adapter,
    uint32_t crb_producer);
void unm_desc_dma_sync(ddi_dma_handle_t handle, uint_t start, uint_t count,
    uint_t range, uint_t unit_size, uint_t direction);
int unm_pci_alloc_consistent(unm_adapter *, int, caddr_t *,
    ddi_dma_cookie_t *, ddi_dma_handle_t *, ddi_acc_handle_t *);
void unm_pci_free_consistent(ddi_dma_handle_t *, ddi_acc_handle_t *);

/* unm_ndd.c */
int unm_nd_init(unm_adapter *adapter);
enum ioc_reply unm_nd_ioctl(unm_adapter *adapter, queue_t *wq,
		mblk_t *mp, struct iocblk *iocp);
void unm_nd_cleanup(unm_adapter *adapter);

/* unm_gem.c */
void unm_destroy_intr(unm_adapter *adapter);
void unm_free_dummy_dma(unm_adapter *adapter);

/*
 * (Internal) return values from ioctl subroutines
 */
enum ioc_reply {
	IOC_INVAL = -1,	/* bad, NAK with EINVAL */
	IOC_DONE, /* OK, reply sent  */
	IOC_ACK, /* OK, just send ACK  */
	IOC_REPLY, /* OK, just send reply */
	IOC_RESTART_ACK, /* OK, restart & ACK */
	IOC_RESTART_REPLY /* OK, restart & reply */
};

/*
 * Shorthand for the NDD parameters
 */
#define	param_adv_autoneg	nd_params[PARAM_ADV_AUTONEG_CAP].ndp_val
#define	param_adv_pause		nd_params[PARAM_ADV_PAUSE_CAP].ndp_val
#define	param_adv_asym_pause	nd_params[PARAM_ADV_ASYM_PAUSE_CAP].ndp_val
#define	param_adv_10000fdx	nd_params[PARAM_ADV_10000FDX_CAP].ndp_val
#define	param_adv_1000fdx	nd_params[PARAM_ADV_1000FDX_CAP].ndp_val
#define	param_adv_1000hdx	nd_params[PARAM_ADV_1000HDX_CAP].ndp_val
#define	param_adv_100fdx	nd_params[PARAM_ADV_100FDX_CAP].ndp_val
#define	param_adv_100hdx	nd_params[PARAM_ADV_100HDX_CAP].ndp_val
#define	param_adv_10fdx		nd_params[PARAM_ADV_10FDX_CAP].ndp_val
#define	param_adv_10hdx		nd_params[PARAM_ADV_10HDX_CAP].ndp_val
#define	param_link_up		nd_params[PARAM_LINK_STATUS].ndp_val
#define	param_link_speed	nd_params[PARAM_LINK_SPEED].ndp_val
#define	param_link_duplex	nd_params[PARAM_LINK_DUPLEX].ndp_val
#define	param_loop_mode		nd_params[PARAM_LOOP_MODE].ndp_val

/*
 * Property lookups
 */
#define	UNM_PROP_EXISTS(d, n) \
	ddi_prop_exists(DDI_DEV_T_ANY, (d), DDI_PROP_DONTPASS, (n))
#define	UNM_PROP_GET_INT(d, n) \
	ddi_prop_get_int(DDI_DEV_T_ANY, (d), DDI_PROP_DONTPASS, (n), -1)

/*
 * Bit flags in the 'debug' word ...
 */
#define	UNM_DBG_TRACE	0x00000002 /* general flow tracing */
#define	UNM_DBG_NDD		0x20000000 /* NDD operations */

#define	MBPS_10		10
#define	MBPS_100	100
#define	MBPS_1000	1000

#ifdef __cplusplus
}
#endif

#endif	/* !_UNM_NIC_ */
