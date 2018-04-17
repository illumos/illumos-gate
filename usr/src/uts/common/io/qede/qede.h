/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef	_QEDE_H
#define	_QEDE_H

#include <sys/stream.h>

#include <sys/ddi.h>
#include <sys/ddifm.h>
#include <sys/dditypes.h>
#include <sys/sunddi.h>
#include <sys/fm/io/ddi.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/kobj.h>
#include <sys/mac.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/gld.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <netinet/udp.h>
#include <sys/ethernet.h>
#include <sys/pci.h>
#include <sys/netlb.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/policy.h>

#include "qede_version.h"
#include "bcm_osal.h"
#include "qede_fp.h"

#if 1
#include "ecore.h"
#include "ecore_status.h"
#include "ecore_utils.h"
#include "ecore_chain.h"
#include "ecore_hsi_common.h"
#include "ecore_hsi_eth.h"
#include "ecore_proto_if.h"
#include "ecore_iov_api.h"
#include "ecore_int_api.h"
#include "ecore_dev_api.h"
#include "ecore_l2_api.h"
#include "ecore_hw.h"
#include "nvm_cfg.h"
#include "ecore_mcp.h"
#include "ecore_dbg_fw_funcs.h"
#include <sys/pcie.h>
#include <sys/time.h>
#else
#include <ecore.h>
#include <ecore_status.h>
#include <ecore_utils.h>
#include <ecore_hsi_common.h>
#include <ecore_hsi_eth.h>
#include <ecore_proto_if.h>
#include <ecore_chain.h>
#include <ecore_iov_api.h>
#include <ecore_int_api.h>
#include <ecore_dev_api.h>
#include <ecore_ll2_api.h>
#include <ecore_l2_api.h>
#include <ecore_mcp.h>
#endif



#ifndef	STRINGIFY
#define	XSTRINGIFY(x)	#x
#define	STRINGIFY(x)	XSTRINGIFY(x)
#endif
#define QEDE_STR_SIZE   32
/* Product Identification Banner */
#define	QEDE_PRODUCT_INFO\
	"QLogic FastLinQ QL45xxx " STRINGIFY(MAJVERSION) \
	"." STRINGIFY(MINVERSION) "." STRINGIFY(REVVERSION)

/*
 * Debug Infrastructure
 */
#define	DEBUG_NONE	0x0
#define	DEBUG_ATTACH	0x1

#ifndef	DEBUG_LEVEL
#define	DEBUG_LEVEL	DEBUG_NONE
#endif

#define	qede_dbg(MASK, ptr, fmt, ...) \
do { \
	if (DEBUG_LEVEL & (MASK)) { \
		qede_print("!%s(%d) STRINGIFY(MASK):" fmt, __func__, \
		    (ptr)->instance, \
##__VA_ARGS__);\
	} \
} while (0);

#define	qede_info(ptr, fmt, ...) \
do { \
	qede_print("!%s(%d):" fmt, __func__, (ptr)->instance, \
##__VA_ARGS__); \
} while (0);

#define	qede_warn(ptr, fmt, ...) \
do { \
	qede_print_err("!%s(%d):" fmt, __func__, (ptr)->instance, \
##__VA_ARGS__); \
} while (0);

#ifdef __sparc
#define	QEDE_PAGE_ALIGNMENT	0x0000000000002000ull
#define	QEDE_PAGE_SIZE	0x0000000000002000ull
#else
#define	QEDE_PAGE_ALIGNMENT	0x0000000000001000ull
#define	QEDE_PAGE_SIZE	0x0000000000001000ull
#endif

#define LE_TO_HOST_64                   LE_64
#define HOST_TO_LE_64                   LE_64
#define HOST_TO_LE_32                   LE_32
#define LE_TO_HOST_32                   LE_32
#define HOST_TO_LE_16                   LE_16
#define LE_TO_HOST_16                   LE_16



#define QEDE_LSO_MAXLEN                 65535

#define	BUF_2K_SIZE			2048
#define	BUF_2K_ALIGNMENT		BUF_2K_SIZE

#define	MIN_TX_RING_COUNT		1
#define	MAX_TX_RING_COUNT		1
#define	DEFAULT_TX_RING_COUNT		1
#define	MAX_TC_COUNT			1
#define	DEFAULT_TRFK_CLASS_COUNT	1

#define	MIN_TX_RING_SIZE		1024
#define	DEFAULT_TX_RING_SIZE	       	8192

#define	DEFAULT_TX_COPY_THRESHOLD	256
#define	DEFAULT_TX_RECYCLE_THRESHOLD	128

#define	TX_RING_MASK			(tx_ring->tx_ring_size - 1)

#define	IP_ALIGNMENT_BYTES		2
#define	QEDE_MAX_ETHER_HDR		18 

#define	MIN_FASTPATH_COUNT		1
#define	MAX_FASTPATH_COUNT		6
#define	DEFAULT_FASTPATH_COUNT		4

#define	MIN_RX_RING_SIZE	        1024
#define	DEFAULT_RX_RING_SIZE	        8192
#define	MAX_RX_RING_SIZE		DEFAULT_RX_RING_SIZE

#define	MIN_RX_BUF_SIZE			2048
#define	MAX_RX_BUF_SIZE			2048
#define	DEFAULT_RX_BUF_SIZE		2048

#define	DEFAULT_RX_COPY_THRESHOLD	128
#define	RX_RING_MASK			(rx_ring->rx_buf_count - 1)
#define	MIN_RX_BUF_COUNT		MIN_RX_RING_SIZE	
#define	MAX_RX_BUF_COUNT		MAX_RX_RING_SIZE	
#define	DEFAULT_RX_BUF_COUNT		DEFAULT_RX_RING_SIZE	
#define	RX_LOW_BUFFER_THRESHOLD	128

#define USER_OPTION_CKSUM_NONE     0x0
#define USER_OPTION_CKSUM_L3       0x1
#define USER_OPTION_CKSUM_L3_L4    0x2
#define DEFAULT_CKSUM_OFFLOAD      USER_OPTION_CKSUM_L3_L4

#define QEDE_OFFLOAD_NONE          0x00000000
#define QEDE_OFFLOAD_TX_IP_CKSUM   0x00000001
#define QEDE_OFFLOAD_RX_IP_CKSUM   0x00000002
#define QEDE_OFFLOAD_TX_TCP_CKSUM  0x00000004
#define QEDE_OFFLOAD_RX_TCP_CKSUM  0x00000008
#define QEDE_OFFLOAD_TX_UDP_CKSUM  0x00000010
#define QEDE_OFFLOAD_RX_UDP_CKSUM  0x00000020

#define	DEFAULT_JUMBO_MTU	9000
#define	MIN_MTU			ETHERMTU
#define	MAX_MTU		        DEFAULT_JUMBO_MTU	
#define	DEFAULT_MTU		ETHERMTU

#define DEFAULT_ECORE_DEBUG_LEVEL	ECORE_LEVEL_VERBOSE 


#define	DEFAULT_ECORE_DEBUG_MODULE	ECORE_MSG_DRV 

#define VLAN_TAGSZ              0x4

#define	MAX_TC	1

#define DUPLEX_HALF	0 
#define DUPLEX_FULL     1

#define ETH_ALLEN 	6

#define	MAC_STRING		"%2x:%2x:%2x:%2x:%2x:%2x"
#define	MACTOSTR(a)		a[0], a[1], a[2], a[3], a[4], a[5]

#define MAX_MC_SOFT_LIMIT 1024

#define qede_delay(_msecs_)   delay(drv_usectohz(_msecs_ * 1000))

#define QEDE_CMD 73


typedef struct _KstatRingMap
{
    uint32_t  idx;	/* ring index */
    void * qede;	/* reference back to qede_t */
} KstatRingMap;

#define IS_ETH_MULTICAST(eth_addr) \
	(((unsigned char *) (eth_addr))[0] & ((unsigned char) 0x01))

#define IS_ETH_ADDRESS_EQUAL(eth_addr1, eth_addr2)  \
	((((unsigned char *) (eth_addr1))[0] ==     \
	((unsigned char *) (eth_addr2))[0]) &&      \
	(((unsigned char *) (eth_addr1))[1] ==      \
	((unsigned char *) (eth_addr2))[1]) &&      \
	(((unsigned char *) (eth_addr1))[2] ==      \
	((unsigned char *) (eth_addr2))[2]) &&      \
	(((unsigned char *) (eth_addr1))[3] ==      \
	((unsigned char *) (eth_addr2))[3]) &&      \
	(((unsigned char *) (eth_addr1))[4] ==      \
	((unsigned char *) (eth_addr2))[4]) &&      \
	(((unsigned char *) (eth_addr1))[5] ==      \
	((unsigned char *) (eth_addr2))[5]))

#define COPY_ETH_ADDRESS(src, dst) \
	((unsigned char *) (dst))[0] = ((unsigned char *) (src))[0]; \
	((unsigned char *) (dst))[1] = ((unsigned char *) (src))[1]; \
	((unsigned char *) (dst))[2] = ((unsigned char *) (src))[2]; \
	((unsigned char *) (dst))[3] = ((unsigned char *) (src))[3]; \
	((unsigned char *) (dst))[4] = ((unsigned char *) (src))[4]; \
	((unsigned char *) (dst))[5] = ((unsigned char *) (src))[5];


union db_prod {
	struct eth_db_data data;
	uint32_t raw;
};

struct qede;
struct qede_fastpath;
struct qede_rx_ring;
struct qede_tx_pktinfo_s;

typedef struct qede_tx_ring {
	struct qede_fastpath	*fp;
	struct qede *qede;
	uint32_t tx_queue_index;
	uint16_t *hw_cons_ptr;

	/* pointer to driver ring control */
	struct ecore_chain	tx_bd_ring;
	u16			sw_tx_cons;
	u16			sw_tx_prod;
	u16			bd_ring_size;

	/* From ecore_sp_tx_queue_start() */
	void __iomem *doorbell_addr;
	ddi_acc_handle_t	doorbell_handle;

	/* Saved copy of doorbell data for this tx queue */
	union db_prod		tx_db;

	uint32_t		fp_idx;
	kmutex_t		tx_lock;
	int			tx_buf_size;
	uint32_t		tx_ring_size;
	bool			queue_started;
	mac_ring_handle_t	mac_ring_handle;

	/* pre-allocated bcopy packets */
	qede_tx_bcopy_list_t	bcopy_list;
	/* pre-allocated dma handles */
	qede_dma_handles_list_t	dmah_list;
	/* List of recycle entires for tx packets */
	qede_tx_recycle_list_t *tx_recycle_list;

#ifdef	DBLK_DMA_PREMAP	
	pm_handle_t		pm_handle;
#endif
	/* dma_handle for tx bd ring */
	ddi_dma_handle_t	tx_bd_dmah;
	ddi_dma_handle_t	tx_pbl_dmah;

	bool			tx_q_sleeping;

	uint64_t 		tx_pkt_count;
	uint64_t 		tx_byte_count;
	uint64_t 		tx_pkt_dropped;
	uint64_t 		tx_copy_count;
	uint64_t 		tx_bind_count;
	uint64_t 		tx_bind_fail;
	uint64_t 		tx_premap_count;
	uint64_t 		tx_premap_fail;
	uint64_t 		tx_pullup_count;
	uint64_t 		tx_too_many_cookies;
	uint64_t 		tx_lso_pkt_count;
	uint64_t 		tx_ring_pause;
	uint64_t 		tx_too_many_mblks;
	uint64_t 		tx_mapped_pkts;
	uint64_t 		tx_jumbo_pkt_count;
	struct ecore_queue_cid *p_cid;
} qede_tx_ring_t;


typedef struct qede_vector_info {
	/* 
	 * Pointer to a fastpath structure,
	 * or to a hwfnc.
	 */ 
	void *fp;
	struct qede *qede;
	uint32_t vect_index;
	bool handler_added;
	/* set and cleared by ISR, checked by stop path
	 * when waiting for quiesce
	 */
	bool in_isr;
} qede_vector_info_t; 


typedef struct qede_fastpath {
	qede_vector_info_t *vect_info;

	/* Status block associated with this fp */
    	ddi_dma_handle_t	sb_dma_handle; 
    	ddi_acc_handle_t	sb_acc_handle;
	struct status_block *sb_virt;
	uint64_t		sb_phys;

	struct ecore_sb_info *sb_info;
	struct qede_rx_ring *rx_ring;
	qede_tx_ring_t	*tx_ring[MAX_TC];
	struct qede *qede;

	uint32_t	fp_index;
	uint32_t	fp_hw_eng_index;
	uint32_t	vport_id;	/* */ 	
	uint32_t	stats_id;	/* vport id to hold stats */	
	uint32_t	rx_queue_index;	
	uint32_t	rss_id;
	kmutex_t	fp_lock;
	uint32_t 	disabled_by_poll;
} qede_fastpath_t;

enum qede_agg_state {
	QEDE_AGG_STATE_NONE  = 0,
	QEDE_AGG_STATE_START = 1,
	QEDE_AGG_STATE_ERROR = 2
};

#define QEDE_MAX_BD_PER_AGG 16
struct qede_rx_buffer_s;
typedef	struct qede_lro_info {
	uint16_t pars_flags;
	uint16_t pad;
	uint16_t vlan_tag;
	uint16_t bd_count;
	uint32_t rss_hash;
	uint32_t header_len;
	uint32_t free_buffer_count;
	struct qede_rx_buffer_s *rx_buffer[QEDE_MAX_BD_PER_AGG];
	enum qede_agg_state agg_state;
} qede_lro_info_t;

typedef	struct qede_dma_info_s {
	ddi_acc_handle_t	acc_handle;
	ddi_dma_handle_t	dma_handle;
	u32	ncookies;
	u32	offset;
	u64	phys_addr;
	void *virt_addr;
	u32	pad;
} qede_dma_info_t;

enum rx_buf_state {
	RX_BUF_STATE_FREE,
	RX_BUF_STATE_WITH_FW,
	RX_BUF_STATE_WITH_OS,
	RX_BUF_STATE_WITH_DRV,
};

struct qede_rx_buf_area;

typedef	struct qede_rx_buffer_s {
	qede_dma_info_t	dma_info;
	mblk_t *mp;
	u32		index;
	struct qede_rx_ring *rx_ring;

	/* Recycle function */
	frtn_t		recycle;
	u32		ref_cnt;
	enum rx_buf_state 	buf_state;
	struct qede_rx_buf_area	*rx_buf_area;
} qede_rx_buffer_t;

typedef	struct qede_rx_buf_list_s {
	kmutex_t		lock;
	u16			head, tail;
	u32			num_entries;
	qede_rx_buffer_t *buf_list[DEFAULT_RX_RING_SIZE];
} qede_rx_buf_list_t;

typedef	struct qede_rx_buf_area {
	//kmutex_t		rx_buf_area_lock;
	qede_rx_buffer_t	rx_buf_pool[DEFAULT_RX_RING_SIZE];

	qede_rx_buf_list_t	active_buf_list;
	qede_rx_buf_list_t	passive_buf_list;
		
	u32			bufs_per_page;
	struct qede_rx_ring *rx_ring;
	u32			inactive;
	u32			buf_upstream;
} qede_rx_buf_area_t;

typedef struct qede_rx_ring {
	uint32_t		rx_buf_count;
	uint32_t		rx_buf_size;
	/*
	 * Pointer to an array of producer indicies. 
	 * Returned in call to ecore_sp_eth_rx_queue_start()
	 * during qede_start(). Driver uses address
	 * to update producer indicies for
	 * CQE and RX buffer chains.
	 */
	void __iomem *hw_rxq_prod_addr;

	/* Pointer to hw cqe consumer index.
	 * Taken from sb_virt->pi_array after
	 * rx_ring has been started by calling
	 * ecore_sp_eth_rx_queue_start().
	 * This value is little endian and requires
	 * swapping on big endian platforms.
	 * It is updated by ecore and read by
	 * the driver while processing rings.
	 */
	uint16_t *hw_cons_ptr;

	u16	sw_rx_cons;
	u16 sw_rx_prod;
	u16			last_cqe_consumer;

	/*
	 * Driver buffer descriptor ring defining
	 * buffers on a one-to-one releationship
	 * to ecore_chain rx_bd_ring.
	 */
	qede_rx_buffer_t *rx_buffers;
	qede_rx_buf_area_t *rx_buf_area;
	/*
	 * Descriptor rings returned from
	 * ecore_chain_alloc()
	 */
	struct ecore_chain      rx_bd_ring;
	struct ecore_chain      rx_cqe_ring;

	uint32_t	rss_id;
	bool	queue_started;
	bool	mac_ring_started;
	kmutex_t	rx_lock;			
	kmutex_t	rx_replen_lock;
	mac_ring_handle_t	mac_ring_handle;
	u64			mr_gen_num; /* Mac rings generation number */
	uint32_t		group_index;
	qede_fastpath_t	*fp;
	struct qede *qede;

	/* dma_handles for rx dma mem */
	ddi_dma_handle_t	rx_bd_dmah;
	ddi_dma_handle_t	rx_cqe_dmah;
	ddi_dma_handle_t	rx_cqe_pbl_dmah;
	uint32_t	rx_copy_threshold;
	uint32_t	rx_low_buffer_threshold;
	struct qede_lro_info lro_info[ETH_TPA_MAX_AGGS_NUM];
	uint32_t lro_active_count;

	uint64_t rx_copy_cnt;
	uint64_t rx_drop_cnt;
	uint64_t rx_low_water_cnt;
	uint64_t rx_poll_cnt;
	uint64_t rx_reg_pkt_cnt;
	uint64_t rx_jumbo_pkt_cnt;
	uint64_t rx_lro_pkt_cnt;
	uint64_t rx_byte_cnt;
	uint64_t rx_pkt_cnt;
	uint8_t intrEnableCnt;
	uint8_t intrDisableCnt;
	struct ecore_queue_cid *p_cid;
} qede_rx_ring_t;

typedef uint32_t qede_offload_t;
typedef struct qede_params {
	qede_offload_t  enabled_offloads;
	boolean_t multi_promisc_fl;
	boolean_t promisc_fl;
	uint32_t link_state;
	u32	loopback_mode;
} qede_params_t;

typedef struct qede_intr_context {
    /* bit field indicating	enable/disable state of vector */
    volatile uint32_t	intr_state;
	qede_vector_info_t *intr_vect_info;
	int intr_vect_info_array_size;			/* based on hw max vectors */
	ddi_intr_handle_t	*intr_hdl_array;		/* handle array from ddi_intr_alloc() */
	int intr_hdl_array_size;			/* based on hw max vectors */
	int intr_types_available;			/* from ddi_intr_get_supported_types */
	int intr_type_forced;				/* from qede.conf */
	int intr_type_in_use;				/* interrupt type currently used */
	int	intr_vect_supported;		/* from ddi_intr_get_nintrs */
	int	intr_vect_available;				/* from ddi_intr_get_navail */
	int intr_vect_to_request;			/* intr count requested */
	int intr_vect_allocated;			/* intr count taken */
	uint32_t	intr_pri;
	int intr_cap;
	uint32_t	intr_fp_vector_count;
    enum ecore_int_mode intr_mode;
} qede_intr_context_t;

#define QEDE_LINK_PAUSE_AUTONEG_ENABLE           (1 << 0)
#define QEDE_LINK_PAUSE_RX_ENABLE                (1 << 1)
#define QEDE_LINK_PAUSE_TX_ENABLE                (1 << 2)

typedef struct qede_props {
	uint32_t link_speed;
	boolean_t link_duplex;
	boolean_t tx_pause;
	boolean_t rx_pause;
	time_t    uptime;
} qede_props_t; 

typedef struct qede_link_props {
	uint8_t port_type;
	boolean_t autoneg;
	boolean_t asym_pause;
	boolean_t pause;
    	boolean_t param_100000fdx;
        boolean_t param_50000fdx;
        boolean_t param_40000fdx;
	boolean_t param_25000fdx;
        boolean_t param_10000fdx;
        boolean_t param_1000fdx;
        boolean_t param_1000hdx;
} qede_link_props_t;

typedef struct qede_link_cfg {
	boolean_t link_up;
	uint32_t speed;
	uint8_t duplex;
	uint8_t port;
	boolean_t autoneg;
	uint32_t pause_cfg;
	qede_link_props_t supp_capab;
	qede_link_props_t adv_capab;
	qede_link_props_t rem_capab;
} qede_link_cfg_t;

enum qede_filter_type {
	QEDE_FILTER_UCAST,
	QEDE_FILTER_MCAST,
	QEDE_FILTER_RX_MODE,
	QEDE_MAX_FILTER_TYPES,

};

enum qede_filter_rx_mode_type {
	QEDE_FILTER_RX_MODE_REGULAR,
	QEDE_FILTER_RX_MODE_MULTI_PROMISC,
	QEDE_FILTER_RX_MODE_PROMISC,
};



struct qede_mcast_filter_params {
	enum qede_filter_rx_mode_type acc_flg;
	struct ecore_filter_mcast mcast;
};

#define QEDE_MAX_UCST_CNT       8
typedef struct qede_mac_addr {
	 struct ether_addr mac_addr;
	  boolean_t         set;
} qede_mac_addr_t;


	
enum qede_state {
	QEDE_STATE_UNKNOWN,	
	QEDE_STATE_ATTACHED,	
	QEDE_STATE_STARTING,	/* Transitioning State */	
	QEDE_STATE_STARTED,	
	QEDE_STATE_STOPPING,	/* Transitioning State */	
	QEDE_STATE_STOPPED,	
	QEDE_STATE_SUSPENDING,	/* Transitioning State */	
	QEDE_STATE_SUSPENDED,	
	QEDE_STATE_RESUMING,	/* Transitioning State */	
	QEDE_STATE_FAILED,	
};

enum qede_attach_resources {
	QEDE_STRUCT_ALLOC = (1 << 0),
	QEDE_FM =			(1 << 1),
	QEDE_PCI = 	(1 << 2),
	QEDE_ECORE_HW_PREP = (1 << 3),
	QEDE_SET_PARAMS = (1 << 4),
	QEDE_CALLBACK = (1 << 5),
	QEDE_IO_STRUCT_ALLOC = (1 << 6),
	QEDE_INIT_LOCKS = (1 << 7),
	QEDE_INTR_ALLOC = (1 << 8),
	QEDE_INTR_CONFIG = (1 << 9),
	QEDE_EDEV_CONFIG = (1 << 10),
	QEDE_KSTAT_INIT = (1 << 11),
	QEDE_GLD_INIT = (1 << 12),
	QEDE_SP_INTR_ENBL = (1 << 13),
	QEDE_ECORE_HW_INIT = (1 << 14),
/*
	 = (1 << 15),
	 = (1 << 16),
	 = (1 << 17),
	 = (1 << 18),
	 = (1 << 19),
	 = (1 << 20),
*/
};

enum qede_vport_state {
	QEDE_VPORT_UNKNOWN,
	QEDE_VPORT_STARTED,
	QEDE_VPORT_ON,
	QEDE_VPORT_OFF,
	QEDE_VPORT_STOPPED
};

#define	QEDE_MAX_GROUPS		1
typedef struct qede_mac_group {
	int				group_index;
	mac_group_handle_t		group_handle;
	struct qede *qede;
} qede_mac_group_t;

typedef struct qede_link_input_params {
	struct ecore_mcp_link_params 	default_link_params;
	u32  				loopback_mode;
}qede_link_input_params_t;

typedef struct qede {
	struct ecore_dev 		edev; /* keep this at the beginning of the structure */
	dev_info_t *dip;
	int 				instance;
	enum qede_state			qede_state;
#define	MAX_QEDE_NAME_LEN		8
	char				name[MAX_QEDE_NAME_LEN];

	/* PCI access handle */
	ddi_acc_handle_t		pci_cfg_handle;

	/* BAR 0 - registers */
	ddi_acc_handle_t		regs_handle;
	off_t				regview_size;
	caddr_t				regview;
	uint64_t			pci_bar0_base;

	/* BAR 2 - doorbell */
	ddi_acc_handle_t		doorbell_handle;
	off_t				doorbell_size;
	caddr_t				doorbell;
	uint64_t			pci_bar2_base;

	/* Vport params */
	struct ecore_sp_vport_update_params	vport_params[MAX_HWFNS_PER_DEVICE];
	struct ecore_rss_params		rss_params[MAX_HWFNS_PER_DEVICE];
	enum qede_vport_state 		vport_state[MAX_HWFNS_PER_DEVICE];

	/* mac Layer related vars */
	mac_handle_t			mac_handle;
	qede_mac_group_t		rx_groups[QEDE_MAX_GROUPS];
	qede_mac_group_t		tx_groups[QEDE_MAX_GROUPS];

	u8 *sp_dpc;
	/* 
	 * pre-mapped buffer cache handle for TX 
	 * used for getting sglist for mbkls
	 * that were already mapped in mac layer
	 */
#ifdef	DBLK_DMA_PREMAP	
	pm_handle_t			pm_handle;
#endif

	/* current operating paramters */
	uint32_t			mtu;
	uint32_t			num_fp;
	uint32_t        		mc_cnt;

	uint32_t			tx_ring_size;
	uint32_t			tx_buf_size;
	uint16_t			tx_recycle_threshold;
	u16				pad; // remove later

	int             		checksum;
	qede_offload_t  		enabled_offloads;
	uint32_t        		rx_ring_size;
	uint32_t        		rx_buf_count;
	uint32_t        		rx_buf_size;
	uint32_t        		rx_copy_threshold;
	uint32_t			rx_low_buffer_threshold;
	boolean_t       		lso_enable;
	boolean_t       		lro_enable;
	boolean_t       		jumbo_enable;
	boolean_t       		log_enable;
	uint32_t        		ecore_debug_level;
	uint32_t			ecore_debug_module;
	boolean_t       		intr_coalesce;
	uint32_t        		intr_rx_coal_usec;
	uint32_t        		intr_tx_coal_usec;

	/* From ecore_hw_init */
	uint32_t			num_hwfns;
	unsigned char			ether_addr[ETHERADDRL];
	uint32_t			num_tc;

	qede_mac_addr_t 		ucst_mac[QEDE_MAX_UCST_CNT];
	uint32_t        		ucst_total;
	uint32_t        		ucst_avail;
	qede_mac_addr_t 		suspnd_mac_list[QEDE_MAX_UCST_CNT];


	/* software data structures for tx/rx */
	qede_intr_context_t		intr_ctx;
	qede_fastpath_t			fp_array[MAX_FASTPATH_COUNT];
	struct ecore_sb_info		sb_array[MAX_FASTPATH_COUNT];
	qede_rx_ring_t			rx_array[MAX_FASTPATH_COUNT];
	qede_tx_ring_t	  tx_array[MAX_TC_COUNT][MAX_FASTPATH_COUNT];

	uint16_t			tx_bcopy_threshold;
	uint16_t			pad1; /* remove later */

	/* status_block phys mem */
	bool 				sb_phy_mem_alloc;

	kmutex_t			drv_lock;
	kmutex_t			watch_lock;
	uint32_t			callback_flags;
	enum qede_attach_resources 	attach_resources;

	/*
	 * qede osal mem management queues
	 */
    	qede_phys_mem_list_t		phys_mem_list;
    	qede_mem_list_t     		mem_list;

	qede_props_t                    props;
	qede_link_cfg_t                 hwinit;
	qede_link_cfg_t                 curcfg;
	qede_params_t                   params;
	volatile uint32_t               plumbed;
	qede_mcast_list_t               mclist;

	uint32_t			mfw_ver;

	char                        	devName[QEDE_STR_SIZE];
	char                        	version[QEDE_STR_SIZE];
	char                        	versionFW[QEDE_STR_SIZE];
	char                        	versionMFW[QEDE_STR_SIZE];
	char                        	chip_name[QEDE_STR_SIZE];
	char                        	chipID[QEDE_STR_SIZE];
	char                        	intrAlloc[QEDE_STR_SIZE];
	char                        	bus_dev_func[QEDE_STR_SIZE];
	char                        	vendor_device[QEDE_STR_SIZE];

	uint64_t                        txTotalPkts;
	uint64_t                        txTotalBytes;
	uint64_t                        txTotalDiscards;
	uint64_t                        rxTotalPkts;
	uint64_t                        rxTotalBytes;
	uint64_t                        rxTotalDiscards;

	uint64_t			intrFired;
	kmutex_t			kstat_lock;
	kmutex_t			gld_lock;
	uint64_t			intrSbCnt[MAX_FASTPATH_COUNT + 1];
	uint64_t     intrSbNoChangeCnt[MAX_FASTPATH_COUNT + 1];
	uint64_t			intrSbPollCnt[MAX_FASTPATH_COUNT + 1];
	uint64_t			intrSbPollNoChangeCnt[MAX_FASTPATH_COUNT + 1];
    
	kstat_t *kstats;
	kstat_t *kstats_link;
	kstat_t *kstats_intr;
	kstat_t *kstats_vport;
	kstat_t *kstats_rxq[MAX_FASTPATH_COUNT];
	KstatRingMap          		kstats_rxq_map[MAX_FASTPATH_COUNT];
	kstat_t *kstats_txq[MAX_FASTPATH_COUNT];
	KstatRingMap          		kstats_txq_map[MAX_FASTPATH_COUNT];
    	struct ecore_eth_stats  	save_stats;

    	mblk_t	*stored_mp;
    	int 		 		mp_index;
    	qede_link_input_params_t 	link_input_params;  /*(test) */
	uint32_t			loop_back_mode;     /*(test) */
	bool				lb_linkup;	    /*(test) */
	uint32_t			forced_speed_10G;
	uint8_t				pci_func;    
        void *nvm_buf;
        void *nvm_buf_start;
	uint32_t			nvm_buf_size;
	uint32_t			copy_len;
	uint8_t 			*reserved_buf;	
	int                             fm_cap;
        uint64_t                        allocbFailures;
        volatile uint32_t               detach_unsafe;

} qede_t;

/*
 * ioctl commands
 */

typedef enum {
	QEDE_DRV_INFO = 2,
	QEDE_RD_PCICFG,
	QEDE_WR_PCICFG,
	QEDE_RW_REG,
	QEDE_RW_NVRAM,
	QEDE_FUNC_INFO,
	QEDE_MAC_ADDR
} qede_ioctl_cmd_t;



/*
 * ioctl message structure for FW update utility
 */

/* regiser read/write commands */ 
#define QEDE_REG_READ 0
#define QEDE_REG_WRITE 1

/* nvram read/write commands */
#define QEDE_NVRAM_CMD_READ 0
#define QEDE_NVRAM_CMD_WRITE 1
#define QEDE_NVRAM_CMD_PUT_FILE_DATA 2
#define QEDE_NVRAM_CMD_SET_SECURE_MODE 3
#define QEDE_NVRAM_CMD_DEL_FILE 4
#define QEDE_NVRAM_CMD_PUT_FILE_BEGIN 5
#define QEDE_NVRAM_CMD_GET_NVRAM_RESP 6

typedef struct {
	uint32_t cmd;
	uint32_t unused1;
	uint64_t off;
	uint32_t size;
	uint32_t rv;
	char uabc[2048];
	uint64_t address;
	void *ptr;	
} qede_ioctl_data_t;

typedef struct {
	uint32_t cmd;
	uint32_t unused1;
	uint64_t off;
	uint32_t size;
	uint32_t buf_size;
	char uabc[2048];
	uint64_t cmd2;
#define START_NVM_WRITE 1
#define ACCUMULATE_NVM_BUF 2
#define STOP_NVM_WRITE 3
#define READ_BUF 4
	void *ptr;
}qede_nvram_data_t;

typedef struct {
       	char drv_name[MAX_QEDE_NAME_LEN];
	char drv_version[QEDE_STR_SIZE];
	char mfw_version[QEDE_STR_SIZE];
	char stormfw_version[QEDE_STR_SIZE];
	uint32_t eeprom_dump_len; /* in bytes */
	uint32_t reg_dump_len; /* in bytes */
	char bus_info[QEDE_STR_SIZE];
} qede_driver_info_t;	

typedef struct {
	uint32_t        supported;	/* Features this interface supports */
	uint32_t        advertising; 	/* Features this interface advertises */
	uint32_t        speed; 		/* The forced speed, 10Mb, 100Mb, gigabit */
	uint32_t        duplex; 	/* Duplex, half or full */
	uint32_t        port; 		/* Which connector port */
	uint32_t        phy_address; 	/* port number*/
	uint32_t        autoneg; 	/* Enable or disable autonegotiation */
} qede_func_info_t;


typedef struct {
	bool    link_up;                                   
	u32     supported_caps; /* In SUPPORTED defs */    
	u32     advertised_caps; /* In ADVERTISED defs */  
	u32     lp_caps; /* In ADVERTISED defs */          
	u32     speed; /* In Mb/s */                       
	u8      duplex; /* In DUPLEX defs */               
	u8      port; /* In PORT defs */                   
	bool    autoneg;                                   
} qede_link_output_t;

#define PORT_FIBRE                      (1)
#define SUPPORTED_FIBRE                 (1 << 15)
#define SUPPORTED_Autoneg               (1 << 16)
#define SUPPORTED_Pause                 (1 << 17)
#define SUPPORTED_Asym_Pause            (1 << 18)
#define SUPPORTED_1000baseT_Half        (1 << 19)
#define SUPPORTED_1000baseT_Full        (1 << 20)
#define SUPPORTED_10000baseKR_Full      (1 << 21)
#define SUPPORTED_20000baseKR2_Full     (1 << 22)
#define SUPPORTED_40000baseKR4_Full     (1 << 23)
#define SUPPORTED_40000baseCR4_Full     (1 << 24)
#define SUPPORTED_40000baseSR4_Full     (1 << 25)
#define SUPPORTED_40000baseLR4_Full     (1 << 26)



typedef struct {
	uint32_t cmd;
#define QEDE_PCICFG_READ 0x01
#define QEDE_PCICFG_WRITE 0x02
	uint32_t reg;
	uint32_t val;
	uint32_t width;
} qede_pcicfg_rdw_t;
/*
 * (Internal) return values from ioctl subroutines
 *
 */
enum ioc_reply {
	IOC_INVAL = -1, /* bad, NAK with EINVAL */
	IOC_DONE, /* OK, reply sent  */
	IOC_ACK, /* OK, just send ACK  */
	IOC_REPLY, /* OK, just send reply */
	IOC_RESTART_ACK, /* OK, restart & ACK */
	IOC_RESTART_REPLY /* OK, restart & reply */
};

/*
 * Loop Back Modes
 */
enum {  
	QEDE_LOOP_NONE,
	QEDE_LOOP_INTERNAL,
	QEDE_LOOP_EXTERNAL,
};

/* Loopback test return values */
enum {  
	QEDE_LB_TEST_OK,
	QEDE_LB_SEND_WAIT_QUEUE_ERR,
	QEDE_LB_NORCV_ERR,
	QEDE_LB_NOMEM_ERR,
	QEDE_LB_TX_QUEUE_ERR,
	QEDE_LB_SHORT_DATA_ERR,
	QEDE_LB_SEQUENCE_ERR,
	QEDE_LB_DATA_ERR,
	QEDE_LB_ERRCNT,
	QEDE_LB_NOT_SUPPORTED,
	QEDE_LB_TEST_CHECK_CABLE,
	QEDE_LB_TEST_IN_PROGRESS
};

extern qede_link_props_t qede_def_link_props;
/* Functions exported by qede_cfg.c */
void qede_cfg_reset(qede_t *qede);
void qede_cfg_init(qede_t *qede);

/* Functions exported by qede_gld.c */
boolean_t qede_gld_init(qede_t *qede);
int qede_multicast(qede_t * qede, boolean_t flag, const uint8_t *ptr_mcaddr);
int qede_set_filter_rx_mode(qede_t *qede, enum qede_filter_rx_mode_type type);
int qede_set_rx_mac_mcast(qede_t *qede, enum ecore_filter_opcode opcode,
    uint8_t *mac, int mc_cnt);
int qede_ucst_find(qede_t *qede, const uint8_t *mac_addr);
int qede_clear_filters(qede_t *qede);
/* Functions exported by qede_main.c */
int
qede_stop(qede_t *);
int
qede_start(qede_t *);

#define	QEDE_DOORBELL_WR	qede_bar2_write32_tx_doorbell
void
qede_bar2_write32_tx_doorbell(qede_tx_ring_t *tx_ring, u32 val);
void
qede_enable_hw_intr(qede_fastpath_t *);
void
qede_disable_hw_intr(qede_fastpath_t *);

/* Functions exported by qede_dbg.c */
extern void
qede_stacktrace(qede_t *);
extern void
qede_print_vport_params(qede_t *,
    struct ecore_sp_vport_update_params *);
void
qede_dump_single_mblk(qede_t *qede, mblk_t *mp);
void
qede_dump_mblk_chain_bnext_ptr(qede_t *qede, mblk_t *mp);
void
qede_dump_mblk_chain_bcont_ptr(qede_t *qede, mblk_t *mp);
void
qede_dump_bytes(char *, int);
void qede_dump_reg_cqe(struct eth_fast_path_rx_reg_cqe *cqe);
void qede_dump_start_lro_cqe(struct eth_fast_path_rx_tpa_start_cqe *);
void qede_dump_cont_lro_cqe(struct eth_fast_path_rx_tpa_cont_cqe *);
void qede_dump_end_lro_cqe(struct eth_fast_path_rx_tpa_end_cqe *);
void qede_dump_mblk_chain_bcont_ptr(qede_t *, mblk_t *);

/* Functions exported by qede_fp.c */
mblk_t *qede_fp_poll(void *arg, int poll_bytes, int poll_pkts);
int qede_fp_stat(mac_ring_driver_t rh, uint_t stat, u64 *val);
mblk_t *
qede_process_fastpath(qede_fastpath_t *fp,
    int nbytes, int npkts, int *work_done);
void
qede_desc_dma_mem_sync(ddi_dma_handle_t *dma_handle,
    uint_t start, uint_t count, uint_t range,
    uint_t unit_size, uint_t direction);

/* Functions exported by qede_osal.c */
u32 qede_osal_cleanup(qede_t *qede);
int
qede_osal_find_dma_handle_for_block(qede_t *qede, void *addr,
    ddi_dma_handle_t *dma_handle);

/* Functions exported by qede_main.c */
int 
qede_get_mag_elem(qede_rx_ring_t *, qede_rx_buffer_t *);
void
qede_update_rx_q_producer(qede_rx_ring_t *rx_ring);
void qede_get_link_info(struct ecore_hwfn *hwfn,struct qede_link_cfg *lnkcfg);
int
qede_put_to_passive_list(qede_rx_ring_t *rx_ring, qede_rx_buffer_t *rx_buffer);
qede_rx_buffer_t *
qede_get_from_active_list(qede_rx_ring_t *, uint32_t *);
void
qede_replenish_rx_buffers(qede_rx_ring_t *);
void
qede_recycle_copied_rx_buffer(qede_rx_buffer_t *rx_buffer);
boolean_t qede_kstat_init(qede_t *qede);
void qede_kstat_fini(qede_t *qede);
/*void qede_get_current_link(qede_t *qede, struct qede_link_cfg *lnkcfg);*/
#endif /* _QEDE_H */
