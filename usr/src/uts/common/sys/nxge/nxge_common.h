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

#ifndef	_SYS_NXGE_NXGE_COMMON_H
#define	_SYS_NXGE_NXGE_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	NXGE_DMA_START			B_TRUE
#define	NXGE_DMA_STOP			B_FALSE

/*
 * Default DMA configurations.
 */
#define	NXGE_RDMA_PER_NIU_PORT		(NXGE_MAX_RDCS/NXGE_PORTS_NIU)
#define	NXGE_TDMA_PER_NIU_PORT		(NXGE_MAX_TDCS_NIU/NXGE_PORTS_NIU)
#define	NXGE_RDMA_PER_NEP_PORT		(NXGE_MAX_RDCS/NXGE_PORTS_NEPTUNE)
#define	NXGE_TDMA_PER_NEP_PORT		(NXGE_MAX_TDCS/NXGE_PORTS_NEPTUNE)
#define	NXGE_RDCGRP_PER_NIU_PORT	(NXGE_MAX_RDC_GROUPS/NXGE_PORTS_NIU)
#define	NXGE_RDCGRP_PER_NEP_PORT	(NXGE_MAX_RDC_GROUPS/NXGE_PORTS_NEPTUNE)

#define	NXGE_TIMER_RESO			2

#define	NXGE_TIMER_LDG			2

/*
 * Receive and Transmit DMA definitions
 */
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
/*
 * N2/NIU: Maximum descriptors if we need to call
 *	   Hypervisor to set up the logical pages
 *	   and the driver must use contiguous memory.
 */
#define	NXGE_NIU_MAX_ENTRY		(1 << 9) /* 512 */
#define	NXGE_NIU_CONTIG_RBR_MAX		(NXGE_NIU_MAX_ENTRY)
#define	NXGE_NIU_CONTIG_RCR_MAX		(NXGE_NIU_MAX_ENTRY)
#define	NXGE_NIU_CONTIG_TX_MAX		(NXGE_NIU_MAX_ENTRY)
#endif

#ifdef	_DMA_USES_VIRTADDR
#ifdef	NIU_PA_WORKAROUND
#define	NXGE_DMA_BLOCK		(16 * 64 * 4)
#else
#define	NXGE_DMA_BLOCK		1
#endif
#else
#define	NXGE_DMA_BLOCK		(64 * 64)
#endif

#define	NXGE_RBR_RBB_MIN	(128)
#define	NXGE_RBR_RBB_MAX	(64 * 128 -1)

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
#define	NXGE_RBR_RBB_DEFAULT	512
#define	NXGE_RBR_SPARE		0
#else
#if	defined(__i386)
#define	NXGE_RBR_RBB_DEFAULT	256
#else
#define	NXGE_RBR_RBB_DEFAULT	(64 * 16) /* x86 hello */
#endif
#define	NXGE_RBR_SPARE		0
#endif


#define	NXGE_RCR_MIN		(NXGE_RBR_RBB_MIN * 2)

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
#define	NXGE_RCR_MAX		(8192)
#define	NXGE_RCR_DEFAULT	(512)
#define	NXGE_TX_RING_DEFAULT	(512)
#else
#ifndef	NIU_PA_WORKAROUND
#define	NXGE_RCR_MAX		(65355) /* MAX hardware supported */
#if defined(_BIG_ENDIAN)
#define	NXGE_RCR_DEFAULT	(NXGE_RBR_RBB_DEFAULT * 8)
#else
#ifdef USE_RX_BIG_BUF
#define	NXGE_RCR_DEFAULT	(NXGE_RBR_RBB_DEFAULT * 8)
#else
#define	NXGE_RCR_DEFAULT	(NXGE_RBR_RBB_DEFAULT * 4)
#endif
#endif
#if	defined(__i386)
#define	NXGE_TX_RING_DEFAULT	(256)
#else
#define	NXGE_TX_RING_DEFAULT	(1024)
#endif
#define	NXGE_TX_RING_MAX	(64 * 128 - 1)
#else
#if	defined(__i386)
#define	NXGE_RCR_DEFAULT	(256)
#define	NXGE_TX_RING_DEFAULT	(256)
#else
#define	NXGE_RCR_DEFAULT	(512)
#define	NXGE_TX_RING_DEFAULT	(512)
#endif
#define	NXGE_RCR_MAX		(1024)
#define	NXGE_TX_RING_MAX	(1024)
#endif
#endif

#define	NXGE_TX_RECLAIM 	32

/* per receive DMA channel configuration data structure */
typedef struct  nxge_rdc_cfg {
	uint32_t	flag;		/* 0: not configured, 1: configured */
	struct nxge_hw_list *nxge_hw_p;
	uint32_t	partition_id;
	uint32_t	port;		/* function number */
	uint32_t	rx_group_id;

	/* Partitioning, DMC function zero. */
	uint32_t	rx_log_page_vld_page0;	/* TRUE or FALSE */
	uint32_t	rx_log_page_vld_page1;	/* TRUE or FALSE */
	uint64_t	rx_log_mask1;
	uint64_t	rx_log_value1;
	uint64_t	rx_log_mask2;
	uint64_t	rx_log_value2;
	uint64_t	rx_log_page_relo1;
	uint64_t	rx_log_page_relo2;
	uint64_t	rx_log_page_hdl;

	/* WRED parameters, DMC function zero */
	uint32_t	red_enable;

	uint32_t	thre_syn;
	uint32_t	win_syn;
	uint32_t	threshold;
	uint32_t	win_non_syn;

	/* RXDMA configuration, DMC */
	char		*rdc_mbaddr_p;	/* mailbox address */
	uint32_t	min_flag;	/* TRUE for 18 bytes header */

	/* Software Reserved Packet Buffer Offset, DMC */
	uint32_t	sw_offset;

	/* RBR Configuration A */
	uint64_t	rbr_staddr;	/* starting address of RBR */
	uint32_t	rbr_nblks;	/* # of RBR entries */
	uint32_t	rbr_len;	/* # of RBR entries in 64B lines */

	/* RBR Configuration B */
	uint32_t	bksize;		/* Block size is fixed. */
#define	RBR_BKSIZE_4K			0
#define	RBR_BKSIZE_4K_BYTES		(4 * 1024)
#define	RBR_BKSIZE_8K			1
#define	RBR_BKSIZE_8K_BYTES		(8 * 1024)
#define	RBR_BKSIZE_16K			2
#define	RBR_BKSIZE_16K_BYTES		(16 * 1024)
#define	RBR_BKSIZE_32K			3
#define	RBR_BKSIZE_32K_BYTES		(32 * 1024)

	uint32_t	bufsz2;
#define	RBR_BUFSZ2_2K			0
#define	RBR_BUFSZ2_2K_BYTES		(2 * 1024)
#define	RBR_BUFSZ2_4K			1
#define	RBR_BUFSZ2_4K_BYTES		(4 * 1024)
#define	RBR_BUFSZ2_8K			2
#define	RBR_BUFSZ2_8K_BYTES		(8 * 1024)
#define	RBR_BUFSZ2_16K			3
#define	RBR_BUFSZ2_16K_BYTES		(16 * 1024)

	uint32_t	bufsz1;
#define	RBR_BUFSZ1_1K			0
#define	RBR_BUFSZ1_1K_BYTES		1024
#define	RBR_BUFSZ1_2K			1
#define	RBR_BUFSZ1_2K_BYTES		(2 * 1024)
#define	RBR_BUFSZ1_4K			2
#define	RBR_BUFSZ1_4K_BYTES		(4 * 1024)
#define	RBR_BUFSZ1_8K			3
#define	RBR_BUFSZ1_8K_BYTES		(8 * 1024)

	uint32_t	bufsz0;
#define	RBR_BUFSZ0_256B			0
#define	RBR_BUFSZ0_256_BYTES		256
#define	RBR_BUFSZ0_512B			1
#define	RBR_BUFSZ0_512B_BYTES		512
#define	RBR_BUFSZ0_1K			2
#define	RBR_BUFSZ0_1K_BYTES		(1024)
#define	RBR_BUFSZ0_2K			3
#define	RBR_BUFSZ0_2K_BYTES		(2 * 1024)

	/* Receive buffers added by the software */
	uint32_t	bkadd;		/* maximum size is 1 million */

	/* Receive Completion Ring Configuration A */
	uint32_t	rcr_len;	/* # of 64B blocks, each RCR is 8B */
	uint64_t	rcr_staddr;

	/* Receive Completion Ring Configuration B */
	uint32_t	pthres;		/* packet threshold */
	uint32_t	entout;		/* enable timeout */
	uint32_t	timeout;	/* timeout value */

	/* Logical Device Group Number */
	uint16_t	rx_ldg;
	uint16_t	rx_ld_state_flags;

	/* Receive DMA Channel Event Mask */
	uint64_t	rx_dma_ent_mask;

	/* 32 bit (set to 1) or 64 bit (set to 0) addressing mode */
	uint32_t	rx_addr_md;
} nxge_rdc_cfg_t, *p_nxge_rdc_cfg_t;

/*
 * Per Transmit DMA Channel Configuration Data Structure (32 TDC)
 */
typedef struct  nxge_tdc_cfg {
	uint32_t	flag;		/* 0: not configured 1: configured */
	struct nxge_hw_list *nxge_hw_p;
	uint32_t	port; 		/* function number */
	/* partitioning, DMC function zero (All 0s for non-partitioning) */
	uint32_t	tx_log_page_vld_page0;	/* TRUE or FALSE */
	uint32_t	tx_log_page_vld_page1;	/* TRUE or FALSE */
	uint64_t	tx_log_mask1;
	uint64_t	tx_log_value1;
	uint64_t	tx_log_mask2;
	uint64_t	tx_log_value2;
	uint64_t	tx_log_page_relo1;
	uint64_t	tx_log_page_relo2;
	uint64_t	tx_log_page_hdl;

	/* Transmit Ring Configuration */
	uint64_t	tx_staddr;
	uint64_t	tx_rng_len;	/* in 64 B Blocks */
#define	TX_MAX_BUF_SIZE			4096

	/* TXDMA configuration, DMC */
	char		*tdc_mbaddr_p;	/* mailbox address */

	/* Logical Device Group Number */
	uint16_t	tx_ldg;
	uint16_t	tx_ld_state_flags;

	/* TXDMA event flags */
	uint64_t	tx_event_mask;

	/* Transmit threshold before reclamation */
	uint32_t	tx_rng_threshold;
#define	TX_RING_THRESHOLD		(TX_DEFAULT_MAX_GPS/4)
#define	TX_RING_JUMBO_THRESHOLD		(TX_DEFAULT_JUMBO_MAX_GPS/4)

	/* For reclaim: a wrap-around counter (packets transmitted) */
	uint32_t	tx_pkt_cnt;
	/* last packet with the mark bit set */
	uint32_t	tx_lastmark;
} nxge_tdc_cfg_t, *p_nxge_tdc_cfg_t;

#define	RDC_TABLE_ENTRY_METHOD_SEQ	0
#define	RDC_TABLE_ENTRY_METHOD_REP	1

/* per transmit DMA channel table group data structure */
typedef struct nxge_tdc_grp {
	uint32_t	start_tdc;	/* assume assigned in sequence */
	uint8_t		max_tdcs;
	dc_map_t	map;
	uint8_t		grp_index;	/* nxge_t.tx_set.group[grp_index] */
} nxge_tdc_grp_t, *p_nxge_tdc_grp_t;

/* per receive DMA channel table group data structure */
typedef struct nxge_rdc_grp {
	boolean_t	flag;		/* 0: not configured 1: configured */
	uint8_t		port;
	uint32_t	start_rdc;	/* assume assigned in sequence	*/
	uint8_t		max_rdcs;
	uint8_t		def_rdc;
	dc_map_t	map;
	uint16_t	config_method;
	uint8_t		grp_index;	/* nxge_t.rx_set.group[grp_index] */
} nxge_rdc_grp_t, *p_nxge_rdc_grp_t;

#define	RDC_MAP_IN(map, rdc) \
	(map |= (1 << rdc))

#define	RDC_MAP_OUT(map, rdc) \
	(map &= (~(1 << rdc)))

/* Common RDC and TDC configuration of DMC */
typedef struct _nxge_dma_common_cfg_t {
	uint16_t	rdc_red_ran_init; /* RED initial seed value */

	/* Transmit Ring */
} nxge_dma_common_cfg_t, *p_nxge_dma_common_cfg_t;

/*
 * VLAN and MAC table configurations:
 *  Each VLAN ID should belong to at most one RDC group.
 *  Each port could own multiple RDC groups.
 *  Each MAC should belong to one RDC group.
 */
typedef struct nxge_mv_cfg {
	uint8_t		flag;			/* 0:unconfigure 1:configured */
	uint8_t		rdctbl;			/* RDC channel table group */
	uint8_t		mpr_npr;		/* MAC and VLAN preference */
} nxge_mv_cfg_t, *p_nxge_mv_cfg_t;

typedef struct nxge_param_map {
#if defined(_BIG_ENDIAN)
	uint32_t		rsrvd2:2;	/* [30:31] rsrvd */
	uint32_t		remove:1;	/* [29] Remove */
	uint32_t		pref:1;		/* [28] preference */
	uint32_t		rsrv:4;		/* [27:24] preference */
	uint32_t		map_to:8;	/* [23:16] map to resource */
	uint32_t		param_id:16;	/* [15:0] Param ID */
#else
	uint32_t		param_id:16;	/* [15:0] Param ID */
	uint32_t		map_to:8;	/* [23:16] map to resource */
	uint32_t		rsrv:4;		/* [27:24] preference */
	uint32_t		pref:1;		/* [28] preference */
	uint32_t		remove:1;	/* [29] Remove */
	uint32_t		rsrvd2:2;	/* [30:31] rsrvd */
#endif
} nxge_param_map_t, *p_nxge_param_map_t;

typedef struct nxge_rcr_param {
#if defined(_BIG_ENDIAN)
	uint32_t		rsrvd2:2;	/* [30:31] rsrvd */
	uint32_t		remove:1;	/* [29] Remove */
	uint32_t		rsrv:5;		/* [28:24] preference */
	uint32_t		rdc:8;		/* [23:16] rdc # */
	uint32_t		cfg_val:16;	/* [15:0] interrupt parameter */
#else
	uint32_t		cfg_val:16;	/* [15:0] interrupt parameter */
	uint32_t		rdc:8;		/* [23:16] rdc # */
	uint32_t		rsrv:5;		/* [28:24] preference */
	uint32_t		remove:1;	/* [29] Remove */
	uint32_t		rsrvd2:2;	/* [30:31] rsrvd */
#endif
} nxge_rcr_param_t, *p_nxge_rcr_param_t;

/*
 * These are the properties of the TxDMA channels for this
 * port (instance).
 * <start> is the index of the first TDC that is being managed
 *		by this port.
 * <count> is the number of TDCs being managed by this port.
 * <owned> is the number of TDCs currently being utilized by this port.
 *
 * <owned> may be less than <count> in hybrid I/O systems.
 */
typedef struct {
	int		start;	/* start TDC (0 - 31) */
	int		count;	/* 8 - 32 */
	int		owned;	/* 1 - count */
} tdc_cfg_t;

/* Needs to have entries in the ndd table */
/*
 * Hardware properties created by fcode.
 * In order for those properties visible to the user
 * command ndd, we need to add the following properties
 * to the ndd defined parameter array and data structures.
 *
 * Use default static configuration for x86.
 */
typedef struct nxge_hw_pt_cfg {
	uint32_t	function_number; /* function number		*/
	tdc_cfg_t	tdc;
	uint32_t	start_rdc;	 /* start RDC (0 - 31)		*/
	uint32_t	max_rdcs;	 /* max rdc in sequence		*/
	uint32_t	ninterrupts;	/* obp interrupts(mac/mif/syserr) */
	uint32_t	mac_ldvid;
	uint32_t	mif_ldvid;
	uint32_t	ser_ldvid;
	uint32_t	def_rdc;	 /* default RDC			*/
	uint32_t	drr_wt;		 /* port DRR weight		*/
	uint32_t	max_grpids;	 /* max group ID		*/
	uint32_t	grpids[NXGE_MAX_RDCS]; /* RDC group IDs		*/
	uint32_t	max_rdc_grpids;	 /* max RDC group ID		*/
	uint32_t	start_ldg;	 /* starting logical group # 	*/
	uint32_t	max_ldgs;	 /* max logical device group	*/
	uint32_t	max_ldvs;	 /* max logical devices		*/
	uint32_t	start_mac_entry; /* where to put the first mac	*/
	uint32_t	max_macs;	 /* the max mac entry allowed	*/
	uint32_t	mac_pref;	 /* preference over VLAN	*/
	uint32_t	def_mac_txdma_grpid; /* default TDC group ID	*/
	uint32_t	def_mac_rxdma_grpid; /* default RDC group ID	*/
	uint32_t	vlan_pref;	 /* preference over MAC		*/

	/* Expand if we have more hardware or default configurations    */
	uint16_t	ldg[NXGE_INT_MAX_LDG];
	uint16_t	ldg_chn_start;
} nxge_hw_pt_cfg_t, *p_nxge_hw_pt_cfg_t;


/* per port configuration */
typedef struct nxge_dma_pt_cfg {
	uint8_t		mac_port;	/* MAC port (function)		*/
	nxge_hw_pt_cfg_t hw_config;	/* hardware configuration 	*/

	uint32_t alloc_buf_size;
	uint32_t rbr_size;
	uint32_t rcr_size;

	/*
	 * Configuration for hardware initialization based on the
	 * hardware properties or the default properties.
	 */
	uint32_t	tx_dma_map;	/* Transmit DMA channel bit map */

	/* Transmit DMA channel: device wise */
	nxge_tdc_grp_t  tdc_grps[NXGE_MAX_TDC_GROUPS];

	/* Receive DMA channel */
	nxge_rdc_grp_t	rdc_grps[NXGE_MAX_RDC_GROUPS];

	uint16_t	rcr_timeout[NXGE_MAX_RDCS];
	uint16_t	rcr_threshold[NXGE_MAX_RDCS];
	uint8_t	rcr_full_header;
	uint16_t	rx_drr_weight;

	/* Add more stuff later */
} nxge_dma_pt_cfg_t, *p_nxge_dma_pt_cfg_t;

/* classification configuration */
typedef struct nxge_class_pt_cfg {

	/* MAC table */
	nxge_mv_cfg_t	mac_host_info[NXGE_MAX_MACS];

	/* VLAN table */
	nxge_mv_cfg_t	vlan_tbl[NXGE_MAX_VLANS];
	/* class config value */
	uint32_t	init_h1;
	uint16_t	init_h2;
	uint8_t mcast_rdcgrp;
	uint8_t mac_rdcgrp;
	uint32_t	class_cfg[TCAM_CLASS_MAX];
} nxge_class_pt_cfg_t, *p_nxge_class_pt_cfg_t;

/* per Neptune sharable resources among ports */
typedef struct nxge_common {
	uint32_t		partition_id;
	boolean_t		mode32;
	/* DMA Channels: RDC and TDC */
	nxge_rdc_cfg_t		rdc_config[NXGE_MAX_RDCS];
	nxge_tdc_cfg_t		tdc_config[NXGE_MAX_TDCS];
	nxge_dma_common_cfg_t	dma_common_config;

	uint32_t		timer_res;
	boolean_t		ld_sys_error_set;
	uint8_t			sys_error_owner;

	/* Layer 2/3/4 */
	uint16_t		class2_etype;
	uint16_t		class3_etype;

	/* FCRAM (hashing) */
	uint32_t		hash1_initval;
	uint32_t		hash2_initval;
} nxge_common_t, *p_nxge_common_t;

/*
 * Partition (logical domain) configuration per Neptune/NIU.
 */
typedef struct nxge_part_cfg {
	uint32_t	rdc_grpbits;	/* RDC group bit masks */
	uint32_t	tdc_bitmap;	/* bounded TDC */
	nxge_dma_pt_cfg_t pt_config[NXGE_MAX_PORTS];

	/* Flow Classification Partition (flow partition select register) */
	uint8_t		hash_lookup;	/* external lookup is available */
	uint8_t		base_mask;	/* select bits in base_h1 to replace */
					/* bits [19:15} in Hash 1. */
	uint8_t		base_h1;	/* value to replace Hash 1 [19:15]. */

	/* Add more here */
	uint32_t	attributes;	/* permission and attribute bits */
#define	FZC_SERVICE_ENTITY		0x01
#define	FZC_READ_WRITE			0x02
#define	FZC_READ_ONLY			0x04
} nxge_part_cfg_t, *p_nxge_part_cfg_t;

typedef struct nxge_usr_l3_cls {
	uint64_t		cls;
	uint16_t		tcam_ref_cnt;
	uint8_t			pid;
	uint8_t			flow_pkt_type;
	uint8_t			valid;
} nxge_usr_l3_cls_t, *p_nxge_usr_l3_cls_t;

typedef struct nxge_hw_list {
	struct nxge_hw_list 	*next;
	nxge_os_mutex_t 	nxge_cfg_lock;
	nxge_os_mutex_t 	nxge_tcam_lock;
	nxge_os_mutex_t 	nxge_vlan_lock;
	nxge_os_mutex_t 	nxge_mdio_lock;

	nxge_dev_info_t		*parent_devp;
#if defined(sun4v)
	/*
	 * With Hybrid I/O, a VR (virtualization region) is the moral
	 * equivalent of a device function as seen in the service domain.
	 * And, a guest domain can map up to 8 VRs for a single NIU for both
	 * of the physical ports.  Hence, need space for up to the maximum
	 * number of VRs (functions) for the guest domain driver.
	 *
	 * For non-sun4v platforms, NXGE_MAX_PORTS provides the correct
	 * number of functions for the device. For sun4v platforms,
	 * NXGE_MAX_FUNCTIONS will be defined by the number of
	 * VRs that the guest domain can map.
	 *
	 * NOTE: This solution only works for one NIU and will need to
	 * revisit this for KT-NIU.
	 */
#define	NXGE_MAX_GUEST_FUNCTIONS	8
#define	NXGE_MAX_FUNCTIONS		NXGE_MAX_GUEST_FUNCTIONS
#else
#define	NXGE_MAX_FUNCTIONS		NXGE_MAX_PORTS
#endif
	struct _nxge_t		*nxge_p[NXGE_MAX_FUNCTIONS];
	uint32_t		ndevs;
	uint32_t 		flags;
	uint32_t 		magic;
	uint32_t		niu_type;
	uint32_t		platform_type;
	uint8_t			xcvr_addr[NXGE_MAX_PORTS];
	uintptr_t		hio;
	void			*tcam;
	uint32_t 		tcam_size;
	uint64_t		tcam_l2_prog_cls[NXGE_L2_PROG_CLS];
	nxge_usr_l3_cls_t	tcam_l3_prog_cls[NXGE_L3_PROG_CLS];
} nxge_hw_list_t, *p_nxge_hw_list_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_COMMON_H */
