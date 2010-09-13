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

#ifndef	_SYS_HXGE_HXGE_H
#define	_SYS_HXGE_HXGE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <hxge_vmac.h>
#include <hxge_pfc.h>
#include <hxge_classify.h>

/*
 * HXGE diagnostics IOCTLS.
 */
#define	HXGE_IOC		((((('N' << 8) + 'X') << 8) + 'G') << 8)

#define	HXGE_GET_TX_RING_SZ	(HXGE_IOC|1)
#define	HXGE_GET_TX_DESC	(HXGE_IOC|2)
#define	HXGE_GLOBAL_RESET	(HXGE_IOC|3)
#define	HXGE_TX_SIDE_RESET	(HXGE_IOC|4)
#define	HXGE_RX_SIDE_RESET	(HXGE_IOC|5)
#define	HXGE_RESET_MAC		(HXGE_IOC|6)
#define	HXGE_RTRACE		(HXGE_IOC|7)
#define	HXGE_GET_TCAM		(HXGE_IOC|8)
#define	HXGE_PUT_TCAM		(HXGE_IOC|9)

#define	HXGE_OK			0
#define	HXGE_ERROR		0x40000000
#define	HXGE_DDI_FAILED		0x20000000

/*
 * Definitions for module_info.
 */
#define	HXGE_DRIVER_NAME	"hxge"			/* module name */
#define	HXGE_CHECK_TIMER	(5000)

typedef enum {
	param_instance,

	param_accept_jumbo,
	param_rxdma_rbr_size,
	param_rxdma_rcr_size,
	param_rxdma_intr_time,
	param_rxdma_intr_pkts,
	param_vlan_ids,
	param_implicit_vlan_id,
	param_tcam_enable,

	param_hash_init_value,
	param_class_cfg_ether_usr1,
	param_class_cfg_ether_usr2,
	param_class_opt_ipv4_tcp,
	param_class_opt_ipv4_udp,
	param_class_opt_ipv4_ah,
	param_class_opt_ipv4_sctp,
	param_class_opt_ipv6_tcp,
	param_class_opt_ipv6_udp,
	param_class_opt_ipv6_ah,
	param_class_opt_ipv6_sctp,
	param_hxge_debug_flag,
	param_hpi_debug_flag,
	param_dump_ptrs,
	param_end
} hxge_param_index_t;


#define	HXGE_PARAM_READ			0x00000001ULL
#define	HXGE_PARAM_WRITE		0x00000002ULL
#define	HXGE_PARAM_SHARED		0x00000004ULL
#define	HXGE_PARAM_PRIV			0x00000008ULL
#define	HXGE_PARAM_RW			HXGE_PARAM_READ | HXGE_PARAM_WRITE
#define	HXGE_PARAM_RWS			HXGE_PARAM_RW | HXGE_PARAM_SHARED
#define	HXGE_PARAM_RWP			HXGE_PARAM_RW | HXGE_PARAM_PRIV

#define	HXGE_PARAM_RXDMA		0x00000010ULL
#define	HXGE_PARAM_TXDMA		0x00000020ULL
#define	HXGE_PARAM_MAC			0x00000040ULL

#define	HXGE_PARAM_CMPLX		0x00010000ULL
#define	HXGE_PARAM_NDD_WR_OK		0x00020000ULL
#define	HXGE_PARAM_INIT_ONLY		0x00040000ULL
#define	HXGE_PARAM_INIT_CONFIG		0x00080000ULL

#define	HXGE_PARAM_READ_PROP		0x00100000ULL
#define	HXGE_PARAM_PROP_ARR32		0x00200000ULL
#define	HXGE_PARAM_PROP_ARR64		0x00400000ULL
#define	HXGE_PARAM_PROP_STR		0x00800000ULL

#define	HXGE_PARAM_DONT_SHOW		0x80000000ULL

#define	HXGE_PARAM_ARRAY_CNT_MASK	0x0000ffff00000000ULL
#define	HXGE_PARAM_ARRAY_CNT_SHIFT	32ULL
#define	HXGE_PARAM_ARRAY_ALLOC_MASK	0xffff000000000000ULL
#define	HXGE_PARAM_ARRAY_ALLOC_SHIFT	48ULL

typedef struct _hxge_param_t {
	int (*getf)();
	int (*setf)();		/* null for read only */
	uint64_t type;		/* R/W/ Common/Port/ .... */
	uint64_t minimum;
	uint64_t maximum;
	uint64_t value;		/* for array params, pointer to value array */
	uint64_t old_value; /* for array params, pointer to old_value array */
	char   *fcode_name;
	char   *name;
} hxge_param_t, *p_hxge_param_t;


typedef enum {
	hxge_lb_normal,
	hxge_lb_mac10g
} hxge_lb_t;

enum hxge_mac_state {
	HXGE_MAC_STOPPED = 0,
	HXGE_MAC_STARTED
};

typedef struct _filter_t {
	uint32_t all_phys_cnt;
	uint32_t all_multicast_cnt;
	uint32_t all_sap_cnt;
} filter_t, *p_filter_t;

typedef struct _hxge_port_stats_t {
	hxge_lb_t		lb_mode;
	uint32_t		poll_mode;
} hxge_port_stats_t, *p_hxge_port_stats_t;


typedef struct _hxge_peu_sys_stats {
	uint32_t	spc_acc_err;
	uint32_t	tdc_pioacc_err;
	uint32_t	rdc_pioacc_err;
	uint32_t	pfc_pioacc_err;
	uint32_t	vmac_pioacc_err;
	uint32_t	cpl_hdrq_parerr;
	uint32_t	cpl_dataq_parerr;
	uint32_t	retryram_xdlh_parerr;
	uint32_t	retrysotram_xdlh_parerr;
	uint32_t	p_hdrq_parerr;
	uint32_t	p_dataq_parerr;
	uint32_t	np_hdrq_parerr;
	uint32_t	np_dataq_parerr;
	uint32_t	eic_msix_parerr;
	uint32_t	hcr_parerr;
} hxge_peu_sys_stats_t, *p_hxge_peu_sys_stats_t;


typedef struct _hxge_stats_t {
	/*
	 *  Overall structure size
	 */
	size_t			stats_size;

	kstat_t			*ksp;
	kstat_t			*rdc_ksp[HXGE_MAX_RDCS];
	kstat_t			*tdc_ksp[HXGE_MAX_TDCS];
	kstat_t			*rdc_sys_ksp;
	kstat_t			*tdc_sys_ksp;
	kstat_t			*pfc_ksp;
	kstat_t			*vmac_ksp;
	kstat_t			*port_ksp;
	kstat_t			*mmac_ksp;
	kstat_t			*peu_sys_ksp;

	hxge_mac_stats_t	mac_stats;
	hxge_vmac_stats_t	vmac_stats;	/* VMAC Statistics */

	hxge_rx_ring_stats_t	rdc_stats[HXGE_MAX_RDCS]; /* per rdc stats */
	hxge_rdc_sys_stats_t	rdc_sys_stats;	/* RDC system stats */

	hxge_tx_ring_stats_t	tdc_stats[HXGE_MAX_TDCS]; /* per tdc stats */
	hxge_tdc_sys_stats_t	tdc_sys_stats;	/* TDC system stats */

	hxge_pfc_stats_t	pfc_stats;	/* pfc stats */
	hxge_port_stats_t	port_stats;	/* port stats */

	hxge_peu_sys_stats_t	peu_sys_stats;	/* PEU system stats */
} hxge_stats_t, *p_hxge_stats_t;

typedef struct _hxge_intr_t {
	boolean_t		intr_registered; /* interrupts are registered */
	boolean_t		intr_enabled; 	/* interrupts are enabled */
	boolean_t		niu_msi_enable;	/* debug or configurable? */
	uint8_t			nldevs;		/* # of logical devices */
	int			intr_types;	/* interrupt types supported */
	int			intr_type;	/* interrupt type to add */
	int			msi_intx_cnt;	/* # msi/intx ints returned */
	int			intr_added;	/* # ints actually needed */
	int			intr_cap;	/* interrupt capabilities */
	size_t			intr_size;	/* size of array to allocate */
	ddi_intr_handle_t 	*htable;	/* For array of interrupts */
	/* Add interrupt number for each interrupt vector */
	int			pri;
} hxge_intr_t, *p_hxge_intr_t;

typedef struct _hxge_ldgv_t {
	uint8_t			ndma_ldvs;
	uint8_t			nldvs;
	uint8_t			start_ldg;
	uint8_t			maxldgs;
	uint8_t			maxldvs;
	uint8_t			ldg_intrs;
	uint32_t		tmres;
	p_hxge_ldg_t		ldgp;
	p_hxge_ldv_t		ldvp;
	p_hxge_ldv_t		ldvp_syserr;
} hxge_ldgv_t, *p_hxge_ldgv_t;

typedef struct _hxge_timeout {
	timeout_id_t	id;
	clock_t		ticks;
	kmutex_t	lock;
	uint32_t	link_status;
	boolean_t	report_link_status;
} hxge_timeout;

typedef struct _hxge_addr {
	boolean_t	set;
	boolean_t	primary;
	uint8_t		addr[ETHERADDRL];
} hxge_addr_t;

#define	HXGE_MAX_MAC_ADDRS	16

typedef struct _hxge_mmac {
	uint8_t		total;
	uint8_t		available;
	hxge_addr_t	addrs[HXGE_MAX_MAC_ADDRS];
} hxge_mmac_t;

/*
 * Ring Group Strucuture.
 */
#define	HXGE_MAX_RX_GROUPS	1

typedef struct _hxge_rx_ring_group_t {
	mac_ring_type_t		type;
	mac_group_handle_t	ghandle;
	struct _hxge_t		*hxgep;
	int			index;
	boolean_t		started;
} hxge_ring_group_t;

/*
 * Ring Handle
 */
typedef struct _hxge_ring_handle_t {
	struct _hxge_t		*hxgep;
	int			index;		/* port-wise */
	mac_ring_handle_t	ring_handle;
	boolean_t		started;
} hxge_ring_handle_t;

typedef hxge_ring_handle_t 	*p_hxge_ring_handle_t;

/*
 * Hydra Device instance state information.
 * Each instance is dynamically allocated on first attach.
 */
struct _hxge_t {
	dev_info_t		*dip;		/* device instance */
	dev_info_t		*p_dip;		/* Parent's device instance */
	int			instance;	/* instance number */
	uint32_t		drv_state;	/* driver state bit flags */
	uint64_t		hxge_debug_level; /* driver state bit flags */
	kmutex_t		genlock[1];
	enum hxge_mac_state	hxge_mac_state;

	p_dev_regs_t		dev_regs;
	hpi_handle_t		hpi_handle;
	hpi_handle_t		hpi_pci_handle;
	hpi_handle_t		hpi_reg_handle;
	hpi_handle_t		hpi_msi_handle;

	hxge_vmac_t		vmac;
	hxge_classify_t		classifier;

	mac_handle_t		mach;		/* mac module handle */

	p_hxge_stats_t		statsp;
	uint32_t		param_count;
	p_hxge_param_t		param_arr;
	hxge_hw_list_t		*hxge_hw_p; 	/* pointer to per Hydra */
	uint8_t			nrdc;
	uint8_t			rdc[HXGE_MAX_RDCS];
	boolean_t		rdc_first_intr[HXGE_MAX_RDCS];
	uint8_t			ntdc;
	uint8_t			tdc[HXGE_MAX_TDCS];

	hxge_ring_handle_t	tx_ring_handles[HXGE_MAX_TDCS];
	hxge_ring_handle_t	rx_ring_handles[HXGE_MAX_RDCS];
	hxge_ring_group_t	rx_groups[HXGE_MAX_RX_GROUPS];

	hxge_intr_t		hxge_intr_type;
	hxge_dma_pt_cfg_t 	pt_config;
	hxge_class_pt_cfg_t 	class_config;

	/* Logical device and group data structures. */
	p_hxge_ldgv_t		ldgvp;

	caddr_t			param_list;	/* Parameter list */

	ether_addr_st		factaddr;	/* factory mac address	    */
	ether_addr_st		ouraddr;	/* individual address	    */
	kmutex_t		ouraddr_lock;	/* lock to protect to uradd */
	hxge_mmac_t		mmac;

	ddi_iblock_cookie_t	interrupt_cookie;

	/*
	 * Blocks of memory may be pre-allocated by the
	 * partition manager or the driver. They may include
	 * blocks for configuration and buffers. The idea is
	 * to preallocate big blocks of contiguous areas in
	 * system memory (i.e. with IOMMU). These blocks then
	 * will be broken up to a fixed number of blocks with
	 * each block having the same block size (4K, 8K, 16K or
	 * 32K) in the case of buffer blocks. For systems that
	 * do not support DVMA, more than one big block will be
	 * allocated.
	 */
	uint32_t		rx_default_block_size;
	hxge_rx_block_size_t	rx_bksize_code;

	p_hxge_dma_pool_t	rx_buf_pool_p;
	p_hxge_dma_pool_t	rx_rbr_cntl_pool_p;
	p_hxge_dma_pool_t	rx_rcr_cntl_pool_p;
	p_hxge_dma_pool_t	rx_mbox_cntl_pool_p;

	p_hxge_dma_pool_t	tx_buf_pool_p;
	p_hxge_dma_pool_t	tx_cntl_pool_p;

	/* Receive buffer block ring and completion ring. */
	p_rx_rbr_rings_t 	rx_rbr_rings;
	p_rx_rcr_rings_t 	rx_rcr_rings;
	p_rx_mbox_areas_t 	rx_mbox_areas_p;

	uint32_t		start_rdc;
	uint32_t		max_rdcs;

	/* Transmit descriptors rings */
	p_tx_rings_t 		tx_rings;
	p_tx_mbox_areas_t	tx_mbox_areas_p;

	uint32_t		start_tdc;
	uint32_t		max_tdcs;
	uint32_t		tdc_mask;

	ddi_dma_handle_t 	dmasparehandle;

	ulong_t 		sys_page_sz;
	ulong_t 		sys_page_mask;
	int 			suspended;

	filter_t 		filter;		/* Current instance filter */
	p_hash_filter_t 	hash_filter;	/* Multicast hash filter. */
	krwlock_t		filter_lock;	/* Lock to protect filters. */

	ulong_t 		sys_burst_sz;
	timeout_id_t 		hxge_timerid;
	uint8_t 		msg_min;

	uint16_t		intr_timeout;
	uint16_t		intr_threshold;

	rtrace_t		rtrace;
	int			fm_capabilities; /* FMA capabilities */

	uint32_t 		hxge_port_rbr_size;
	uint32_t 		hxge_port_rcr_size;
	uint32_t 		hxge_port_tx_ring_size;

	kmutex_t		vmac_lock;
	kmutex_t		pio_lock;
	hxge_timeout		timeout;
};

/*
 * Driver state flags.
 */
#define	STATE_REGS_MAPPED	0x000000001	/* device registers mapped */
#define	STATE_KSTATS_SETUP	0x000000002	/* kstats allocated	*/
#define	STATE_NODE_CREATED	0x000000004	/* device node created	*/
#define	STATE_HW_CONFIG_CREATED	0x000000008	/* hardware properties	*/
#define	STATE_HW_INITIALIZED	0x000000010	/* hardware initialized	*/

typedef struct _hxge_port_kstat_t {
	/*
	 * Transciever state informations.
	 */
	kstat_named_t	cap_autoneg;
	kstat_named_t	cap_10gfdx;

	/*
	 * Link partner capabilities.
	 */
	kstat_named_t	lp_cap_autoneg;
	kstat_named_t	lp_cap_10gfdx;

	/*
	 * Shared link setup.
	 */
	kstat_named_t	link_speed;
	kstat_named_t	link_duplex;
	kstat_named_t	link_up;

	/*
	 * Lets the user know the MTU currently in use by
	 * the physical MAC port.
	 */
	kstat_named_t	lb_mode;

	kstat_named_t	tx_max_pend;
	kstat_named_t	rx_jumbo_pkts;

	/*
	 * Misc MAC statistics.
	 */
	kstat_named_t	ifspeed;
	kstat_named_t	promisc;
} hxge_port_kstat_t, *p_hxge_port_kstat_t;

typedef struct _hxge_rdc_kstat {
	/*
	 * Receive DMA channel statistics.
	 * This structure needs to be consistent with hxge_rdc_stat_index_t
	 * in hxge_kstat.c
	 */
	kstat_named_t	ipackets;
	kstat_named_t	rbytes;
	kstat_named_t	errors;
	kstat_named_t	jumbo_pkts;

	kstat_named_t	rcr_unknown_err;
	kstat_named_t	rcr_sha_par_err;
	kstat_named_t	rbr_pre_par_err;
	kstat_named_t	rbr_pre_emty;

	kstat_named_t	rcr_shadow_full;
	kstat_named_t	rbr_tmout;
	kstat_named_t	peu_resp_err;

	kstat_named_t	ctrl_fifo_ecc_err;
	kstat_named_t	data_fifo_ecc_err;

	kstat_named_t	rcrfull;
	kstat_named_t	rbr_empty;
	kstat_named_t	rbr_empty_fail;
	kstat_named_t	rbr_empty_restore;
	kstat_named_t	rbrfull;
	kstat_named_t	rcr_invalids;	/* Account for invalid RCR entries. */

	kstat_named_t	rcr_to;
	kstat_named_t	rcr_thresh;
	kstat_named_t	pkt_drop;
} hxge_rdc_kstat_t, *p_hxge_rdc_kstat_t;

typedef struct _hxge_rdc_sys_kstat {
	/*
	 * Receive DMA system statistics.
	 * This structure needs to be consistent with hxge_rdc_sys_stat_idx_t
	 * in hxge_kstat.c
	 */
	kstat_named_t	ctrl_fifo_sec;
	kstat_named_t	ctrl_fifo_ded;
	kstat_named_t	data_fifo_sec;
	kstat_named_t	data_fifo_ded;
} hxge_rdc_sys_kstat_t, *p_hxge_rdc_sys_kstat_t;

typedef	struct _hxge_tdc_kstat {
	/*
	 * Transmit DMA channel statistics.
	 * This structure needs to be consistent with hxge_tdc_stats_index_t
	 * in hxge_kstat.c
	 */
	kstat_named_t	opackets;
	kstat_named_t	obytes;
	kstat_named_t	obytes_with_pad;
	kstat_named_t	oerrors;
	kstat_named_t	tx_inits;
	kstat_named_t	tx_no_buf;

	kstat_named_t	peu_resp_err;
	kstat_named_t	pkt_size_err;
	kstat_named_t	tx_rng_oflow;
	kstat_named_t	pkt_size_hdr_err;
	kstat_named_t	runt_pkt_drop_err;
	kstat_named_t	pref_par_err;
	kstat_named_t	tdr_pref_cpl_to;
	kstat_named_t	pkt_cpl_to;
	kstat_named_t	invalid_sop;
	kstat_named_t	unexpected_sop;

	kstat_named_t	count_hdr_size_err;
	kstat_named_t	count_runt;
	kstat_named_t	count_abort;

	kstat_named_t	tx_starts;
	kstat_named_t	tx_no_desc;
	kstat_named_t	tx_dma_bind_fail;
	kstat_named_t	tx_hdr_pkts;
	kstat_named_t	tx_ddi_pkts;
	kstat_named_t	tx_jumbo_pkts;
	kstat_named_t	tx_max_pend;
	kstat_named_t	tx_marks;
} hxge_tdc_kstat_t, *p_hxge_tdc_kstat_t;

typedef struct _hxge_tdc_sys_kstat {
	/*
	 * Transmit DMA system statistics.
	 * This structure needs to be consistent with hxge_tdc_sys_stat_idx_t
	 * in hxge_kstat.c
	 */
	kstat_named_t	reord_tbl_par_err;
	kstat_named_t	reord_buf_ded_err;
	kstat_named_t	reord_buf_sec_err;
} hxge_tdc_sys_kstat_t, *p_hxge_tdc_sys_kstat_t;

typedef	struct _hxge_vmac_kstat {
	/*
	 * VMAC statistics.
	 * This structure needs to be consistent with hxge_vmac_stat_index_t
	 * in hxge_kstat.c
	 */
	kstat_named_t	tx_frame_cnt;
	kstat_named_t	tx_byte_cnt;

	kstat_named_t	rx_frame_cnt;
	kstat_named_t	rx_byte_cnt;
	kstat_named_t	rx_drop_frame_cnt;
	kstat_named_t	rx_drop_byte_cnt;
	kstat_named_t	rx_crc_cnt;
	kstat_named_t	rx_pause_cnt;
	kstat_named_t	rx_bcast_fr_cnt;
	kstat_named_t	rx_mcast_fr_cnt;
} hxge_vmac_kstat_t, *p_hxge_vmac_kstat_t;

typedef struct _hxge_pfc_kstat {
	/*
	 * This structure needs to be consistent with hxge_pfc_stat_index_t
	 * in hxge_kstat.c
	 */
	kstat_named_t	pfc_pkt_drop;
	kstat_named_t	pfc_tcam_parity_err;
	kstat_named_t	pfc_vlan_parity_err;
	kstat_named_t	pfc_bad_cs_count;
	kstat_named_t	pfc_drop_count;
	kstat_named_t	pfc_tcp_ctrl_drop;
	kstat_named_t	pfc_l2_addr_drop;
	kstat_named_t	pfc_class_code_drop;
	kstat_named_t	pfc_tcam_drop;
	kstat_named_t	pfc_vlan_drop;
} hxge_pfc_kstat_t, *p_hxge_pfc_kstat_t;

typedef struct _hxge_mmac_kstat {
	/*
	 * This structure needs to be consistent with hxge_mmac_stat_index_t
	 * in hxge_kstat.c
	 */
	kstat_named_t	mmac_max_addr_cnt;
	kstat_named_t	mmac_avail_addr_cnt;
	kstat_named_t	mmac_addr1;
	kstat_named_t	mmac_addr2;
	kstat_named_t	mmac_addr3;
	kstat_named_t	mmac_addr4;
	kstat_named_t	mmac_addr5;
	kstat_named_t	mmac_addr6;
	kstat_named_t	mmac_addr7;
	kstat_named_t	mmac_addr8;
	kstat_named_t	mmac_addr9;
	kstat_named_t	mmac_addr10;
	kstat_named_t	mmac_addr11;
	kstat_named_t	mmac_addr12;
	kstat_named_t	mmac_addr13;
	kstat_named_t	mmac_addr14;
	kstat_named_t	mmac_addr15;
	kstat_named_t	mmac_addr16;
} hxge_mmac_kstat_t, *p_hxge_mmac_kstat_t;

typedef struct _hxge_peu_sys_kstat {
	/*
	 * This structure needs to be consistent with hxge_peu_sys_stat_idx_t
	 * in hxge_kstat.c
	 */
	kstat_named_t	spc_acc_err;
	kstat_named_t	tdc_pioacc_err;
	kstat_named_t	rdc_pioacc_err;
	kstat_named_t	pfc_pioacc_err;
	kstat_named_t	vmac_pioacc_err;
	kstat_named_t	cpl_hdrq_parerr;
	kstat_named_t	cpl_dataq_parerr;
	kstat_named_t	retryram_xdlh_parerr;
	kstat_named_t	retrysotram_xdlh_parerr;
	kstat_named_t	p_hdrq_parerr;
	kstat_named_t	p_dataq_parerr;
	kstat_named_t	np_hdrq_parerr;
	kstat_named_t	np_dataq_parerr;
	kstat_named_t	eic_msix_parerr;
	kstat_named_t	hcr_parerr;
} hxge_peu_sys_kstat_t, *p_hxge_peu_sys_kstat_t;

/*
 * Prototype definitions.
 */
hxge_status_t hxge_init(p_hxge_t);
void hxge_uninit(p_hxge_t);

typedef	void	(*fptrv_t)();
timeout_id_t hxge_start_timer(p_hxge_t hxgep, fptrv_t func, int msec);
void hxge_stop_timer(p_hxge_t hxgep, timeout_id_t timerid);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_H */
