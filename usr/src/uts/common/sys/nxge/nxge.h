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

#ifndef	_SYS_NXGE_NXGE_H
#define	_SYS_NXGE_NXGE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_mac.h>
#include <nxge_ipp.h>
#include <nxge_fflp.h>

/*
 * NXGE diagnostics IOCTLS.
 */
#define	NXGE_IOC		((((('N' << 8) + 'X') << 8) + 'G') << 8)

#define	NXGE_GET64		(NXGE_IOC|1)
#define	NXGE_PUT64		(NXGE_IOC|2)
#define	NXGE_GET_TX_RING_SZ	(NXGE_IOC|3)
#define	NXGE_GET_TX_DESC	(NXGE_IOC|4)
#define	NXGE_GLOBAL_RESET	(NXGE_IOC|5)
#define	NXGE_TX_SIDE_RESET	(NXGE_IOC|6)
#define	NXGE_RX_SIDE_RESET	(NXGE_IOC|7)
#define	NXGE_RESET_MAC		(NXGE_IOC|8)

#define	NXGE_GET_MII		(NXGE_IOC|11)
#define	NXGE_PUT_MII		(NXGE_IOC|12)
#define	NXGE_RTRACE		(NXGE_IOC|13)
#define	NXGE_RTRACE_TEST	(NXGE_IOC|20)
#define	NXGE_TX_REGS_DUMP	(NXGE_IOC|21)
#define	NXGE_RX_REGS_DUMP	(NXGE_IOC|22)
#define	NXGE_INT_REGS_DUMP	(NXGE_IOC|23)
#define	NXGE_VIR_REGS_DUMP	(NXGE_IOC|24)
#define	NXGE_VIR_INT_REGS_DUMP	(NXGE_IOC|25)
#define	NXGE_RDUMP		(NXGE_IOC|26)
#define	NXGE_RDC_GRPS_DUMP	(NXGE_IOC|27)
#define	NXGE_PIO_TEST		(NXGE_IOC|28)

#define	NXGE_GET_TCAM		(NXGE_IOC|29)
#define	NXGE_PUT_TCAM		(NXGE_IOC|30)
#define	NXGE_INJECT_ERR		(NXGE_IOC|40)

#define	NXGE_RX_CLASS		(NXGE_IOC|41)
#define	NXGE_RX_HASH		(NXGE_IOC|42)

#define	NXGE_OK			0
#define	NXGE_ERROR		0x40000000
#define	NXGE_DDI_FAILED		0x20000000
#define	NXGE_GET_PORT_NUM(n)	n

/*
 * Definitions for module_info.
 */
#define	NXGE_IDNUM		(0)			/* module ID number */
#define	NXGE_DRIVER_NAME	"nxge"			/* module name */

#define	NXGE_MINPSZ		(0)			/* min packet size */
#define	NXGE_MAXPSZ		(ETHERMTU)		/* max packet size */
#define	NXGE_HIWAT		(2048 * NXGE_MAXPSZ)	/* hi-water mark */
#define	NXGE_LOWAT		(1)			/* lo-water mark */
#define	NXGE_HIWAT_MAX		(192000 * NXGE_MAXPSZ)
#define	NXGE_HIWAT_MIN		(2 * NXGE_MAXPSZ)
#define	NXGE_LOWAT_MAX		(192000 * NXGE_MAXPSZ)
#define	NXGE_LOWAT_MIN		(1)

#ifndef	D_HOTPLUG
#define	D_HOTPLUG		0x00
#endif

#define	INIT_BUCKET_SIZE	16	/* Initial Hash Bucket Size */

#define	NXGE_CHECK_TIMER	(5000)

/* KT/NIU OBP creates a compatible property for KT */
#define	KT_NIU_COMPATIBLE	"SUNW,niusl-kt"

typedef enum {
	param_instance,
	param_main_instance,
	param_function_number,
	param_partition_id,
	param_read_write_mode,
	param_fw_version,
	param_port_mode,
	param_niu_cfg_type,
	param_tx_quick_cfg,
	param_rx_quick_cfg,
	param_master_cfg_enable,
	param_master_cfg_value,

	param_autoneg,
	param_anar_10gfdx,
	param_anar_10ghdx,
	param_anar_1000fdx,
	param_anar_1000hdx,
	param_anar_100T4,
	param_anar_100fdx,
	param_anar_100hdx,
	param_anar_10fdx,
	param_anar_10hdx,

	param_anar_asmpause,
	param_anar_pause,
	param_use_int_xcvr,
	param_enable_ipg0,
	param_ipg0,
	param_ipg1,
	param_ipg2,
	param_txdma_weight,
	param_txdma_channels_begin,

	param_txdma_channels,
	param_txdma_info,
	param_rxdma_channels_begin,
	param_rxdma_channels,
	param_rxdma_drr_weight,
	param_rxdma_full_header,
	param_rxdma_info,
	param_rxdma_rbr_size,
	param_rxdma_rcr_size,
	param_default_port_rdc,
	param_rxdma_intr_time,
	param_rxdma_intr_pkts,

	param_rdc_grps_start,
	param_rx_rdc_grps,
	param_default_grp0_rdc,
	param_default_grp1_rdc,
	param_default_grp2_rdc,
	param_default_grp3_rdc,
	param_default_grp4_rdc,
	param_default_grp5_rdc,
	param_default_grp6_rdc,
	param_default_grp7_rdc,

	param_info_rdc_groups,
	param_start_ldg,
	param_max_ldg,
	param_mac_2rdc_grp,
	param_vlan_2rdc_grp,
	param_fcram_part_cfg,
	param_fcram_access_ratio,
	param_tcam_access_ratio,
	param_tcam_enable,
	param_hash_lookup_enable,
	param_llc_snap_enable,

	param_h1_init_value,
	param_h2_init_value,
	param_class_cfg_ether_usr1,
	param_class_cfg_ether_usr2,
	param_class_cfg_ip_usr4,
	param_class_cfg_ip_usr5,
	param_class_cfg_ip_usr6,
	param_class_cfg_ip_usr7,
	param_class_opt_ip_usr4,
	param_class_opt_ip_usr5,
	param_class_opt_ip_usr6,
	param_class_opt_ip_usr7,
	param_class_opt_ipv4_tcp,
	param_class_opt_ipv4_udp,
	param_class_opt_ipv4_ah,
	param_class_opt_ipv4_sctp,
	param_class_opt_ipv6_tcp,
	param_class_opt_ipv6_udp,
	param_class_opt_ipv6_ah,
	param_class_opt_ipv6_sctp,
	param_nxge_debug_flag,
	param_npi_debug_flag,
	param_dump_rdc,
	param_dump_tdc,
	param_dump_mac_regs,
	param_dump_ipp_regs,
	param_dump_fflp_regs,
	param_dump_vlan_table,
	param_dump_rdc_table,
	param_dump_ptrs,
	param_end
} nxge_param_index_t;

typedef enum {
	SOLARIS_DOMAIN,
	SOLARIS_SERVICE_DOMAIN,
	SOLARIS_GUEST_DOMAIN,
	LINUX_SERVICE_DOMAIN,
	LINUX_GUEST_DOMAIN
} nxge_environs_t;

/*
 * Named Dispatch Parameter Management Structure
 */
typedef	int (*nxge_ndgetf_t)(p_nxge_t, queue_t *, MBLKP, caddr_t, cred_t *);
typedef	int (*nxge_ndsetf_t)(p_nxge_t, queue_t *,
	    MBLKP, char *, caddr_t, cred_t *);

#define	NXGE_PARAM_READ			0x00000001ULL
#define	NXGE_PARAM_WRITE		0x00000002ULL
#define	NXGE_PARAM_SHARED		0x00000004ULL
#define	NXGE_PARAM_PRIV			0x00000008ULL
#define	NXGE_PARAM_RW			NXGE_PARAM_READ | NXGE_PARAM_WRITE
#define	NXGE_PARAM_RWS			NXGE_PARAM_RW | NXGE_PARAM_SHARED
#define	NXGE_PARAM_RWP			NXGE_PARAM_RW | NXGE_PARAM_PRIV

#define	NXGE_PARAM_RXDMA		0x00000010ULL
#define	NXGE_PARAM_TXDMA		0x00000020ULL
#define	NXGE_PARAM_CLASS_GEN	0x00000040ULL
#define	NXGE_PARAM_MAC			0x00000080ULL
#define	NXGE_PARAM_CLASS_BIN	NXGE_PARAM_CLASS_GEN | NXGE_PARAM_BASE_BIN
#define	NXGE_PARAM_CLASS_HEX	NXGE_PARAM_CLASS_GEN | NXGE_PARAM_BASE_HEX
#define	NXGE_PARAM_CLASS		NXGE_PARAM_CLASS_HEX

#define	NXGE_PARAM_CMPLX		0x00010000ULL
#define	NXGE_PARAM_NDD_WR_OK		0x00020000ULL
#define	NXGE_PARAM_INIT_ONLY		0x00040000ULL
#define	NXGE_PARAM_INIT_CONFIG		0x00080000ULL

#define	NXGE_PARAM_READ_PROP		0x00100000ULL
#define	NXGE_PARAM_PROP_ARR32		0x00200000ULL
#define	NXGE_PARAM_PROP_ARR64		0x00400000ULL
#define	NXGE_PARAM_PROP_STR		0x00800000ULL

#define	NXGE_PARAM_BASE_DEC		0x00000000ULL
#define	NXGE_PARAM_BASE_BIN		0x10000000ULL
#define	NXGE_PARAM_BASE_HEX		0x20000000ULL
#define	NXGE_PARAM_BASE_STR		0x40000000ULL
#define	NXGE_PARAM_DONT_SHOW		0x80000000ULL

#define	NXGE_PARAM_ARRAY_CNT_MASK	0x0000ffff00000000ULL
#define	NXGE_PARAM_ARRAY_CNT_SHIFT	32ULL
#define	NXGE_PARAM_ARRAY_ALLOC_MASK	0xffff000000000000ULL
#define	NXGE_PARAM_ARRAY_ALLOC_SHIFT	48ULL

typedef struct _nxge_param_t {
	int (*getf)();
	int (*setf)();   /* null for read only */
	uint64_t type;  /* R/W/ Common/Port/ .... */
	uint64_t minimum;
	uint64_t maximum;
	uint64_t value;	/* for array params, pointer to value array */
	uint64_t old_value; /* for array params, pointer to old_value array */
	char   *fcode_name;
	char   *name;
} nxge_param_t, *p_nxge_param_t;


/*
 * Do not change the order of the elements of this enum as that will
 * break the driver code.
 */
typedef enum {
	nxge_lb_normal,
	nxge_lb_ext10g,
	nxge_lb_ext1000,
	nxge_lb_ext100,
	nxge_lb_ext10,
	nxge_lb_phy10g,
	nxge_lb_phy1000,
	nxge_lb_phy,
	nxge_lb_serdes10g,
	nxge_lb_serdes1000,
	nxge_lb_serdes,
	nxge_lb_mac10g,
	nxge_lb_mac1000,
	nxge_lb_mac
} nxge_lb_t;

enum nxge_mac_state {
	NXGE_MAC_STOPPED = 0,
	NXGE_MAC_STARTED,
	NXGE_MAC_STOPPING
};

/*
 * Private DLPI full dlsap address format.
 */
typedef struct _nxge_dladdr_t {
	ether_addr_st dl_phys;
	uint16_t dl_sap;
} nxge_dladdr_t, *p_nxge_dladdr_t;

typedef struct _mc_addr_t {
	ether_addr_st multcast_addr;
	uint_t mc_addr_cnt;
} mc_addr_t, *p_mc_addr_t;

typedef struct _mc_bucket_t {
	p_mc_addr_t addr_list;
	uint_t list_size;
} mc_bucket_t, *p_mc_bucket_t;

typedef struct _mc_table_t {
	p_mc_bucket_t bucket_list;
	uint_t buckets_used;
} mc_table_t, *p_mc_table_t;

typedef struct _filter_t {
	uint32_t all_phys_cnt;
	uint32_t all_multicast_cnt;
	uint32_t all_sap_cnt;
} filter_t, *p_filter_t;


typedef struct _nxge_port_stats_t {
	/*
	 *  Overall structure size
	 */
	size_t			stats_size;

	/*
	 * Link Input/Output stats
	 */
	uint64_t		ipackets;
	uint64_t		ierrors;
	uint64_t		opackets;
	uint64_t		oerrors;
	uint64_t		collisions;

	/*
	 * MIB II variables
	 */
	uint64_t		rbytes;    /* # bytes received */
	uint64_t		obytes;    /* # bytes transmitted */
	uint32_t		multircv;  /* # multicast packets received */
	uint32_t		multixmt;  /* # multicast packets for xmit */
	uint32_t		brdcstrcv; /* # broadcast packets received */
	uint32_t		brdcstxmt; /* # broadcast packets for xmit */
	uint32_t		norcvbuf;  /* # rcv packets discarded */
	uint32_t		noxmtbuf;  /* # xmit packets discarded */

	/*
	 * Lets the user know the MTU currently in use by
	 * the physical MAC port.
	 */
	nxge_lb_t		lb_mode;
	uint32_t		qos_mode;
	uint32_t		trunk_mode;
	uint32_t		poll_mode;

	/*
	 * Tx Statistics.
	 */
	uint32_t		tx_inits;
	uint32_t		tx_starts;
	uint32_t		tx_nocanput;
	uint32_t		tx_msgdup_fail;
	uint32_t		tx_allocb_fail;
	uint32_t		tx_no_desc;
	uint32_t		tx_dma_bind_fail;
	uint32_t		tx_uflo;
	uint32_t		tx_hdr_pkts;
	uint32_t		tx_ddi_pkts;
	uint32_t		tx_dvma_pkts;

	uint32_t		tx_max_pend;

	/*
	 * Rx Statistics.
	 */
	uint32_t		rx_inits;
	uint32_t		rx_hdr_pkts;
	uint32_t		rx_mtu_pkts;
	uint32_t		rx_split_pkts;
	uint32_t		rx_no_buf;
	uint32_t		rx_no_comp_wb;
	uint32_t		rx_ov_flow;
	uint32_t		rx_len_mm;
	uint32_t		rx_tag_err;
	uint32_t		rx_nocanput;
	uint32_t		rx_msgdup_fail;
	uint32_t		rx_allocb_fail;

	/*
	 * Receive buffer management statistics.
	 */
	uint32_t		rx_new_pages;
	uint32_t		rx_new_hdr_pgs;
	uint32_t		rx_new_mtu_pgs;
	uint32_t		rx_new_nxt_pgs;
	uint32_t		rx_reused_pgs;
	uint32_t		rx_hdr_drops;
	uint32_t		rx_mtu_drops;
	uint32_t		rx_nxt_drops;

	/*
	 * Receive flow statistics
	 */
	uint32_t		rx_rel_flow;
	uint32_t		rx_rel_bit;

	uint32_t		rx_pkts_dropped;

	/*
	 * PCI-E Bus Statistics.
	 */
	uint32_t		pci_bus_speed;
	uint32_t		pci_err;
	uint32_t		pci_rta_err;
	uint32_t		pci_rma_err;
	uint32_t		pci_parity_err;
	uint32_t		pci_bad_ack_err;
	uint32_t		pci_drto_err;
	uint32_t		pci_dmawz_err;
	uint32_t		pci_dmarz_err;

	uint32_t		rx_taskq_waits;

	uint32_t		tx_jumbo_pkts;

	/*
	 * Some statistics added to support bringup, these
	 * should be removed.
	 */
	uint32_t		user_defined;
} nxge_port_stats_t, *p_nxge_port_stats_t;


typedef struct _nxge_stats_t {
	/*
	 *  Overall structure size
	 */
	size_t			stats_size;

	kstat_t			*ksp;
	kstat_t			*rdc_ksp[NXGE_MAX_RDCS];
	kstat_t			*tdc_ksp[NXGE_MAX_TDCS];
	kstat_t			*rdc_sys_ksp;
	kstat_t			*fflp_ksp[1];
	kstat_t			*ipp_ksp;
	kstat_t			*txc_ksp;
	kstat_t			*mac_ksp;
	kstat_t			*zcp_ksp;
	kstat_t			*port_ksp;
	kstat_t			*mmac_ksp;

	nxge_mac_stats_t	mac_stats;	/* Common MAC Statistics */
	nxge_xmac_stats_t	xmac_stats;	/* XMAC Statistics */
	nxge_bmac_stats_t	bmac_stats;	/* BMAC Statistics */

	nxge_rx_ring_stats_t	rx_stats;	/* per port RX stats */
	nxge_ipp_stats_t	ipp_stats;	/* per port IPP stats */
	nxge_zcp_stats_t	zcp_stats;	/* per port IPP stats */
	nxge_rx_ring_stats_t	rdc_stats[NXGE_MAX_RDCS]; /* per rdc stats */
	nxge_rdc_sys_stats_t	rdc_sys_stats;	/* per port RDC stats */

	nxge_tx_ring_stats_t	tx_stats;	/* per port TX stats */
	nxge_txc_stats_t	txc_stats;	/* per port TX stats */
	nxge_tx_ring_stats_t	tdc_stats[NXGE_MAX_TDCS]; /* per tdc stats */
	nxge_fflp_stats_t	fflp_stats;	/* fflp stats */
	nxge_port_stats_t	port_stats;	/* fflp stats */
	nxge_mmac_stats_t	mmac_stats;	/* Multi mac. stats */

} nxge_stats_t, *p_nxge_stats_t;



typedef struct _nxge_intr_t {
	boolean_t		intr_registered; /* interrupts are registered */
	boolean_t		intr_enabled; 	/* interrupts are enabled */
	boolean_t		niu_msi_enable;	/* debug or configurable? */
	int			intr_types;	/* interrupt types supported */
	int			intr_type;	/* interrupt type to add */
	int			max_int_cnt;	/* max MSIX/INT HW supports */
	int			start_inum;	/* start inum (in sequence?) */
	int			msi_intx_cnt;	/* # msi/intx ints returned */
	int			intr_added;	/* # ints actually needed */
	int			intr_cap;	/* interrupt capabilities */
	size_t			intr_size;	/* size of array to allocate */
	ddi_intr_handle_t 	*htable;	/* For array of interrupts */
	/* Add interrupt number for each interrupt vector */
	int			pri;
} nxge_intr_t, *p_nxge_intr_t;

typedef struct _nxge_ldgv_t {
	uint8_t			ndma_ldvs;
	uint8_t			nldvs;
	uint8_t			maxldgs;
	uint8_t			maxldvs;
	uint8_t			ldg_intrs;
	uint32_t		tmres;
	p_nxge_ldg_t		ldgp;
	p_nxge_ldv_t		ldvp;
	p_nxge_ldv_t		ldvp_syserr;
	boolean_t		ldvp_syserr_alloced;
} nxge_ldgv_t, *p_nxge_ldgv_t;

typedef enum {
	NXGE_TRANSMIT_GROUP,	/* Legacy transmit group */
	NXGE_RECEIVE_GROUP,	/* Legacy receive group */
	NXGE_VR_GROUP,		/* Virtualization Region group */
	EXT_TRANSMIT_GROUP,	/* External (Crossbow) transmit group */
	EXT_RECEIVE_GROUP	/* External (Crossbow) receive group */
} nxge_grp_type_t;

#define	NXGE_ILLEGAL_CHANNEL	(NXGE_MAX_TDCS + 1)

typedef uint8_t nxge_channel_t;

typedef struct nxge_grp {
	nxge_t			*nxge;
	nxge_grp_type_t		type; /* Tx or Rx */

	int			sequence; /* When it was created. */
	int			index; /* nxge_grp_set_t.group[index] */

	struct nx_dc		*dc; /* Linked list of DMA channels. */
	size_t			count; /* A count of <dc> above. */

	boolean_t		active;	/* Is it being used? */

	dc_map_t		map; /* A bitmap of the channels in <dc>. */
	nxge_channel_t		legend[NXGE_MAX_TDCS];

} nxge_grp_t;

typedef struct {
	lg_map_t		map;
	size_t			count;
} lg_data_t;

typedef struct {
	dc_map_t		map;
	size_t			count;
} dc_data_t;

#define	NXGE_DC_SET(map, channel)	map |= (1 << channel)
#define	NXGE_DC_RESET(map, channel)	map &= (~(1 << channel))

/* For now, we only support up to 8 RDC/TDC groups */
#define	NXGE_LOGICAL_GROUP_MAX	NXGE_MAX_RDC_GROUPS

typedef struct {
	int			sequence; /* To order groups in time. */

	/* These are this instance's logical groups. */
	nxge_grp_t		*group[NXGE_LOGICAL_GROUP_MAX];
	lg_data_t		lg;

	dc_data_t		shared;	/* These DCs are being shared. */
	dc_data_t		owned; /* These DCs belong to me. */
	dc_data_t		dead; /* These DCs are in an error state. */

} nxge_grp_set_t;

/*
 * Transmit Ring Group
 * TX groups will be used exclusively for the purpose of Hybrid I/O.  From
 * the point of view of the nxge driver, the groups will be software
 * constructs which will be used to establish the relationship between TX
 * rings and shares.
 *
 * Receive Ring Group
 * One of the advanced virtualization features is the ability to bundle
 * multiple Receive Rings in a single group.  One or more MAC addresses may
 * be assigned to a group.  Incoming packets destined to the group's MAC
 * address(es) are delivered to any ring member, according to a programmable
 * or predefined RTS policy.  Member rings can be polled individually.
 * RX ring groups can come with a predefined set of member rings, or they
 * are programmable by adding and removing rings to/from them.
 */
typedef struct _nxge_ring_group_t {
	mac_group_handle_t	ghandle;
	p_nxge_t		nxgep;
	boolean_t		started;
	boolean_t		port_default_grp;
	mac_ring_type_t		type;
	int			gindex;
	int			sindex;
	int			rdctbl;
	int			n_mac_addrs;
} nxge_ring_group_t;

/*
 * Ring Handle
 */
typedef struct _nxge_ring_handle_t {
	p_nxge_t		nxgep;
	int			index;		/* port-wise */
	mac_ring_handle_t	ring_handle;
	uint64_t		ring_gen_num;	/* For RX Ring Start */
	uint32_t		channel;
} nxge_ring_handle_t, *p_nxge_ring_handle_t;

/*
 * Share Handle
 */
typedef struct _nxge_share_handle_t {
	p_nxge_t		nxgep;		/* Driver Handle */
	int			index;
	void			*vrp;
	uint64_t		tmap;
	uint64_t		rmap;
	int			rxgroup;
	boolean_t		active;
} nxge_share_handle_t;

/*
 * Neptune Device instance state information.
 *
 * Each instance is dynamically allocated on first attach.
 */
struct _nxge_t {
	dev_info_t		*dip;		/* device instance */
	dev_info_t		*p_dip;		/* Parent's device instance */
	int			instance;	/* instance number */
	int			function_num;	/* device function number */
	int			nports;		/* # of ports on this device */
	int			board_ver;	/* Board Version */
	int			use_partition;	/* partition is enabled */
	uint32_t		drv_state;	/* driver state bit flags */
	uint64_t		nxge_debug_level; /* driver state bit flags */
	kmutex_t		genlock[1];
	enum nxge_mac_state	nxge_mac_state;

	p_dev_regs_t		dev_regs;
	npi_handle_t		npi_handle;
	npi_handle_t		npi_pci_handle;
	npi_handle_t		npi_reg_handle;
	npi_handle_t		npi_msi_handle;
	npi_handle_t		npi_vreg_handle;
	npi_handle_t		npi_v2reg_handle;

	nxge_xcvr_table_t	xcvr;
	boolean_t		hot_swappable_phy;
	boolean_t		phy_absent;
	uint32_t		xcvr_addr;
	uint16_t		chip_id;
	nxge_nlp_conn_t		nlp_conn;
	nxge_phy_prop_t		phy_prop;
	nxge_serdes_prop_t	srds_prop;

	nxge_mac_t		mac;
	nxge_ipp_t		ipp;
	nxge_txc_t		txc;
	nxge_classify_t		classifier;

	mac_handle_t		mach;	/* mac module handle */
	p_nxge_stats_t		statsp;
	uint32_t		param_count;
	p_nxge_param_t		param_arr;

	uint32_t		param_en_pause:1,
				param_en_asym_pause:1,
				param_en_1000fdx:1,
				param_en_100fdx:1,
				param_en_10fdx:1,
				param_pad_to_32:27;

	nxge_hw_list_t		*nxge_hw_p; 	/* pointer to per Neptune */
	niu_type_t		niu_type;
	platform_type_t		platform_type;
	boolean_t		os_addr_mode32;	/* set to 1 for 32 bit mode */

	uint8_t			def_rdc;

	nxge_intr_t		nxge_intr_type;
	nxge_dma_pt_cfg_t 	pt_config;
	nxge_class_pt_cfg_t 	class_config;

	/* Logical device and group data structures. */
	p_nxge_ldgv_t		ldgvp;

	npi_vpd_info_t		vpd_info;

	ether_addr_st		factaddr;	/* factory mac address	    */
	ether_addr_st		ouraddr;	/* individual address	    */
	boolean_t		primary;	/* primary addr set?.	    */
	kmutex_t		ouraddr_lock;	/* lock to protect to uradd */

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
	nxge_rx_block_size_t	rx_bksize_code;

	p_nxge_dma_pool_t	rx_buf_pool_p;
	p_nxge_dma_pool_t	rx_cntl_pool_p;

	p_nxge_dma_pool_t	tx_buf_pool_p;
	p_nxge_dma_pool_t	tx_cntl_pool_p;

	/* Receive buffer block ring and completion ring. */
	p_rx_rbr_rings_t 	rx_rbr_rings;
	p_rx_rcr_rings_t 	rx_rcr_rings;
	p_rx_mbox_areas_t 	rx_mbox_areas_p;

	uint32_t		rdc_mask;

	/* Transmit descriptors rings */
	p_tx_rings_t 		tx_rings;
	p_tx_mbox_areas_t	tx_mbox_areas_p;

	ddi_dma_handle_t 	dmasparehandle;

	ulong_t 		sys_page_sz;
	ulong_t 		sys_page_mask;
	int 			suspended;

	mii_bmsr_t 		bmsr;		/* xcvr status at last poll. */
	mii_bmsr_t 		soft_bmsr;	/* xcvr status kept by SW. */

	kmutex_t 		mif_lock;	/* Lock to protect the list. */

	void 			(*mii_read)();
	void 			(*mii_write)();
	void 			(*mii_poll)();
	filter_t 		filter;		/* Current instance filter */
	p_hash_filter_t 	hash_filter;	/* Multicast hash filter. */
	krwlock_t		filter_lock;	/* Lock to protect filters. */

	ulong_t 		sys_burst_sz;

	uint8_t 		cache_line;

	timeout_id_t 		nxge_link_poll_timerid;
	timeout_id_t 		nxge_timerid;

	uint_t 			need_periodic_reclaim;
	timeout_id_t 		reclaim_timer;

	uint8_t 		msg_min;
	uint8_t 		crc_size;

	boolean_t 		hard_props_read;

	uint32_t 		nxge_ncpus;
	uint16_t 		intr_timeout;
	uint16_t 		intr_threshold;

	int			fm_capabilities; /* FMA capabilities */

	uint32_t 		nxge_port_rbr_size;
	uint32_t 		nxge_port_rbr_spare_size;
	uint32_t 		nxge_port_rcr_size;
	uint32_t		nxge_port_rx_cntl_alloc_size;
	uint32_t 		nxge_port_tx_ring_size;
	nxge_mmac_t		nxge_mmac_info;
#if	defined(sun4v)
	boolean_t		niu_hsvc_available;
	hsvc_info_t		niu_hsvc;
	uint64_t		niu_min_ver;
#endif
	boolean_t		link_notify;
	int			link_check_count;

	kmutex_t		poll_lock;
	kcondvar_t		poll_cv;
	link_mon_enable_t	poll_state;
#define	NXGE_MAGIC		0x3ab434e3
	uint32_t		nxge_magic;

	int			soft_lso_enable;
	/* The following fields are LDOMs-specific additions. */
	nxge_environs_t		environs;
	ether_addr_t		hio_mac_addr;
	uint32_t		niu_cfg_hdl;
	kmutex_t		group_lock;

	struct nxge_hio_vr	*hio_vr;

	nxge_grp_set_t		rx_set;
	nxge_grp_set_t		tx_set;
	boolean_t		tdc_is_shared[NXGE_MAX_TDCS];

	/* Ring Handles */
	nxge_ring_handle_t	tx_ring_handles[NXGE_MAX_TDCS];
	nxge_ring_handle_t	rx_ring_handles[NXGE_MAX_RDCS];

	nxge_ring_group_t	tx_hio_groups[NXGE_MAX_TDC_GROUPS];
	nxge_ring_group_t	rx_hio_groups[NXGE_MAX_RDC_GROUPS];

	nxge_share_handle_t	shares[NXGE_MAX_VRS];

	/*
	 * KT-NIU:
	 *	KT family will have up to 4 NIUs per system.
	 *	Differences between N2/NIU and KT/NIU:
	 *		SerDes, Hypervisor interfaces,
	 *		additional NIU classification features.
	 */
	niu_hw_type_t		niu_hw_type;
};

/*
 * Driver state flags.
 */
#define	STATE_REGS_MAPPED	0x000000001	/* device registers mapped */
#define	STATE_KSTATS_SETUP	0x000000002	/* kstats allocated	*/
#define	STATE_NODE_CREATED	0x000000004	/* device node created	*/
#define	STATE_HW_CONFIG_CREATED	0x000000008	/* hardware properties	*/
#define	STATE_HW_INITIALIZED	0x000000010	/* hardware initialized	*/
#define	STATE_MDIO_LOCK_INIT	0x000000020	/* mdio lock initialized */
#define	STATE_MII_LOCK_INIT	0x000000040	/* mii lock initialized */

#define	STOP_POLL_THRESH 	9
#define	START_POLL_THRESH	2

typedef struct _nxge_port_kstat_t {
	/*
	 * Transciever state informations.
	 */
	kstat_named_t	xcvr_inits;
	kstat_named_t	xcvr_inuse;
	kstat_named_t	xcvr_addr;
	kstat_named_t	xcvr_id;
	kstat_named_t	cap_autoneg;
	kstat_named_t	cap_10gfdx;
	kstat_named_t	cap_10ghdx;
	kstat_named_t	cap_1000fdx;
	kstat_named_t	cap_1000hdx;
	kstat_named_t	cap_100T4;
	kstat_named_t	cap_100fdx;
	kstat_named_t	cap_100hdx;
	kstat_named_t	cap_10fdx;
	kstat_named_t	cap_10hdx;
	kstat_named_t	cap_asmpause;
	kstat_named_t	cap_pause;

	/*
	 * Link partner capabilities.
	 */
	kstat_named_t	lp_cap_autoneg;
	kstat_named_t	lp_cap_10gfdx;
	kstat_named_t	lp_cap_10ghdx;
	kstat_named_t	lp_cap_1000fdx;
	kstat_named_t	lp_cap_1000hdx;
	kstat_named_t	lp_cap_100T4;
	kstat_named_t	lp_cap_100fdx;
	kstat_named_t	lp_cap_100hdx;
	kstat_named_t	lp_cap_10fdx;
	kstat_named_t	lp_cap_10hdx;
	kstat_named_t	lp_cap_asmpause;
	kstat_named_t	lp_cap_pause;

	/*
	 * Shared link setup.
	 */
	kstat_named_t	link_T4;
	kstat_named_t	link_speed;
	kstat_named_t	link_duplex;
	kstat_named_t	link_asmpause;
	kstat_named_t	link_pause;
	kstat_named_t	link_up;

	/*
	 * Lets the user know the MTU currently in use by
	 * the physical MAC port.
	 */
	kstat_named_t	mac_mtu;
	kstat_named_t	lb_mode;
	kstat_named_t	qos_mode;
	kstat_named_t	trunk_mode;

	/*
	 * Misc MAC statistics.
	 */
	kstat_named_t	ifspeed;
	kstat_named_t	promisc;
	kstat_named_t	rev_id;

	/*
	 * Some statistics added to support bringup, these
	 * should be removed.
	 */
	kstat_named_t	user_defined;
} nxge_port_kstat_t, *p_nxge_port_kstat_t;

typedef struct _nxge_rdc_kstat {
	/*
	 * Receive DMA channel statistics.
	 */
	kstat_named_t	ipackets;
	kstat_named_t	rbytes;
	kstat_named_t	errors;
	kstat_named_t	dcf_err;
	kstat_named_t	rcr_ack_err;

	kstat_named_t	dc_fifoflow_err;
	kstat_named_t	rcr_sha_par_err;
	kstat_named_t	rbr_pre_par_err;
	kstat_named_t	wred_drop;
	kstat_named_t	rbr_pre_emty;

	kstat_named_t	rcr_shadow_full;
	kstat_named_t	rbr_tmout;
	kstat_named_t	rsp_cnt_err;
	kstat_named_t	byte_en_bus;
	kstat_named_t	rsp_dat_err;

	kstat_named_t	pkt_too_long_err;
	kstat_named_t	compl_l2_err;
	kstat_named_t	compl_l4_cksum_err;
	kstat_named_t	compl_zcp_soft_err;
	kstat_named_t	compl_fflp_soft_err;
	kstat_named_t	config_err;

	kstat_named_t	rcrincon;
	kstat_named_t	rcrfull;
	kstat_named_t	rbr_empty;
	kstat_named_t	rbrfull;
	kstat_named_t	rbrlogpage;

	kstat_named_t	cfiglogpage;
	kstat_named_t	port_drop_pkt;
	kstat_named_t	rcr_to;
	kstat_named_t	rcr_thresh;
	kstat_named_t	rcr_mex;
	kstat_named_t	id_mismatch;
	kstat_named_t	zcp_eop_err;
	kstat_named_t	ipp_eop_err;
} nxge_rdc_kstat_t, *p_nxge_rdc_kstat_t;

typedef struct _nxge_rdc_sys_kstat {
	/*
	 * Receive DMA system statistics.
	 */
	kstat_named_t	pre_par;
	kstat_named_t	sha_par;
	kstat_named_t	id_mismatch;
	kstat_named_t	ipp_eop_err;
	kstat_named_t	zcp_eop_err;
} nxge_rdc_sys_kstat_t, *p_nxge_rdc_sys_kstat_t;

typedef	struct _nxge_tdc_kstat {
	/*
	 * Transmit DMA channel statistics.
	 */
	kstat_named_t	opackets;
	kstat_named_t	obytes;
	kstat_named_t	oerrors;
	kstat_named_t	tx_inits;
	kstat_named_t	tx_no_buf;

	kstat_named_t	mbox_err;
	kstat_named_t	pkt_size_err;
	kstat_named_t	tx_ring_oflow;
	kstat_named_t	pref_buf_ecc_err;
	kstat_named_t	nack_pref;
	kstat_named_t	nack_pkt_rd;
	kstat_named_t	conf_part_err;
	kstat_named_t	pkt_prt_err;
	kstat_named_t	reset_fail;
/* used to in the common (per port) counter */

	kstat_named_t	tx_starts;
	kstat_named_t	tx_nocanput;
	kstat_named_t	tx_msgdup_fail;
	kstat_named_t	tx_allocb_fail;
	kstat_named_t	tx_no_desc;
	kstat_named_t	tx_dma_bind_fail;
	kstat_named_t	tx_uflo;
	kstat_named_t	tx_hdr_pkts;
	kstat_named_t	tx_ddi_pkts;
	kstat_named_t	tx_dvma_pkts;
	kstat_named_t	tx_max_pend;
} nxge_tdc_kstat_t, *p_nxge_tdc_kstat_t;

typedef	struct _nxge_txc_kstat {
	/*
	 * Transmit port TXC block statistics.
	 */
	kstat_named_t	pkt_stuffed;
	kstat_named_t	pkt_xmit;
	kstat_named_t	ro_correct_err;
	kstat_named_t	ro_uncorrect_err;
	kstat_named_t	sf_correct_err;
	kstat_named_t	sf_uncorrect_err;
	kstat_named_t	address_failed;
	kstat_named_t	dma_failed;
	kstat_named_t	length_failed;
	kstat_named_t	pkt_assy_dead;
	kstat_named_t	reorder_err;
} nxge_txc_kstat_t, *p_nxge_txc_kstat_t;

typedef struct _nxge_ipp_kstat {
	/*
	 * Receive port IPP block statistics.
	 */
	kstat_named_t	eop_miss;
	kstat_named_t	sop_miss;
	kstat_named_t	dfifo_ue;
	kstat_named_t	ecc_err_cnt;
	kstat_named_t	pfifo_perr;
	kstat_named_t	pfifo_over;
	kstat_named_t	pfifo_und;
	kstat_named_t	bad_cs_cnt;
	kstat_named_t	pkt_dis_cnt;
} nxge_ipp_kstat_t, *p_nxge_ipp_kstat_t;

typedef	struct _nxge_zcp_kstat {
	/*
	 * ZCP statistics.
	 */
	kstat_named_t	errors;
	kstat_named_t	inits;
	kstat_named_t	rrfifo_underrun;
	kstat_named_t	rrfifo_overrun;
	kstat_named_t	rspfifo_uncorr_err;
	kstat_named_t	buffer_overflow;
	kstat_named_t	stat_tbl_perr;
	kstat_named_t	dyn_tbl_perr;
	kstat_named_t	buf_tbl_perr;
	kstat_named_t	tt_program_err;
	kstat_named_t	rsp_tt_index_err;
	kstat_named_t	slv_tt_index_err;
	kstat_named_t	zcp_tt_index_err;
	kstat_named_t	access_fail;
	kstat_named_t	cfifo_ecc;
} nxge_zcp_kstat_t, *p_nxge_zcp_kstat_t;

typedef	struct _nxge_mac_kstat {
	/*
	 * Transmit MAC statistics.
	 */
	kstat_named_t	tx_frame_cnt;
	kstat_named_t	tx_underflow_err;
	kstat_named_t	tx_overflow_err;
	kstat_named_t	tx_maxpktsize_err;
	kstat_named_t	tx_fifo_xfr_err;
	kstat_named_t	tx_byte_cnt;

	/*
	 * Receive MAC statistics.
	 */
	kstat_named_t	rx_frame_cnt;
	kstat_named_t	rx_underflow_err;
	kstat_named_t	rx_overflow_err;
	kstat_named_t	rx_len_err_cnt;
	kstat_named_t	rx_crc_err_cnt;
	kstat_named_t	rx_viol_err_cnt;
	kstat_named_t	rx_byte_cnt;
	kstat_named_t	rx_hist1_cnt;
	kstat_named_t	rx_hist2_cnt;
	kstat_named_t	rx_hist3_cnt;
	kstat_named_t	rx_hist4_cnt;
	kstat_named_t	rx_hist5_cnt;
	kstat_named_t	rx_hist6_cnt;
	kstat_named_t	rx_hist7_cnt;
	kstat_named_t	rx_broadcast_cnt;
	kstat_named_t	rx_mult_cnt;
	kstat_named_t	rx_frag_cnt;
	kstat_named_t	rx_frame_align_err_cnt;
	kstat_named_t	rx_linkfault_err_cnt;
	kstat_named_t	rx_local_fault_err_cnt;
	kstat_named_t	rx_remote_fault_err_cnt;
} nxge_mac_kstat_t, *p_nxge_mac_kstat_t;

typedef	struct _nxge_xmac_kstat {
	/*
	 * XMAC statistics.
	 */
	kstat_named_t	tx_frame_cnt;
	kstat_named_t	tx_underflow_err;
	kstat_named_t	tx_maxpktsize_err;
	kstat_named_t	tx_overflow_err;
	kstat_named_t	tx_fifo_xfr_err;
	kstat_named_t	tx_byte_cnt;
	kstat_named_t	rx_frame_cnt;
	kstat_named_t	rx_underflow_err;
	kstat_named_t	rx_overflow_err;
	kstat_named_t	rx_crc_err_cnt;
	kstat_named_t	rx_len_err_cnt;
	kstat_named_t	rx_viol_err_cnt;
	kstat_named_t	rx_byte_cnt;
	kstat_named_t	rx_hist1_cnt;
	kstat_named_t	rx_hist2_cnt;
	kstat_named_t	rx_hist3_cnt;
	kstat_named_t	rx_hist4_cnt;
	kstat_named_t	rx_hist5_cnt;
	kstat_named_t	rx_hist6_cnt;
	kstat_named_t	rx_hist7_cnt;
	kstat_named_t	rx_broadcast_cnt;
	kstat_named_t	rx_mult_cnt;
	kstat_named_t	rx_frag_cnt;
	kstat_named_t	rx_frame_align_err_cnt;
	kstat_named_t	rx_linkfault_err_cnt;
	kstat_named_t	rx_remote_fault_err_cnt;
	kstat_named_t	rx_local_fault_err_cnt;
	kstat_named_t	rx_pause_cnt;
	kstat_named_t	xpcs_deskew_err_cnt;
	kstat_named_t	xpcs_ln0_symbol_err_cnt;
	kstat_named_t	xpcs_ln1_symbol_err_cnt;
	kstat_named_t	xpcs_ln2_symbol_err_cnt;
	kstat_named_t	xpcs_ln3_symbol_err_cnt;
} nxge_xmac_kstat_t, *p_nxge_xmac_kstat_t;

typedef	struct _nxge_bmac_kstat {
	/*
	 * BMAC statistics.
	 */
	kstat_named_t tx_frame_cnt;
	kstat_named_t tx_underrun_err;
	kstat_named_t tx_max_pkt_err;
	kstat_named_t tx_byte_cnt;
	kstat_named_t rx_frame_cnt;
	kstat_named_t rx_byte_cnt;
	kstat_named_t rx_overflow_err;
	kstat_named_t rx_align_err_cnt;
	kstat_named_t rx_crc_err_cnt;
	kstat_named_t rx_len_err_cnt;
	kstat_named_t rx_viol_err_cnt;
	kstat_named_t rx_pause_cnt;
	kstat_named_t tx_pause_state;
	kstat_named_t tx_nopause_state;
} nxge_bmac_kstat_t, *p_nxge_bmac_kstat_t;


typedef struct _nxge_fflp_kstat {
	/*
	 * FFLP statistics.
	 */

	kstat_named_t	fflp_tcam_perr;
	kstat_named_t	fflp_tcam_ecc_err;
	kstat_named_t	fflp_vlan_perr;
	kstat_named_t	fflp_hasht_lookup_err;
	kstat_named_t	fflp_hasht_data_err[MAX_PARTITION];
} nxge_fflp_kstat_t, *p_nxge_fflp_kstat_t;

typedef struct _nxge_mmac_kstat {
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
} nxge_mmac_kstat_t, *p_nxge_mmac_kstat_t;

/*
 * Prototype definitions.
 */
nxge_status_t nxge_init(p_nxge_t);
void nxge_uninit(p_nxge_t);
void nxge_get64(p_nxge_t, p_mblk_t);
void nxge_put64(p_nxge_t, p_mblk_t);
void nxge_pio_loop(p_nxge_t, p_mblk_t);

typedef	void	(*fptrv_t)();
timeout_id_t	nxge_start_timer(p_nxge_t, fptrv_t, int);
void		nxge_stop_timer(p_nxge_t, timeout_id_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_H */
