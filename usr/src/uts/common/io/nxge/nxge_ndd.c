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

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_hio.h>

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>

extern uint64_t npi_debug_level;

#define	NXGE_PARAM_MAC_RW \
	NXGE_PARAM_RW | NXGE_PARAM_MAC | \
	NXGE_PARAM_NDD_WR_OK | NXGE_PARAM_READ_PROP

#define	NXGE_PARAM_MAC_DONT_SHOW \
	NXGE_PARAM_RW | NXGE_PARAM_MAC | NXGE_PARAM_DONT_SHOW

#define	NXGE_PARAM_RXDMA_RW \
	NXGE_PARAM_RWP | NXGE_PARAM_RXDMA | NXGE_PARAM_NDD_WR_OK | \
	NXGE_PARAM_READ_PROP

#define	NXGE_PARAM_RXDMA_RWC \
	NXGE_PARAM_RWP | NXGE_PARAM_RXDMA | NXGE_PARAM_INIT_ONLY | \
	NXGE_PARAM_READ_PROP

#define	NXGE_PARAM_L2CLASS_CFG \
	NXGE_PARAM_RW | NXGE_PARAM_PROP_ARR32 | NXGE_PARAM_READ_PROP | \
	NXGE_PARAM_NDD_WR_OK

#define	NXGE_PARAM_CLASS_RWS \
	NXGE_PARAM_RWS |  NXGE_PARAM_READ_PROP

#define	NXGE_PARAM_ARRAY_INIT_SIZE	0x20ULL

#define	SET_RX_INTR_TIME_DISABLE 0
#define	SET_RX_INTR_TIME_ENABLE 1
#define	SET_RX_INTR_PKTS 2

#define	BASE_ANY	0
#define	BASE_BINARY 	2
#define	BASE_HEX	16
#define	BASE_DECIMAL	10
#define	ALL_FF_64	0xFFFFFFFFFFFFFFFFULL
#define	ALL_FF_32	0xFFFFFFFFUL

#define	NXGE_NDD_INFODUMP_BUFF_SIZE	2048 /* is 2k enough? */
#define	NXGE_NDD_INFODUMP_BUFF_8K	8192
#define	NXGE_NDD_INFODUMP_BUFF_16K	0x2000
#define	NXGE_NDD_INFODUMP_BUFF_64K	0x8000

#define	PARAM_OUTOF_RANGE(vptr, eptr, rval, pa)	\
	((vptr == eptr) || (rval < pa->minimum) || (rval > pa->maximum))

#define	ADVANCE_PRINT_BUFFER(pmp, plen, rlen) { \
	((mblk_t *)pmp)->b_wptr += plen; \
	rlen -= plen; \
}

int nxge_param_set_mac(p_nxge_t, queue_t *,
	mblk_t *, char *, caddr_t);
static int nxge_param_set_port_rdc(p_nxge_t, queue_t *,
	mblk_t *, char *, caddr_t);
static int nxge_param_set_grp_rdc(p_nxge_t, queue_t *,
	mblk_t *, char *, caddr_t);
static int nxge_param_set_ether_usr(p_nxge_t,
	queue_t *, mblk_t *, char *, caddr_t);
static int nxge_param_set_ip_usr(p_nxge_t,
	queue_t *, mblk_t *, char *, caddr_t);
static int nxge_param_set_vlan_rdcgrp(p_nxge_t,
	queue_t *, mblk_t *, char *, caddr_t);
static int nxge_param_set_mac_rdcgrp(p_nxge_t,
	queue_t *, mblk_t *, char *, caddr_t);
static int nxge_param_fflp_hash_init(p_nxge_t,
	queue_t *, mblk_t *, char *, caddr_t);
static int nxge_param_llc_snap_enable(p_nxge_t, queue_t *,
	mblk_t *, char *, caddr_t);
static int nxge_param_hash_lookup_enable(p_nxge_t, queue_t *,
	mblk_t *, char *, caddr_t);
static int nxge_param_tcam_enable(p_nxge_t, queue_t *,
	mblk_t *, char *, caddr_t);
static int nxge_param_get_fw_ver(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_get_port_mode(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_get_rxdma_info(p_nxge_t, queue_t *q,
	p_mblk_t, caddr_t);
static int nxge_param_get_txdma_info(p_nxge_t, queue_t *q,
	p_mblk_t, caddr_t);
static int nxge_param_get_vlan_rdcgrp(p_nxge_t, queue_t *,
	p_mblk_t, caddr_t);
static int nxge_param_get_mac_rdcgrp(p_nxge_t, queue_t *,
	p_mblk_t, caddr_t);
static int nxge_param_get_rxdma_rdcgrp_info(p_nxge_t, queue_t *,
	p_mblk_t, caddr_t);
static int nxge_param_get_rx_intr_time(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_get_rx_intr_pkts(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_get_ip_opt(p_nxge_t, queue_t *, mblk_t *, caddr_t);
static int nxge_param_get_mac(p_nxge_t, queue_t *q, p_mblk_t, caddr_t);
static int nxge_param_get_debug_flag(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_set_nxge_debug_flag(p_nxge_t, queue_t *, mblk_t *,
	char *, caddr_t);
static int nxge_param_set_npi_debug_flag(p_nxge_t,
	queue_t *, mblk_t *, char *, caddr_t);
static int nxge_param_dump_rdc(p_nxge_t, queue_t *q, p_mblk_t, caddr_t);
static int nxge_param_dump_tdc(p_nxge_t, queue_t *q, p_mblk_t, caddr_t);
static int nxge_param_dump_mac_regs(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_dump_ipp_regs(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_dump_fflp_regs(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_dump_vlan_table(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_dump_rdc_table(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static int nxge_param_dump_ptrs(p_nxge_t, queue_t *, p_mblk_t, caddr_t);
static void nxge_param_sync(p_nxge_t);

/*
 * Global array of Neptune changable parameters.
 * This array is initialized to correspond to the default
 * Neptune 4 port configuration. This array would be copied
 * into each port's parameter structure and modifed per
 * fcode and nxge.conf configuration. Later, the parameters are
 * exported to ndd to display and run-time configuration (at least
 * some of them).
 *
 * Parameters with DONT_SHOW are not shown by ndd.
 *
 */

static nxge_param_t	nxge_param_arr[] = {
	/*
	 * min	max	value	old	hw-name	conf-name
	 */
	{ nxge_param_get_generic, NULL, NXGE_PARAM_DONT_SHOW,
		0, 999, 1000, 0, "instance", "instance"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_DONT_SHOW,
		0, 999, 1000, 0, "main-instance", "main_instance"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ,
		0, 3, 0, 0, "function-number", "function_number"},

	/* Partition Id */
	{ nxge_param_get_generic, NULL, NXGE_PARAM_DONT_SHOW,
		0, 8, 0, 0, "partition-id", "partition_id"},

	/* Read Write Permission Mode */
	{ nxge_param_get_generic, NULL, NXGE_PARAM_DONT_SHOW,
		0, 2, 0, 0, "read-write-mode", "read_write_mode"},

	{ nxge_param_get_fw_ver, NULL, NXGE_PARAM_READ,
		0, 32, 0, 0, "version",	"fw_version"},

	{ nxge_param_get_port_mode, NULL, NXGE_PARAM_READ,
		0, 32, 0, 0, "port-mode", "port_mode"},

	/* hw cfg types */
	/* control the DMA config of Neptune/NIU */
	{ nxge_param_get_generic, NULL, NXGE_PARAM_DONT_SHOW,
		CFG_DEFAULT, CFG_CUSTOM, CFG_DEFAULT, CFG_DEFAULT,
		"niu-cfg-type", "niu_cfg_type"},

	/* control the TXDMA config of the Port controlled by tx-quick-cfg */
	{ nxge_param_get_generic, NULL, NXGE_PARAM_DONT_SHOW,
		CFG_DEFAULT, CFG_CUSTOM, CFG_NOT_SPECIFIED, CFG_DEFAULT,
		"tx-qcfg-type", "tx_qcfg_type"},

	/* control the RXDMA config of the Port controlled by rx-quick-cfg */
	{ nxge_param_get_generic, NULL, NXGE_PARAM_DONT_SHOW,
		CFG_DEFAULT, CFG_CUSTOM, CFG_NOT_SPECIFIED, CFG_DEFAULT,
		"rx-qcfg-type", "rx_qcfg_type"},

	{ nxge_param_get_mac, nxge_param_set_mac,
		NXGE_PARAM_RW  | NXGE_PARAM_DONT_SHOW,
		0, 1, 0, 0, "master-cfg-enable", "master_cfg_enable"},

	{ nxge_param_get_mac, nxge_param_set_mac,
		NXGE_PARAM_DONT_SHOW,
		0, 1, 0, 0, "master-cfg-value", "master_cfg_value"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_RW,
		0, 1, 1, 1, "adv-autoneg-cap", "adv_autoneg_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_RW,
		0, 1, 1, 1, "adv-10gfdx-cap", "adv_10gfdx_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_DONT_SHOW,
		0, 1, 0, 0, "adv-10ghdx-cap", "adv_10ghdx_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_RW,
		0, 1, 1, 1, "adv-1000fdx-cap", "adv_1000fdx_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_DONT_SHOW,
		0, 1, 0, 0, "adv-1000hdx-cap",	"adv_1000hdx_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_DONT_SHOW,
		0, 1, 0, 0, "adv-100T4-cap", "adv_100T4_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_RW,
		0, 1, 1, 1, "adv-100fdx-cap", "adv_100fdx_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_DONT_SHOW,
		0, 1, 0, 0, "adv-100hdx-cap", "adv_100hdx_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_RW,
		0, 1, 1, 1, "adv-10fdx-cap", "adv_10fdx_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_DONT_SHOW,
		0, 1, 0, 0, "adv-10hdx-cap", "adv_10hdx_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_DONT_SHOW,
		0, 1, 0, 0, "adv-asmpause-cap",	"adv_asmpause_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_MAC_RW,
		0, 1, 0, 0, "adv-pause-cap", "adv_pause_cap"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_DONT_SHOW,
		0, 1, 0, 0, "use-int-xcvr", "use_int_xcvr"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_DONT_SHOW,
		0, 1, 1, 1, "enable-ipg0", "enable_ipg0"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_DONT_SHOW,
		0, 255,	8, 8, "ipg0", "ipg0"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_DONT_SHOW,
		0, 255,	8, 8, "ipg1", "ipg1"},

	{ nxge_param_get_mac, nxge_param_set_mac, NXGE_PARAM_DONT_SHOW,
		0, 255,	4, 4, "ipg2", "ipg2"},

	/* Transmit DMA channels */
	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_READ_PROP | NXGE_PARAM_DONT_SHOW,
		0, 3, 0, 0, "tx-dma-weight", "tx_dma_weight"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_READ_PROP | NXGE_PARAM_DONT_SHOW,
		0, 31, 0, 0, "tx-dma-channels-begin", "tx_dma_channels_begin"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_READ_PROP | NXGE_PARAM_DONT_SHOW,
		0, 32, 0, 0, "tx-dma-channels", "tx_dma_channels"},
	{ nxge_param_get_txdma_info, NULL,
		NXGE_PARAM_READ | NXGE_PARAM_READ_PROP | NXGE_PARAM_DONT_SHOW,
		0, 32, 0, 0, "tx-dma-info", "tx_dma_info"},

	/* Receive DMA channels */
	{ nxge_param_get_generic, NULL,
		NXGE_PARAM_READ | NXGE_PARAM_READ_PROP | NXGE_PARAM_DONT_SHOW,
		0, 31, 0, 0, "rx-dma-channels-begin", "rx_dma_channels_begin"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_READ_PROP | NXGE_PARAM_DONT_SHOW,
		0, 32, 0, 0, "rx-dma-channels",	"rx_dma_channels"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_READ_PROP | NXGE_PARAM_DONT_SHOW,
		0, 65535, PT_DRR_WT_DEFAULT_10G, 0,
		"rx-drr-weight", "rx_drr_weight"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_READ_PROP | NXGE_PARAM_DONT_SHOW,
		0, 1, 1, 0, "rx-full-header", "rx_full_header"},

	{ nxge_param_get_rxdma_info, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_DONT_SHOW,
		0, 32, 0, 0, "rx-dma-info", "rx_dma_info"},

	{ nxge_param_get_rxdma_info, NULL,
		NXGE_PARAM_READ | NXGE_PARAM_DONT_SHOW,
		NXGE_RBR_RBB_MIN, NXGE_RBR_RBB_MAX, NXGE_RBR_RBB_DEFAULT, 0,
		"rx-rbr-size", "rx_rbr_size"},

	{ nxge_param_get_rxdma_info, NULL,
		NXGE_PARAM_READ | NXGE_PARAM_DONT_SHOW,
		NXGE_RCR_MIN, NXGE_RCR_MAX, NXGE_RCR_DEFAULT, 0,
		"rx-rcr-size", "rx_rcr_size"},

	{ nxge_param_get_generic, nxge_param_set_port_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15, 0, 0, "default-port-rdc", "default_port_rdc"},

	{ nxge_param_get_rx_intr_time, nxge_param_rx_intr_time,
		NXGE_PARAM_RXDMA_RW,
		NXGE_RDC_RCR_TIMEOUT_MIN, NXGE_RDC_RCR_TIMEOUT_MAX,
		NXGE_RDC_RCR_TIMEOUT, 0, "rxdma-intr-time", "rxdma_intr_time"},

	{ nxge_param_get_rx_intr_pkts, nxge_param_rx_intr_pkts,
		NXGE_PARAM_RXDMA_RW,
		NXGE_RDC_RCR_THRESHOLD_MIN, NXGE_RDC_RCR_THRESHOLD_MAX,
		NXGE_RDC_RCR_THRESHOLD, 0,
		"rxdma-intr-pkts", "rxdma_intr_pkts"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ_PROP |
		NXGE_PARAM_DONT_SHOW,
		0, 8, 0, 0, "rx-rdc-grps-begin", "rx_rdc_grps_begin"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ_PROP |
		NXGE_PARAM_DONT_SHOW,
		0, 8, 0, 0, "rx-rdc-grps", "rx_rdc_grps"},

	{ nxge_param_get_generic, nxge_param_set_grp_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15, 0, 0, "default-grp0-rdc", "default_grp0_rdc"},

	{ nxge_param_get_generic, nxge_param_set_grp_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15,	2, 0, "default-grp1-rdc", "default_grp1_rdc"},

	{ nxge_param_get_generic, nxge_param_set_grp_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15, 4, 0, "default-grp2-rdc", "default_grp2_rdc"},

	{ nxge_param_get_generic, nxge_param_set_grp_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15, 6, 0, "default-grp3-rdc", "default_grp3_rdc"},

	{ nxge_param_get_generic, nxge_param_set_grp_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15, 8, 0, "default-grp4-rdc", "default_grp4_rdc"},

	{ nxge_param_get_generic, nxge_param_set_grp_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15, 10, 0, "default-grp5-rdc", "default_grp5_rdc"},

	{ nxge_param_get_generic, nxge_param_set_grp_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15, 12, 0, "default-grp6-rdc", "default_grp6_rdc"},

	{ nxge_param_get_generic, nxge_param_set_grp_rdc,
		NXGE_PARAM_RXDMA_RW | NXGE_PARAM_DONT_SHOW,
		0, 15, 14, 0, "default-grp7-rdc", "default_grp7_rdc"},

	{ nxge_param_get_rxdma_rdcgrp_info, NULL,
		NXGE_PARAM_READ | NXGE_PARAM_CMPLX | NXGE_PARAM_DONT_SHOW,
		0, 8, 0, 0, "rdc-groups-info", "rdc_groups_info"},

	/* Logical device groups */
	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ | NXGE_PARAM_DONT_SHOW,
		0, 63, 0, 0, "start-ldg", "start_ldg"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_READ | NXGE_PARAM_DONT_SHOW,
		0, 64, 0, 0, "max-ldg", "max_ldg" },

	/* MAC table information */
	{ nxge_param_get_mac_rdcgrp, nxge_param_set_mac_rdcgrp,
		NXGE_PARAM_L2CLASS_CFG | NXGE_PARAM_DONT_SHOW,
		0, 31, 0, 0, "mac-2rdc-grp", "mac_2rdc_grp"},

	/* VLAN table information */
	{ nxge_param_get_vlan_rdcgrp, nxge_param_set_vlan_rdcgrp,
		NXGE_PARAM_L2CLASS_CFG | NXGE_PARAM_DONT_SHOW,
		0, 31, 0, 0, "vlan-2rdc-grp", "vlan_2rdc_grp"},

	{ nxge_param_get_generic, NULL,
		NXGE_PARAM_READ_PROP | NXGE_PARAM_READ |
		NXGE_PARAM_PROP_ARR32 | NXGE_PARAM_DONT_SHOW,
		0, 0x0ffff, 0x0ffff, 0, "fcram-part-cfg", "fcram_part_cfg"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_CLASS_RWS |
		NXGE_PARAM_DONT_SHOW,
		0, 0x10, 0xa, 0, "fcram-access-ratio", "fcram_access_ratio"},

	{ nxge_param_get_generic, NULL, NXGE_PARAM_CLASS_RWS |
		NXGE_PARAM_DONT_SHOW,
		0, 0x10, 0xa, 0, "tcam-access-ratio", "tcam_access_ratio"},

	{ nxge_param_get_generic, nxge_param_tcam_enable,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, 0x1, 0x0, 0, "tcam-enable", "tcam_enable"},

	{ nxge_param_get_generic, nxge_param_hash_lookup_enable,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, 0x01, 0x0, 0, "hash-lookup-enable", "hash_lookup_enable"},

	{ nxge_param_get_generic, nxge_param_llc_snap_enable,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, 0x01, 0x01, 0, "llc-snap-enable", "llc_snap_enable"},

	{ nxge_param_get_generic, nxge_param_fflp_hash_init,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, ALL_FF_32, 0, "h1-init-value", "h1_init_value"},

	{ nxge_param_get_generic,	nxge_param_fflp_hash_init,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, 0x0ffff, 0x0ffff, 0, "h2-init-value", "h2_init_value"},

	{ nxge_param_get_generic, nxge_param_set_ether_usr,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-cfg-ether-usr1", "class_cfg_ether_usr1"},

	{ nxge_param_get_generic, nxge_param_set_ether_usr,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-cfg-ether-usr2", "class_cfg_ether_usr2"},

	{ nxge_param_get_generic, nxge_param_set_ip_usr,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-cfg-ip-usr4", "class_cfg_ip_usr4"},

	{ nxge_param_get_generic, nxge_param_set_ip_usr,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-cfg-ip-usr5", "class_cfg_ip_usr5"},

	{ nxge_param_get_generic, nxge_param_set_ip_usr,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-cfg-ip-usr6", "class_cfg_ip_usr6"},

	{ nxge_param_get_generic, nxge_param_set_ip_usr,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-cfg-ip-usr7", "class_cfg_ip_usr7"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-opt-ip-usr4", "class_opt_ip_usr4"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-opt-ip-usr5", "class_opt_ip_usr5"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-opt-ip-usr6", "class_opt_ip_usr6"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt,
		NXGE_PARAM_CLASS_RWS | NXGE_PARAM_DONT_SHOW,
		0, ALL_FF_32, 0x0, 0,
		"class-opt-ip-usr7", "class_opt_ip_usr7"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt,
		NXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, NXGE_CLASS_FLOW_GEN_SERVER, 0,
		"class-opt-ipv4-tcp", "class_opt_ipv4_tcp"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt,
		NXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, NXGE_CLASS_FLOW_GEN_SERVER, 0,
		"class-opt-ipv4-udp", "class_opt_ipv4_udp"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt,
		NXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, NXGE_CLASS_FLOW_GEN_SERVER, 0,
		"class-opt-ipv4-ah", "class_opt_ipv4_ah"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt,
		NXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, NXGE_CLASS_FLOW_GEN_SERVER, 0,
		"class-opt-ipv4-sctp", "class_opt_ipv4_sctp"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt, NXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, NXGE_CLASS_FLOW_GEN_SERVER, 0,
		"class-opt-ipv6-tcp", "class_opt_ipv6_tcp"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt, NXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, NXGE_CLASS_FLOW_GEN_SERVER, 0,
		"class-opt-ipv6-udp", "class_opt_ipv6_udp"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt, NXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, NXGE_CLASS_FLOW_GEN_SERVER, 0,
		"class-opt-ipv6-ah", "class_opt_ipv6_ah"},

	{ nxge_param_get_ip_opt, nxge_param_set_ip_opt, NXGE_PARAM_CLASS_RWS,
		0, ALL_FF_32, NXGE_CLASS_FLOW_GEN_SERVER, 0,
		"class-opt-ipv6-sctp",	"class_opt_ipv6_sctp"},

	{ nxge_param_get_debug_flag, nxge_param_set_nxge_debug_flag,
		NXGE_PARAM_RW | NXGE_PARAM_DONT_SHOW,
		0ULL, ALL_FF_64, 0ULL, 0ULL,
		"nxge-debug-flag", "nxge_debug_flag"},

	{ nxge_param_get_debug_flag, nxge_param_set_npi_debug_flag,
		NXGE_PARAM_RW | NXGE_PARAM_DONT_SHOW,
		0ULL, ALL_FF_64, 0ULL, 0ULL,
		"npi-debug-flag", "npi_debug_flag"},

	{ nxge_param_dump_tdc, NULL, NXGE_PARAM_READ | NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0, "dump-tdc", "dump_tdc"},

	{ nxge_param_dump_rdc, NULL, NXGE_PARAM_READ | NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0, "dump-rdc", "dump_rdc"},

	{ nxge_param_dump_mac_regs, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0, "dump-mac-regs", "dump_mac_regs"},

	{ nxge_param_dump_ipp_regs, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0, "dump-ipp-regs", "dump_ipp_regs"},

	{ nxge_param_dump_fflp_regs, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0,
		"dump-fflp-regs", "dump_fflp_regs"},

	{ nxge_param_dump_vlan_table, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0,
		"dump-vlan-table", "dump_vlan_table"},

	{ nxge_param_dump_rdc_table, NULL, NXGE_PARAM_READ |
		NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0,
		"dump-rdc-table", "dump_rdc_table"},

	{ nxge_param_dump_ptrs,	NULL, NXGE_PARAM_READ |
		NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0, "dump-ptrs", "dump_ptrs"},

	{  NULL, NULL, NXGE_PARAM_READ | NXGE_PARAM_DONT_SHOW,
		0, 0x0fffffff, 0x0fffffff, 0, "end", "end"},
};

extern void 		*nxge_list;

void
nxge_get_param_soft_properties(p_nxge_t nxgep)
{

	p_nxge_param_t 		param_arr;
	uint_t 			prop_len;
	int 			i, j;
	uint32_t		param_count;
	uint32_t		*int_prop_val;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, " ==> nxge_get_param_soft_properties"));

	param_arr = nxgep->param_arr;
	param_count = nxgep->param_count;
	for (i = 0; i < param_count; i++) {
		if ((param_arr[i].type & NXGE_PARAM_READ_PROP) == 0)
			continue;
		if ((param_arr[i].type & NXGE_PARAM_PROP_STR))
			continue;
		if ((param_arr[i].type & NXGE_PARAM_PROP_ARR32) ||
		    (param_arr[i].type & NXGE_PARAM_PROP_ARR64)) {
			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
			    nxgep->dip, 0, param_arr[i].fcode_name,
			    (int **)&int_prop_val,
			    (uint_t *)&prop_len)
			    == DDI_PROP_SUCCESS) {
				uint32_t *cfg_value;
				uint64_t prop_count;

				if (prop_len > NXGE_PARAM_ARRAY_INIT_SIZE)
					prop_len = NXGE_PARAM_ARRAY_INIT_SIZE;
#if defined(__i386)
				cfg_value =
				    (uint32_t *)(int32_t)param_arr[i].value;
#else
				cfg_value = (uint32_t *)param_arr[i].value;
#endif
				for (j = 0; j < prop_len; j++) {
					cfg_value[j] = int_prop_val[j];
				}
				prop_count = prop_len;
				param_arr[i].type |=
				    (prop_count << NXGE_PARAM_ARRAY_CNT_SHIFT);
				ddi_prop_free(int_prop_val);
			}
			continue;
		}

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, nxgep->dip, 0,
		    param_arr[i].fcode_name,
		    (int **)&int_prop_val,
		    &prop_len) == DDI_PROP_SUCCESS) {
			if ((*int_prop_val >= param_arr[i].minimum) &&
			    (*int_prop_val <= param_arr[i].maximum))
				param_arr[i].value = *int_prop_val;
#ifdef NXGE_DEBUG_ERROR
			else {
				NXGE_DEBUG_MSG((nxgep, OBP_CTL,
				    "nxge%d: 'prom' file parameter error\n",
				    nxgep->instance));
				NXGE_DEBUG_MSG((nxgep, OBP_CTL,
				    "Parameter keyword '%s'"
				    " is outside valid range\n",
				    param_arr[i].name));
			}
#endif
			ddi_prop_free(int_prop_val);
		}

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, nxgep->dip, 0,
		    param_arr[i].name,
		    (int **)&int_prop_val,
		    &prop_len) == DDI_PROP_SUCCESS) {
			if ((*int_prop_val >= param_arr[i].minimum) &&
			    (*int_prop_val <= param_arr[i].maximum))
				param_arr[i].value = *int_prop_val;
#ifdef NXGE_DEBUG_ERROR
			else {
				NXGE_DEBUG_MSG((nxgep, OBP_CTL,
				    "nxge%d: 'conf' file parameter error\n",
				    nxgep->instance));
				NXGE_DEBUG_MSG((nxgep, OBP_CTL,
				    "Parameter keyword '%s'"
				    "is outside valid range\n",
				    param_arr[i].name));
			}
#endif
			ddi_prop_free(int_prop_val);
		}
	}
}

static int
nxge_private_param_register(p_nxge_t nxgep, p_nxge_param_t param_arr)
{
	int status = B_TRUE;
	int channel;
	uint8_t grp;
	char *prop_name;
	char *end;
	uint32_t name_chars;

	NXGE_DEBUG_MSG((nxgep, NDD2_CTL,
	    "nxge_private_param_register %s", param_arr->name));

	if ((param_arr->type & NXGE_PARAM_PRIV) != NXGE_PARAM_PRIV)
		return (B_TRUE);

	prop_name =  param_arr->name;
	if (param_arr->type & NXGE_PARAM_RXDMA) {
		if (strncmp("rxdma_intr", prop_name, 10) == 0)
			return (B_TRUE);
		name_chars = strlen("default_grp");
		if (strncmp("default_grp", prop_name, name_chars) == 0) {
			prop_name += name_chars;
			grp = mi_strtol(prop_name, &end, 10);
				/* now check if this rdcgrp is in config */
			return (nxge_check_rdcgrp_port_member(nxgep, grp));
		}
		name_chars = strlen(prop_name);
		if (strncmp("default_port_rdc", prop_name, name_chars) == 0) {
			return (B_TRUE);
		}
		return (B_FALSE);
	}

	if (param_arr->type & NXGE_PARAM_TXDMA) {
		name_chars = strlen("txdma");
		if (strncmp("txdma", prop_name, name_chars) == 0) {
			prop_name += name_chars;
			channel = mi_strtol(prop_name, &end, 10);
				/* now check if this rdc is in config */
			NXGE_DEBUG_MSG((nxgep, NDD2_CTL,
			    " nxge_private_param_register: %d",
			    channel));
			return (nxge_check_txdma_port_member(nxgep, channel));
		}
		return (B_FALSE);
	}

	status = B_FALSE;
	NXGE_DEBUG_MSG((nxgep, NDD2_CTL, "<== nxge_private_param_register"));

	return (status);
}

void
nxge_setup_param(p_nxge_t nxgep)
{
	p_nxge_param_t param_arr;
	int i;
	pfi_t set_pfi;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_setup_param"));

	/*
	 * Make sure the param_instance is set to a valid device instance.
	 */
	if (nxge_param_arr[param_instance].value == 1000)
		nxge_param_arr[param_instance].value = nxgep->instance;

	param_arr = nxgep->param_arr;
	param_arr[param_instance].value = nxgep->instance;
	param_arr[param_function_number].value = nxgep->function_num;

	for (i = 0; i < nxgep->param_count; i++) {
		if ((param_arr[i].type & NXGE_PARAM_PRIV) &&
		    (nxge_private_param_register(nxgep,
		    &param_arr[i]) == B_FALSE)) {
			param_arr[i].setf = NULL;
			param_arr[i].getf = NULL;
		}

		if (param_arr[i].type & NXGE_PARAM_CMPLX)
			param_arr[i].setf = NULL;

		if (param_arr[i].type & NXGE_PARAM_DONT_SHOW) {
			param_arr[i].setf = NULL;
			param_arr[i].getf = NULL;
		}

		set_pfi = (pfi_t)param_arr[i].setf;

		if ((set_pfi) && (param_arr[i].type & NXGE_PARAM_INIT_ONLY)) {
			set_pfi = NULL;
		}

	}
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_setup_param"));
}

void
nxge_init_param(p_nxge_t nxgep)
{
	p_nxge_param_t param_arr;
	int i, alloc_size;
	uint64_t alloc_count;
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_init_param"));
	/*
	 * Make sure the param_instance is set to a valid device instance.
	 */
	if (nxge_param_arr[param_instance].value == 1000)
		nxge_param_arr[param_instance].value = nxgep->instance;

	param_arr = nxgep->param_arr;
	if (param_arr == NULL) {
		param_arr = (p_nxge_param_t)
		    KMEM_ZALLOC(sizeof (nxge_param_arr), KM_SLEEP);
	}

	for (i = 0; i < sizeof (nxge_param_arr)/sizeof (nxge_param_t); i++) {
		param_arr[i] = nxge_param_arr[i];
		if ((param_arr[i].type & NXGE_PARAM_PROP_ARR32) ||
		    (param_arr[i].type & NXGE_PARAM_PROP_ARR64)) {
			alloc_count = NXGE_PARAM_ARRAY_INIT_SIZE;
			alloc_size = alloc_count * sizeof (uint64_t);
			param_arr[i].value =
#if defined(__i386)
			    (uint64_t)(uint32_t)KMEM_ZALLOC(alloc_size,
			    KM_SLEEP);
#else
			(uint64_t)KMEM_ZALLOC(alloc_size, KM_SLEEP);
#endif
			param_arr[i].old_value =
#if defined(__i386)
			    (uint64_t)(uint32_t)KMEM_ZALLOC(alloc_size,
			    KM_SLEEP);
#else
			(uint64_t)KMEM_ZALLOC(alloc_size, KM_SLEEP);
#endif
			param_arr[i].type |=
			    (alloc_count << NXGE_PARAM_ARRAY_ALLOC_SHIFT);
		}
	}

	nxgep->param_arr = param_arr;
	nxgep->param_count = sizeof (nxge_param_arr)/sizeof (nxge_param_t);

	nxge_param_sync(nxgep);

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_init_param: count %d",
	    nxgep->param_count));
}

void
nxge_destroy_param(p_nxge_t nxgep)
{
	int i;
	uint64_t free_size, free_count;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_destroy_param"));

	if (nxgep->param_arr == NULL)
		return;
	/*
	 * Make sure the param_instance is set to a valid device instance.
	 */
	if (nxge_param_arr[param_instance].value == nxgep->instance) {
		for (i = 0; i <= nxge_param_arr[param_instance].maximum; i++) {
			if ((ddi_get_soft_state(nxge_list, i) != NULL) &&
			    (i != nxgep->instance))
				break;
		}
		nxge_param_arr[param_instance].value = i;
	}

	for (i = 0; i < nxgep->param_count; i++)
		if ((nxgep->param_arr[i].type & NXGE_PARAM_PROP_ARR32) ||
		    (nxgep->param_arr[i].type & NXGE_PARAM_PROP_ARR64)) {
			free_count = ((nxgep->param_arr[i].type &
			    NXGE_PARAM_ARRAY_ALLOC_MASK) >>
			    NXGE_PARAM_ARRAY_ALLOC_SHIFT);
			free_count = NXGE_PARAM_ARRAY_INIT_SIZE;
			free_size = sizeof (uint64_t) * free_count;
#if defined(__i386)
			KMEM_FREE((void *)(uint32_t)nxgep->param_arr[i].value,
			    free_size);
#else
			KMEM_FREE((void *)nxgep->param_arr[i].value, free_size);
#endif
#if defined(__i386)
			KMEM_FREE((void *)(uint32_t)
			    nxgep->param_arr[i].old_value, free_size);
#else
			KMEM_FREE((void *)nxgep->param_arr[i].old_value,
			    free_size);
#endif
		}

	KMEM_FREE(nxgep->param_arr, sizeof (nxge_param_arr));
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_destroy_param"));
}

/*
 * Extracts the value from the 'nxge' parameter array and prints the
 * parameter value. cp points to the required parameter.
 */

/* ARGSUSED */
int
nxge_param_get_generic(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	p_nxge_param_t pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL,
	    "==> nxge_param_get_generic name %s ", pa->name));

	if (pa->value > 0xffffffff)
		(void) mi_mpprintf(mp, "%x%x",
		    (int)(pa->value >> 32), (int)(pa->value & 0xffffffff));
	else
		(void) mi_mpprintf(mp, "%x", (int)pa->value);

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_generic"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_get_mac(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	p_nxge_param_t pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_mac"));

	(void) mi_mpprintf(mp, "%d", (uint32_t)pa->value);
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_mac"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_get_fw_ver(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_fw_ver"));

	(void) mi_mpprintf(mp, "Firmware version for nxge%d:  %s\n",
	    nxgep->instance, nxgep->vpd_info.ver);

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_fw_ver"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_get_port_mode(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_port_mode"));

	switch (nxgep->mac.portmode) {
	case PORT_1G_COPPER:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  1G Copper %s\n",
		    nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	case PORT_1G_FIBER:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  1G Fiber %s\n",
		    nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	case PORT_10G_COPPER:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  10G Copper "
		    "%s\n", nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	case PORT_10G_FIBER:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  10G Fiber %s\n",
		    nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	case PORT_10G_SERDES:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  10G Serdes "
		    "%s\n", nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	case PORT_1G_SERDES:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  1G Serdes %s\n",
		    nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	case PORT_1G_RGMII_FIBER:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  1G RGMII "
		    "Fiber %s\n", nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	case PORT_HSP_MODE:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  Hot Swappable "
		    "PHY, Currently NOT present\n", nxgep->instance);
		break;
	case PORT_10G_TN1010:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:"
		    " 10G Copper with TN1010 %s\n", nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	case PORT_1G_TN1010:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:"
		    " 1G Copper with TN1010 %s\n", nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	default:
		(void) mi_mpprintf(mp, "Port mode for nxge%d:  Unknown %s\n",
		    nxgep->instance,
		    nxgep->hot_swappable_phy ? "[Hot Swappable]" : "");
		break;
	}

	(void) mi_mpprintf(mp, "Software LSO for nxge%d: %s\n",
	    nxgep->instance,
	    nxgep->soft_lso_enable ? "enable" : "disable");

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_port_mode"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_get_rx_intr_time(p_nxge_t nxgep, queue_t *q, mblk_t *mp, caddr_t cp)
{
	p_nxge_param_t pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_rx_intr_time"));

	pa->value = (uint32_t)nxgep->intr_timeout;
	(void) mi_mpprintf(mp, "%d", (uint32_t)nxgep->intr_timeout);

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_rx_intr_time"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_get_rx_intr_pkts(p_nxge_t nxgep, queue_t *q, mblk_t *mp, caddr_t cp)
{
	p_nxge_param_t pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_rx_intr_pkts"));

	pa->value = (uint32_t)nxgep->intr_threshold;
	(void) mi_mpprintf(mp, "%d", (uint32_t)nxgep->intr_threshold);

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_rx_intr_pkts"));
	return (0);
}

/* ARGSUSED */
int
nxge_param_get_txdma_info(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{

	uint_t print_len, buf_len;
	p_mblk_t np;

	int buff_alloc_size = NXGE_NDD_INFODUMP_BUFF_SIZE;
	int tdc;

	nxge_grp_set_t *set;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_txdma_info"));

	(void) mi_mpprintf(mp, "TXDMA Information for Port\t %d \n",
	    nxgep->function_num);

	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}

	buf_len = buff_alloc_size;
	mp->b_cont = np;
	print_len = 0;

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "TDC\t HW TDC\t\n");
	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;

	set = &nxgep->tx_set;
	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			print_len = snprintf((char *)((mblk_t *)np)->b_wptr,
			    buf_len, "%d\n", tdc);
			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;
		}
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_txdma_info"));
	return (0);
}

/* ARGSUSED */
int
nxge_param_get_rxdma_info(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	uint_t			print_len, buf_len;
	p_mblk_t		np;
	int			rdc;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	int			buff_alloc_size = NXGE_NDD_INFODUMP_BUFF_SIZE;
	p_rx_rcr_rings_t 	rx_rcr_rings;
	p_rx_rcr_ring_t		*rcr_rings;
	p_rx_rbr_rings_t 	rx_rbr_rings;
	p_rx_rbr_ring_t		*rbr_rings;
	nxge_grp_set_t		*set;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_rxdma_info"));

	(void) mi_mpprintf(mp, "RXDMA Information for Port\t %d \n",
	    nxgep->function_num);

	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}

	buf_len = buff_alloc_size;
	mp->b_cont = np;
	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	rx_rcr_rings = nxgep->rx_rcr_rings;
	rcr_rings = rx_rcr_rings->rcr_rings;
	rx_rbr_rings = nxgep->rx_rbr_rings;
	rbr_rings = rx_rbr_rings->rbr_rings;

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "Total RDCs\t %d\n", p_cfgp->max_rdcs);

	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "RDC\t HW RDC\t Timeout\t Packets RBR ptr \t"
	    "chunks\t RCR ptr\n");

	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;

	set = &nxgep->rx_set;
	for (rdc = 0; rdc < NXGE_MAX_RDCS; rdc++) {
		if ((1 << rdc) & set->owned.map) {
			print_len = snprintf((char *)
			    ((mblk_t *)np)->b_wptr, buf_len,
			    " %d\t   %x\t\t %x\t $%p\t 0x%x\t $%p\n",
			    rdc,
			    p_dma_cfgp->rcr_timeout[rdc],
			    p_dma_cfgp->rcr_threshold[rdc],
			    (void *)rbr_rings[rdc],
			    rbr_rings[rdc]->num_blocks, (void *)rcr_rings[rdc]);
			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;
		}
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_rxdma_info"));
	return (0);
}

/* ARGSUSED */
int
nxge_param_get_rxdma_rdcgrp_info(p_nxge_t nxgep, queue_t *q,
    p_mblk_t mp, caddr_t cp)
{
	uint_t			print_len, buf_len;
	p_mblk_t		np;
	int			offset, rdc, i, rdc_grp;
	p_nxge_rdc_grp_t	rdc_grp_p;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;

	int buff_alloc_size = NXGE_NDD_INFODUMP_BUFF_SIZE;
	NXGE_DEBUG_MSG((nxgep, NDD_CTL,
	    "==> nxge_param_get_rxdma_rdcgrp_info"));

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	(void) mi_mpprintf(mp, "RXDMA RDC Group Information for Port\t %d \n",
	    nxgep->function_num);

	rdc_grp = p_cfgp->def_mac_rxdma_grpid;
	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}

	buf_len = buff_alloc_size;
	mp->b_cont = np;
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "Total RDC Groups\t %d \n"
	    "default RDC group\t %d\n",
	    p_cfgp->max_rdc_grpids,
	    p_cfgp->def_mac_rxdma_grpid);

	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;

	for (i = 0; i < NXGE_MAX_RDC_GROUPS; i++) {
		if (p_cfgp->grpids[i]) {
			rdc_grp_p = &p_dma_cfgp->rdc_grps[i];
			print_len = snprintf((char *)((mblk_t *)np)->b_wptr,
			    buf_len,
			    "\nRDC Group Info for Group [%d] %d\n"
			    "RDC Count %d\tstart RDC %d\n"
			    "RDC Group Population Information"
			    " (offsets 0 - 15)\n",
			    i, rdc_grp, rdc_grp_p->max_rdcs,
			    rdc_grp_p->start_rdc);

			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;
			print_len = snprintf((char *)((mblk_t *)np)->b_wptr,
			    buf_len, "\n");
			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;

			for (rdc = 0; rdc < rdc_grp_p->max_rdcs; rdc++) {
				print_len = snprintf(
				    (char *)((mblk_t *)np)->b_wptr,
				    buf_len, "[%d]=%d ", rdc,
				    rdc_grp_p->start_rdc + rdc);
				((mblk_t *)np)->b_wptr += print_len;
				buf_len -= print_len;
			}
			print_len = snprintf((char *)((mblk_t *)np)->b_wptr,
			    buf_len, "\n");
			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;

			for (offset = 0; offset < 16; offset++) {
				print_len = snprintf(
				    (char *)((mblk_t *)np)->b_wptr,
				    buf_len, " %c",
				    rdc_grp_p->map & (1 << offset) ?
				    '1' : '0');
				((mblk_t *)np)->b_wptr += print_len;
				buf_len -= print_len;
			}
			print_len = snprintf((char *)((mblk_t *)np)->b_wptr,
			    buf_len, "\n");
			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;
		}
	}
	NXGE_DEBUG_MSG((nxgep, NDD_CTL,
	    "<== nxge_param_get_rxdma_rdcgrp_info"));
	return (0);
}

int
nxge_mk_mblk_tail_space(p_mblk_t mp, p_mblk_t *nmp, size_t size)
{
	p_mblk_t tmp;

	tmp = mp;
	while (tmp->b_cont)
		tmp = tmp->b_cont;
	if ((tmp->b_wptr + size) >= tmp->b_datap->db_lim) {
		tmp->b_cont = allocb(1024, BPRI_HI);
		tmp = tmp->b_cont;
		if (!tmp)
			return (ENOMEM);
	}

	*nmp = tmp;
	return (0);
}


/* ARGSUSED */
int
nxge_param_set_generic(p_nxge_t nxgep, queue_t *q, mblk_t *mp,
    char *value, caddr_t cp)
{
	char *end;
	uint32_t new_value;
	p_nxge_param_t pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, " ==> nxge_param_set_generic"));
	new_value = (uint32_t)mi_strtol(value, &end, 10);
	if (end == value || new_value < pa->minimum ||
	    new_value > pa->maximum) {
			return (EINVAL);
	}
	pa->value = new_value;
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, " <== nxge_param_set_generic"));
	return (0);
}


/* ARGSUSED */
int
nxge_param_set_instance(p_nxge_t nxgep, queue_t *q, mblk_t *mp,
    char *value, caddr_t cp)
{
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, " ==> nxge_param_set_instance"));
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, " <== nxge_param_set_instance"));
	return (0);
}


/* ARGSUSED */
int
nxge_param_set_mac(p_nxge_t nxgep, queue_t *q, mblk_t *mp,
    char *value, caddr_t cp)
{
	char		*end;
	uint32_t	new_value;
	int		status = 0;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_mac"));
	new_value = (uint32_t)mi_strtol(value, &end, BASE_DECIMAL);
	if (PARAM_OUTOF_RANGE(value, end, new_value, pa)) {
		return (EINVAL);
	}

	if (pa->value != new_value) {
		pa->old_value = pa->value;
		pa->value = new_value;
	}

	if (!nxge_param_link_update(nxgep)) {
		NXGE_DEBUG_MSG((nxgep, NDD_CTL,
		    " false ret from nxge_param_link_update"));
		status = EINVAL;
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_mac"));
	return (status);
}

/* ARGSUSED */
int
nxge_param_rx_intr_pkts(p_nxge_t nxgep, queue_t *q, mblk_t *mp,
    char *value, caddr_t cp)
{
	char		*end;
	uint32_t	cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_rx_intr_pkts"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_ANY);

	if ((cfg_value > NXGE_RDC_RCR_THRESHOLD_MAX) ||
	    (cfg_value < NXGE_RDC_RCR_THRESHOLD_MIN)) {
		return (EINVAL);
	}

	if ((pa->value != cfg_value)) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		nxgep->intr_threshold = pa->value;
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_rx_intr_pkts"));
	return (0);
}

/* ARGSUSED */
int
nxge_param_rx_intr_time(p_nxge_t nxgep, queue_t *q, mblk_t *mp,
    char *value, caddr_t cp)
{
	char		*end;
	uint32_t	cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_rx_intr_time"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_ANY);

	if ((cfg_value > NXGE_RDC_RCR_TIMEOUT_MAX) ||
	    (cfg_value < NXGE_RDC_RCR_TIMEOUT_MIN)) {
		return (EINVAL);
	}

	if ((pa->value != cfg_value)) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		nxgep->intr_timeout = pa->value;
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_rx_intr_time"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_set_mac_rdcgrp(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char			 *end;
	uint32_t		status = 0, cfg_value;
	p_nxge_param_t		pa = (p_nxge_param_t)cp;
	uint32_t		cfg_it = B_FALSE;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	uint32_t		*val_ptr, *old_val_ptr;
	nxge_param_map_t	*mac_map;
	p_nxge_class_pt_cfg_t	p_class_cfgp;
	nxge_mv_cfg_t		*mac_host_info;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_mac_rdcgrp "));

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	mac_host_info = (nxge_mv_cfg_t	*)&p_class_cfgp->mac_host_info[0];
	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);

	/*
	 * now do decoding
	 */
	mac_map = (nxge_param_map_t *)&cfg_value;
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, " cfg_value %x id %x map_to %x",
	    cfg_value, mac_map->param_id, mac_map->map_to));

	if ((mac_map->param_id < p_cfgp->max_macs) &&
	    p_cfgp->grpids[mac_map->map_to]) {
		NXGE_DEBUG_MSG((nxgep, NDD_CTL,
		    " nxge_param_set_mac_rdcgrp mapping"
		    " id %d grp %d", mac_map->param_id, mac_map->map_to));
#if defined(__i386)
		val_ptr = (uint32_t *)(uint32_t)pa->value;
#else
		val_ptr = (uint32_t *)pa->value;
#endif
#if defined(__i386)
		old_val_ptr = (uint32_t *)(uint32_t)pa->old_value;
#else
		old_val_ptr = (uint32_t *)pa->old_value;
#endif
		if (val_ptr[mac_map->param_id] != cfg_value) {
			old_val_ptr[mac_map->param_id] =
			    val_ptr[mac_map->param_id];
			val_ptr[mac_map->param_id] = cfg_value;
			mac_host_info[mac_map->param_id].mpr_npr =
			    mac_map->pref;
			mac_host_info[mac_map->param_id].flag = 1;
			mac_host_info[mac_map->param_id].rdctbl =
			    mac_map->map_to;
			cfg_it = B_TRUE;
		}
	} else {
		return (EINVAL);
	}

	if (cfg_it == B_TRUE) {
		status = nxge_logical_mac_assign_rdc_table(nxgep,
		    (uint8_t)mac_map->param_id);
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_mac_rdcgrp"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_set_vlan_rdcgrp(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char			*end;
	uint32_t		status = 0, cfg_value;
	p_nxge_param_t		pa = (p_nxge_param_t)cp;
	uint32_t		cfg_it = B_FALSE;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	uint32_t		*val_ptr, *old_val_ptr;
	nxge_param_map_t	*vmap, *old_map;
	p_nxge_class_pt_cfg_t	p_class_cfgp;
	uint64_t		cfgd_vlans;
	int			i, inc = 0, cfg_position;
	nxge_mv_cfg_t		*vlan_tbl;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_vlan_rdcgrp "));

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	vlan_tbl = (nxge_mv_cfg_t *)&p_class_cfgp->vlan_tbl[0];

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);

	/* now do decoding */
	cfgd_vlans = ((pa->type &  NXGE_PARAM_ARRAY_CNT_MASK) >>
	    NXGE_PARAM_ARRAY_CNT_SHIFT);

	if (cfgd_vlans == NXGE_PARAM_ARRAY_INIT_SIZE) {
		/*
		 * for now, we process only upto max
		 * NXGE_PARAM_ARRAY_INIT_SIZE parameters
		 * In the future, we may want to expand
		 * the storage array and continue
		 */
		return (EINVAL);
	}

	vmap = (nxge_param_map_t *)&cfg_value;
	if ((vmap->param_id) &&
	    (vmap->param_id < NXGE_MAX_VLANS) &&
	    (vmap->map_to < p_cfgp->max_rdc_grpids)) {
		NXGE_DEBUG_MSG((nxgep, NDD_CTL,
		    "nxge_param_set_vlan_rdcgrp mapping"
		    " id %d grp %d",
		    vmap->param_id, vmap->map_to));
#if defined(__i386)
		val_ptr = (uint32_t *)(uint32_t)pa->value;
#else
		val_ptr = (uint32_t *)pa->value;
#endif
#if defined(__i386)
		old_val_ptr = (uint32_t *)(uint32_t)pa->old_value;
#else
		old_val_ptr = (uint32_t *)pa->old_value;
#endif

		/* search to see if this vlan id is already configured */
		for (i = 0; i < cfgd_vlans; i++) {
			old_map = (nxge_param_map_t *)&val_ptr[i];
			if ((old_map->param_id == 0) ||
			    (vmap->param_id == old_map->param_id) ||
			    (vlan_tbl[vmap->param_id].flag)) {
				cfg_position = i;
				break;
			}
		}

		if (cfgd_vlans == 0) {
			cfg_position = 0;
			inc++;
		}

		if (i == cfgd_vlans) {
			cfg_position = i;
			inc++;
		}

		NXGE_DEBUG_MSG((nxgep, NDD2_CTL,
		    "set_vlan_rdcgrp mapping"
		    " i %d cfgd_vlans %llx position %d ",
		    i, cfgd_vlans, cfg_position));
		if (val_ptr[cfg_position] != cfg_value) {
			old_val_ptr[cfg_position] = val_ptr[cfg_position];
			val_ptr[cfg_position] = cfg_value;
			vlan_tbl[vmap->param_id].mpr_npr = vmap->pref;
			vlan_tbl[vmap->param_id].flag = 1;
			vlan_tbl[vmap->param_id].rdctbl =
			    vmap->map_to + p_cfgp->def_mac_rxdma_grpid;
			cfg_it = B_TRUE;
			if (inc) {
				cfgd_vlans++;
				pa->type &= ~NXGE_PARAM_ARRAY_CNT_MASK;
				pa->type |= (cfgd_vlans <<
				    NXGE_PARAM_ARRAY_CNT_SHIFT);

			}
			NXGE_DEBUG_MSG((nxgep, NDD2_CTL,
			    "after: param_set_vlan_rdcgrp "
			    " cfg_vlans %llx position %d \n",
			    cfgd_vlans, cfg_position));
		}
	} else {
		return (EINVAL);
	}

	if (cfg_it == B_TRUE) {
		status = nxge_fflp_config_vlan_table(nxgep,
		    (uint16_t)vmap->param_id);
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_vlan_rdcgrp"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_get_vlan_rdcgrp(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, caddr_t cp)
{

	uint_t 			print_len, buf_len;
	p_mblk_t		np;
	int			i;
	uint32_t		*val_ptr;
	nxge_param_map_t	*vmap;
	p_nxge_param_t		pa = (p_nxge_param_t)cp;
	p_nxge_class_pt_cfg_t 	p_class_cfgp;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	uint64_t		cfgd_vlans = 0;
	nxge_mv_cfg_t		*vlan_tbl;
	int			buff_alloc_size =
	    NXGE_NDD_INFODUMP_BUFF_SIZE * 32;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_vlan_rdcgrp "));
	(void) mi_mpprintf(mp, "VLAN RDC Mapping Information for Port\t %d \n",
	    nxgep->function_num);

	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	buf_len = buff_alloc_size;
	mp->b_cont = np;
	cfgd_vlans = (pa->type &  NXGE_PARAM_ARRAY_CNT_MASK) >>
	    NXGE_PARAM_ARRAY_CNT_SHIFT;

	i = (int)cfgd_vlans;
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	vlan_tbl = (nxge_mv_cfg_t *)&p_class_cfgp->vlan_tbl[0];
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "Configured VLANs %d\n"
	    "VLAN ID\t RDC GRP (Actual/Port)\t"
	    " Prefernce\n", i);
	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;
#if defined(__i386)
	val_ptr = (uint32_t *)(uint32_t)pa->value;
#else
	val_ptr = (uint32_t *)pa->value;
#endif

	for (i = 0; i < cfgd_vlans; i++) {
		vmap = (nxge_param_map_t *)&val_ptr[i];
		if (p_class_cfgp->vlan_tbl[vmap->param_id].flag) {
			print_len = snprintf((char *)((mblk_t *)np)->b_wptr,
			    buf_len,
			    "  %d\t\t %d/%d\t\t %d\n",
			    vmap->param_id,
			    vlan_tbl[vmap->param_id].rdctbl,
			    vlan_tbl[vmap->param_id].rdctbl -
			    p_cfgp->def_mac_rxdma_grpid,
			    vlan_tbl[vmap->param_id].mpr_npr);
			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;
		}
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_vlan_rdcgrp"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_get_mac_rdcgrp(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, caddr_t cp)
{
	uint_t			print_len, buf_len;
	p_mblk_t		np;
	int			i;
	p_nxge_class_pt_cfg_t 	p_class_cfgp;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	nxge_mv_cfg_t		*mac_host_info;

	int buff_alloc_size = NXGE_NDD_INFODUMP_BUFF_SIZE * 32;
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_mac_rdcgrp "));
	(void) mi_mpprintf(mp,
	    "MAC ADDR RDC Mapping Information for Port\t %d\n",
	    nxgep->function_num);

	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}

	buf_len = buff_alloc_size;
	mp->b_cont = np;
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;
	mac_host_info = (nxge_mv_cfg_t	*)&p_class_cfgp->mac_host_info[0];
	print_len = snprintf((char *)np->b_wptr, buf_len,
	    "MAC ID\t RDC GRP (Actual/Port)\t"
	    " Prefernce\n");
	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;
	for (i = 0; i < p_cfgp->max_macs; i++) {
		if (mac_host_info[i].flag) {
			print_len = snprintf((char *)((mblk_t *)np)->b_wptr,
			    buf_len,
			    "   %d\t  %d/%d\t\t %d\n",
			    i, mac_host_info[i].rdctbl,
			    mac_host_info[i].rdctbl -
			    p_cfgp->def_mac_rxdma_grpid,
			    mac_host_info[i].mpr_npr);
			((mblk_t *)np)->b_wptr += print_len;
			buf_len -= print_len;
		}
	}
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "Done Info Dumping \n");
	((mblk_t *)np)->b_wptr += print_len;
	buf_len -= print_len;
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_macrdcgrp"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_tcam_enable(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	uint32_t	status = 0, cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;
	char		*end;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_tcam_enable"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_BINARY);
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		if (pa->value)
			status = nxge_fflp_config_tcam_enable(nxgep);
		else
			status = nxge_fflp_config_tcam_disable(nxgep);
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, " <== nxge_param_tcam_enable"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_hash_lookup_enable(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	uint32_t	status = 0, cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;
	char		*end;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_hash_lookup_enable"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_BINARY);
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		if (pa->value)
			status = nxge_fflp_config_hash_lookup_enable(nxgep);
		else
			status = nxge_fflp_config_hash_lookup_disable(nxgep);
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, " <== nxge_param_hash_lookup_enable"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_llc_snap_enable(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status = 0, cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_llc_snap_enable"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_BINARY);
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		if (pa->value)
			status = nxge_fflp_config_tcam_enable(nxgep);
		else
			status = nxge_fflp_config_tcam_disable(nxgep);
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, " <== nxge_param_llc_snap_enable"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_set_ether_usr(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status = 0, cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;
	uint8_t		cfg_it = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_ether_usr"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}

	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	/* do the actual hw setup  */
	if (cfg_it == B_TRUE) {
		(void) mi_strtol(pa->name, &end, BASE_DECIMAL);
		NXGE_DEBUG_MSG((nxgep, NDD_CTL, " nxge_param_set_ether_usr"));
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_ether_usr"));
	return (status);
}

/* ARGSUSED */
static int
nxge_param_set_ip_usr(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	tcam_class_t	class;
	uint32_t	status, cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_ip_usr"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}

	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	/* do the actual hw setup with cfg_value. */
	if (cfg_it == B_TRUE) {
		class = mi_strtol(pa->name, &end, 10);
		status = nxge_fflp_ip_usr_class_config(nxgep, class, pa->value);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_ip_usr"));
	return (status);
}

/* ARGSUSED */
static int
nxge_class_name_2value(p_nxge_t nxgep, char *name)
{
	int		i;
	int		class_instance = param_class_opt_ip_usr4;
	p_nxge_param_t	param_arr;

	param_arr = nxgep->param_arr;
	for (i = TCAM_CLASS_IP_USER_4; i <= TCAM_CLASS_SCTP_IPV6; i++) {
		if (strcmp(param_arr[class_instance].name, name) == 0)
			return (i);
		class_instance++;
	}
	return (-1);
}

/* ARGSUSED */
int
nxge_param_set_ip_opt(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status, cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;
	tcam_class_t	class;
	uint32_t	cfg_it = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_ip_opt"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}

	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		/* do the actual hw setup  */
		class = nxge_class_name_2value(nxgep, pa->name);
		if (class == -1)
			return (EINVAL);

		/* Filter out the allowed bits */
		pa->value &= (NXGE_CLASS_FLOW_USE_PORTNUM |
		    NXGE_CLASS_FLOW_USE_L2DA | NXGE_CLASS_FLOW_USE_VLAN |
		    NXGE_CLASS_FLOW_USE_PROTO | NXGE_CLASS_FLOW_USE_IPSRC |
		    NXGE_CLASS_FLOW_USE_IPDST | NXGE_CLASS_FLOW_USE_SRC_PORT |
		    NXGE_CLASS_FLOW_USE_DST_PORT);

		status = nxge_fflp_ip_class_config(nxgep, class, pa->value);
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_ip_opt"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_get_ip_opt(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, caddr_t cp)
{
	uint32_t status, cfg_value;
	p_nxge_param_t pa = (p_nxge_param_t)cp;
	tcam_class_t class;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_ip_opt"));

	/* do the actual hw setup  */
	class = nxge_class_name_2value(nxgep, pa->name);
	if (class == -1)
		return (EINVAL);

	cfg_value = 0;
	status = nxge_fflp_ip_class_config_get(nxgep, class, &cfg_value);
	if (status != NXGE_OK)
		return (EINVAL);

	/* Filter out the allowed bits */
	cfg_value &= (NXGE_CLASS_FLOW_USE_PORTNUM | NXGE_CLASS_FLOW_USE_L2DA |
	    NXGE_CLASS_FLOW_USE_VLAN | NXGE_CLASS_FLOW_USE_PROTO |
	    NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_IPDST |
	    NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_DST_PORT);

	NXGE_DEBUG_MSG((nxgep, NDD_CTL,
	    "nxge_param_get_ip_opt_get %x ", cfg_value));

	pa->value = cfg_value;
	(void) mi_mpprintf(mp, "%x", cfg_value);

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_ip_opt status "));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_fflp_hash_init(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status, cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;
	tcam_class_t	class;
	uint32_t	cfg_it = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_fflp_hash_init"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_HEX);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL,
	    "nxge_param_fflp_hash_init value %x", cfg_value));

	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		char *h_name;

		/* do the actual hw setup */
		h_name = pa->name;
		h_name++;
		class = mi_strtol(h_name, &end, 10);
		switch (class) {
			case 1:
				status = nxge_fflp_set_hash1(nxgep,
				    (uint32_t)pa->value);
				break;
			case 2:
				status = nxge_fflp_set_hash2(nxgep,
				    (uint16_t)pa->value);
				break;

			default:
			NXGE_DEBUG_MSG((nxgep, NDD_CTL,
			    " nxge_param_fflp_hash_init"
			    " %s Wrong hash var %d",
			    pa->name, class));
			return (EINVAL);
		}
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, " <== nxge_param_fflp_hash_init"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_set_grp_rdc(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char			*end;
	uint32_t		status = 0, cfg_value;
	p_nxge_param_t		pa = (p_nxge_param_t)cp;
	uint32_t		cfg_it = B_FALSE;
	int			rdc_grp;
	uint8_t			real_rdc;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	p_nxge_rdc_grp_t	rdc_grp_p;

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_grp_rdc"));

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_ANY);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}

	if (cfg_value >= p_cfgp->max_rdcs) {
		return (EINVAL);
	}

	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		char *grp_name;
		grp_name = pa->name;
		grp_name += strlen("default-grp");
		rdc_grp = mi_strtol(grp_name, &end, 10);
		rdc_grp_p = &p_dma_cfgp->rdc_grps[rdc_grp];
		real_rdc = rdc_grp_p->start_rdc + cfg_value;
		if (nxge_check_rxdma_rdcgrp_member(nxgep, rdc_grp,
		    cfg_value) == B_FALSE) {
			pa->value = pa->old_value;
			NXGE_DEBUG_MSG((nxgep, NDD_CTL,
			    " nxge_param_set_grp_rdc"
			    " %d read %d actual %d outof range",
			    rdc_grp, cfg_value, real_rdc));
			return (EINVAL);
		}
		status = nxge_rxdma_cfg_rdcgrp_default_rdc(nxgep, rdc_grp,
		    real_rdc);
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_grp_rdc"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_set_port_rdc(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status = B_TRUE, cfg_value;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;
	uint32_t	cfg_it = B_FALSE;

	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_port_rdc"));
	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	cfg_value = (uint32_t)mi_strtol(value, &end, BASE_ANY);
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		return (EINVAL);
	}

	if (pa->value != cfg_value) {
		if (cfg_value >= p_cfgp->max_rdcs)
			return (EINVAL);
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		int rdc;
		if ((rdc = nxge_dci_map(nxgep, VP_BOUND_RX, cfg_value)) < 0)
			return (EINVAL);
		status = nxge_rxdma_cfg_port_default_rdc(nxgep,
		    nxgep->function_num, rdc);
		if (status != NXGE_OK)
			return (EINVAL);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_port_rdc"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_set_nxge_debug_flag(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char *end;
	uint32_t status = 0;
	uint64_t cfg_value = 0;
	p_nxge_param_t pa = (p_nxge_param_t)cp;
	uint32_t cfg_it = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_nxge_debug_flag"));
	cfg_value = mi_strtol(value, &end, BASE_HEX);

	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		NXGE_DEBUG_MSG((nxgep, NDD_CTL,
		    " nxge_param_set_nxge_debug_flag"
		    " outof range %llx", cfg_value));
		return (EINVAL);
	}
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		nxgep->nxge_debug_level = pa->value;
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_nxge_debug_flag"));
	return (status);
}

/* ARGSUSED */
static int
nxge_param_get_debug_flag(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	int		status = 0;
	p_nxge_param_t	pa = (p_nxge_param_t)cp;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_get_debug_flag"));

	if (pa->value > 0xffffffff)
		(void) mi_mpprintf(mp, "%x%x",  (int)(pa->value >> 32),
		    (int)(pa->value & 0xffffffff));
	else
		(void) mi_mpprintf(mp, "%x", (int)pa->value);

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_debug_flag"));
	return (status);
}

/* ARGSUSED */
static int
nxge_param_set_npi_debug_flag(p_nxge_t nxgep, queue_t *q,
    mblk_t *mp, char *value, caddr_t cp)
{
	char		*end;
	uint32_t	status = 0;
	uint64_t	 cfg_value = 0;
	p_nxge_param_t	pa;
	uint32_t	cfg_it = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_set_npi_debug_flag"));
	cfg_value = mi_strtol(value, &end, BASE_HEX);
	pa = (p_nxge_param_t)cp;
	if (PARAM_OUTOF_RANGE(value, end, cfg_value, pa)) {
		NXGE_DEBUG_MSG((nxgep, NDD_CTL, " nxge_param_set_npi_debug_flag"
		    " outof range %llx", cfg_value));
		return (EINVAL);
	}
	if (pa->value != cfg_value) {
		pa->old_value = pa->value;
		pa->value = cfg_value;
		cfg_it = B_TRUE;
	}

	if (cfg_it == B_TRUE) {
		npi_debug_level = pa->value;
	}
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_set_debug_flag"));
	return (status);
}

/* ARGSUSED */
static int
nxge_param_dump_rdc(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	nxge_grp_set_t *set = &nxgep->rx_set;
	int rdc;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "==> nxge_param_dump_rdc"));

	if (!isLDOMguest(nxgep))
		(void) npi_rxdma_dump_fzc_regs(NXGE_DEV_NPI_HANDLE(nxgep));

	for (rdc = 0; rdc < NXGE_MAX_TDCS; rdc++) {
		if ((1 << rdc) & set->owned.map) {
			(void) nxge_dump_rxdma_channel(nxgep, rdc);
		}
	}

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_param_dump_rdc"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_dump_tdc(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	nxge_grp_set_t *set = &nxgep->tx_set;
	int tdc;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "==> nxge_param_dump_tdc"));

	for (tdc = 0; tdc < NXGE_MAX_TDCS; tdc++) {
		if ((1 << tdc) & set->owned.map) {
			(void) nxge_txdma_regs_dump(nxgep, tdc);
		}
	}

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_param_dump_tdc"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_dump_fflp_regs(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "==> nxge_param_dump_fflp_regs"));

	(void) npi_fflp_dump_regs(NXGE_DEV_NPI_HANDLE(nxgep));

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_param_dump_fflp_regs"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_dump_mac_regs(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "==> nxge_param_dump_mac_regs"));

	(void) npi_mac_dump_regs(NXGE_DEV_NPI_HANDLE(nxgep),
	    nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_param_dump_mac_regs"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_dump_ipp_regs(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "==> nxge_param_dump_ipp_regs"));

	(void) npi_ipp_dump_regs(NXGE_DEV_NPI_HANDLE(nxgep),
	    nxgep->function_num);
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_param_dump_ipp_regs"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_dump_vlan_table(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_dump_vlan_table"));

	(void) npi_fflp_vlan_tbl_dump(NXGE_DEV_NPI_HANDLE(nxgep));

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_dump_vlan_table"));
	return (0);
}

/* ARGSUSED */
static int
nxge_param_dump_rdc_table(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	uint8_t	table;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_dump_rdc_table"));
	for (table = 0; table < NXGE_MAX_RDC_GROUPS; table++) {
		(void) npi_rxdma_dump_rdc_table(NXGE_DEV_NPI_HANDLE(nxgep),
		    table);
	}

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_dump_rdc_table"));
	return (0);
}

typedef struct block_info {
	char		*name;
	uint32_t	offset;
} block_info_t;

block_info_t reg_block[] = {
	{"PIO",		PIO},
	{"FZC_PIO",	FZC_PIO},
	{"FZC_XMAC",	FZC_MAC},
	{"FZC_IPP",	FZC_IPP},
	{"FFLP",	FFLP},
	{"FZC_FFLP",	FZC_FFLP},
	{"PIO_VADDR",	PIO_VADDR},
	{"ZCP",	ZCP},
	{"FZC_ZCP",	FZC_ZCP},
	{"DMC",	DMC},
	{"FZC_DMC",	FZC_DMC},
	{"TXC",	TXC},
	{"FZC_TXC",	FZC_TXC},
	{"PIO_LDSV",	PIO_LDSV},
	{"PIO_LDGIM",	PIO_LDGIM},
	{"PIO_IMASK0",	PIO_IMASK0},
	{"PIO_IMASK1",	PIO_IMASK1},
	{"FZC_PROM",	FZC_PROM},
	{"END",	ALL_FF_32},
};

/* ARGSUSED */
static int
nxge_param_dump_ptrs(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t cp)
{
	uint_t			print_len, buf_len;
	p_mblk_t		np;
	int			rdc, tdc, block;
	uint64_t		base;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	int			buff_alloc_size = NXGE_NDD_INFODUMP_BUFF_8K;
	p_tx_ring_t 		*tx_rings;
	p_rx_rcr_rings_t 	rx_rcr_rings;
	p_rx_rcr_ring_t		*rcr_rings;
	p_rx_rbr_rings_t 	rx_rbr_rings;
	p_rx_rbr_ring_t		*rbr_rings;

	NXGE_DEBUG_MSG((nxgep, IOC_CTL,
	    "==> nxge_param_dump_ptrs"));

	(void) mi_mpprintf(mp, "ptr information for Port\t %d \n",
	    nxgep->function_num);

	if ((np = allocb(buff_alloc_size, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, "%s\n", "out of buffer");
		return (0);
	}

	buf_len = buff_alloc_size;
	mp->b_cont = np;
	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	rx_rcr_rings = nxgep->rx_rcr_rings;
	rcr_rings = rx_rcr_rings->rcr_rings;
	rx_rbr_rings = nxgep->rx_rbr_rings;
	rbr_rings = rx_rbr_rings->rbr_rings;
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "nxgep (nxge_t) $%p\n"
	    "dev_regs (dev_regs_t) $%p\n",
	    (void *)nxgep, (void *)nxgep->dev_regs);

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);

	/* do register pointers */
	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "reg base (npi_reg_ptr_t) $%p\t "
	    "pci reg (npi_reg_ptr_t) $%p\n",
	    (void *)nxgep->dev_regs->nxge_regp,
	    (void *)nxgep->dev_regs->nxge_pciregp);

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "\nBlock \t Offset \n");

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	block = 0;
#if defined(__i386)
	base = (uint64_t)(uint32_t)nxgep->dev_regs->nxge_regp;
#else
	base = (uint64_t)nxgep->dev_regs->nxge_regp;
#endif
	while (reg_block[block].offset != ALL_FF_32) {
		print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
		    "%9s\t 0x%llx\n",
		    reg_block[block].name,
		    (unsigned long long)(reg_block[block].offset + base));
		ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
		block++;
	}

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "\nRDC\t rcrp (rx_rcr_ring_t)\t "
	    "rbrp (rx_rbr_ring_t)\n");

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);

	for (rdc = 0; rdc < p_cfgp->max_rdcs; rdc++) {
		print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
		    " %d\t  $%p\t\t   $%p\n",
		    rdc, (void *)rcr_rings[rdc],
		    (void *)rbr_rings[rdc]);
		ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	}

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
	    "\nTDC\t tdcp (tx_ring_t)\n");

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	tx_rings = nxgep->tx_rings->rings;
	for (tdc = 0; tdc < p_cfgp->tdc.count; tdc++) {
		print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len,
		    " %d\t  $%p\n", tdc, (void *)tx_rings[tdc]);
		ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	}

	print_len = snprintf((char *)((mblk_t *)np)->b_wptr, buf_len, "\n\n");

	ADVANCE_PRINT_BUFFER(np, print_len, buf_len);
	NXGE_DEBUG_MSG((nxgep, IOC_CTL, "<== nxge_param_dump_ptrs"));
	return (0);
}


/* ARGSUSED */
int
nxge_nd_get_names(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t param)
{
	ND		*nd;
	NDE		*nde;
	char		*rwtag;
	boolean_t	get_ok, set_ok;
	size_t		param_len;
	int		status = 0;

	nd = (ND *)param;
	if (!nd)
		return (ENOENT);

	for (nde = nd->nd_tbl; nde->nde_name; nde++) {
		get_ok = (nde->nde_get_pfi != nxge_get_default) &&
		    (nde->nde_get_pfi != NULL);
		set_ok = (nde->nde_set_pfi != nxge_set_default) &&
		    (nde->nde_set_pfi != NULL);
		if (get_ok) {
			if (set_ok)
				rwtag = "read and write";
			else
				rwtag = "read only";
		} else if (set_ok)
			rwtag = "write only";
		else {
			continue;
		}
		param_len = strlen(rwtag);
		param_len += strlen(nde->nde_name);
		param_len += 4;

		(void) mi_mpprintf(mp, "%s (%s)", nde->nde_name, rwtag);
	}
	return (status);
}

/* ARGSUSED */
int
nxge_get_default(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, caddr_t data)
{
	return (EACCES);
}

/* ARGSUSED */
int
nxge_set_default(p_nxge_t nxgep, queue_t *q, p_mblk_t mp, char *value,
    caddr_t data)
{
	return (EACCES);
}

boolean_t
nxge_param_link_update(p_nxge_t nxgep)
{
	p_nxge_param_t 		param_arr;
	nxge_param_index_t 	i;
	boolean_t 		update_xcvr;
	boolean_t 		update_dev;
	int 			instance;
	boolean_t 		status = B_TRUE;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_param_link_update"));

	param_arr = nxgep->param_arr;
	instance = nxgep->instance;
	update_xcvr = B_FALSE;
	for (i = param_anar_1000fdx; i < param_anar_asmpause; i++) {
		update_xcvr |= param_arr[i].value;
	}

	if (update_xcvr) {
		update_xcvr = B_FALSE;
		for (i = param_autoneg; i < param_enable_ipg0; i++) {
			update_xcvr |=
			    (param_arr[i].value != param_arr[i].old_value);
			param_arr[i].old_value = param_arr[i].value;
		}
		if (update_xcvr) {
			NXGE_DEBUG_MSG((nxgep, NDD_CTL,
			    "==> nxge_param_link_update: update xcvr"));
			RW_ENTER_WRITER(&nxgep->filter_lock);
			(void) nxge_link_monitor(nxgep, LINK_MONITOR_STOP);
			(void) nxge_link_init(nxgep);
			(void) nxge_mac_init(nxgep);
			(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);
			RW_EXIT(&nxgep->filter_lock);
		}
	} else {
		cmn_err(CE_WARN, " Last setting will leave nxge%d with "
		    " no link capabilities.", instance);
		cmn_err(CE_WARN, " Restoring previous setting.");
		for (i = param_anar_1000fdx; i < param_anar_asmpause; i++)
			param_arr[i].value = param_arr[i].old_value;
	}

	update_dev = B_FALSE;

	if (update_dev) {
		RW_ENTER_WRITER(&nxgep->filter_lock);
		NXGE_DEBUG_MSG((nxgep, NDD_CTL,
		    "==> nxge_param_link_update: update dev"));
		(void) nxge_rx_mac_disable(nxgep);
		(void) nxge_tx_mac_disable(nxgep);
		(void) nxge_tx_mac_enable(nxgep);
		(void) nxge_rx_mac_enable(nxgep);
		RW_EXIT(&nxgep->filter_lock);
	}

nxge_param_hw_update_exit:
	NXGE_DEBUG_MSG((nxgep, DDI_CTL,
	    "<== nxge_param_link_update status = 0x%08x", status));
	return (status);
}

/*
 * synchronize the  adv* and en* parameters.
 *
 * See comments in <sys/dld.h> for details of the *_en_*
 * parameters.  The usage of ndd for setting adv parameters will
 * synchronize all the en parameters with the nxge parameters,
 * implicitly disabling any settings made via dladm.
 */
static void
nxge_param_sync(p_nxge_t nxgep)
{
	p_nxge_param_t	param_arr;
	param_arr = nxgep->param_arr;

	nxgep->param_en_pause	= param_arr[param_anar_pause].value;
	nxgep->param_en_1000fdx	= param_arr[param_anar_1000fdx].value;
	nxgep->param_en_100fdx	= param_arr[param_anar_100fdx].value;
	nxgep->param_en_10fdx	= param_arr[param_anar_10fdx].value;
}

/* ARGSUSED */
int
nxge_dld_get_ip_opt(p_nxge_t nxgep, caddr_t cp)
{
	uint32_t status, cfg_value;
	p_nxge_param_t pa = (p_nxge_param_t)cp;
	tcam_class_t class;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "==> nxge_dld_get_ip_opt"));

	/* do the actual hw setup  */
	class = nxge_class_name_2value(nxgep, pa->name);
	if (class == -1)
		return (EINVAL);

	cfg_value = 0;
	status = nxge_fflp_ip_class_config_get(nxgep, class, &cfg_value);
	if (status != NXGE_OK)
		return (EINVAL);

	/* Filter out the allowed bits */
	cfg_value &= (NXGE_CLASS_FLOW_USE_PORTNUM | NXGE_CLASS_FLOW_USE_L2DA |
	    NXGE_CLASS_FLOW_USE_VLAN | NXGE_CLASS_FLOW_USE_PROTO |
	    NXGE_CLASS_FLOW_USE_IPSRC | NXGE_CLASS_FLOW_USE_IPDST |
	    NXGE_CLASS_FLOW_USE_SRC_PORT | NXGE_CLASS_FLOW_USE_DST_PORT);

	NXGE_DEBUG_MSG((nxgep, NDD_CTL,
	    "nxge_param_get_ip_opt_get %x ", cfg_value));

	pa->value = cfg_value;

	NXGE_DEBUG_MSG((nxgep, NDD_CTL, "<== nxge_param_get_ip_opt status "));
	return (0);
}
