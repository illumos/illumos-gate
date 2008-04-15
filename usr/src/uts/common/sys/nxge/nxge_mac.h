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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_MAC_H
#define	_SYS_NXGE_NXGE_MAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_mac_hw.h>
#include <npi_mac.h>

#define	NXGE_MTU_DEFAULT_MAX	1522	/* 0x5f2 */
#define	NXGE_DEFAULT_MTU	1500	/* 0x5dc */
#define	NXGE_MIN_MAC_FRAMESIZE	64
#define	NXGE_MAX_MAC_FRAMESIZE	NXGE_MTU_DEFAULT_MAX
/*
 * Maximum MTU: maximum frame size supported by the
 * hardware (9216) - (22).
 * (22 = ether header size (including VLAN) - CRC size (4)).
 */
#define	NXGE_EHEADER_VLAN_CRC	(sizeof (struct ether_header) + ETHERFCSL + 4)
#define	NXGE_MAXIMUM_MTU	(TX_JUMBO_MTU - NXGE_EHEADER_VLAN_CRC)

#define	NXGE_XMAC_TX_INTRS	(ICFG_XMAC_TX_ALL & \
					~(ICFG_XMAC_TX_FRAME_XMIT |\
					ICFG_XMAC_TX_BYTE_CNT_EXP |\
					ICFG_XMAC_TX_FRAME_CNT_EXP))
#define	NXGE_XMAC_RX_INTRS	(ICFG_XMAC_RX_ALL & \
					~(ICFG_XMAC_RX_FRAME_RCVD |\
					ICFG_XMAC_RX_OCT_CNT_EXP |\
					ICFG_XMAC_RX_HST_CNT1_EXP |\
					ICFG_XMAC_RX_HST_CNT2_EXP |\
					ICFG_XMAC_RX_HST_CNT3_EXP |\
					ICFG_XMAC_RX_HST_CNT4_EXP |\
					ICFG_XMAC_RX_HST_CNT5_EXP |\
					ICFG_XMAC_RX_HST_CNT6_EXP |\
					ICFG_XMAC_RX_BCAST_CNT_EXP |\
					ICFG_XMAC_RX_MCAST_CNT_EXP |\
					ICFG_XMAC_RX_HST_CNT7_EXP))
#define	NXGE_BMAC_TX_INTRS	(ICFG_BMAC_TX_ALL & \
					~(ICFG_BMAC_TX_FRAME_SENT |\
					ICFG_BMAC_TX_BYTE_CNT_EXP |\
					ICFG_BMAC_TX_FRAME_CNT_EXP))
#define	NXGE_BMAC_RX_INTRS	(ICFG_BMAC_RX_ALL & \
					~(ICFG_BMAC_RX_FRAME_RCVD |\
					ICFG_BMAC_RX_FRAME_CNT_EXP |\
					ICFG_BMAC_RX_BYTE_CNT_EXP))

typedef enum  {
	LINK_NO_CHANGE,
	LINK_IS_UP,
	LINK_IS_DOWN
} nxge_link_state_t;

/* Common MAC statistics */

typedef	struct _nxge_mac_stats {
	/*
	 * MTU size
	 */
	uint32_t	mac_mtu;
	uint16_t	rev_id;

	/*
	 * Transciever state informations.
	 */
	uint32_t	xcvr_inits;
	xcvr_inuse_t	xcvr_inuse;
	uint32_t	xcvr_portn;
	uint32_t	xcvr_id;
	uint32_t	serdes_inits;
	uint32_t	serdes_portn;
	uint32_t	cap_autoneg;
	uint32_t	cap_10gfdx;
	uint32_t	cap_10ghdx;
	uint32_t	cap_1000fdx;
	uint32_t	cap_1000hdx;
	uint32_t	cap_100T4;
	uint32_t	cap_100fdx;
	uint32_t	cap_100hdx;
	uint32_t	cap_10fdx;
	uint32_t	cap_10hdx;
	uint32_t	cap_asmpause;
	uint32_t	cap_pause;

	/*
	 * Advertised capabilities.
	 */
	uint32_t	adv_cap_autoneg;
	uint32_t	adv_cap_10gfdx;
	uint32_t	adv_cap_10ghdx;
	uint32_t	adv_cap_1000fdx;
	uint32_t	adv_cap_1000hdx;
	uint32_t	adv_cap_100T4;
	uint32_t	adv_cap_100fdx;
	uint32_t	adv_cap_100hdx;
	uint32_t	adv_cap_10fdx;
	uint32_t	adv_cap_10hdx;
	uint32_t	adv_cap_asmpause;
	uint32_t	adv_cap_pause;

	/*
	 * Link partner capabilities.
	 */
	uint32_t	lp_cap_autoneg;
	uint32_t	lp_cap_10gfdx;
	uint32_t	lp_cap_10ghdx;
	uint32_t	lp_cap_1000fdx;
	uint32_t	lp_cap_1000hdx;
	uint32_t	lp_cap_100T4;
	uint32_t	lp_cap_100fdx;
	uint32_t	lp_cap_100hdx;
	uint32_t	lp_cap_10fdx;
	uint32_t	lp_cap_10hdx;
	uint32_t	lp_cap_asmpause;
	uint32_t	lp_cap_pause;

	/*
	 * Physical link statistics.
	 */
	uint32_t	link_T4;
	uint32_t	link_speed;
	uint32_t	link_duplex;
	uint32_t	link_asmpause;
	uint32_t	link_pause;
	uint32_t	link_up;

	/* Promiscous mode */
	boolean_t	promisc;
} nxge_mac_stats_t;

/* XMAC Statistics */

typedef	struct _nxge_xmac_stats {
	uint32_t tx_frame_cnt;
	uint32_t tx_underflow_err;
	uint32_t tx_maxpktsize_err;
	uint32_t tx_overflow_err;
	uint32_t tx_fifo_xfr_err;
	uint64_t tx_byte_cnt;
	uint32_t rx_frame_cnt;
	uint32_t rx_underflow_err;
	uint32_t rx_overflow_err;
	uint32_t rx_crc_err_cnt;
	uint32_t rx_len_err_cnt;
	uint32_t rx_viol_err_cnt;
	uint64_t rx_byte_cnt;
	uint64_t rx_hist1_cnt;
	uint64_t rx_hist2_cnt;
	uint64_t rx_hist3_cnt;
	uint64_t rx_hist4_cnt;
	uint64_t rx_hist5_cnt;
	uint64_t rx_hist6_cnt;
	uint64_t rx_hist7_cnt;
	uint64_t rx_broadcast_cnt;
	uint64_t rx_mult_cnt;
	uint32_t rx_frag_cnt;
	uint32_t rx_frame_align_err_cnt;
	uint32_t rx_linkfault_err_cnt;
	uint32_t rx_remotefault_err;
	uint32_t rx_localfault_err;
	uint32_t rx_pause_cnt;
	uint32_t tx_pause_state;
	uint32_t tx_nopause_state;
	uint32_t xpcs_deskew_err_cnt;
	uint32_t xpcs_ln0_symbol_err_cnt;
	uint32_t xpcs_ln1_symbol_err_cnt;
	uint32_t xpcs_ln2_symbol_err_cnt;
	uint32_t xpcs_ln3_symbol_err_cnt;
} nxge_xmac_stats_t, *p_nxge_xmac_stats_t;

/* BMAC Statistics */

typedef	struct _nxge_bmac_stats {
	uint64_t tx_frame_cnt;
	uint32_t tx_underrun_err;
	uint32_t tx_max_pkt_err;
	uint64_t tx_byte_cnt;
	uint64_t rx_frame_cnt;
	uint64_t rx_byte_cnt;
	uint32_t rx_overflow_err;
	uint32_t rx_align_err_cnt;
	uint32_t rx_crc_err_cnt;
	uint32_t rx_len_err_cnt;
	uint32_t rx_viol_err_cnt;
	uint32_t rx_pause_cnt;
	uint32_t tx_pause_state;
	uint32_t tx_nopause_state;
} nxge_bmac_stats_t, *p_nxge_bmac_stats_t;

typedef struct _hash_filter_t {
	uint_t hash_ref_cnt;
	uint16_t hash_filter_regs[NMCFILTER_REGS];
	uint32_t hash_bit_ref_cnt[NMCFILTER_BITS];
} hash_filter_t, *p_hash_filter_t;

typedef	struct _nxge_mac {
	uint8_t			portnum;
	nxge_port_t		porttype;
	nxge_port_mode_t	portmode;
	nxge_linkchk_mode_t	linkchkmode;
	boolean_t		is_jumbo;
	uint32_t		tx_config;
	uint32_t		rx_config;
	uint32_t		xif_config;
	uint32_t		tx_iconfig;
	uint32_t		rx_iconfig;
	uint32_t		ctl_iconfig;
	uint16_t		minframesize;
	uint16_t		maxframesize;
	uint16_t		maxburstsize;
	uint16_t		ctrltype;
	uint16_t		pa_size;
	uint8_t			ipg[3];
	struct ether_addr	mac_addr;
	struct ether_addr	alt_mac_addr[MAC_MAX_ALT_ADDR_ENTRY];
	struct ether_addr	mac_addr_filter;
	uint16_t		hashtab[MAC_MAX_HASH_ENTRY];
	hostinfo_t		hostinfo[MAC_MAX_HOST_INFO_ENTRY];
	nxge_mac_stats_t	*mac_stats;
	nxge_xmac_stats_t	*xmac_stats;
	nxge_bmac_stats_t	*bmac_stats;
	uint32_t		default_mtu;
} nxge_mac_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_MAC_H */
