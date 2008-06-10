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

#ifndef	_SYS_MAC_NXGE_MAC_HW_H
#define	_SYS_MAC_NXGE_MAC_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_defs.h>

/* -------------------------- From May's template --------------------------- */

#define	NXGE_1GETHERMIN			255
#define	NXGE_ETHERMIN			97
#define	NXGE_MAX_HEADER			250

/* Hardware reset */
typedef enum  {
	NXGE_TX_DISABLE,			/* Disable Tx side */
	NXGE_RX_DISABLE,			/* Disable Rx side */
	NXGE_CHIP_RESET				/* Full chip reset */
} nxge_reset_t;

#define	NXGE_DELAY_AFTER_TXRX		10000	/* 10ms after idling rx/tx */
#define	NXGE_DELAY_AFTER_RESET		1000	/* 1ms after the reset */
#define	NXGE_DELAY_AFTER_EE_RESET	10000	/* 10ms after EEPROM reset */
#define	NXGE_DELAY_AFTER_LINK_RESET	13	/* 13 Us after link reset */
#define	NXGE_LINK_RESETS		8	/* Max PHY resets to wait for */
						/* linkup */

#define	FILTER_M_CTL 			0xDCEF1
#define	HASH_BITS			8
#define	NMCFILTER_BITS			(1 << HASH_BITS)
#define	HASH_REG_WIDTH			16
#define	BROADCAST_HASH_WORD		0x0f
#define	BROADCAST_HASH_BIT		0x8000
#define	NMCFILTER_REGS			NMCFILTER_BITS / HASH_REG_WIDTH
					/* Number of multicast filter regs */

/* -------------------------------------------------------------------------- */

#define	XMAC_PORT_0			0
#define	XMAC_PORT_1			1
#define	BMAC_PORT_0			2
#define	BMAC_PORT_1			3

#define	MAC_RESET_WAIT			10	/* usecs */

#define	MAC_ADDR_REG_MASK		0xFFFF

/*
 * Neptune port PHY type and Speed encoding.
 *
 * Per port, 4 bits are reserved for port speed (1G/10G) and 4 bits
 * are reserved for port PHY type (Copper/Fibre). Bits 0 thru 3 are for port0
 * speed, bits 4 thru 7 are for port1 speed, bits 8 thru 11 are for port2 speed
 * and bits 12 thru 15 are for port3 speed. Thus, the first 16 bits hold the
 * speed encoding for the 4 ports. The next 16 bits (16 thru 31) hold the phy
 * type encoding for the ports 0 thru 3.
 *
 *  p3phy  p2phy  p1phy  p0phy  p3spd p2spd  p1spd p0spd
 *    |      |      |      |      |     |      |     |
 *   ---    ---    ---    ---    ---   ---    ---   ---
 *  /   \  /   \  /   \  /   \  /   \ /   \  /   \ /   \
 * 31..28 27..24 23..20 19..16 15..12 11.. 8 7.. 4 3.. 0
 */

#define	NXGE_PORT_SPD_NONE	0x0
#define	NXGE_PORT_SPD_1G	0x1
#define	NXGE_PORT_SPD_10G	0x2
#define	NXGE_PORT_SPD_RSVD	0x7

#define	NXGE_PHY_NONE		0x0
#define	NXGE_PHY_COPPER		0x1
#define	NXGE_PHY_FIBRE		0x2
#define	NXGE_PHY_SERDES		0x3
#define	NXGE_PHY_RGMII_FIBER	0x4
#define	NXGE_PHY_TN1010		0x5
#define	NXGE_PHY_RSVD		0x7

#define	NXGE_PORT_SPD_SHIFT	0
#define	NXGE_PORT_SPD_MASK	0x0f

#define	NXGE_PHY_SHIFT		16
#define	NXGE_PHY_MASK		0x0f0000

/*
 * "xgc" as a possible value for the device property "phy-type"
 * was intended for the portmode == PORT_10G_COPPER case. But
 * the first 10G copper network I/O device available is the
 * TN1010 based copper XAUI card and we use PORT_10G_TN1010 or
 * PORT_1G_TN1010 as the portmode, so PORT_10G_COPPER is never
 * used as portmode. The driver code related to PORT_10G_COPPER
 * is kept in the driver as a place holder for possble future
 * 10G copper devices.
 */
#define	NXGE_PORT_10G_COPPER	(NXGE_PORT_SPD_10G |	\
	(NXGE_PHY_COPPER << NXGE_PHY_SHIFT))

#define	NXGE_PORT_1G_COPPER	(NXGE_PORT_SPD_1G |	\
	(NXGE_PHY_COPPER << NXGE_PHY_SHIFT))
#define	NXGE_PORT_1G_FIBRE	(NXGE_PORT_SPD_1G |	\
	(NXGE_PHY_FIBRE << NXGE_PHY_SHIFT))
#define	NXGE_PORT_10G_FIBRE	(NXGE_PORT_SPD_10G |	\
	(NXGE_PHY_FIBRE << NXGE_PHY_SHIFT))
#define	NXGE_PORT_1G_SERDES	(NXGE_PORT_SPD_1G |	\
	(NXGE_PHY_SERDES << NXGE_PHY_SHIFT))
#define	NXGE_PORT_10G_SERDES	(NXGE_PORT_SPD_10G |	\
	(NXGE_PHY_SERDES << NXGE_PHY_SHIFT))
#define	NXGE_PORT_1G_RGMII_FIBER	(NXGE_PORT_SPD_1G |	\
	(NXGE_PHY_RGMII_FIBER << NXGE_PHY_SHIFT))

/* The speed of TN1010 will be determined by each nxge instance */
#define	NXGE_PORT_TN1010	(NXGE_PORT_SPD_NONE |	\
	(NXGE_PHY_TN1010 << NXGE_PHY_SHIFT))

#define	NXGE_PORT_NONE		(NXGE_PORT_SPD_NONE |	\
	(NXGE_PHY_NONE << NXGE_PHY_SHIFT))
#define	NXGE_PORT_RSVD		(NXGE_PORT_SPD_RSVD |	\
	(NXGE_PHY_RSVD << NXGE_PHY_SHIFT))

#define	NXGE_PORT_TYPE_MASK	(NXGE_PORT_SPD_MASK | NXGE_PHY_MASK)

/* number of bits used for phy/spd encoding per port */
#define	NXGE_PORT_TYPE_SHIFT	4

/* Network Modes */

typedef enum nxge_network_mode {
	NET_2_10GE_FIBER = 1,
	NET_2_10GE_COPPER,
	NET_1_10GE_FIBER_3_1GE_COPPER,
	NET_1_10GE_COPPER_3_1GE_COPPER,
	NET_1_10GE_FIBER_3_1GE_FIBER,
	NET_1_10GE_COPPER_3_1GE_FIBER,
	NET_2_1GE_FIBER_2_1GE_COPPER,
	NET_QGE_FIBER,
	NET_QGE_COPPER
} nxge_network_mode_t;

typedef	enum nxge_port {
	PORT_TYPE_XMAC = 1,
	PORT_TYPE_BMAC,
	PORT_TYPE_LOGICAL
} nxge_port_t;

typedef	enum nxge_port_mode {
	PORT_1G_COPPER = 1,
	PORT_1G_FIBER,
	PORT_10G_COPPER,
	PORT_10G_FIBER,
	PORT_10G_SERDES,	/* Port0 or 1 of Alonso or Monza */
	PORT_1G_SERDES,		/* Port0 or 1 of Alonso or Monza */
	PORT_1G_RGMII_FIBER,	/* Port2 or 3 of Alonso or ARTM  */
	PORT_HSP_MODE,
	PORT_LOGICAL,
	PORT_1G_TN1010,		/* Teranetics PHY in 1G mode */
	PORT_10G_TN1010		/* Teranetics PHY in 10G mode */
} nxge_port_mode_t;

typedef	enum nxge_linkchk_mode {
	LINKCHK_INTR = 1,
	LINKCHK_TIMER
} nxge_linkchk_mode_t;

typedef enum {
	LINK_INTR_STOP,
	LINK_INTR_START
} link_intr_enable_t, *link_intr_enable_pt;

typedef	enum {
	LINK_MONITOR_STOP,
	LINK_MONITOR_START,
	LINK_MONITOR_STOPPING
} link_mon_enable_t, *link_mon_enable_pt;

typedef enum {
	NO_XCVR,
	INT_MII_XCVR,
	EXT_MII_XCVR,
	PCS_XCVR,
	XPCS_XCVR,
	HSP_XCVR,
	LOGICAL_XCVR
} xcvr_inuse_t;

/* macros for port offset calculations */

#define	PORT_1_OFFSET			0x6000
#define	PORT_GT_1_OFFSET		0x4000

/* XMAC address macros */

#define	XMAC_ADDR_OFFSET_0		0
#define	XMAC_ADDR_OFFSET_1		0x6000

#define	XMAC_ADDR_OFFSET(port_num)\
	(XMAC_ADDR_OFFSET_0 + ((port_num) * PORT_1_OFFSET))

#define	XMAC_REG_ADDR(port_num, reg)\
	(FZC_MAC + (XMAC_ADDR_OFFSET(port_num)) + (reg))

#define	XMAC_PORT_ADDR(port_num)\
	(FZC_MAC + XMAC_ADDR_OFFSET(port_num))

/* BMAC address macros */

#define	BMAC_ADDR_OFFSET_2		0x0C000
#define	BMAC_ADDR_OFFSET_3		0x10000

#define	BMAC_ADDR_OFFSET(port_num)\
	(BMAC_ADDR_OFFSET_2 + (((port_num) - 2) * PORT_GT_1_OFFSET))

#define	BMAC_REG_ADDR(port_num, reg)\
	(FZC_MAC + (BMAC_ADDR_OFFSET(port_num)) + (reg))

#define	BMAC_PORT_ADDR(port_num)\
	(FZC_MAC + BMAC_ADDR_OFFSET(port_num))

/* PCS address macros */

#define	PCS_ADDR_OFFSET_0		0x04000
#define	PCS_ADDR_OFFSET_1		0x0A000
#define	PCS_ADDR_OFFSET_2		0x0E000
#define	PCS_ADDR_OFFSET_3		0x12000

#define	PCS_ADDR_OFFSET(port_num)\
	((port_num <= 1) ? \
	(PCS_ADDR_OFFSET_0 + (port_num) * PORT_1_OFFSET) : \
	(PCS_ADDR_OFFSET_2 + (((port_num) - 2) * PORT_GT_1_OFFSET)))

#define	PCS_REG_ADDR(port_num, reg)\
	(FZC_MAC + (PCS_ADDR_OFFSET((port_num)) + (reg)))

#define	PCS_PORT_ADDR(port_num)\
	(FZC_MAC + (PCS_ADDR_OFFSET(port_num)))

/* XPCS address macros */

#define	XPCS_ADDR_OFFSET_0		0x02000
#define	XPCS_ADDR_OFFSET_1		0x08000
#define	XPCS_ADDR_OFFSET(port_num)\
	(XPCS_ADDR_OFFSET_0 + ((port_num) * PORT_1_OFFSET))

#define	XPCS_ADDR(port_num, reg)\
	(FZC_MAC + (XPCS_ADDR_OFFSET((port_num)) + (reg)))

#define	XPCS_PORT_ADDR(port_num)\
	(FZC_MAC + (XPCS_ADDR_OFFSET(port_num)))

/* ESR address macro */
#define	ESR_ADDR_OFFSET		0x14000
#define	ESR_ADDR(reg)\
	(FZC_MAC + (ESR_ADDR_OFFSET) + (reg))

/* MIF address macros */
#define	MIF_ADDR_OFFSET		0x16000
#define	MIF_ADDR(reg)\
	(FZC_MAC + (MIF_ADDR_OFFSET) + (reg))

/* BMAC registers offset */
#define	BTXMAC_SW_RST_REG		0x000	/* TX MAC software reset */
#define	BRXMAC_SW_RST_REG		0x008	/* RX MAC software reset */
#define	MAC_SEND_PAUSE_REG		0x010	/* send pause command */
#define	BTXMAC_STATUS_REG		0x020	/* TX MAC status */
#define	BRXMAC_STATUS_REG		0x028	/* RX MAC status */
#define	BMAC_CTRL_STAT_REG		0x030	/* MAC control status */
#define	BTXMAC_STAT_MSK_REG		0x040	/* TX MAC mask */
#define	BRXMAC_STAT_MSK_REG		0x048	/* RX MAC mask */
#define	BMAC_C_S_MSK_REG		0x050	/* MAC control mask */
#define	TXMAC_CONFIG_REG		0x060	/* TX MAC config */
/* cfg register bitmap */

typedef union _btxmac_config_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsrvd	: 22;
			uint32_t hdx_ctrl2	: 1;
			uint32_t no_fcs	: 1;
			uint32_t hdx_ctrl	: 7;
			uint32_t txmac_enable	: 1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t txmac_enable	: 1;
			uint32_t hdx_ctrl	: 7;
			uint32_t no_fcs	: 1;
			uint32_t hdx_ctrl2	: 1;
			uint32_t rsrvd	: 22;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} btxmac_config_t, *p_btxmac_config_t;

#define	RXMAC_CONFIG_REG		0x068	/* RX MAC config */

typedef union _brxmac_config_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsrvd	: 20;
			uint32_t mac_reg_sw_test : 2;
			uint32_t mac2ipp_pkt_cnt_en : 1;
			uint32_t rx_crs_extend_en : 1;
			uint32_t error_chk_dis	: 1;
			uint32_t addr_filter_en	: 1;
			uint32_t hash_filter_en	: 1;
			uint32_t promiscuous_group	: 1;
			uint32_t promiscuous	: 1;
			uint32_t strip_fcs	: 1;
			uint32_t strip_pad	: 1;
			uint32_t rxmac_enable	: 1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t rxmac_enable	: 1;
			uint32_t strip_pad	: 1;
			uint32_t strip_fcs	: 1;
			uint32_t promiscuous	: 1;
			uint32_t promiscuous_group	: 1;
			uint32_t hash_filter_en	: 1;
			uint32_t addr_filter_en	: 1;
			uint32_t error_chk_dis	: 1;
			uint32_t rx_crs_extend_en : 1;
			uint32_t mac2ipp_pkt_cnt_en : 1;
			uint32_t mac_reg_sw_test : 2;
			uint32_t rsrvd	: 20;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} brxmac_config_t, *p_brxmac_config_t;

#define	MAC_CTRL_CONFIG_REG		0x070	/* MAC control config */
#define	MAC_XIF_CONFIG_REG		0x078	/* XIF config */

typedef union _bxif_config_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsrvd2		: 24;
			uint32_t sel_clk_25mhz	: 1;
			uint32_t led_polarity	: 1;
			uint32_t force_led_on	: 1;
			uint32_t used		: 1;
			uint32_t gmii_mode	: 1;
			uint32_t rsrvd		: 1;
			uint32_t loopback	: 1;
			uint32_t tx_output_en	: 1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t tx_output_en	: 1;
			uint32_t loopback	: 1;
			uint32_t rsrvd		: 1;
			uint32_t gmii_mode	: 1;
			uint32_t used		: 1;
			uint32_t force_led_on	: 1;
			uint32_t led_polarity	: 1;
			uint32_t sel_clk_25mhz	: 1;
			uint32_t rsrvd2		: 24;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} bxif_config_t, *p_bxif_config_t;

#define	BMAC_MIN_REG			0x0a0	/* min frame size */
#define	BMAC_MAX_REG			0x0a8	/* max frame size reg */
#define	MAC_PA_SIZE_REG			0x0b0	/* num of preamble bytes */
#define	MAC_CTRL_TYPE_REG		0x0c8	/* type field of MAC ctrl */
#define	BMAC_ADDR0_REG			0x100	/* MAC unique ad0 reg (HI 0) */
#define	BMAC_ADDR1_REG			0x108	/* MAC unique ad1 reg */
#define	BMAC_ADDR2_REG			0x110	/* MAC unique ad2 reg */
#define	BMAC_ADDR3_REG			0x118	/* MAC alt ad0 reg (HI 1) */
#define	BMAC_ADDR4_REG			0x120	/* MAC alt ad0 reg */
#define	BMAC_ADDR5_REG			0x128	/* MAC alt ad0 reg */
#define	BMAC_ADDR6_REG			0x130	/* MAC alt ad1 reg (HI 2) */
#define	BMAC_ADDR7_REG			0x138	/* MAC alt ad1 reg */
#define	BMAC_ADDR8_REG			0x140	/* MAC alt ad1 reg */
#define	BMAC_ADDR9_REG			0x148	/* MAC alt ad2 reg (HI 3) */
#define	BMAC_ADDR10_REG			0x150	/* MAC alt ad2 reg */
#define	BMAC_ADDR11_REG			0x158	/* MAC alt ad2 reg */
#define	BMAC_ADDR12_REG			0x160	/* MAC alt ad3 reg (HI 4) */
#define	BMAC_ADDR13_REG			0x168	/* MAC alt ad3 reg */
#define	BMAC_ADDR14_REG			0x170	/* MAC alt ad3 reg */
#define	BMAC_ADDR15_REG			0x178	/* MAC alt ad4 reg (HI 5) */
#define	BMAC_ADDR16_REG			0x180	/* MAC alt ad4 reg */
#define	BMAC_ADDR17_REG			0x188	/* MAC alt ad4 reg */
#define	BMAC_ADDR18_REG			0x190	/* MAC alt ad5 reg (HI 6) */
#define	BMAC_ADDR19_REG			0x198	/* MAC alt ad5 reg */
#define	BMAC_ADDR20_REG			0x1a0	/* MAC alt ad5 reg */
#define	BMAC_ADDR21_REG			0x1a8	/* MAC alt ad6 reg (HI 7) */
#define	BMAC_ADDR22_REG			0x1b0	/* MAC alt ad6 reg */
#define	BMAC_ADDR23_REG			0x1b8	/* MAC alt ad6 reg */
#define	MAC_FC_ADDR0_REG		0x268	/* FC frame addr0 (HI 0, p3) */
#define	MAC_FC_ADDR1_REG		0x270	/* FC frame addr1 */
#define	MAC_FC_ADDR2_REG		0x278	/* FC frame addr2 */
#define	MAC_ADDR_FILT0_REG		0x298	/* bits [47:32] (HI 0, p2) */
#define	MAC_ADDR_FILT1_REG		0x2a0	/* bits [31:16] */
#define	MAC_ADDR_FILT2_REG		0x2a8	/* bits [15:0]  */
#define	MAC_ADDR_FILT12_MASK_REG 	0x2b0	/* addr filter 2 & 1 mask */
#define	MAC_ADDR_FILT00_MASK_REG	0x2b8	/* addr filter 0 mask */
#define	MAC_HASH_TBL0_REG		0x2c0	/* hash table 0 reg */
#define	MAC_HASH_TBL1_REG		0x2c8	/* hash table 1 reg */
#define	MAC_HASH_TBL2_REG		0x2d0	/* hash table 2 reg */
#define	MAC_HASH_TBL3_REG		0x2d8	/* hash table 3 reg */
#define	MAC_HASH_TBL4_REG		0x2e0	/* hash table 4 reg */
#define	MAC_HASH_TBL5_REG		0x2e8	/* hash table 5 reg */
#define	MAC_HASH_TBL6_REG		0x2f0	/* hash table 6 reg */
#define	MAC_HASH_TBL7_REG		0x2f8	/* hash table 7 reg */
#define	MAC_HASH_TBL8_REG		0x300	/* hash table 8 reg */
#define	MAC_HASH_TBL9_REG		0x308	/* hash table 9 reg */
#define	MAC_HASH_TBL10_REG		0x310	/* hash table 10 reg */
#define	MAC_HASH_TBL11_REG		0x318	/* hash table 11 reg */
#define	MAC_HASH_TBL12_REG		0x320	/* hash table 12 reg */
#define	MAC_HASH_TBL13_REG		0x328	/* hash table 13 reg */
#define	MAC_HASH_TBL14_REG		0x330	/* hash table 14 reg */
#define	MAC_HASH_TBL15_REG		0x338	/* hash table 15 reg */
#define	RXMAC_FRM_CNT_REG		0x370	/* receive frame counter */
#define	MAC_LEN_ER_CNT_REG		0x378	/* length error counter */
#define	BMAC_AL_ER_CNT_REG		0x380	/* alignment error counter */
#define	BMAC_CRC_ER_CNT_REG		0x388	/* FCS error counter */
#define	BMAC_CD_VIO_CNT_REG		0x390	/* RX code violation err */
#define	BMAC_SM_REG			0x3a0	/* (ro) state machine reg */
#define	BMAC_ALTAD_CMPEN_REG		0x3f8	/* Alt addr compare enable */
#define	BMAC_HOST_INF0_REG		0x400	/* Host info */
						/* (own da, add filter, fc) */
#define	BMAC_HOST_INF1_REG		0x408	/* Host info (alt ad 0) */
#define	BMAC_HOST_INF2_REG		0x410	/* Host info (alt ad 1) */
#define	BMAC_HOST_INF3_REG		0x418	/* Host info (alt ad 2) */
#define	BMAC_HOST_INF4_REG		0x420	/* Host info (alt ad 3) */
#define	BMAC_HOST_INF5_REG		0x428	/* Host info (alt ad 4) */
#define	BMAC_HOST_INF6_REG		0x430	/* Host info (alt ad 5) */
#define	BMAC_HOST_INF7_REG		0x438	/* Host info (alt ad 6) */
#define	BMAC_HOST_INF8_REG		0x440	/* Host info (hash hit, miss) */
#define	BTXMAC_BYTE_CNT_REG		0x448	/* Tx byte count */
#define	BTXMAC_FRM_CNT_REG		0x450	/* frame count */
#define	BRXMAC_BYTE_CNT_REG		0x458	/* Rx byte count */
/* x ranges from 0 to 6 (BMAC_MAX_ALT_ADDR_ENTRY - 1) */
#define	BMAC_ALT_ADDR0N_REG_ADDR(x)	(BMAC_ADDR3_REG + (x) * 24)
#define	BMAC_ALT_ADDR1N_REG_ADDR(x)	(BMAC_ADDR3_REG + 8 + (x) * 24)
#define	BMAC_ALT_ADDR2N_REG_ADDR(x)	(BMAC_ADDR3_REG + 0x10 + (x) * 24)
#define	BMAC_HASH_TBLN_REG_ADDR(x)	(MAC_HASH_TBL0_REG + (x) * 8)
#define	BMAC_HOST_INFN_REG_ADDR(x)	(BMAC_HOST_INF0_REG + (x) * 8)

/* XMAC registers offset */
#define	XTXMAC_SW_RST_REG		0x000	/* XTX MAC soft reset */
#define	XRXMAC_SW_RST_REG		0x008	/* XRX MAC soft reset */
#define	XTXMAC_STATUS_REG		0x020	/* XTX MAC status */
#define	XRXMAC_STATUS_REG		0x028	/* XRX MAC status */
#define	XMAC_CTRL_STAT_REG		0x030	/* Control / Status */
#define	XTXMAC_STAT_MSK_REG		0x040	/* XTX MAC Status mask */
#define	XRXMAC_STAT_MSK_REG		0x048	/* XRX MAC Status mask */
#define	XMAC_C_S_MSK_REG		0x050	/* Control / Status mask */
#define	XMAC_CONFIG_REG			0x060	/* Configuration */

/* xmac config bit fields */
typedef union _xmac_cfg_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t sel_clk_25mhz : 1;
		uint32_t pcs_bypass	: 1;
		uint32_t xpcs_bypass	: 1;
		uint32_t mii_gmii_mode	: 2;
		uint32_t lfs_disable	: 1;
		uint32_t loopback	: 1;
		uint32_t tx_output_en	: 1;
		uint32_t sel_por_clk_src : 1;
		uint32_t led_polarity	: 1;
		uint32_t force_led_on	: 1;
		uint32_t pass_fctl_frames : 1;
		uint32_t recv_pause_en	: 1;
		uint32_t mac2ipp_pkt_cnt_en : 1;
		uint32_t strip_crc	: 1;
		uint32_t addr_filter_en	: 1;
		uint32_t hash_filter_en	: 1;
		uint32_t code_viol_chk_dis	: 1;
		uint32_t reserved_mcast	: 1;
		uint32_t rx_crc_chk_dis	: 1;
		uint32_t error_chk_dis	: 1;
		uint32_t promisc_grp	: 1;
		uint32_t promiscuous	: 1;
		uint32_t rx_mac_enable	: 1;
		uint32_t warning_msg_en	: 1;
		uint32_t used		: 3;
		uint32_t always_no_crc	: 1;
		uint32_t var_min_ipg_en	: 1;
		uint32_t strech_mode	: 1;
		uint32_t tx_enable	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t tx_enable	: 1;
		uint32_t strech_mode	: 1;
		uint32_t var_min_ipg_en	: 1;
		uint32_t always_no_crc	: 1;
		uint32_t used		: 3;
		uint32_t warning_msg_en	: 1;
		uint32_t rx_mac_enable	: 1;
		uint32_t promiscuous	: 1;
		uint32_t promisc_grp	: 1;
		uint32_t error_chk_dis	: 1;
		uint32_t rx_crc_chk_dis	: 1;
		uint32_t reserved_mcast	: 1;
		uint32_t code_viol_chk_dis	: 1;
		uint32_t hash_filter_en	: 1;
		uint32_t addr_filter_en	: 1;
		uint32_t strip_crc	: 1;
		uint32_t mac2ipp_pkt_cnt_en : 1;
		uint32_t recv_pause_en	: 1;
		uint32_t pass_fctl_frames : 1;
		uint32_t force_led_on	: 1;
		uint32_t led_polarity	: 1;
		uint32_t sel_por_clk_src : 1;
		uint32_t tx_output_en	: 1;
		uint32_t loopback	: 1;
		uint32_t lfs_disable	: 1;
		uint32_t mii_gmii_mode	: 2;
		uint32_t xpcs_bypass	: 1;
		uint32_t pcs_bypass	: 1;
		uint32_t sel_clk_25mhz : 1;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xmac_cfg_t, *p_xmac_cfg_t;

#define	XMAC_IPG_REG			0x080	/* Inter-Packet-Gap */
#define	XMAC_MIN_REG			0x088	/* min frame size register */
#define	XMAC_MAX_REG			0x090	/* max frame/burst size */
#define	XMAC_ADDR0_REG			0x0a0	/* [47:32] of MAC addr (HI17) */
#define	XMAC_ADDR1_REG			0x0a8	/* [31:16] of MAC addr */
#define	XMAC_ADDR2_REG			0x0b0	/* [15:0] of MAC addr */
#define	XRXMAC_BT_CNT_REG		0x100	/* bytes received / 8 */
#define	XRXMAC_BC_FRM_CNT_REG		0x108	/* good BC frames received */
#define	XRXMAC_MC_FRM_CNT_REG		0x110	/* good MC frames received */
#define	XRXMAC_FRAG_CNT_REG		0x118	/* frag frames rejected */
#define	XRXMAC_HIST_CNT1_REG		0x120	/* 64 bytes frames */
#define	XRXMAC_HIST_CNT2_REG		0x128	/* 65-127 bytes frames */
#define	XRXMAC_HIST_CNT3_REG		0x130	/* 128-255 bytes frames */
#define	XRXMAC_HIST_CNT4_REG		0x138	/* 256-511 bytes frames */
#define	XRXMAC_HIST_CNT5_REG		0x140	/* 512-1023 bytes frames */
#define	XRXMAC_HIST_CNT6_REG		0x148	/* 1024-1522 bytes frames */
#define	XRXMAC_MPSZER_CNT_REG		0x150	/* frames > maxframesize */
#define	XRXMAC_CRC_ER_CNT_REG		0x158	/* frames failed CRC */
#define	XRXMAC_CD_VIO_CNT_REG		0x160	/* frames with code vio */
#define	XRXMAC_AL_ER_CNT_REG		0x168	/* frames with align error */
#define	XTXMAC_FRM_CNT_REG		0x170	/* tx frames */
#define	XTXMAC_BYTE_CNT_REG		0x178	/* tx bytes / 8 */
#define	XMAC_LINK_FLT_CNT_REG		0x180	/* link faults */
#define	XRXMAC_HIST_CNT7_REG		0x188	/* MAC2IPP/>1523 bytes frames */
#define	XMAC_SM_REG			0x1a8	/* State machine */
#define	XMAC_INTERN1_REG		0x1b0	/* internal signals for diag */
#define	XMAC_INTERN2_REG		0x1b8	/* internal signals for diag */
#define	XMAC_ADDR_CMPEN_REG		0x208	/* alt MAC addr check */
#define	XMAC_ADDR3_REG			0x218	/* alt MAC addr 0 (HI 0) */
#define	XMAC_ADDR4_REG			0x220	/* alt MAC addr 0 */
#define	XMAC_ADDR5_REG			0x228	/* alt MAC addr 0 */
#define	XMAC_ADDR6_REG			0x230	/* alt MAC addr 1 (HI 1) */
#define	XMAC_ADDR7_REG			0x238	/* alt MAC addr 1 */
#define	XMAC_ADDR8_REG			0x240	/* alt MAC addr 1 */
#define	XMAC_ADDR9_REG			0x248	/* alt MAC addr 2 (HI 2) */
#define	XMAC_ADDR10_REG			0x250	/* alt MAC addr 2 */
#define	XMAC_ADDR11_REG			0x258	/* alt MAC addr 2 */
#define	XMAC_ADDR12_REG			0x260	/* alt MAC addr 3 (HI 3) */
#define	XMAC_ADDR13_REG			0x268	/* alt MAC addr 3 */
#define	XMAC_ADDR14_REG			0x270	/* alt MAC addr 3 */
#define	XMAC_ADDR15_REG			0x278	/* alt MAC addr 4 (HI 4) */
#define	XMAC_ADDR16_REG			0x280	/* alt MAC addr 4 */
#define	XMAC_ADDR17_REG			0x288	/* alt MAC addr 4 */
#define	XMAC_ADDR18_REG			0x290	/* alt MAC addr 5 (HI 5) */
#define	XMAC_ADDR19_REG			0x298	/* alt MAC addr 5 */
#define	XMAC_ADDR20_REG			0x2a0	/* alt MAC addr 5 */
#define	XMAC_ADDR21_REG			0x2a8	/* alt MAC addr 6 (HI 6) */
#define	XMAC_ADDR22_REG			0x2b0	/* alt MAC addr 6 */
#define	XMAC_ADDR23_REG			0x2b8	/* alt MAC addr 6 */
#define	XMAC_ADDR24_REG			0x2c0	/* alt MAC addr 7 (HI 7) */
#define	XMAC_ADDR25_REG			0x2c8	/* alt MAC addr 7 */
#define	XMAC_ADDR26_REG			0x2d0	/* alt MAC addr 7 */
#define	XMAC_ADDR27_REG			0x2d8	/* alt MAC addr 8 (HI 8) */
#define	XMAC_ADDR28_REG			0x2e0	/* alt MAC addr 8 */
#define	XMAC_ADDR29_REG			0x2e8	/* alt MAC addr 8 */
#define	XMAC_ADDR30_REG			0x2f0	/* alt MAC addr 9 (HI 9) */
#define	XMAC_ADDR31_REG			0x2f8	/* alt MAC addr 9 */
#define	XMAC_ADDR32_REG			0x300	/* alt MAC addr 9 */
#define	XMAC_ADDR33_REG			0x308	/* alt MAC addr 10 (HI 10) */
#define	XMAC_ADDR34_REG			0x310	/* alt MAC addr 10 */
#define	XMAC_ADDR35_REG			0x318	/* alt MAC addr 10 */
#define	XMAC_ADDR36_REG			0x320	/* alt MAC addr 11 (HI 11) */
#define	XMAC_ADDR37_REG			0x328	/* alt MAC addr 11 */
#define	XMAC_ADDR38_REG			0x330	/* alt MAC addr 11 */
#define	XMAC_ADDR39_REG			0x338	/* alt MAC addr 12 (HI 12) */
#define	XMAC_ADDR40_REG			0x340	/* alt MAC addr 12 */
#define	XMAC_ADDR41_REG			0x348	/* alt MAC addr 12 */
#define	XMAC_ADDR42_REG			0x350	/* alt MAC addr 13 (HI 13) */
#define	XMAC_ADDR43_REG			0x358	/* alt MAC addr 13 */
#define	XMAC_ADDR44_REG			0x360	/* alt MAC addr 13 */
#define	XMAC_ADDR45_REG			0x368	/* alt MAC addr 14 (HI 14) */
#define	XMAC_ADDR46_REG			0x370	/* alt MAC addr 14 */
#define	XMAC_ADDR47_REG			0x378	/* alt MAC addr 14 */
#define	XMAC_ADDR48_REG			0x380	/* alt MAC addr 15 (HI 15) */
#define	XMAC_ADDR49_REG			0x388	/* alt MAC addr 15 */
#define	XMAC_ADDR50_REG			0x390	/* alt MAC addr 15 */
#define	XMAC_ADDR_FILT0_REG		0x818	/* [47:32] addr filter (HI18) */
#define	XMAC_ADDR_FILT1_REG		0x820	/* [31:16] of addr filter */
#define	XMAC_ADDR_FILT2_REG		0x828	/* [15:0] of addr filter */
#define	XMAC_ADDR_FILT12_MASK_REG 	0x830	/* addr filter 2 & 1 mask */
#define	XMAC_ADDR_FILT0_MASK_REG	0x838	/* addr filter 0 mask */
#define	XMAC_HASH_TBL0_REG		0x840	/* hash table 0 reg */
#define	XMAC_HASH_TBL1_REG		0x848	/* hash table 1 reg */
#define	XMAC_HASH_TBL2_REG		0x850	/* hash table 2 reg */
#define	XMAC_HASH_TBL3_REG		0x858	/* hash table 3 reg */
#define	XMAC_HASH_TBL4_REG		0x860	/* hash table 4 reg */
#define	XMAC_HASH_TBL5_REG		0x868	/* hash table 5 reg */
#define	XMAC_HASH_TBL6_REG		0x870	/* hash table 6 reg */
#define	XMAC_HASH_TBL7_REG		0x878	/* hash table 7 reg */
#define	XMAC_HASH_TBL8_REG		0x880	/* hash table 8 reg */
#define	XMAC_HASH_TBL9_REG		0x888	/* hash table 9 reg */
#define	XMAC_HASH_TBL10_REG		0x890	/* hash table 10 reg */
#define	XMAC_HASH_TBL11_REG		0x898	/* hash table 11 reg */
#define	XMAC_HASH_TBL12_REG		0x8a0	/* hash table 12 reg */
#define	XMAC_HASH_TBL13_REG		0x8a8	/* hash table 13 reg */
#define	XMAC_HASH_TBL14_REG		0x8b0	/* hash table 14 reg */
#define	XMAC_HASH_TBL15_REG		0x8b8	/* hash table 15 reg */
#define	XMAC_HOST_INF0_REG		0x900	/* Host info 0 (alt ad 0) */
#define	XMAC_HOST_INF1_REG		0x908	/* Host info 1 (alt ad 1) */
#define	XMAC_HOST_INF2_REG		0x910	/* Host info 2 (alt ad 2) */
#define	XMAC_HOST_INF3_REG		0x918	/* Host info 3 (alt ad 3) */
#define	XMAC_HOST_INF4_REG		0x920	/* Host info 4 (alt ad 4) */
#define	XMAC_HOST_INF5_REG		0x928	/* Host info 5 (alt ad 5) */
#define	XMAC_HOST_INF6_REG		0x930	/* Host info 6 (alt ad 6) */
#define	XMAC_HOST_INF7_REG		0x938	/* Host info 7 (alt ad 7) */
#define	XMAC_HOST_INF8_REG		0x940	/* Host info 8 (alt ad 8) */
#define	XMAC_HOST_INF9_REG		0x948	/* Host info 9 (alt ad 9) */
#define	XMAC_HOST_INF10_REG		0x950	/* Host info 10 (alt ad 10) */
#define	XMAC_HOST_INF11_REG		0x958	/* Host info 11 (alt ad 11) */
#define	XMAC_HOST_INF12_REG		0x960	/* Host info 12 (alt ad 12) */
#define	XMAC_HOST_INF13_REG		0x968	/* Host info 13 (alt ad 13) */
#define	XMAC_HOST_INF14_REG		0x970	/* Host info 14 (alt ad 14) */
#define	XMAC_HOST_INF15_REG		0x978	/* Host info 15 (alt ad 15) */
#define	XMAC_HOST_INF16_REG		0x980	/* Host info 16 (hash hit) */
#define	XMAC_HOST_INF17_REG		0x988	/* Host info 17 (own da) */
#define	XMAC_HOST_INF18_REG		0x990	/* Host info 18 (filter hit) */
#define	XMAC_HOST_INF19_REG		0x998	/* Host info 19 (fc hit) */
#define	XMAC_PA_DATA0_REG		0xb80	/* preamble [31:0] */
#define	XMAC_PA_DATA1_REG		0xb88	/* preamble [63:32] */
#define	XMAC_DEBUG_SEL_REG		0xb90	/* debug select */
#define	XMAC_TRAINING_VECT_REG		0xb98	/* training vector */
/* x ranges from 0 to 15 (XMAC_MAX_ALT_ADDR_ENTRY - 1) */
#define	XMAC_ALT_ADDR0N_REG_ADDR(x)	(XMAC_ADDR3_REG + (x) * 24)
#define	XMAC_ALT_ADDR1N_REG_ADDR(x)	(XMAC_ADDR3_REG + 8 + (x) * 24)
#define	XMAC_ALT_ADDR2N_REG_ADDR(x)	(XMAC_ADDR3_REG + 16 + (x) * 24)
#define	XMAC_HASH_TBLN_REG_ADDR(x)	(XMAC_HASH_TBL0_REG + (x) * 8)
#define	XMAC_HOST_INFN_REG_ADDR(x)	(XMAC_HOST_INF0_REG + (x) * 8)

/* MIF registers offset */
#define	MIF_BB_MDC_REG			0	   /* MIF bit-bang clock */
#define	MIF_BB_MDO_REG			0x008	   /* MIF bit-bang data */
#define	MIF_BB_MDO_EN_REG		0x010	   /* MIF bit-bang output en */
#define	MIF_OUTPUT_FRAME_REG		0x018	   /* MIF frame/output reg */
#define	MIF_CONFIG_REG			0x020	   /* MIF config reg */
#define	MIF_POLL_STATUS_REG		0x028	   /* MIF poll status reg */
#define	MIF_POLL_MASK_REG		0x030	   /* MIF poll mask reg */
#define	MIF_STATE_MACHINE_REG		0x038	   /* MIF state machine reg */
#define	MIF_STATUS_REG			0x040	   /* MIF status reg */
#define	MIF_MASK_REG			0x048	   /* MIF mask reg */


/* PCS registers offset */
#define	PCS_MII_CTRL_REG		0	   /* PCS MII control reg */
#define	PCS_MII_STATUS_REG		0x008	   /* PCS MII status reg */
#define	PCS_MII_ADVERT_REG		0x010	   /* PCS MII advertisement */
#define	PCS_MII_LPA_REG			0x018	   /* link partner ability */
#define	PCS_CONFIG_REG			0x020	   /* PCS config reg */
#define	PCS_STATE_MACHINE_REG		0x028	   /* PCS state machine */
#define	PCS_INTR_STATUS_REG		0x030	/* PCS interrupt status */
#define	PCS_DATAPATH_MODE_REG		0x0a0	   /* datapath mode reg */
#define	PCS_PACKET_COUNT_REG		0x0c0	   /* PCS packet counter */

#define	XPCS_CTRL_1_REG			0	/* Control */
#define	XPCS_STATUS_1_REG		0x008
#define	XPCS_DEV_ID_REG			0x010	/* 32bits IEEE manufacture ID */
#define	XPCS_SPEED_ABILITY_REG		0x018
#define	XPCS_DEV_IN_PKG_REG		0x020
#define	XPCS_CTRL_2_REG			0x028
#define	XPCS_STATUS_2_REG		0x030
#define	XPCS_PKG_ID_REG			0x038	/* Package ID */
#define	XPCS_STATUS_REG			0x040
#define	XPCS_TEST_CTRL_REG		0x048
#define	XPCS_CFG_VENDOR_1_REG		0x050
#define	XPCS_DIAG_VENDOR_2_REG		0x058
#define	XPCS_MASK_1_REG			0x060
#define	XPCS_PKT_CNTR_REG		0x068
#define	XPCS_TX_STATE_MC_REG		0x070
#define	XPCS_DESKEW_ERR_CNTR_REG	0x078
#define	XPCS_SYM_ERR_CNTR_L0_L1_REG	0x080
#define	XPCS_SYM_ERR_CNTR_L2_L3_REG	0x088
#define	XPCS_TRAINING_VECTOR_REG	0x090

/* ESR registers offset */
#define	ESR_RESET_REG			0
#define	ESR_CONFIG_REG			0x008
#define	ESR_0_PLL_CONFIG_REG		0x010
#define	ESR_0_CONTROL_REG		0x018
#define	ESR_0_TEST_CONFIG_REG		0x020
#define	ESR_1_PLL_CONFIG_REG		0x028
#define	ESR_1_CONTROL_REG		0x030
#define	ESR_1_TEST_CONFIG_REG		0x038
#define	ESR_ENET_RGMII_CFG_REG		0x040
#define	ESR_INTERNAL_SIGNALS_REG	0x800
#define	ESR_DEBUG_SEL_REG		0x808


/* Reset Register */
#define	MAC_SEND_PAUSE_TIME_MASK	0x0000FFFF /* value of pause time */
#define	MAC_SEND_PAUSE_SEND		0x00010000 /* send pause flow ctrl */

/* Tx MAC Status Register */
#define	MAC_TX_FRAME_XMIT		0x00000001 /* successful tx frame */
#define	MAC_TX_UNDERRUN			0x00000002 /* starvation in xmit */
#define	MAC_TX_MAX_PACKET_ERR		0x00000004 /* TX frame exceeds max */
#define	MAC_TX_BYTE_CNT_EXP		0x00000400 /* TX byte cnt overflow */
#define	MAC_TX_FRAME_CNT_EXP		0x00000800 /* Tx frame cnt overflow */

/* Rx MAC Status Register */
#define	MAC_RX_FRAME_RECV		0x00000001 /* successful rx frame */
#define	MAC_RX_OVERFLOW			0x00000002 /* RX FIFO overflow */
#define	MAC_RX_FRAME_COUNT		0x00000004 /* rx frame cnt rollover */
#define	MAC_RX_ALIGN_ERR		0x00000008 /* alignment err rollover */
#define	MAC_RX_CRC_ERR			0x00000010 /* crc error cnt rollover */
#define	MAC_RX_LEN_ERR			0x00000020 /* length err cnt rollover */
#define	MAC_RX_VIOL_ERR			0x00000040 /* code vio err rollover */
#define	MAC_RX_BYTE_CNT_EXP		0x00000080 /* RX MAC byte rollover */

/* MAC Control Status Register */
#define	MAC_CTRL_PAUSE_RECEIVED		0x00000001 /* successful pause frame */
#define	MAC_CTRL_PAUSE_STATE		0x00000002 /* notpause-->pause */
#define	MAC_CTRL_NOPAUSE_STATE		0x00000004 /* pause-->notpause */
#define	MAC_CTRL_PAUSE_TIME_MASK	0xFFFF0000 /* value of pause time */
#define	MAC_CTRL_PAUSE_TIME_SHIFT	16

/* Tx MAC Configuration Register */
#define	MAC_TX_CFG_TXMAC_ENABLE		0x00000001 /* enable TX MAC. */
#define	MAC_TX_CFG_NO_FCS		0x00000100 /* TX not generate CRC */

/* Rx MAC Configuration Register */
#define	MAC_RX_CFG_RXMAC_ENABLE		0x00000001 /* enable RX MAC */
#define	MAC_RX_CFG_STRIP_PAD		0x00000002 /* not supported, set to 0 */
#define	MAC_RX_CFG_STRIP_FCS		0x00000004 /* strip last 4bytes (CRC) */
#define	MAC_RX_CFG_PROMISC		0x00000008 /* promisc mode enable */
#define	MAC_RX_CFG_PROMISC_GROUP  	0x00000010 /* accept all MC frames */
#define	MAC_RX_CFG_HASH_FILTER_EN	0x00000020 /* use hash table */
#define	MAC_RX_CFG_ADDR_FILTER_EN    	0x00000040 /* use address filter */
#define	MAC_RX_CFG_DISABLE_DISCARD	0x00000080 /* do not set abort bit */
#define	MAC_RX_MAC2IPP_PKT_CNT_EN	0x00000200 /* rx pkt cnt -> BMAC-IPP */
#define	MAC_RX_MAC_REG_RW_TEST_MASK	0x00000c00 /* BMAC reg RW test */
#define	MAC_RX_MAC_REG_RW_TEST_SHIFT	10

/* MAC Control Configuration Register */
#define	MAC_CTRL_CFG_SEND_PAUSE_EN	0x00000001 /* send pause flow ctrl */
#define	MAC_CTRL_CFG_RECV_PAUSE_EN	0x00000002 /* receive pause flow ctrl */
#define	MAC_CTRL_CFG_PASS_CTRL		0x00000004 /* accept MAC ctrl pkts */

/* MAC XIF Configuration Register */
#define	MAC_XIF_TX_OUTPUT_EN		0x00000001 /* enable Tx output driver */
#define	MAC_XIF_MII_INT_LOOPBACK	0x00000002 /* loopback GMII xmit data */
#define	MAC_XIF_GMII_MODE		0x00000008 /* operates with GMII clks */
#define	MAC_XIF_LINK_LED		0x00000020 /* LINKLED# active (low) */
#define	MAC_XIF_LED_POLARITY		0x00000040 /* LED polarity */
#define	MAC_XIF_SEL_CLK_25MHZ		0x00000080 /* Select 10/100Mbps */

/* MAC IPG Registers */
#define	BMAC_MIN_FRAME_MASK		0x3FF	   /* 10-bit reg */

/* MAC Max Frame Size Register */
#define	BMAC_MAX_BURST_MASK    		0x3FFF0000 /* max burst size [30:16] */
#define	BMAC_MAX_BURST_SHIFT   		16
#define	BMAC_MAX_FRAME_MASK    		0x00007FFF /* max frame size [14:0] */
#define	BMAC_MAX_FRAME_SHIFT   		0

/* MAC Preamble size register */
#define	BMAC_PA_SIZE_MASK		0x000003FF
	/* # of preable bytes TxMAC sends at the beginning of each frame */

/*
 * mac address registers:
 *	register	contains			comparison
 *	--------	--------			----------
 *	0		16 MSB of primary MAC addr	[47:32] of DA field
 *	1		16 middle bits ""		[31:16] of DA field
 *	2		16 LSB ""			[15:0] of DA field
 *	3*x		16MSB of alt MAC addr 1-7	[47:32] of DA field
 *	4*x		16 middle bits ""		[31:16]
 *	5*x		16 LSB ""			[15:0]
 *	42		16 MSB of MAC CTRL addr		[47:32] of DA.
 *	43		16 middle bits ""		[31:16]
 *	44		16 LSB ""			[15:0]
 *	MAC CTRL addr must be the reserved multicast addr for MAC CTRL frames.
 *	if there is a match, MAC will set the bit for alternative address
 *	filter pass [15]
 *
 *	here is the map of registers given MAC address notation: a:b:c:d:e:f
 *			ab		cd		ef
 *	primary addr	reg 2		reg 1		reg 0
 *	alt addr 1	reg 5		reg 4		reg 3
 *	alt addr x	reg 5*x		reg 4*x		reg 3*x
 *	|		|		|		|
 *	|		|		|		|
 *	alt addr 7	reg 23		reg 22		reg 21
 *	ctrl addr	reg 44		reg 43		reg 42
 */

#define	BMAC_ALT_ADDR_BASE		0x118
#define	BMAC_MAX_ALT_ADDR_ENTRY		7	   /* 7 alternate MAC addr */
#define	BMAC_MAX_ADDR_ENTRY		(BMAC_MAX_ALT_ADDR_ENTRY + 1)

/* hash table registers */
#define	MAC_MAX_HASH_ENTRY		16

/* 27-bit register has the current state for key state machines in the MAC */
#define	MAC_SM_RLM_MASK			0x07800000
#define	MAC_SM_RLM_SHIFT		23
#define	MAC_SM_RX_FC_MASK		0x00700000
#define	MAC_SM_RX_FC_SHIFT		20
#define	MAC_SM_TLM_MASK			0x000F0000
#define	MAC_SM_TLM_SHIFT		16
#define	MAC_SM_ENCAP_SM_MASK		0x0000F000
#define	MAC_SM_ENCAP_SM_SHIFT		12
#define	MAC_SM_TX_REQ_MASK		0x00000C00
#define	MAC_SM_TX_REQ_SHIFT		10
#define	MAC_SM_TX_FC_MASK		0x000003C0
#define	MAC_SM_TX_FC_SHIFT		6
#define	MAC_SM_FIFO_WRITE_SEL_MASK	0x00000038
#define	MAC_SM_FIFO_WRITE_SEL_SHIFT	3
#define	MAC_SM_TX_FIFO_EMPTY_MASK	0x00000007
#define	MAC_SM_TX_FIFO_EMPTY_SHIFT	0

#define	BMAC_ADDR0_CMPEN		0x00000001
#define	BMAC_ADDRN_CMPEN(x)		(BMAC_ADDR0_CMP_EN << (x))

/* MAC Host Info Table Registers */
#define	BMAC_MAX_HOST_INFO_ENTRY	9 	/* 9 host entries */

/*
 * ********************* XMAC registers *********************************
 */

/* Reset Register */
#define	XTXMAC_SOFT_RST			0x00000001 /* XTX MAC software reset */
#define	XTXMAC_REG_RST			0x00000002 /* XTX MAC registers reset */
#define	XRXMAC_SOFT_RST			0x00000001 /* XRX MAC software reset */
#define	XRXMAC_REG_RST			0x00000002 /* XRX MAC registers reset */

/* XTX MAC Status Register */
#define	XMAC_TX_FRAME_XMIT		0x00000001 /* successful tx frame */
#define	XMAC_TX_UNDERRUN		0x00000002 /* starvation in xmit */
#define	XMAC_TX_MAX_PACKET_ERR		0x00000004 /* XTX frame exceeds max */
#define	XMAC_TX_OVERFLOW		0x00000008 /* XTX byte cnt overflow */
#define	XMAC_TX_FIFO_XFR_ERR		0x00000010 /* xtlm state mach error */
#define	XMAC_TX_BYTE_CNT_EXP		0x00000400 /* XTX byte cnt overflow */
#define	XMAC_TX_FRAME_CNT_EXP		0x00000800 /* XTX frame cnt overflow */

/* XRX MAC Status Register */
#define	XMAC_RX_FRAME_RCVD		0x00000001 /* successful rx frame */
#define	XMAC_RX_OVERFLOW		0x00000002 /* RX FIFO overflow */
#define	XMAC_RX_UNDERFLOW		0x00000004 /* RX FIFO underrun */
#define	XMAC_RX_CRC_ERR_CNT_EXP		0x00000008 /* crc error cnt rollover */
#define	XMAC_RX_LEN_ERR_CNT_EXP		0x00000010 /* length err cnt rollover */
#define	XMAC_RX_VIOL_ERR_CNT_EXP	0x00000020 /* code vio err rollover */
#define	XMAC_RX_OCT_CNT_EXP		0x00000040 /* XRX MAC byte rollover */
#define	XMAC_RX_HST_CNT1_EXP		0x00000080 /* XRX MAC hist1 rollover */
#define	XMAC_RX_HST_CNT2_EXP		0x00000100 /* XRX MAC hist2 rollover */
#define	XMAC_RX_HST_CNT3_EXP		0x00000200 /* XRX MAC hist3 rollover */
#define	XMAC_RX_HST_CNT4_EXP		0x00000400 /* XRX MAC hist4 rollover */
#define	XMAC_RX_HST_CNT5_EXP		0x00000800 /* XRX MAC hist5 rollover */
#define	XMAC_RX_HST_CNT6_EXP		0x00001000 /* XRX MAC hist6 rollover */
#define	XMAC_RX_BCAST_CNT_EXP		0x00002000 /* XRX BC cnt rollover */
#define	XMAC_RX_MCAST_CNT_EXP		0x00004000 /* XRX MC cnt rollover */
#define	XMAC_RX_FRAG_CNT_EXP		0x00008000 /* fragment cnt rollover */
#define	XMAC_RX_ALIGNERR_CNT_EXP	0x00010000 /* framealign err rollover */
#define	XMAC_RX_LINK_FLT_CNT_EXP	0x00020000 /* link fault cnt rollover */
#define	XMAC_RX_REMOTE_FLT_DET		0x00040000 /* Remote Fault detected */
#define	XMAC_RX_LOCAL_FLT_DET		0x00080000 /* Local Fault detected */
#define	XMAC_RX_HST_CNT7_EXP		0x00100000 /* XRX MAC hist7 rollover */


#define	XMAC_CTRL_PAUSE_RCVD		0x00000001 /* successful pause frame */
#define	XMAC_CTRL_PAUSE_STATE		0x00000002 /* notpause-->pause */
#define	XMAC_CTRL_NOPAUSE_STATE		0x00000004 /* pause-->notpause */
#define	XMAC_CTRL_PAUSE_TIME_MASK	0xFFFF0000 /* value of pause time */
#define	XMAC_CTRL_PAUSE_TIME_SHIFT	16

/* XMAC Configuration Register */
#define	XMAC_CONFIG_TX_BIT_MASK		0x000000ff /* bits [7:0] */
#define	XMAC_CONFIG_RX_BIT_MASK		0x001fff00 /* bits [20:8] */
#define	XMAC_CONFIG_XIF_BIT_MASK	0xffe00000 /* bits [31:21] */

/* XTX MAC config bits */
#define	XMAC_TX_CFG_TX_ENABLE		0x00000001 /* enable XTX MAC */
#define	XMAC_TX_CFG_STRETCH_MD		0x00000002 /* WAN application */
#define	XMAC_TX_CFG_VAR_MIN_IPG_EN	0x00000004 /* Transmit pkts < minpsz */
#define	XMAC_TX_CFG_ALWAYS_NO_CRC	0x00000008 /* No CRC generated */

#define	XMAC_WARNING_MSG_ENABLE		0x00000080 /* Sim warning msg enable */

/* XRX MAC config bits */
#define	XMAC_RX_CFG_RX_ENABLE		0x00000100 /* enable XRX MAC */
#define	XMAC_RX_CFG_PROMISC		0x00000200 /* promisc mode enable */
#define	XMAC_RX_CFG_PROMISC_GROUP  	0x00000400 /* accept all MC frames */
#define	XMAC_RX_CFG_ERR_CHK_DISABLE	0x00000800 /* do not set abort bit */
#define	XMAC_RX_CFG_CRC_CHK_DISABLE	0x00001000 /* disable CRC logic */
#define	XMAC_RX_CFG_RESERVED_MCAST	0x00002000 /* reserved MCaddr compare */
#define	XMAC_RX_CFG_CD_VIO_CHK		0x00004000 /* rx code violation chk */
#define	XMAC_RX_CFG_HASH_FILTER_EN	0x00008000 /* use hash table */
#define	XMAC_RX_CFG_ADDR_FILTER_EN	0x00010000 /* use alt addr filter */
#define	XMAC_RX_CFG_STRIP_CRC		0x00020000 /* strip last 4bytes (CRC) */
#define	XMAC_RX_MAC2IPP_PKT_CNT_EN	0x00040000 /* histo_cntr7 cnt mode */
#define	XMAC_RX_CFG_RX_PAUSE_EN		0x00080000 /* receive pause flow ctrl */
#define	XMAC_RX_CFG_PASS_FLOW_CTRL	0x00100000 /* accept MAC ctrl pkts */


/* MAC transceiver (XIF) configuration registers */

#define	XMAC_XIF_FORCE_LED_ON		0x00200000 /* Force Link LED on */
#define	XMAC_XIF_LED_POLARITY		0x00400000 /* LED polarity */
#define	XMAC_XIF_SEL_POR_CLK_SRC	0x00800000 /* Select POR clk src */
#define	XMAC_XIF_TX_OUTPUT_EN		0x01000000 /* enable MII/GMII modes */
#define	XMAC_XIF_LOOPBACK		0x02000000 /* loopback xmac xgmii tx */
#define	XMAC_XIF_LFS_DISABLE		0x04000000 /* disable link fault sig */
#define	XMAC_XIF_MII_MODE_MASK		0x18000000 /* MII/GMII/XGMII mode */
#define	XMAC_XIF_MII_MODE_SHIFT		27
#define	XMAC_XIF_XGMII_MODE		0x00
#define	XMAC_XIF_GMII_MODE		0x01
#define	XMAC_XIF_MII_MODE		0x02
#define	XMAC_XIF_ILLEGAL_MODE		0x03
#define	XMAC_XIF_XPCS_BYPASS		0x20000000 /* use external xpcs */
#define	XMAC_XIF_1G_PCS_BYPASS		0x40000000 /* use external pcs */
#define	XMAC_XIF_SEL_CLK_25MHZ		0x80000000 /* 25Mhz clk for 100mbps */

/* IPG register */
#define	XMAC_IPG_VALUE_MASK		0x00000007 /* IPG in XGMII mode */
#define	XMAC_IPG_VALUE_SHIFT		0
#define	XMAC_IPG_VALUE1_MASK		0x0000ff00 /* IPG in GMII/MII mode */
#define	XMAC_IPG_VALUE1_SHIFT		8
#define	XMAC_IPG_STRETCH_RATIO_MASK	0x001f0000
#define	XMAC_IPG_STRETCH_RATIO_SHIFT	16
#define	XMAC_IPG_STRETCH_CONST_MASK	0x00e00000
#define	XMAC_IPG_STRETCH_CONST_SHIFT	21

#define	IPG_12_15_BYTE			3
#define	IPG_16_19_BYTE			4
#define	IPG_20_23_BYTE			5
#define	IPG1_12_BYTES			10
#define	IPG1_13_BYTES			11
#define	IPG1_14_BYTES			12
#define	IPG1_15_BYTES			13
#define	IPG1_16_BYTES			14


#define	XMAC_MIN_TX_FRM_SZ_MASK		0x3ff	   /* Min tx frame size */
#define	XMAC_MIN_TX_FRM_SZ_SHIFT	0
#define	XMAC_SLOT_TIME_MASK		0x0003fc00 /* slot time */
#define	XMAC_SLOT_TIME_SHIFT		10
#define	XMAC_MIN_RX_FRM_SZ_MASK		0x3ff00000 /* Min rx frame size */
#define	XMAC_MIN_RX_FRM_SZ_SHIFT	20
#define	XMAC_MAX_FRM_SZ_MASK		0x00003fff /* max tx frame size */

/* State Machine Register */
#define	XMAC_SM_TX_LNK_MGMT_MASK	0x00000007
#define	XMAC_SM_TX_LNK_MGMT_SHIFT	0
#define	XMAC_SM_SOP_DETECT		0x00000008
#define	XMAC_SM_LNK_FLT_SIG_MASK	0x00000030
#define	XMAC_SM_LNK_FLT_SIG_SHIFT	4
#define	XMAC_SM_MII_GMII_MD_RX_LNK	0x00000040
#define	XMAC_SM_XGMII_MD_RX_LNK		0x00000080
#define	XMAC_SM_XGMII_ONLY_VAL_SIG	0x00000100
#define	XMAC_SM_ALT_ADR_N_HSH_FN_SIG	0x00000200
#define	XMAC_SM_RXMAC_IPP_STAT_MASK	0x00001c00
#define	XMAC_SM_RXMAC_IPP_STAT_SHIFT	10
#define	XMAC_SM_RXFIFO_WPTR_CLK_MASK	0x007c0000
#define	XMAC_SM_RXFIFO_WPTR_CLK_SHIFT	18
#define	XMAC_SM_RXFIFO_RPTR_CLK_MASK	0x0F800000
#define	XMAC_SM_RXFIFO_RPTR_CLK_SHIFT	23
#define	XMAC_SM_TXFIFO_FULL_CLK		0x10000000
#define	XMAC_SM_TXFIFO_EMPTY_CLK	0x20000000
#define	XMAC_SM_RXFIFO_FULL_CLK		0x40000000
#define	XMAC_SM_RXFIFO_EMPTY_CLK	0x80000000

/* Internal Signals 1 Register */
#define	XMAC_IS1_OPP_TXMAC_STAT_MASK	0x0000000F
#define	XMAC_IS1_OPP_TXMAC_STAT_SHIFT	0
#define	XMAC_IS1_OPP_TXMAC_ABORT	0x00000010
#define	XMAC_IS1_OPP_TXMAC_TAG 		0x00000020
#define	XMAC_IS1_OPP_TXMAC_ACK		0x00000040
#define	XMAC_IS1_TXMAC_OPP_REQ		0x00000080
#define	XMAC_IS1_RXMAC_IPP_STAT_MASK	0x0FFFFF00
#define	XMAC_IS1_RXMAC_IPP_STAT_SHIFT	8
#define	XMAC_IS1_RXMAC_IPP_CTRL		0x10000000
#define	XMAC_IS1_RXMAC_IPP_TAG		0x20000000
#define	XMAC_IS1_IPP_RXMAC_REQ		0x40000000
#define	XMAC_IS1_RXMAC_IPP_ACK		0x80000000

/* Internal Signals 2 Register */
#define	XMAC_IS2_TX_HB_TIMER_MASK	0x0000000F
#define	XMAC_IS2_TX_HB_TIMER_SHIFT	0
#define	XMAC_IS2_RX_HB_TIMER_MASK	0x000000F0
#define	XMAC_IS2_RX_HB_TIMER_SHIFT	4
#define	XMAC_IS2_XPCS_RXC_MASK		0x0000FF00
#define	XMAC_IS2_XPCS_RXC_SHIFT		8
#define	XMAC_IS2_XPCS_TXC_MASK		0x00FF0000
#define	XMAC_IS2_XPCS_TXC_SHIFT		16
#define	XMAC_IS2_LOCAL_FLT_OC_SYNC	0x01000000
#define	XMAC_IS2_RMT_FLT_OC_SYNC	0x02000000

/* Register size masking */

#define	XTXMAC_FRM_CNT_MASK		0xFFFFFFFF
#define	XTXMAC_BYTE_CNT_MASK		0xFFFFFFFF
#define	XRXMAC_CRC_ER_CNT_MASK		0x000000FF
#define	XRXMAC_MPSZER_CNT_MASK		0x000000FF
#define	XRXMAC_CD_VIO_CNT_MASK		0x000000FF
#define	XRXMAC_BT_CNT_MASK		0xFFFFFFFF
#define	XRXMAC_HIST_CNT1_MASK		0x001FFFFF
#define	XRXMAC_HIST_CNT2_MASK		0x001FFFFF
#define	XRXMAC_HIST_CNT3_MASK		0x000FFFFF
#define	XRXMAC_HIST_CNT4_MASK		0x0007FFFF
#define	XRXMAC_HIST_CNT5_MASK		0x0003FFFF
#define	XRXMAC_HIST_CNT6_MASK		0x0001FFFF
#define	XRXMAC_HIST_CNT7_MASK		0x07FFFFFF
#define	XRXMAC_BC_FRM_CNT_MASK		0x001FFFFF
#define	XRXMAC_MC_FRM_CNT_MASK		0x001FFFFF
#define	XRXMAC_FRAG_CNT_MASK		0x001FFFFF
#define	XRXMAC_AL_ER_CNT_MASK		0x000000FF
#define	XMAC_LINK_FLT_CNT_MASK		0x000000FF
#define	BTXMAC_FRM_CNT_MASK		0x001FFFFF
#define	BTXMAC_BYTE_CNT_MASK		0x07FFFFFF
#define	RXMAC_FRM_CNT_MASK		0x0000FFFF
#define	BRXMAC_BYTE_CNT_MASK		0x07FFFFFF
#define	BMAC_AL_ER_CNT_MASK		0x0000FFFF
#define	MAC_LEN_ER_CNT_MASK		0x0000FFFF
#define	BMAC_CRC_ER_CNT_MASK		0x0000FFFF
#define	BMAC_CD_VIO_CNT_MASK		0x0000FFFF
#define	XMAC_XPCS_DESKEW_ERR_CNT_MASK	0x000000FF
#define	XMAC_XPCS_SYM_ERR_CNT_L0_MASK	0x0000FFFF
#define	XMAC_XPCS_SYM_ERR_CNT_L1_MASK	0xFFFF0000
#define	XMAC_XPCS_SYM_ERR_CNT_L1_SHIFT	16
#define	XMAC_XPCS_SYM_ERR_CNT_L2_MASK	0x0000FFFF
#define	XMAC_XPCS_SYM_ERR_CNT_L3_MASK	0xFFFF0000
#define	XMAC_XPCS_SYM_ERR_CNT_L3_SHIFT	16

/* Alternate MAC address registers */
#define	XMAC_MAX_ALT_ADDR_ENTRY		16	   /* 16 alternate MAC addrs */
#define	XMAC_MAX_ADDR_ENTRY		(XMAC_MAX_ALT_ADDR_ENTRY + 1)

/* Max / Min parameters for Neptune MAC */

#define	MAC_MAX_ALT_ADDR_ENTRY		XMAC_MAX_ALT_ADDR_ENTRY
#define	MAC_MAX_HOST_INFO_ENTRY		XMAC_MAX_HOST_INFO_ENTRY

/* HostInfo entry for the unique MAC address */
#define	XMAC_UNIQUE_HOST_INFO_ENTRY	17
#define	BMAC_UNIQUE_HOST_INFO_ENTRY	0

/* HostInfo entry for the multicat address */
#define	XMAC_MULTI_HOST_INFO_ENTRY	16
#define	BMAC_MULTI_HOST_INFO_ENTRY	8

/* XMAC Host Info Register */
typedef union hostinfo {

	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t reserved2	: 23;
		uint32_t mac_pref	: 1;
		uint32_t reserved1	: 5;
		uint32_t rdc_tbl_num	: 3;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t rdc_tbl_num	: 3;
		uint32_t reserved1	: 5;
		uint32_t mac_pref	: 1;
		uint32_t reserved2	: 23;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;

} hostinfo_t;

typedef union hostinfo *hostinfo_pt;

#define	XMAC_HI_RDC_TBL_NUM_MASK	0x00000007
#define	XMAC_HI_MAC_PREF		0x00000100

#define	XMAC_MAX_HOST_INFO_ENTRY	20	   /* 20 host entries */

/*
 * ******************** MIF registers *********************************
 */

/*
 * 32-bit register serves as an instruction register when the MIF is
 * programmed in frame mode. load this register w/ a valid instruction
 * (as per IEEE 802.3u MII spec). poll this register to check for instruction
 * execution completion. during a read operation, this register will also
 * contain the 16-bit data returned by the transceiver. unless specified
 * otherwise, fields are considered "don't care" when polling for
 * completion.
 */

#define	MIF_FRAME_START_MASK		0xC0000000 /* start of frame mask */
#define	MIF_FRAME_ST_22			0x40000000 /* STart of frame, Cl 22 */
#define	MIF_FRAME_ST_45			0x00000000 /* STart of frame, Cl 45 */
#define	MIF_FRAME_OPCODE_MASK		0x30000000 /* opcode */
#define	MIF_FRAME_OP_READ_22		0x20000000 /* read OPcode, Cl 22 */
#define	MIF_FRAME_OP_WRITE_22		0x10000000 /* write OPcode, Cl 22 */
#define	MIF_FRAME_OP_ADDR_45		0x00000000 /* addr of reg to access */
#define	MIF_FRAME_OP_READ_45		0x30000000 /* read OPcode, Cl 45 */
#define	MIF_FRAME_OP_WRITE_45		0x10000000 /* write OPcode, Cl 45 */
#define	MIF_FRAME_OP_P_R_I_A_45		0x10000000 /* post-read-inc-addr */
#define	MIF_FRAME_PHY_ADDR_MASK		0x0F800000 /* phy address mask */
#define	MIF_FRAME_PHY_ADDR_SHIFT	23
#define	MIF_FRAME_REG_ADDR_MASK		0x007C0000 /* reg addr in Cl 22 */
						/* dev addr in Cl 45 */
#define	MIF_FRAME_REG_ADDR_SHIFT	18
#define	MIF_FRAME_TURN_AROUND_MSB	0x00020000 /* turn around, MSB. */
#define	MIF_FRAME_TURN_AROUND_LSB	0x00010000 /* turn around, LSB. */
#define	MIF_FRAME_DATA_MASK		0x0000FFFF /* instruction payload */

/* Clause 45 frame field values */
#define	FRAME45_ST		0
#define	FRAME45_OP_ADDR		0
#define	FRAME45_OP_WRITE	1
#define	FRAME45_OP_READ_INC	2
#define	FRAME45_OP_READ		3

typedef union _mif_frame_t {

	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t st		: 2;
		uint32_t op		: 2;
		uint32_t phyad		: 5;
		uint32_t regad		: 5;
		uint32_t ta_msb		: 1;
		uint32_t ta_lsb		: 1;
		uint32_t data		: 16;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t data		: 16;
		uint32_t ta_lsb		: 1;
		uint32_t ta_msb		: 1;
		uint32_t regad		: 5;
		uint32_t phyad		: 5;
		uint32_t op		: 2;
		uint32_t st		: 2;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} mif_frame_t;

#define	MIF_CFG_POLL_EN			0x00000008 /* enable polling */
#define	MIF_CFG_BB_MODE			0x00000010 /* bit-bang mode */
#define	MIF_CFG_POLL_REG_MASK		0x000003E0 /* reg addr to be polled */
#define	MIF_CFG_POLL_REG_SHIFT		5
#define	MIF_CFG_POLL_PHY_MASK		0x00007C00 /* XCVR addr to be polled */
#define	MIF_CFG_POLL_PHY_SHIFT		10
#define	MIF_CFG_INDIRECT_MODE		0x0000800
					/* used to decide if Cl 22 */
					/* or Cl 45 frame is */
					/* constructed. */
					/* 1 = Clause 45,ST = '00' */
					/* 0 = Clause 22,ST = '01' */
#define	MIF_CFG_ATCE_GE_EN	0x00010000 /* Enable ATCA gigabit mode */

typedef union _mif_cfg_t {

	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */

#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res2		: 15;
		uint32_t atca_ge	: 1;
		uint32_t indirect_md	: 1;
		uint32_t phy_addr	: 5;
		uint32_t reg_addr	: 5;
		uint32_t bb_mode	: 1;
		uint32_t poll_en	: 1;
		uint32_t res1		: 2;
		uint32_t res		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t res		: 1;
		uint32_t res1		: 2;
		uint32_t poll_en	: 1;
		uint32_t bb_mode	: 1;
		uint32_t reg_addr	: 5;
		uint32_t phy_addr	: 5;
		uint32_t indirect_md	: 1;
		uint32_t atca_ge	: 1;
		uint32_t res2		: 15;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;

} mif_cfg_t;

#define	MIF_POLL_STATUS_DATA_MASK	0xffff0000
#define	MIF_POLL_STATUS_STAT_MASK	0x0000ffff

typedef union _mif_poll_stat_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t data;
		uint16_t status;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t status;
		uint16_t data;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} mif_poll_stat_t;


#define	MIF_POLL_MASK_MASK	0x0000ffff

typedef union _mif_poll_mask_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t rsvd;
		uint16_t mask;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t mask;
		uint16_t rsvd;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} mif_poll_mask_t;

#define	MIF_STATUS_INIT_DONE_MASK	0x00000001
#define	MIF_STATUS_XGE_ERR0_MASK	0x00000002
#define	MIF_STATUS_XGE_ERR1_MASK	0x00000004
#define	MIF_STATUS_PEU_ERR_MASK		0x00000008
#define	MIF_STATUS_EXT_PHY_INTR0_MASK	0x00000010
#define	MIF_STATUS_EXT_PHY_INTR1_MASK	0x00000020

typedef union _mif_stat_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t rsvd:26;
		uint32_t ext_phy_intr_flag1:1;
		uint32_t ext_phy_intr_flag0:1;
		uint32_t peu_err:1;
		uint32_t xge_err1:1;
		uint32_t xge_err0:1;
		uint32_t mif_init_done_stat:1;

#elif defined(_BIT_FIELDS_LTOH)
		uint32_t mif_init_done_stat:1;
		uint32_t xge_err0:1;
		uint32_t xge_err1:1;
		uint32_t ext_phy_intr_flag0:1;
		uint32_t ext_phy_intr_flag1:1;
		uint32_t rsvd:26;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} mif_stat_t;

/* MIF State Machine Register */

#define	MIF_SM_EXECUTION_MASK		0x0000003f /* execution state */
#define	MIF_SM_EXECUTION_SHIFT		0
#define	MIF_SM_CONTROL_MASK		0x000001c0 /* control state */
#define	MIF_SM_CONTROL_MASK_SHIFT	6
#define	MIF_SM_MDI			0x00000200
#define	MIF_SM_MDO			0x00000400
#define	MIF_SM_MDO_EN			0x00000800
#define	MIF_SM_MDC			0x00001000
#define	MIF_SM_MDI_0			0x00002000
#define	MIF_SM_MDI_1			0x00004000
#define	MIF_SM_MDI_2			0x00008000
#define	MIF_SM_PORT_ADDR_MASK		0x001f0000
#define	MIF_SM_PORT_ADDR_SHIFT		16
#define	MIF_SM_INT_SIG_MASK		0xffe00000
#define	MIF_SM_INT_SIG_SHIFT		21


/*
 * ******************** PCS registers *********************************
 */

/* PCS Registers */
#define	PCS_MII_CTRL_1000_SEL		0x0040	   /* reads 1. ignored on wr */
#define	PCS_MII_CTRL_COLLISION_TEST	0x0080	   /* COL signal */
#define	PCS_MII_CTRL_DUPLEX		0x0100	   /* forced 0x0. */
#define	PCS_MII_RESTART_AUTONEG		0x0200	   /* self clearing. */
#define	PCS_MII_ISOLATE			0x0400	   /* read 0. ignored on wr */
#define	PCS_MII_POWER_DOWN		0x0800	   /* read 0. ignored on wr */
#define	PCS_MII_AUTONEG_EN		0x1000	   /* autonegotiation */
#define	PCS_MII_10_100_SEL		0x2000	   /* read 0. ignored on wr */
#define	PCS_MII_RESET			0x8000	   /* reset PCS. */

typedef union _pcs_ctrl_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res0		: 16;
			uint32_t reset		: 1;
			uint32_t res1		: 1;
			uint32_t sel_10_100	: 1;
			uint32_t an_enable	: 1;
			uint32_t pwr_down	: 1;
			uint32_t isolate	: 1;
			uint32_t restart_an	: 1;
			uint32_t duplex		: 1;
			uint32_t col_test	: 1;
			uint32_t sel_1000	: 1;
			uint32_t res2		: 6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2		: 6;
			uint32_t sel_1000	: 1;
			uint32_t col_test	: 1;
			uint32_t duplex		: 1;
			uint32_t restart_an	: 1;
			uint32_t isolate	: 1;
			uint32_t pwr_down	: 1;
			uint32_t an_enable	: 1;
			uint32_t sel_10_100	: 1;
			uint32_t res1		: 1;
			uint32_t reset		: 1;
			uint32_t res0		: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} pcs_ctrl_t;

#define	PCS_MII_STATUS_EXTEND_CAP	0x0001	   /* reads 0 */
#define	PCS_MII_STATUS_JABBER_DETECT	0x0002	   /* reads 0 */
#define	PCS_MII_STATUS_LINK_STATUS	0x0004	   /* link status */
#define	PCS_MII_STATUS_AUTONEG_ABLE	0x0008	   /* reads 1 */
#define	PCS_MII_STATUS_REMOTE_FAULT	0x0010	   /* remote fault detected */
#define	PCS_MII_STATUS_AUTONEG_COMP	0x0020	   /* auto-neg completed */
#define	PCS_MII_STATUS_EXTEND_STATUS	0x0100	   /* 1000 Base-X PHY */

typedef union _pcs_stat_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res0		: 23;
		uint32_t ext_stat	: 1;
		uint32_t res1		: 2;
		uint32_t an_complete	: 1;
		uint32_t remote_fault	: 1;
		uint32_t an_able	: 1;
		uint32_t link_stat	: 1;
		uint32_t jabber_detect	: 1;
		uint32_t ext_cap	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t ext_cap	: 1;
		uint32_t jabber_detect	: 1;
		uint32_t link_stat	: 1;
		uint32_t an_able	: 1;
		uint32_t remote_fault	: 1;
		uint32_t an_complete	: 1;
		uint32_t res1		: 2;
		uint32_t ext_stat	: 1;
		uint32_t res0		: 23;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} pcs_stat_t;

#define	PCS_MII_ADVERT_FD		0x0020	   /* advertise full duplex */
#define	PCS_MII_ADVERT_HD		0x0040	   /* advertise half-duplex */
#define	PCS_MII_ADVERT_SYM_PAUSE	0x0080	   /* advertise PAUSE sym */
#define	PCS_MII_ADVERT_ASYM_PAUSE	0x0100	   /* advertises PAUSE asym */
#define	PCS_MII_ADVERT_RF_MASK		0x3000	   /* remote fault */
#define	PCS_MII_ADVERT_RF_SHIFT		12
#define	PCS_MII_ADVERT_ACK		0x4000	   /* (ro) */
#define	PCS_MII_ADVERT_NEXT_PAGE	0x8000	   /* (ro) forced 0x0 */

#define	PCS_MII_LPA_FD			PCS_MII_ADVERT_FD
#define	PCS_MII_LPA_HD			PCS_MII_ADVERT_HD
#define	PCS_MII_LPA_SYM_PAUSE		PCS_MII_ADVERT_SYM_PAUSE
#define	PCS_MII_LPA_ASYM_PAUSE		PCS_MII_ADVERT_ASYM_PAUSE
#define	PCS_MII_LPA_RF_MASK		PCS_MII_ADVERT_RF_MASK
#define	PCS_MII_LPA_RF_SHIFT		PCS_MII_ADVERT_RF_SHIFT
#define	PCS_MII_LPA_ACK			PCS_MII_ADVERT_ACK
#define	PCS_MII_LPA_NEXT_PAGE		PCS_MII_ADVERT_NEXT_PAGE

typedef union _pcs_anar_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res0		: 16;
		uint32_t next_page	: 1;
		uint32_t ack		: 1;
		uint32_t remote_fault	: 2;
		uint32_t res1		: 3;
		uint32_t asm_pause	: 1;
		uint32_t pause		: 1;
		uint32_t half_duplex	: 1;
		uint32_t full_duplex	: 1;
		uint32_t res2		: 5;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t res2		: 5;
		uint32_t full_duplex	: 1;
		uint32_t half_duplex	: 1;
		uint32_t pause		: 1;
		uint32_t asm_pause	: 1;
		uint32_t res1		: 3;
		uint32_t remore_fault	: 2;
		uint32_t ack		: 1;
		uint32_t next_page	: 1;
		uint32_t res0		: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} pcs_anar_t, *p_pcs_anar_t;

#define	PCS_CFG_EN			0x0001	   /* enable PCS. */
#define	PCS_CFG_SD_OVERRIDE		0x0002
#define	PCS_CFG_SD_ACTIVE_LOW		0x0004	   /* sig detect active low */
#define	PCS_CFG_JITTER_STUDY_MASK	0x0018	   /* jitter measurements */
#define	PCS_CFG_JITTER_STUDY_SHIFT	4
#define	PCS_CFG_10MS_TIMER_OVERRIDE	0x0020	   /* shortens autoneg timer */
#define	PCS_CFG_MASK			0x0040	   /* PCS global mask bit */

typedef union _pcs_cfg_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res0			: 25;
		uint32_t mask			: 1;
		uint32_t override_10ms_timer	: 1;
		uint32_t jitter_study		: 2;
		uint32_t sig_det_a_low		: 1;
		uint32_t sig_det_override	: 1;
		uint32_t enable			: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t enable			: 1;
		uint32_t sig_det_override	: 1;
		uint32_t sig_det_a_low		: 1;
		uint32_t jitter_study		: 2;
		uint32_t override_10ms_timer	: 1;
		uint32_t mask			: 1;
		uint32_t res0			: 25;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} pcs_cfg_t, *p_pcs_cfg_t;


/* used for diagnostic purposes. bits 20-22 autoclear on read */
#define	PCS_SM_TX_STATE_MASK		0x0000000F /* Tx idle state mask */
#define	PCS_SM_TX_STATE_SHIFT		0
#define	PCS_SM_RX_STATE_MASK		0x000000F0 /* Rx idle state mask */
#define	PCS_SM_RX_STATE_SHIFT		4
#define	PCS_SM_WORD_SYNC_STATE_MASK	0x00000700 /* loss of sync state mask */
#define	PCS_SM_WORD_SYNC_STATE_SHIFT	8
#define	PCS_SM_SEQ_DETECT_STATE_MASK	0x00001800 /* sequence detect */
#define	PCS_SM_SEQ_DETECT_STATE_SHIFT	11
#define	PCS_SM_LINK_STATE_MASK		0x0001E000 /* link state */
#define	PCS_SM_LINK_STATE_SHIFT		13
#define	PCS_SM_LOSS_LINK_C		0x00100000 /* loss of link */
#define	PCS_SM_LOSS_LINK_SYNC		0x00200000 /* loss of sync */
#define	PCS_SM_LOSS_SIGNAL_DETECT	0x00400000 /* signal detect fail */
#define	PCS_SM_NO_LINK_BREAKLINK	0x01000000 /* receipt of breaklink */
#define	PCS_SM_NO_LINK_SERDES		0x02000000 /* serdes initializing */
#define	PCS_SM_NO_LINK_C		0x04000000 /* C codes not stable */
#define	PCS_SM_NO_LINK_SYNC		0x08000000 /* word sync not achieved */
#define	PCS_SM_NO_LINK_WAIT_C		0x10000000 /* waiting for C codes */
#define	PCS_SM_NO_LINK_NO_IDLE		0x20000000 /* linkpartner send C code */

typedef union _pcs_stat_mc_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res2		: 2;
		uint32_t lnk_dwn_ni	: 1;
		uint32_t lnk_dwn_wc	: 1;
		uint32_t lnk_dwn_ls	: 1;
		uint32_t lnk_dwn_nc	: 1;
		uint32_t lnk_dwn_ser	: 1;
		uint32_t lnk_loss_bc	: 1;
		uint32_t res1		: 1;
		uint32_t loss_sd	: 1;
		uint32_t lnk_loss_sync	: 1;
		uint32_t lnk_loss_c	: 1;
		uint32_t res0		: 3;
		uint32_t link_cfg_stat	: 4;
		uint32_t seq_detc_stat	: 2;
		uint32_t word_sync	: 3;
		uint32_t rx_ctrl	: 4;
		uint32_t tx_ctrl	: 4;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t tx_ctrl	: 4;
		uint32_t rx_ctrl	: 4;
		uint32_t word_sync	: 3;
		uint32_t seq_detc_stat	: 2;
		uint32_t link_cfg_stat	: 4;
		uint32_t res0		: 3;
		uint32_t lnk_loss_c	: 1;
		uint32_t lnk_loss_sync	: 1;
		uint32_t loss_sd	: 1;
		uint32_t res1		: 1;
		uint32_t lnk_loss_bc	: 1;
		uint32_t lnk_dwn_ser	: 1;
		uint32_t lnk_dwn_nc	: 1;
		uint32_t lnk_dwn_ls	: 1;
		uint32_t lnk_dwn_wc	: 1;
		uint32_t lnk_dwn_ni	: 1;
		uint32_t res2		: 2;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} pcs_stat_mc_t, *p_pcs_stat_mc_t;

#define	PCS_INTR_STATUS_LINK_CHANGE	0x04	/* link status has changed */

/*
 * control which network interface is used. no more than one bit should
 * be set.
 */
#define	PCS_DATAPATH_MODE_PCS		0	   /* Internal PCS is used */
#define	PCS_DATAPATH_MODE_MII		0x00000002 /* GMII/RGMII is selected. */

#define	PCS_PACKET_COUNT_TX_MASK	0x000007FF /* pkts xmitted by PCS */
#define	PCS_PACKET_COUNT_RX_MASK	0x07FF0000 /* pkts recvd by PCS */
#define	PCS_PACKET_COUNT_RX_SHIFT	16

/*
 * ******************** XPCS registers *********************************
 */

/* XPCS Base 10G Control1 Register */
#define	XPCS_CTRL1_RST			0x8000 /* Self clearing reset. */
#define	XPCS_CTRL1_LOOPBK		0x4000 /* xpcs Loopback */
#define	XPCS_CTRL1_SPEED_SEL_3		0x2000 /* 1 indicates 10G speed */
#define	XPCS_CTRL1_LOW_PWR		0x0800 /* low power mode. */
#define	XPCS_CTRL1_SPEED_SEL_1		0x0040 /* 1 indicates 10G speed */
#define	XPCS_CTRL1_SPEED_SEL_0_MASK	0x003c /* 0 indicates 10G speed. */
#define	XPCS_CTRL1_SPEED_SEL_0_SHIFT	2



typedef union _xpcs_ctrl1_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res3		: 16;
		uint32_t reset		: 1;
		uint32_t csr_lb		: 1;
		uint32_t csr_speed_sel3	: 1;
		uint32_t res2		: 1;
		uint32_t csr_low_pwr	: 1;
		uint32_t res1		: 4;
		uint32_t csr_speed_sel1	: 1;
		uint32_t csr_speed_sel0	: 4;
		uint32_t res0		: 2;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t res0		: 2;
		uint32_t csr_speed_sel0	: 4;
		uint32_t csr_speed_sel1	: 1;
		uint32_t res1		: 4;
		uint32_t csr_low_pwr	: 1;
		uint32_t res2		: 1;
		uint32_t csr_speed_sel3	: 1;
		uint32_t csr_lb		: 1;
		uint32_t reset		: 1;
		uint32_t res3		: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_ctrl1_t;


/* XPCS Base 10G Status1 Register (Read Only) */
#define	XPCS_STATUS1_FAULT		0x0080
#define	XPCS_STATUS1_RX_LINK_STATUS_UP	0x0004 /* Link status interrupt */
#define	XPCS_STATUS1_LOW_POWER_ABILITY	0x0002 /* low power mode */
#define	XPCS_STATUS_RX_LINK_STATUS_UP	0x1000 /* Link status interrupt */


typedef	union _xpcs_stat1_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res4			: 16;
		uint32_t res3			: 8;
		uint32_t csr_fault		: 1;
		uint32_t res1			: 4;
		uint32_t csr_rx_link_stat	: 1;
		uint32_t csr_low_pwr_ability	: 1;
		uint32_t res0			: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t res0			: 1;
		uint32_t csr_low_pwr_ability	: 1;
		uint32_t csr_rx_link_stat	: 1;
		uint32_t res1			: 4;
		uint32_t csr_fault		: 1;
		uint32_t res3			: 8;
		uint32_t res4			: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_stat1_t;


/* XPCS Base Speed Ability Register. Indicates 10G capability */
#define	XPCS_SPEED_ABILITY_10_GIG	0x0001


typedef	union _xpcs_speed_ab_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1		: 16;
		uint32_t res0		: 15;
		uint32_t csr_10gig	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t csr_10gig	: 1;
		uint32_t res0		: 15;
		uint32_t res1		: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_speed_ab_t;


/* XPCS Base 10G Devices in Package Register */
#define	XPCS_DEV_IN_PKG_CSR_VENDOR2	0x80000000
#define	XPCS_DEV_IN_PKG_CSR_VENDOR1	0x40000000
#define	XPCS_DEV_IN_PKG_DTE_XS		0x00000020
#define	XPCS_DEV_IN_PKG_PHY_XS		0x00000010
#define	XPCS_DEV_IN_PKG_PCS		0x00000008
#define	XPCS_DEV_IN_PKG_WIS		0x00000004
#define	XPCS_DEV_IN_PKG_PMD_PMA		0x00000002
#define	XPCS_DEV_IN_PKG_CLS_22_REG	0x00000000



typedef	union _xpcs_dev_in_pkg_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t csr_vendor2	: 1;
		uint32_t csr_vendor1	: 1;
		uint32_t res1		: 14;
		uint32_t res0		: 10;
		uint32_t dte_xs		: 1;
		uint32_t phy_xs		: 1;
		uint32_t pcs		: 1;
		uint32_t wis		: 1;
		uint32_t pmd_pma	: 1;
		uint32_t clause_22_reg	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t clause_22_reg	: 1;
		uint32_t pmd_pma	: 1;
		uint32_t wis		: 1;
		uint32_t pcs		: 1;
		uint32_t phy_xs		: 1;
		uint32_t dte_xs		: 1;
		uint32_t res0		: 10;
		uint32_t res1		: 14;
		uint32_t csr_vendor1	: 1;
		uint32_t csr_vendor2	: 1;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_dev_in_pkg_t;


/* XPCS Base 10G Control2 Register */
#define	XPCS_PSC_SEL_MASK		0x0003
#define	PSC_SEL_10G_BASE_X_PCS		0x0001


typedef	union _xpcs_ctrl2_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1		: 16;
		uint32_t res0		: 14;
		uint32_t csr_psc_sel	: 2;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t csr_psc_sel	: 2;
		uint32_t res0		: 14;
		uint32_t res1		: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_ctrl2_t;


/* XPCS Base10G Status2 Register */
#define	XPCS_STATUS2_DEV_PRESENT_MASK	0xc000	/* ?????? */
#define	XPCS_STATUS2_TX_FAULT		0x0800	/* Fault on tx path */
#define	XPCS_STATUS2_RX_FAULT		0x0400	/* Fault on rx path */
#define	XPCS_STATUS2_TEN_GBASE_W	0x0004	/* 10G-Base-W */
#define	XPCS_STATUS2_TEN_GBASE_X	0x0002	/* 10G-Base-X */
#define	XPCS_STATUS2_TEN_GBASE_R	0x0001	/* 10G-Base-R */

typedef	union _xpcs_stat2_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res2		: 16;
		uint32_t csr_dev_pres	: 2;
		uint32_t res1		: 2;
		uint32_t csr_tx_fault	: 1;
		uint32_t csr_rx_fault	: 1;
		uint32_t res0		: 7;
		uint32_t ten_gbase_w	: 1;
		uint32_t ten_gbase_x	: 1;
		uint32_t ten_gbase_r	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t ten_gbase_r	: 1;
		uint32_t ten_gbase_x	: 1;
		uint32_t ten_gbase_w	: 1;
		uint32_t res0		: 7;
		uint32_t csr_rx_fault	: 1;
		uint32_t csr_tx_fault	: 1;
		uint32_t res1		: 2;
		uint32_t csr_dev_pres	: 2;
		uint32_t res2		: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_stat2_t;



/* XPCS Base10G Status Register */
#define	XPCS_STATUS_LANE_ALIGN		0x1000 /* 10GBaseX PCS rx lanes align */
#define	XPCS_STATUS_PATTERN_TEST_ABLE	0x0800 /* able to generate patterns. */
#define	XPCS_STATUS_LANE3_SYNC		0x0008 /* Lane 3 is synchronized */
#define	XPCS_STATUS_LANE2_SYNC		0x0004 /* Lane 2 is synchronized */
#define	XPCS_STATUS_LANE1_SYNC		0x0002 /* Lane 1 is synchronized */
#define	XPCS_STATUS_LANE0_SYNC		0x0001 /* Lane 0 is synchronized */

typedef	union _xpcs_stat_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res2			: 16;
		uint32_t res1			: 3;
		uint32_t csr_lane_align		: 1;
		uint32_t csr_pattern_test_able	: 1;
		uint32_t res0			: 7;
		uint32_t csr_lane3_sync		: 1;
		uint32_t csr_lane2_sync		: 1;
		uint32_t csr_lane1_sync		: 1;
		uint32_t csr_lane0_sync		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t csr_lane0_sync		: 1;
		uint32_t csr_lane1_sync		: 1;
		uint32_t csr_lane2_sync		: 1;
		uint32_t csr_lane3_sync		: 1;
		uint32_t res0			: 7;
		uint32_t csr_pat_test_able	: 1;
		uint32_t csr_lane_align		: 1;
		uint32_t res1			: 3;
		uint32_t res2			: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_stat_t;

/* XPCS Base10G Test Control Register */
#define	XPCS_TEST_CTRL_TX_TEST_ENABLE		0x0004
#define	XPCS_TEST_CTRL_TEST_PATTERN_SEL_MASK	0x0003
#define	TEST_PATTERN_HIGH_FREQ			0
#define	TEST_PATTERN_LOW_FREQ			1
#define	TEST_PATTERN_MIXED_FREQ			2

typedef	union _xpcs_test_ctl_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1			: 16;
		uint32_t res0			: 13;
		uint32_t csr_tx_test_en		: 1;
		uint32_t csr_test_pat_sel	: 2;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t csr_test_pat_sel	: 2;
		uint32_t csr_tx_test_en		: 1;
		uint32_t res0			: 13;
		uint32_t res1			: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_test_ctl_t;

/* XPCS Base10G Diagnostic Register */
#define	XPCS_DIAG_EB_ALIGN_ERR3		0x40
#define	XPCS_DIAG_EB_ALIGN_ERR2		0x20
#define	XPCS_DIAG_EB_ALIGN_ERR1		0x10
#define	XPCS_DIAG_EB_DESKEW_OK		0x08
#define	XPCS_DIAG_EB_ALIGN_DET3		0x04
#define	XPCS_DIAG_EB_ALIGN_DET2		0x02
#define	XPCS_DIAG_EB_ALIGN_DET1		0x01
#define	XPCS_DIAG_EB_DESKEW_LOSS	0

#define	XPCS_DIAG_SYNC_3_INVALID	0x8
#define	XPCS_DIAG_SYNC_2_INVALID	0x4
#define	XPCS_DIAG_SYNC_1_INVALID	0x2
#define	XPCS_DIAG_SYNC_IN_SYNC		0x1
#define	XPCS_DIAG_SYNC_LOSS_SYNC	0

#define	XPCS_RX_SM_RECEIVE_STATE	1
#define	XPCS_RX_SM_FAULT_STATE		0

typedef	union _xpcs_diag_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1			: 7;
		uint32_t sync_sm_lane3		: 4;
		uint32_t sync_sm_lane2		: 4;
		uint32_t sync_sm_lane1		: 4;
		uint32_t sync_sm_lane0		: 4;
		uint32_t elastic_buffer_sm	: 8;
		uint32_t receive_sm		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t receive_sm		: 1;
		uint32_t elastic_buffer_sm	: 8;
		uint32_t sync_sm_lane0		: 4;
		uint32_t sync_sm_lane1		: 4;
		uint32_t sync_sm_lane2		: 4;
		uint32_t sync_sm_lane3		: 4;
		uint32_t res1			: 7;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_diag_t;

/* XPCS Base10G Tx State Machine Register */
#define	XPCS_TX_SM_SEND_UNDERRUN	0x9
#define	XPCS_TX_SM_SEND_RANDOM_Q	0x8
#define	XPCS_TX_SM_SEND_RANDOM_K	0x7
#define	XPCS_TX_SM_SEND_RANDOM_A	0x6
#define	XPCS_TX_SM_SEND_RANDOM_R	0x5
#define	XPCS_TX_SM_SEND_Q		0x4
#define	XPCS_TX_SM_SEND_K		0x3
#define	XPCS_TX_SM_SEND_A		0x2
#define	XPCS_TX_SM_SEND_SDP		0x1
#define	XPCS_TX_SM_SEND_DATA		0

/* XPCS Base10G Configuration Register */
#define	XPCS_CFG_VENDOR_DBG_SEL_MASK	0x78
#define	XPCS_CFG_VENDOR_DBG_SEL_SHIFT	3
#define	XPCS_CFG_BYPASS_SIG_DETECT	0x0004
#define	XPCS_CFG_ENABLE_TX_BUFFERS	0x0002
#define	XPCS_CFG_XPCS_ENABLE		0x0001

typedef	union _xpcs_config_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res1			: 16;
		uint32_t res0			: 9;
		uint32_t csr_vendor_dbg_sel	: 4;
		uint32_t csr_bypass_sig_detect	: 1;
		uint32_t csr_en_tx_buf		: 1;
		uint32_t csr_xpcs_en		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t csr_xpcs_en		: 1;
		uint32_t csr_en_tx_buf		: 1;
		uint32_t csr_bypass_sig_detect	: 1;
		uint32_t csr_vendor_dbg_sel	: 4;
		uint32_t res0			: 9;
		uint32_t res1			: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} xpcs_config_t;



/* XPCS Base10G Mask1 Register */
#define	XPCS_MASK1_FAULT_MASK		0x0080	/* mask fault interrupt. */
#define	XPCS_MASK1_RX_LINK_STATUS_MASK	0x0040	/* mask linkstat interrupt */

/* XPCS Base10G Packet Counter */
#define	XPCS_PKT_CNTR_TX_PKT_CNT_MASK	0xffff0000
#define	XPCS_PKT_CNTR_TX_PKT_CNT_SHIFT	16
#define	XPCS_PKT_CNTR_RX_PKT_CNT_MASK	0x0000ffff
#define	XPCS_PKT_CNTR_RX_PKT_CNT_SHIFT	0

/* XPCS Base10G TX State Machine status register */
#define	XPCS_TX_STATE_MC_TX_STATE_MASK	0x0f
#define	XPCS_DESKEW_ERR_CNTR_MASK	0xff

/* XPCS Base10G Lane symbol error counters */
#define	XPCS_SYM_ERR_CNT_L1_MASK  0xffff0000
#define	XPCS_SYM_ERR_CNT_L0_MASK  0x0000ffff
#define	XPCS_SYM_ERR_CNT_L3_MASK  0xffff0000
#define	XPCS_SYM_ERR_CNT_L2_MASK  0x0000ffff

#define	XPCS_SYM_ERR_CNT_MULTIPLIER	16

/* ESR Reset Register */
#define	ESR_RESET_1			2
#define	ESR_RESET_0			1

/* ESR Configuration Register */
#define	ESR_BLUNT_END_LOOPBACK		2
#define	ESR_FORCE_SERDES_SERDES_RDY	1

/* ESR Neptune Serdes PLL Configuration */
#define	ESR_PLL_CFG_FBDIV_0		0x1
#define	ESR_PLL_CFG_FBDIV_1		0x2
#define	ESR_PLL_CFG_FBDIV_2		0x4
#define	ESR_PLL_CFG_HALF_RATE_0		0x8
#define	ESR_PLL_CFG_HALF_RATE_1		0x10
#define	ESR_PLL_CFG_HALF_RATE_2		0x20
#define	ESR_PLL_CFG_HALF_RATE_3		0x40
#define	ESR_PLL_CFG_1G_SERDES		(ESR_PLL_CFG_FBDIV_0 |		\
					ESR_PLL_CFG_HALF_RATE_0 |	\
					ESR_PLL_CFG_HALF_RATE_1 |	\
					ESR_PLL_CFG_HALF_RATE_2 |	\
					ESR_PLL_CFG_HALF_RATE_3)

#define	ESR_PLL_CFG_10G_SERDES		ESR_PLL_CFG_FBDIV_2

/* ESR Neptune Serdes Control Register */
#define	ESR_CTL_EN_SYNCDET_0		0x00000001
#define	ESR_CTL_EN_SYNCDET_1		0x00000002
#define	ESR_CTL_EN_SYNCDET_2		0x00000004
#define	ESR_CTL_EN_SYNCDET_3		0x00000008
#define	ESR_CTL_OUT_EMPH_0_MASK		0x00000070
#define	ESR_CTL_OUT_EMPH_0_SHIFT	4
#define	ESR_CTL_OUT_EMPH_1_MASK		0x00000380
#define	ESR_CTL_OUT_EMPH_1_SHIFT	7
#define	ESR_CTL_OUT_EMPH_2_MASK		0x00001c00
#define	ESR_CTL_OUT_EMPH_2_SHIFT	10
#define	ESR_CTL_OUT_EMPH_3_MASK		0x0000e000
#define	ESR_CTL_OUT_EMPH_3_SHIFT	13
#define	ESR_CTL_LOSADJ_0_MASK		0x00070000
#define	ESR_CTL_LOSADJ_0_SHIFT		16
#define	ESR_CTL_LOSADJ_1_MASK		0x00380000
#define	ESR_CTL_LOSADJ_1_SHIFT		19
#define	ESR_CTL_LOSADJ_2_MASK		0x01c00000
#define	ESR_CTL_LOSADJ_2_SHIFT		22
#define	ESR_CTL_LOSADJ_3_MASK		0x0e000000
#define	ESR_CTL_LOSADJ_3_SHIFT		25
#define	ESR_CTL_RXITERM_0		0x10000000
#define	ESR_CTL_RXITERM_1		0x20000000
#define	ESR_CTL_RXITERM_2		0x40000000
#define	ESR_CTL_RXITERM_3		0x80000000
#define	ESR_CTL_1G_SERDES		(ESR_CTL_EN_SYNCDET_0 | \
					ESR_CTL_EN_SYNCDET_1 |	\
					ESR_CTL_EN_SYNCDET_2 |	\
					ESR_CTL_EN_SYNCDET_3 |  \
					(0x1 << ESR_CTL_OUT_EMPH_0_SHIFT) | \
					(0x1 << ESR_CTL_OUT_EMPH_1_SHIFT) | \
					(0x1 << ESR_CTL_OUT_EMPH_2_SHIFT) | \
					(0x1 << ESR_CTL_OUT_EMPH_3_SHIFT) | \
					(0x1 << ESR_CTL_OUT_EMPH_3_SHIFT) | \
					(0x1 << ESR_CTL_LOSADJ_0_SHIFT) | \
					(0x1 << ESR_CTL_LOSADJ_1_SHIFT) | \
					(0x1 << ESR_CTL_LOSADJ_2_SHIFT) | \
					(0x1 << ESR_CTL_LOSADJ_3_SHIFT))

/* ESR Neptune Serdes Test Configuration Register */
#define	ESR_TSTCFG_LBTEST_MD_0_MASK	0x00000003
#define	ESR_TSTCFG_LBTEST_MD_0_SHIFT	0
#define	ESR_TSTCFG_LBTEST_MD_1_MASK	0x0000000c
#define	ESR_TSTCFG_LBTEST_MD_1_SHIFT	2
#define	ESR_TSTCFG_LBTEST_MD_2_MASK	0x00000030
#define	ESR_TSTCFG_LBTEST_MD_2_SHIFT	4
#define	ESR_TSTCFG_LBTEST_MD_3_MASK	0x000000c0
#define	ESR_TSTCFG_LBTEST_MD_3_SHIFT	6
#define	ESR_TSTCFG_LBTEST_PAD		(ESR_PAD_LOOPBACK_CH3 | \
					ESR_PAD_LOOPBACK_CH2 | \
					ESR_PAD_LOOPBACK_CH1 | \
					ESR_PAD_LOOPBACK_CH0)

/* ESR Neptune Ethernet RGMII Configuration Register */
#define	ESR_RGMII_PT0_IN_USE		0x00000001
#define	ESR_RGMII_PT1_IN_USE		0x00000002
#define	ESR_RGMII_PT2_IN_USE		0x00000004
#define	ESR_RGMII_PT3_IN_USE		0x00000008
#define	ESR_RGMII_REG_RW_TEST		0x00000010

/* ESR Internal Signals Observation Register */
#define	ESR_SIG_MASK			0xFFFFFFFF
#define	ESR_SIG_P0_BITS_MASK		0x33E0000F
#define	ESR_SIG_P1_BITS_MASK		0x0C1F00F0
#define	ESR_SIG_SERDES_RDY0_P0		0x20000000
#define	ESR_SIG_DETECT0_P0		0x10000000
#define	ESR_SIG_SERDES_RDY0_P1		0x08000000
#define	ESR_SIG_DETECT0_P1		0x04000000
#define	ESR_SIG_XSERDES_RDY_P0		0x02000000
#define	ESR_SIG_XDETECT_P0_CH3		0x01000000
#define	ESR_SIG_XDETECT_P0_CH2		0x00800000
#define	ESR_SIG_XDETECT_P0_CH1		0x00400000
#define	ESR_SIG_XDETECT_P0_CH0		0x00200000
#define	ESR_SIG_XSERDES_RDY_P1		0x00100000
#define	ESR_SIG_XDETECT_P1_CH3		0x00080000
#define	ESR_SIG_XDETECT_P1_CH2		0x00040000
#define	ESR_SIG_XDETECT_P1_CH1		0x00020000
#define	ESR_SIG_XDETECT_P1_CH0		0x00010000
#define	ESR_SIG_LOS_P1_CH3		0x00000080
#define	ESR_SIG_LOS_P1_CH2		0x00000040
#define	ESR_SIG_LOS_P1_CH1		0x00000020
#define	ESR_SIG_LOS_P1_CH0		0x00000010
#define	ESR_SIG_LOS_P0_CH3		0x00000008
#define	ESR_SIG_LOS_P0_CH2		0x00000004
#define	ESR_SIG_LOS_P0_CH1		0x00000002
#define	ESR_SIG_LOS_P0_CH0		0x00000001
#define	ESR_SIG_P0_BITS_MASK_1G		(ESR_SIG_SERDES_RDY0_P0 | \
					ESR_SIG_DETECT0_P0)
#define	ESR_SIG_P1_BITS_MASK_1G		(ESR_SIG_SERDES_RDY0_P1 | \
					ESR_SIG_DETECT0_P1)

/* ESR Debug Selection Register */
#define	ESR_DEBUG_SEL_MASK		0x00000003f

/* ESR Test Configuration Register */
#define	ESR_NO_LOOPBACK_CH3		(0x0 << 6)
#define	ESR_EWRAP_CH3			(0x1 << 6)
#define	ESR_PAD_LOOPBACK_CH3		(0x2 << 6)
#define	ESR_REVLOOPBACK_CH3		(0x3 << 6)
#define	ESR_NO_LOOPBACK_CH2		(0x0 << 4)
#define	ESR_EWRAP_CH2			(0x1 << 4)
#define	ESR_PAD_LOOPBACK_CH2		(0x2 << 4)
#define	ESR_REVLOOPBACK_CH2		(0x3 << 4)
#define	ESR_NO_LOOPBACK_CH1		(0x0 << 2)
#define	ESR_EWRAP_CH1			(0x1 << 2)
#define	ESR_PAD_LOOPBACK_CH1		(0x2 << 2)
#define	ESR_REVLOOPBACK_CH1		(0x3 << 2)
#define	ESR_NO_LOOPBACK_CH0		0x0
#define	ESR_EWRAP_CH0			0x1
#define	ESR_PAD_LOOPBACK_CH0		0x2
#define	ESR_REVLOOPBACK_CH0		0x3

/* convert values */
#define	NXGE_BASE(x, y)	\
	(((y) << (x ## _SHIFT)) & (x ## _MASK))

#define	NXGE_VAL_GET(fieldname, regval)		\
	(((regval) & ((fieldname) ## _MASK)) >> ((fieldname) ## _SHIFT))

#define	NXGE_VAL_SET(fieldname, regval, val)		\
{							\
	(regval) &= ~((fieldname) ## _MASK);		\
	(regval) |= ((val) << (fieldname ## _SHIFT)); 	\
}


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MAC_NXGE_MAC_HW_H */
