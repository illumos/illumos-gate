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

#ifndef _SYS_NGE_CHIP_H
#define	_SYS_NGE_CHIP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "nge.h"

#define	VENDOR_ID_NVIDIA	0x10de

#define	DEVICE_ID_MCP04_37	0x37
#define	DEVICE_ID_MCP04_38	0x38
#define	DEVICE_ID_CK804_56	0x56
#define	DEVICE_ID_CK804_57	0x57
#define	DEVICE_ID_MCP51_269	0x269
#define	DEVICE_ID_MCP51_268	0x268
#define	DEVICE_ID_MCP55_373	0x373
#define	DEVICE_ID_MCP55_372	0x372
#define	DEVICE_ID_MCP61_3EE	0x3ee
#define	DEVICE_ID_MCP61_3EF	0x3ef
#define	DEVICE_ID_MCP77_760	0x760
#define	DEVICE_ID_MCP79_AB0	0xab0
#define	DEVICE_ID_NF3_E6	0xe6
#define	DEVICE_ID_NF3_DF	0xdf

/* Private PCI configuration register for bus config of ck804/mcp55 */
#define	PCI_CONF_HT_INTERNAL	0x4c

typedef union _nge_interbus_conf {
	uint32_t	conf_val;
	struct {
		uint32_t	unit_id:5;
		uint32_t	resv5_23:19;
		uint32_t	aux_val:3;
		uint32_t	resv27:1;
		uint32_t	msi_off:1;
		uint32_t	msix_off:1; /* mcp55 only */
		uint32_t	resv30_31:2;
	} conf_bits;
} nge_interbus_conf;

/* Private PCI configuration register for MSI mask of mcp55 */
#define	PCI_CONF_HT_MSI_MASK	0x60

typedef union _nge_msi_mask_conf {
	uint32_t	msi_mask_conf_val;
	struct {
		uint32_t	vec0_off:1;
		uint32_t	vec1_off:1;
		uint32_t	vec2_off:1;
		uint32_t	vec3_off:1;
		uint32_t	vec4_off:1;
		uint32_t	vec5_off:1;
		uint32_t	vec6_off:1;
		uint32_t	vec7_off:1;
		uint32_t	resv8_31:24;
	} msi_mask_bits;
} nge_msi_mask_conf;

/* Private PCI configuration register for MSI map capability of mcp55 */
#define	PCI_CONF_HT_MSI_MAP_CAP	0x6c

typedef union _nge_msi_map_cap_conf {
	uint32_t	msi_map_cap_conf_val;
	struct {
		uint32_t	cap_id:8;
		uint32_t	next_ptr:8;
		uint32_t	map_en:1;
		uint32_t	map_fixed:1;
		uint32_t	resv18_26:9;
		uint32_t	cap_type:5;
	} map_cap_conf_bits;
} nge_msi_map_cap_conf;

/*
 * Master interrupt
 */
#define	NGE_INTR_SRC		0x000
#define	INTR_SRC_ALL		0x00007fff
typedef union _nge_intr_src {
	uint32_t	intr_val;
	struct {
		uint32_t	reint:1;
		uint32_t	rcint:1;
		uint32_t	miss:1;
		uint32_t	teint:1;
		uint32_t	tcint:1;
		uint32_t	stint:1;
		uint32_t	mint:1;
		uint32_t	rfint:1;
		uint32_t	tfint:1;
		uint32_t	feint:1;
		uint32_t	resv10:1;
		uint32_t	resv11:1;
		uint32_t	resv12:1;
		uint32_t	resv13:1;
		uint32_t	phyint:1;
		uint32_t	resv15_31:17;
	} int_bits;
} nge_intr_src;

/*
 * Master interrupt Mask
 */
#define	NGE_INTR_MASK		0x004
#define	NGE_INTR_ALL_EN		0x00007fff
typedef union _nge_intr_mask {
	uint32_t	mask_val;
	struct {
		uint32_t	reint:1;
		uint32_t	rcint:1;
		uint32_t	miss:1;
		uint32_t	teint:1;
		uint32_t	tcint:1;
		uint32_t	stint:1;
		uint32_t	mint:1;
		uint32_t	rfint:1;
		uint32_t	tfint:1;
		uint32_t	feint:1;
		uint32_t	resv10:1;
		uint32_t	resv11:1;
		uint32_t	resv12:1;
		uint32_t	resv13:1;
		uint32_t	phyint:1;
		uint32_t	resv15_31:17;
	} mask_bits;
} nge_intr_mask;

/*
 * Software timer control register
 */
#define	NGE_SWTR_CNTL		0x008
typedef union _nge_swtr_cntl {
	uint8_t	ctrl_val;
	struct {
		uint8_t	stren:1;
		uint8_t	sten:1;
		uint8_t	resv2_7:6;
	} cntl_bits;
} nge_swtr_cntl;

/*
 * Software Timer Interval
 */
#define	NGE_SWTR_ITC		0x00c

/* Default timer interval, 97 would mean 1 ms */
#define	SWTR_ITC		0x8
typedef union _nge_itc {
	uint32_t	itc_val;
	struct {
		uint32_t	sw_intv:16;
		uint32_t	sw_cur_val:16;
	} itc_bits;
} nge_itc;

/*
 * Fatal error register
 */
#define	NGE_REG010		0x010
typedef union _nge_reg010 {
	uint32_t	reg010_val;
	struct {
		uint32_t	resv0:1;
		uint32_t	resv1:1;
		uint32_t	resv2:1;
		uint32_t	resv3:1;
		uint32_t	resv4:1;
		uint32_t	resv5:1;
		uint32_t	resv6:1;
		uint32_t	resv7:1;
		uint32_t	resv8:1;
		uint32_t	resv9:1;
		uint32_t	resv10:1;
		uint32_t	resv11_31:21;
	} reg010_bits;
} nge_reg010;

/*
 * MSI vector map register 0
 */
#define	NGE_MSI_MAP0		0x020
typedef union _nge_msi_map0_vec {
	uint32_t msi_map0_val;
	struct {
		uint32_t reint_vec:4;
		uint32_t rcint_vec:4;
		uint32_t miss_vec:4;
		uint32_t teint_vec:4;
		uint32_t tcint_vec:4;
		uint32_t stint_vec:4;
		uint32_t mint_vec:4;
		uint32_t rfint_vec:4;
	} vecs_bits;
} nge_msi_map0_vec;

/*
 * MSI vector map register 1
 */
#define	NGE_MSI_MAP1		0x024
typedef union _nge_msi_map1_vec {
	uint32_t msi_map1_val;
	struct {
		uint32_t tfint_vec:4;
		uint32_t feint_vec:4;
		uint32_t resv8_11:4;
		uint32_t resv12_15:4;
		uint32_t resv16_19:4;
		uint32_t resv20_23:4;
		uint32_t resv24_31:8;
	} vecs_bits;
} nge_msi_map1_vec;


/*
 * MSI vector map register 2
 */
#define	NGE_MSI_MAP2		0x028

/*
 * MSI vector map register 2
 */
#define	NGE_MSI_MAP3		0x02c

/*
 * MSI mask register for mcp55
 */
#define	NGE_MSI_MASK	0x30
typedef union _nge_msi_mask {
	uint32_t	msi_mask_val;
	struct {
		uint32_t	vec0:1;
		uint32_t	vec1:1;
		uint32_t	vec2:1;
		uint32_t	vec3:1;
		uint32_t	vec4:1;
		uint32_t	vec5:1;
		uint32_t	vec6:1;
		uint32_t	vec7:1;
		uint32_t	resv8_31:24;
	}msi_msk_bits;
}nge_msi_mask;

/*
 * Software misc register for mcp51
 */
#define	NGE_SOFT_MISC		0x034
typedef union _nge_soft_misc {
	uint32_t misc_val;
	struct {
		uint32_t	rx_clk_vx_rst:1;
		uint32_t	tx_clk_vx_rst:1;
		uint32_t	clk12m_vx_rst:1;
		uint32_t	fpci_clk_vx_rst:1;
		uint32_t	rx_clk_vc_rst:1;
		uint32_t	tx_clk_vc_rst:1;
		uint32_t	fs_clk_vc_rst:1;
		uint32_t	rst_ex_m2pintf:1;
		uint32_t	resv8_31:24;
	} misc_bits;
} nge_soft_misc;

/*
 * DMA configuration
 */
#define	NGE_DMA_CFG		0x040
typedef union _nge_dma_cfg {
	uint32_t cfg_val;
	struct {
		uint32_t	tx_start_pri:3;
		uint32_t	tx_start_pri_flag:1;
		uint32_t	tx_prd_rpri:3;
		uint32_t	tx_prd_rpri_flag:1;
		uint32_t	tx_prd_wpri:3;
		uint32_t	tx_prd_wpri_flag:1;
		uint32_t	rx_start_pri:3;
		uint32_t	rx_start_pri_flag:1;
		uint32_t	rx_prd_rpri:3;
		uint32_t	rx_prd_rpri_flag:1;
		uint32_t	rx_prd_wpri:3;
		uint32_t	rx_prd_wpri_flag:1;
		uint32_t	dma_max_pri:3;
		uint32_t	dma_wrr_disable:1;
		uint32_t	dma_pri_disable:1;
	} cfg_bits;
} nge_dma_cfg;

/*
 * Request DMA configuration
 */
#define	NGE_DMA_RCFG		0x044
typedef union _nge_dma_rcfg {
	uint32_t dma_rcfg_val;
	struct {
		uint32_t	tx_prd_coh_state:2;
		uint32_t	tx_data_coh_state:2;
		uint32_t	rx_prd_coh_state:2;
		uint32_t	rx_data_coh_state:2;
		uint32_t	max_roffset:5;
		uint32_t	resv13_31:19;
	} rcfg_bis;
} nge_dma_rcfg;

/*
 * Hot DMA configuration
 */
#define	NGE_DMA_HOT_CFG		0x048
typedef union _nge_dma_hcfg {
	uint32_t	dma_hcfg_val;
	struct {
		uint32_t	resv0_3:4;
		uint32_t	noti_wstart_pri:3;
		uint32_t	noti_wstart_pri_flag:1;
		uint32_t	cmd_rstart_pri:3;
		uint32_t	cmd_rstart_pri_flag:1;
		uint32_t	cmd_wstart_pri:3;
		uint32_t	cmd_wstart_pri_flag:1;
		uint32_t	resv16_31:16;
	} hcfg_bits;
} nge_dma_hcfg;

/*
 * PMU control register 0 for mcp51
 */
#define	NGE_PMU_CNTL0			0x060
#define	NGE_PMU_CORE_SPD10_BUSY		0x8
#define	NGE_PMU_CORE_SPD10_IDLE		0xB
#define	NGE_PMU_CORE_SPD100_BUSY	0x4
#define	NGE_PMU_CORE_SPD100_IDLE	0x7
#define	NGE_PMU_CORE_SPD1000_BUSY	0x0
#define	NGE_PMU_CORE_SPD1000_IDLE	0x3

typedef union _nge_pmu_cntl0 {
	uint32_t	cntl0_val;
	struct {
		uint32_t	core_spd10_fp:4;
		uint32_t	core_spd10_idle:4;
		uint32_t	core_spd100_fp:4;
		uint32_t	core_spd100_idle:4;
		uint32_t	core_spd1000_fp:4;
		uint32_t	core_spd1000_idle:4;
		uint32_t	core_sts_cur:8;
	} cntl0_bits;
} nge_pmu_cntl0;

/*
 * PMU control register 1 for mcp51
 */
#define	NGE_PMU_CNTL1		0x064
typedef union _nge_pmu_cntl1 {
	uint32_t	cntl1_val;
	struct {
		uint32_t	dev_fp:4;
		uint32_t	dev_idle:4;
		uint32_t	resv8_27:20;
		uint32_t	dev_sts_cur:4;
	} cntl1_bits;
} nge_pmu_cntl1;

/*
 * PMU control register 2 for mcp51
 */
#define	NGE_PMU_CNTL2		0x068
typedef union _nge_pmu_cntl2 {
	uint32_t	cntl2_val;
	struct {
		uint32_t	core_override:4;
		uint32_t	resv4_7:4;
		uint32_t	dev_override:4;
		uint32_t	resv12_15:4;
		uint32_t	core_override_en:1;
		uint32_t	dev_override_en:1;
		uint32_t	core_enable:1;
		uint32_t	dev_enable:1;
		uint32_t	rx_wake_dis:1;
		uint32_t	cidle_timer:1;
		uint32_t	didle_timer:1;
		uint32_t	resv23_31:9;
	} cntl2_bits;
} nge_pmu_cntl2;

/*
 * PMU core idle limit register for mcp51
 */
#define	NGE_PMU_CIDLE_LIMIT	0x06c
#define	NGE_PMU_CIDLE_LIMIT_DEF	0xffff

/*
 * PMU device idle limit register for mcp51
 */
#define	NGE_PMU_DIDLE_LIMIT	0x070
#define	NGE_PMU_DIDLE_LIMIT_DEF	0xffff

/*
 * PMU core idle count value register for mcp51
 */
#define	NGE_PMU_CIDLE_COUNT	0x074
#define	NGE_PMU_CIDEL_COUNT_DEF	0xffff

/*
 * PMU device idle count value register for mcp51
 */
#define	NGE_PMU_DIDLE_COUNT	0x078
#define	NGE_PMU_DIDEL_COUNT_DEF	0xffff

/*
 * Transmit control
 */
#define	NGE_TX_CNTL		0x080
typedef union _nge_tx_cntl {
	uint32_t	cntl_val;
	struct {
		uint32_t	paen:1; /* only for mcp55, otherwise reserve */
		uint32_t	resv1:1;
		uint32_t	retry_en:1;
		uint32_t	pad_en:1;
		uint32_t	fappend_en:1;
		uint32_t	two_def_en:1;
		uint32_t	resv6_7:2;
		uint32_t	max_retry:4;
		uint32_t	burst_en:1;
		uint32_t	resv13_15:3;
		uint32_t	retry_emask:1;
		uint32_t	exdef_mask:1;
		uint32_t	def_mask:1;
		uint32_t	lcar_mask:1;
		uint32_t	tlcol_mask:1;
		uint32_t	uflo_err_mask:1;
		uint32_t	resv22_23:2;
		uint32_t	jam_seq_en:1;
		uint32_t	resv25_31:7;
	} cntl_bits;
} nge_tx_cntl;

/*
 * Transmit enable
 * Note: for ck804 or mcp51, this is 8-bit register;
 * for mcp55, it is a 32-bit register.
 */
#define	NGE_TX_EN		0x084
#define	NGE_SMU_FREE		0x0
#define	NGE_SMU_GET		0xf
typedef union _nge_tx_en {
	uint32_t	val;
	struct {
		uint32_t	tx_en:1;
		uint32_t	resv1_7:7;
		uint32_t	smu2mac:4;
		uint32_t	mac2smu:4;
		uint32_t	resv16_31:16;
	} bits;
} nge_tx_en;

/*
 * Transmit status
 */
#define	NGE_TX_STA		0x088
typedef union _nge_tx_sta {
	uint32_t	sta_val;
	struct {
		uint32_t	tx_chan_sta:1;
		uint32_t	resv1_15:15;
		uint32_t	retry_err:1;
		uint32_t	exdef:1;
		uint32_t	def:1;
		uint32_t	lcar:1;
		uint32_t	tlcol:1;
		uint32_t	uflo:1;
		uint32_t	resv22_31:10;
	} sta_bits;
} nge_tx_sta;

/*
 * Receive control
 */
#define	NGE_RX_CNTL0		0x08c
typedef union _nge_rx_cntrl0 {
	uint32_t	cntl_val;
	struct {
		uint32_t	resv0:1;
		uint32_t	padsen:1;
		uint32_t	fcsren:1;
		uint32_t	paen:1;
		uint32_t	lben:1;
		uint32_t	afen:1;
		uint32_t	runten:1;
		uint32_t	brdis:1;
		uint32_t	rdfen:1;
		uint32_t	slfb:1;
		uint32_t	resv10_15:6;
		uint32_t	runtm:1;
		uint32_t	rlcolm:1;
		uint32_t	maxerm:1;
		uint32_t	lferm:1;
		uint32_t	crcm:1;
		uint32_t	ofolm:1;
		uint32_t	framerm:1;
		uint32_t 	resv23_31:9;
	} cntl_bits;
} nge_rx_cntrl0;

/*
 * Maximum receive Frame size
 */
#define	NGE_RX_CNTL1		0x090
typedef union _nge_rx_cntl1 {
	uint32_t	cntl_val;
	struct {
		uint32_t	length:14;
		uint32_t	resv14_31:18;
	} cntl_bits;
} nge_rx_cntl1;

/*
 * Receive enable register
 * Note: for ck804 and mcp51, this is a 8-bit register;
 * for mcp55, it is a 32-bit register.
 */
#define	NGE_RX_EN		0x094
typedef union _nge_rx_en {
	uint8_t	val;
	struct {
		uint8_t	rx_en:1;
		uint8_t	resv1_7:7;
	} bits;
} nge_rx_en;

/*
 * Receive status register
 */
#define	NGE_RX_STA		0x098
typedef union _nge_rx_sta {
	uint32_t	sta_val;
	struct {
		uint32_t	rx_chan_sta:1;
		uint32_t	resv1_15:15;
		uint32_t	runt_sta:1;
		uint32_t	rlcol_sta:1;
		uint32_t	mlen_err:1;
		uint32_t	lf_err:1;
		uint32_t	crc_err:1;
		uint32_t	ofol_err:1;
		uint32_t	fram_err:1;
		uint32_t	resv23_31:9;
	} sta_bits;
} nge_rx_sta;

/*
 * Backoff Control
 */
#define	NGE_BKOFF_CNTL		0x09c
#define	BKOFF_RSEED		0x8
#define	BKOFF_SLIM_GMII		0x3ff
#define	BKOFF_SLIM_MII		0x7f
typedef union _nge_bkoff_cntl	{
	uint32_t	cntl_val;
	struct {
		uint32_t	rseed:8;
		uint32_t	sltm:10;
		uint32_t	resv18_30:13;
		uint32_t	leg_bk_en:1;
	} bkoff_bits;
} nge_bkoff_cntl;

/*
 * Transmit defferral timing
 */
#define	NGE_TX_DEF		0x0a0
#define	TX_TIFG_MII		0x15
#define	TX_IFG_RGMII_1000_FD	0x14
#define	TX_IFG_RGMII_OTHER	0x16
#define	TX_IFG2_MII		0x5
#define	TX_IFG2_RGMII_10_100	0x7
#define	TX_IFG2_RGMII_1000	0x5
#define	TX_IFG2_DEFAULT		0X0
#define	TX_IFG1_DEFAULT		0xf
typedef union _nge_tx_def {
	uint32_t	def_val;
	struct {
		uint32_t	ifg1_def:8;
		uint32_t	ifg2_def:8;
		uint32_t	if_def:8;
		uint32_t	resv24_31:8;
	} def_bits;
} nge_tx_def;

/*
 * Receive defferral timing
 */
#define	NGE_RX_DEf		0x0a4
#define	RX_DEF_DEFAULT		0x16
typedef union _nge_rx_def {
	uint8_t	def_val;
	struct {
		uint8_t rifg;
	} def_bits;
} nge_rx_def;

/*
 * Low 32 bit unicast address
 */
#define	NGE_UNI_ADDR0		0x0a8
union {
	uint32_t	addr_val;
	struct {
		uint32_t	addr;
	} addr_bits;
} nge_uni_addr0;

/*
 * High 32 bit unicast address
 */
#define	NGE_UNI_ADDR1		0x0ac
typedef union _nge_uni_addr1 {
	uint32_t	addr_val;
	struct {
		uint32_t	addr:16;
		uint32_t	resv16_31:16;
	} addr_bits;
} nge_uni_addr1;

#define	LOW_24BITS_MASK		0xffffffULL
#define	REVERSE_MAC_ELITE	0x211900ULL
#define	REVERSE_MAC_GIGABYTE	0xe61600ULL
#define	REVERSE_MAC_ASUS	0x601d00ULL

/*
 * Low 32 bit multicast address
 */
#define	NGE_MUL_ADDR0		0x0b0
union {
	uint32_t	addr_val;
	struct {
		uint32_t	addr;
	}addr_bits;
}nge_mul_addr0;

/*
 * High 32 bit multicast address
 */
#define	NGE_MUL_ADDR1		0x0b4
typedef union _nge_mul_addr1 {
	uint32_t	addr_val;
	struct {
		uint32_t	addr:16;
		uint32_t	resv16_31:16;
	}addr_bits;
}nge_mul_addr1;

/*
 * Low 32 bit multicast mask
 */
#define	NGE_MUL_MASK		0x0b8
union {
	uint32_t	mask_val;
	struct {
		uint32_t	mask;
	} mask_bits;
} nge_mul_mask0;

/*
 * High 32 bit multicast mask
 */
#define	NGE_MUL_MASK1		0x0bc
union {
	uint32_t	mask_val;
	struct {
		uint32_t	mask:16;
		uint32_t	resv16_31:16;
	} mask_bits;
} nge_mul_mask1;

/*
 * Mac-to Phy Interface
 */
#define	NGE_MAC2PHY		0x0c0
#define	low_speed		0x0
#define	fast_speed		0x1
#define	giga_speed		0x2
#define	err_speed		0x4
#define	MII_IN			0x0
#define	RGMII_IN		0x1
#define	ERR_IN1			0x3
#define	ERR_IN2			0x4
typedef union _nge_mac2phy {
	uint32_t	m2p_val;
	struct {
		uint32_t	speed:2;
		uint32_t	resv2_7:6;
		uint32_t	hdup_en:1;
		uint32_t	resv9:1;
		uint32_t	phyintr:1;    /* for mcp55 only */
		uint32_t	phyintrlvl:1; /* for mcp55 only */
		uint32_t	resv12_27:16;
		uint32_t	in_type:2;
		uint32_t	resv30_31:2;
	} m2p_bits;
} nge_mac2phy;

/*
 * Transmit Descriptor Ring address
 */
#define	NGE_TX_DADR		0x100
typedef union _nge_tx_addr	{
	uint32_t	addr_val;
	struct {
		uint32_t	resv0_2:3;
		uint32_t	addr:29;
	} addr_bits;
} nge_tx_addr;

/*
 * Receive Descriptor Ring address
 */
#define	NGE_RX_DADR		0x104
typedef union _nge_rx_addr {
	uint32_t	addr_val;
	struct {
		uint32_t	resv0_2:3;
		uint32_t	addr:29;
	} addr_bits;
} nge_rx_addr;

/*
 * Rx/tx descriptor ring leng
 * Note: for mcp55, tdlen/rdlen are 14 bit.
 */
#define	NGE_RXTX_DLEN		0x108
typedef union _nge_rxtx_dlen {
	uint32_t	dlen_val;
	struct {
		uint32_t	tdlen:14;
		uint32_t	resv14_15:2;
		uint32_t	rdlen:14;
		uint32_t	resv30_31:2;
	} dlen_bits;
} nge_rxtx_dlen;

/*
 * Transmit polling register
 */
#define	NGE_TX_POLL		0x10c
#define	TX_POLL_INTV_1G		10
#define	TX_POLL_INTV_100M	100
#define	TX_POLL_INTV_10M	1000

typedef union _nge_tx_poll {
	uint32_t	poll_val;
	struct {
		uint32_t	tpi:16;
		uint32_t	tpen:1;
		uint32_t	resv17_31:15;
	} poll_bits;
} nge_tx_poll;

/*
 * Receive polling register
 */
#define	NGE_RX_POLL		0x110
#define	RX_POLL_INTV_1G		10
#define	RX_POLL_INTV_100M	100
#define	RX_POLL_INTV_10M	1000
typedef union _nge_rx_poll {
	uint32_t	poll_val;
	struct {
		uint32_t	rpi:16;
		uint32_t	rpen:1;
		uint32_t	resv17_31:15;
	} poll_bits;
} nge_rx_poll;

/*
 * Transmit polling count
 */
#define	NGE_TX_PCNT		0x114
union {
	uint32_t	cnt_val;
	struct {
		uint32_t	pcnt:32;
	} cnt_bits;
} nge_tx_pcnt;

/*
 * Receive polling count
 */
#define	NGE_RX_PCNT		0x118
union {
	uint32_t	cnt_val;
	struct {
		uint32_t	pcnt:32;
	} cnt_bits;
} nge_rx_pcnt;


/*
 * Current tx's descriptor address
 */
#define	NGE_TX_CUR_DADR		0x11c
union {
	uint32_t	addr_val;
	struct {
		uint32_t	resv0_2:3;
		uint32_t	addr:29;
	} addr_bits;
} nge_tx_cur_addr;

/*
 * Current rx's descriptor address
 */
#define	NGE_RX_CUR_DADR		0x120
union {
	uint32_t	addr_val;
	struct {
		uint32_t	resv0_2:3;
		uint32_t	addr:29;
	} addr_bits;
} nge_rx_cur_addr;

/*
 * Current tx's data buffer address
 */
#define	NGE_TX_CUR_PRD0		0x124
union {
	uint32_t	prd0_val;
	struct {
		uint32_t	prd0:32;
	} prd0_bits;
} nge_tx_cur_prd0;

/*
 * Current tx's data buffer status
 */
#define	NGE_TX_CUR_PRD1		0x128
union {
	uint32_t	prd1_val;
	struct {
		uint32_t	rebytes:16;
		uint32_t	status:16;
	} prd1_bits;
} nge_tx_cur_prd1;

/*
 * Current rx's data buffer address
 */
#define	NGE_RX_CUR_PRD0		0x12c
union {
	uint32_t	prd0_val;
	struct {
		uint32_t	prd0:32;
	}prd0_bits;
}nge_rx_cur_prd0;

/*
 * Current rx's data buffer status
 */
#define	NGE_RX_CUR_PRD1		0x130

/*
 * Next tx's descriptor address
 */
#define	NGE_TX_NXT_DADR		0x134
union {
	uint32_t	dadr_val;
	struct {
		uint32_t	addr:32;
	}addr_bits;
}nge_tx_nxt_dadr;

/*
 * Next rx's descriptor address
 */
#define	NGE_RX_NXT_DADR		0x138
union {
	uint32_t	dadr_val;
	struct {
		uint32_t	addr:32;
	} addr_bits;
} nge_rx_nxt_dadr;

/*
 * Transmit fifo watermark
 */
#define	NGE_TX_FIFO_WM		0x13c
#define	TX_FIFO_TBFW		0
#define	TX_FIFO_NOB_WM_MII	1
#define	TX_FIFO_NOB_WM_GMII	8
#define	TX_FIFO_DATA_LWM	0x20
#define	TX_FIFO_PRD_LWM		0x8
#define	TX_FIFO_PRD_HWM		0x38
typedef union _nge_tx_fifo_wm {
	uint32_t	wm_val;
	struct {
		uint32_t	data_lwm:9;
		uint32_t	resv8_11:3;
		uint32_t	prd_lwm:6;
		uint32_t	uprd_hwm:6;
		uint32_t	nbfb_wm:4;
		uint32_t	fb_wm:4;
	} wm_bits;
} nge_tx_fifo_wm;

/*
 * Receive fifo watermark
 */
#define	NGE_RX_FIFO_WM		0x140
typedef union _nge_rx_fifo_wm {
	uint32_t	wm_val;
	struct {
		uint32_t	data_hwm:9;
		uint32_t	resv9_11:3;
		uint32_t	prd_lwm:4;
		uint32_t	resv16_17:2;
		uint32_t	prd_hwm:4;
		uint32_t	resv22_31:10;
	} wm_bits;
} nge_rx_fifo_wm;

/*
 * Chip mode control
 */
#define	NGE_MODE_CNTL		0x144
#define	DESC_MCP1		0x0
#define	DESC_OFFLOAD		0x1
#define	DESC_HOT		0x2
#define	DESC_RESV		0x3
#define	MACHINE_BUSY		0x0
#define	MACHINE_IDLE		0x1
typedef union _nge_mode_cntl {
	uint32_t	mode_val;
	struct {
		uint32_t	txdm:1;
		uint32_t	rxdm:1;
		uint32_t	dma_dis:1;
		uint32_t	dma_status:1;
		uint32_t	bm_reset:1;
		uint32_t	resv5:1;
		uint32_t	vlan_strip:1;	/* mcp55 chip only */
		uint32_t	vlan_ins:1;	/* mcp55 chip only */
		uint32_t	desc_type:2;
		uint32_t	rx_sum_en:1;
		uint32_t	tx_prd_cu_en:1;
		uint32_t	w64_dis:1;
		uint32_t	tx_rcom_en:1;
		uint32_t	rx_filter_en:1;
		uint32_t	resv15:1;
		uint32_t	resv16:1;	/* ck804 and mcp51 only */
		uint32_t	resv17:1;	/* ck804 and mcp51 only */
		uint32_t	resv18:1;	/* ck804 and mcp51 only */
		uint32_t	resv19_21:3;
		uint32_t	tx_fetch_prd:1;	/* mcp51/mcp55 only */
		uint32_t	rx_fetch_prd:1;	/* mcp51/mcp55 only */
		uint32_t	resv24_29:6;
		uint32_t	rx_status:1;
		uint32_t	tx_status:1;
	} mode_bits;
} nge_mode_cntl;

#define	NGE_TX_DADR_HI		0x148
#define	NGE_RX_DADR_HI		0x14c

/*
 * Mii interrupt register
 * Note: for mcp55, this is a 32-bit register.
 */
#define	NGE_MINTR_SRC		0x180
typedef union _nge_mintr_src {
	uint8_t	src_val;
	struct {
		uint8_t	mrei:1;
		uint8_t	mcc2:1;
		uint8_t	mcc1:1;
		uint8_t	mapi:1;
		uint8_t	mpdi:1;
		uint8_t	resv5_7:3;
	} src_bits;
} nge_mintr_src;

/*
 * Mii interrupt mask
 * Note: for mcp55, this is a 32-bit register.
 */
#define	NGE_MINTR_MASK		0x184
typedef union _nge_mintr_mask {
	uint8_t	mask_val;
	struct {
		uint8_t	mrei:1;
		uint8_t	mcc2:1;
		uint8_t	mcc1:1;
		uint8_t	mapi:1;
		uint8_t	mpdi:1;
		uint8_t	resv5_7:3;
	} mask_bits;
} nge_mintr_mask;

/*
 * Mii control and status
 */
#define	NGE_MII_CS		0x188
#define	MII_POLL_INTV		0x4
typedef union _nge_mii_cs {
	uint32_t	cs_val;
	struct {
		uint32_t	excap:1;
		uint32_t	jab_dec:1;
		uint32_t	lk_up:1;
		uint32_t	ana_cap:1;
		uint32_t	rfault:1;
		uint32_t	auto_neg:1;
		uint32_t	mfps:1;
		uint32_t	resv7:1;
		uint32_t	exst:1;
		uint32_t	hdup_100m_t2:1;
		uint32_t	fdup_100m_t2:1;
		uint32_t	hdup_10m:1;
		uint32_t	fdup_10m:1;
		uint32_t	hdup_100m_x:1;
		uint32_t	fdup_100m_x:1;
		uint32_t	cap_100m_t4:1;
		uint32_t	ap_intv:4;
		uint32_t	ap_en:1;
		uint32_t	resv21_23:3;
		uint32_t	ap_paddr:5;
		uint32_t	resv29_31:3;
	} cs_bits;
} nge_mii_cs;

/*
 * Mii Clock timer register
 */
#define	NGE_MII_TM		0x18c
typedef union _nge_mii_tm {
	uint16_t	tm_val;
	struct {
		uint16_t	timer_interv:8;
		uint16_t	timer_en:1;
		uint16_t	resv9_14:6;
		uint16_t	timer_status:1;
	} tm_bits;
} nge_mii_tm;

/*
 * Mdio address
 */
#define	NGE_MDIO_ADR		0x190
typedef union _nge_mdio_adr {
	uint16_t	adr_val;
	struct {
		uint16_t	phy_reg:5;
		uint16_t	phy_adr:5;
		uint16_t	mdio_rw:1;
		uint16_t	resv11_14:4;
		uint16_t	mdio_clc:1;
	} adr_bits;
} nge_mdio_adr;

/*
 * Mdio data
 */
#define	NGE_MDIO_DATA		0x194

/*
 * Power Management and Control
 */
#define	NGE_PM_CNTL		0x200
typedef union _nge_pm_cntl {
	uint32_t	cntl_val;
	struct {
		/*
		 * mp_en:  Magic Packet Enable
		 * pm_en:  Pattern Match Enable
		 * lc_en:  Link Change Enable
		 */
		uint32_t	mp_en_d0:1;
		uint32_t	pm_en_d0:1;
		uint32_t	lc_en_d0:1;
		uint32_t	resv3:1;
		uint32_t	mp_en_d1:1;
		uint32_t	pm_en_d1:1;
		uint32_t	lc_en_d1:1;
		uint32_t	resv7:1;
		uint32_t	mp_en_d2:1;
		uint32_t	pm_en_d2:1;
		uint32_t	lc_en_d2:1;
		uint32_t	resv11:1;
		uint32_t	mp_en_d3:1;
		uint32_t	pm_en_d3:1;
		uint32_t	lc_en_d3:1;
		uint32_t	resv15:1;
		uint32_t	pat_match_en:5;
		uint32_t	resv21_23:3;
		uint32_t	pat_match_stat:5;
		uint32_t	magic_status:1;
		uint32_t	netman_status:1;
		uint32_t	resv31:1;
	} cntl_bits;
} nge_pm_cntl;

#define	NGE_MPT_CRC0	0x204
#define	NGE_PMC_MK00	0x208
#define	NGE_PMC_MK01	0x20C
#define	NGE_PMC_MK02	0x210
#define	NGE_PMC_MK03	0x214
#define	NGE_MPT_CRC1	0x218
#define	NGE_PMC_MK10	0x21c
#define	NGE_PMC_MK11	0x220
#define	NGE_PMC_MK12	0x224
#define	NGE_PMC_MK13	0x228
#define	NGE_MPT_CRC2	0x22c
#define	NGE_PMC_MK20	0x230
#define	NGE_PMC_MK21	0x234
#define	NGE_PMC_MK22	0x238
#define	NGE_PMC_MK23	0x23c
#define	NGE_MPT_CRC3	0x240
#define	NGE_PMC_MK30	0x244
#define	NGE_PMC_MK31	0x248
#define	NGE_PMC_MK32	0x24c
#define	NGE_PMC_MK33	0x250
#define	NGE_MPT_CRC4	0x254
#define	NGE_PMC_MK40	0x258
#define	NGE_PMC_MK41	0x25c
#define	NGE_PMC_MK42	0x260
#define	NGE_PMC_MK43	0x264
#define	NGE_PMC_ALIAS	0x268
#define	NGE_PMCSR_ALIAS	0x26c

/*
 * Seeprom control
 */
#define	NGE_EP_CNTL		0x500
#define	EEPROM_CLKDIV		249
#define	EEPROM_WAITCLK		0x7
typedef union _nge_cp_cntl {
	uint32_t	cntl_val;
	struct {
		uint32_t	clkdiv:8;
		uint32_t	rom_size:3;
		uint32_t	resv11:1;
		uint32_t	word_wid:1;
		uint32_t	resv13_15:3;
		uint32_t	wait_slots:4;
		uint32_t	resv20_31:12;
	} cntl_bits;
} nge_cp_cntl;

/*
 * Seeprom cmd control
 */
#define	NGE_EP_CMD			0x504
#define	SEEPROM_CMD_READ		0x0
#define	SEEPROM_CMD_WRITE_ENABLE	0x1
#define	SEEPROM_CMD_ERASE		0x2
#define	SEEPROM_CMD_WRITE		0x3
#define	SEEPROM_CMD_ERALSE_ALL		0x4
#define	SEEPROM_CMD_WRITE_ALL		0x5
#define	SEEPROM_CMD_WRITE_DIS		0x6
#define	SEEPROM_READY			0x1
typedef union _nge_ep_cmd {
	uint32_t	cmd_val;
	struct {
		uint32_t	addr:16;
		uint32_t	cmd:3;
		uint32_t	resv19_30:12;
		uint32_t	sts:1;
	} cmd_bits;
} nge_ep_cmd;

/*
 * Seeprom data register
 */
#define	NGE_EP_DATA		0x508
typedef union _nge_ep_data {
	uint32_t	data_val;
	struct {
		uint32_t	data:16;
		uint32_t	resv16_31:16;
	} data_bits;
} nge_ep_data;

/*
 * Power management control 2nd register (since MCP51)
 */
#define	NGE_PM_CNTL2		0x600
typedef union _nge_pm_cntl2 {
	uint32_t	cntl_val;
	struct {
		uint32_t	phy_coma_set:1;
		uint32_t	phy_coma_status:1;
		uint32_t	resv2_3:2;
		uint32_t	resv4:1;
		uint32_t	resv5_7:3;
		uint32_t	resv8_11:4;
		uint32_t	resv12_15:4;
		uint32_t	pmt5_en:1;
		uint32_t	pmt6_en:1;
		uint32_t	pmt7_en:1;
		uint32_t	resv19_23:5;
		uint32_t	pmt5_status:1;
		uint32_t	pmt6_status:1;
		uint32_t	pmt7_status:1;
		uint32_t	resv27_31:5;
	} cntl_bits;
} nge_pm_cntl2;


/*
 * ASF RAM 0x800-0xfff
 */

/*
 * Hardware-defined Statistics Block Offsets
 *
 * These are given in the manual as addresses in NIC memory, starting
 * from the NIC statistics area base address of 0x2000;
 */

#define	KS_BASE			0x0280
#define	KS_ADDR(x)		(((x)-KS_BASE)/sizeof (uint32_t))

typedef enum {
	KS_ifHOutOctets = KS_ADDR(0x0280),
	KS_ifHOutZeroRetranCount,
	KS_ifHOutOneRetranCount,
	KS_ifHOutMoreRetranCount,
	KS_ifHOutColCount,
	KS_ifHOutFifoovCount,
	KS_ifHOutLOCCount,
	KS_ifHOutExDecCount,
	KS_ifHOutRetryCount,

	KS_ifHInFrameErrCount,
	KS_ifHInExtraOctErrCount,
	KS_ifHInLColErrCount,
	KS_ifHInRuntCount,
	KS_ifHInOversizeErrCount,
	KS_ifHInFovErrCount,
	KS_ifHInFCSErrCount,
	KS_ifHInAlignErrCount,
	KS_ifHInLenErrCount,
	KS_ifHInUniPktsCount,
	KS_ifHInBroadPksCount,
	KS_ifHInMulPksCount,
	KS_STATS_SIZE = KS_ADDR(0x2d0)

} nge_stats_offset_t;

/*
 * Hardware-defined Statistics Block
 *
 * Another view of the statistic block, as a array and a structure ...
 */

typedef union {
	uint64_t a[KS_STATS_SIZE];
	struct {
	uint64_t OutOctets;
	uint64_t OutZeroRetranCount;
	uint64_t OutOneRetranCount;
	uint64_t OutMoreRetranCount;
	uint64_t OutColCount;
	uint64_t OutFifoovCount;
	uint64_t OutLOCCount;
	uint64_t OutExDecCount;
	uint64_t OutRetryCount;

	uint64_t InFrameErrCount;
	uint64_t InExtraOctErrCount;
	uint64_t InLColErrCount;
	uint64_t InRuntCount;
	uint64_t InOversizeErrCount;
	uint64_t InFovErrCount;
	uint64_t InFCSErrCount;
	uint64_t InAlignErrCount;
	uint64_t InLenErrCount;
	uint64_t InUniPktsCount;
	uint64_t InBroadPksCount;
	uint64_t InMulPksCount;
	} s;
} nge_hw_statistics_t;

/*
 * MII (PHY) registers, beyond those already defined in <sys/miiregs.h>
 */

#define	NGE_PHY_NUMBER	32
#define	MII_LP_ASYM_PAUSE	0x0800
#define	MII_LP_PAUSE		0x0400

#define	MII_100BASE_T4		0x0200
#define	MII_100BASET_FD		0x0100
#define	MII_100BASET_HD		0x0080
#define	MII_10BASET_FD		0x0040
#define	MII_10BASET_HD		0x0020

#define	MII_ID_MARVELL		0x5043
#define	MII_ID_CICADA		0x03f1
#define	MII_IDL_MASK		0xfc00
#define	MII_AN_LPNXTPG		8


#define	MII_IEEE_EXT_STATUS	15

/*
 * New bits in the MII_CONTROL register
 */
#define	MII_CONTROL_1000MB	0x0040

/*
 * Bits in the MII_1000BASE_T_CONTROL register
 *
 * The MASTER_CFG bit enables manual configuration of Master/Slave mode
 * (otherwise, roles are automatically negotiated).  When this bit is set,
 * the MASTER_SEL bit forces Master mode, otherwise Slave mode is forced.
 */
#define	MII_1000BASE_T_CONTROL		9
#define	MII_1000BT_CTL_MASTER_CFG	0x1000	/* enable role select	*/
#define	MII_1000BT_CTL_MASTER_SEL	0x0800	/* role select bit	*/
#define	MII_1000BT_CTL_ADV_FDX		0x0200
#define	MII_1000BT_CTL_ADV_HDX		0x0100

/*
 * Bits in the MII_1000BASE_T_STATUS register
 */
#define	MII_1000BASE_T_STATUS		10
#define	MII_1000BT_STAT_MASTER_FAULT	0x8000
#define	MII_1000BT_STAT_MASTER_MODE	0x4000
#define	MII_1000BT_STAT_LCL_RCV_OK	0x2000
#define	MII_1000BT_STAT_RMT_RCV_OK	0x1000
#define	MII_1000BT_STAT_LP_FDX_CAP	0x0800
#define	MII_1000BT_STAT_LP_HDX_CAP	0x0400

#define	MII_CICADA_BYPASS_CONTROL	MII_VENDOR(2)
#define	CICADA_125MHZ_CLOCK_ENABLE	0x0001

#define	MII_CICADA_10BASET_CONTROL	MII_VENDOR(6)
#define	MII_CICADA_DISABLE_ECHO_MODE	0x2000

#define	MII_CICADA_EXT_CONTROL		MII_VENDOR(7)
#define	MII_CICADA_MODE_SELECT_BITS 	0xf000
#define	MII_CICADA_MODE_SELECT_RGMII	0x1000
#define	MII_CICADA_POWER_SUPPLY_BITS	0x0e00
#define	MII_CICADA_POWER_SUPPLY_3_3V	0x0000
#define	MII_CICADA_POWER_SUPPLY_2_5V	0x0200

#define	MII_CICADA_AUXCTRL_STATUS	MII_VENDOR(12)
#define	MII_CICADA_PIN_PRORITY_SETTING	0x0004
#define	MII_CICADA_PIN_PRORITY_DEFAULT	0x0000


#define	NGE_REG_SIZE		0xfff
#define	NGE_MII_SIZE		0x20
#define	NGE_SEEROM_SIZE	0x800
/*
 * Legacy rx's bd which does not support
 * any hardware offload
 */
typedef struct _legacy_rx_bd {
	uint32_t	host_buf_addr;
	union {
		uint32_t	cntl_val;
		struct {
			uint32_t	bcnt:16;
			uint32_t	end:1;
			uint32_t	miss:1;
			uint32_t	extra:1;
			uint32_t	inten:1;
			uint32_t	bam:1;
			uint32_t	mam:1;
			uint32_t	pam:1;
			uint32_t	runt:1;
			uint32_t	lcol:1;
			uint32_t	max:1;
			uint32_t	lfer:1;
			uint32_t	crc:1;
			uint32_t	ofol:1;
			uint32_t	fram:1;
			uint32_t	err:1;
			uint32_t	own:1;
		} cntl_bits;
	} cntl_status;
} legacy_rx_bd, *plegacy_rx_bd;

/*
 * Stand offload rx's bd which supports hareware checksum
 * for tcp/ip
 */
#define	CK8G_NO_HSUM			0x0
#define	CK8G_TCP_SUM_ERR		0x1
#define	CK8G_UDP_SUM_ERR		0x2
#define	CK8G_IP_HSUM_ERR		0x3
#define	CK8G_IP_HSUM			0x4
#define	CK8G_TCP_SUM			0x5
#define	CK8G_UDP_SUM			0x6
#define	CK8G_RESV			0x7
typedef struct _sum_rx_bd {
	uint32_t	host_buf_addr;
	union {
		uint32_t	cntl_val;
		struct {
			uint32_t	bcnt:14;
			uint32_t	resv14_29:16;
			uint32_t	inten:1;
			uint32_t	own:1;
		} control_bits;
		struct {
			uint32_t	bcnt:14;
			uint32_t	resv14:1;
			uint32_t	bam:1;
			uint32_t	mam:1;
			uint32_t	pam:1;
			uint32_t	runt:1;
			uint32_t	lcol:1;
			uint32_t	max:1;
			uint32_t	lfer:1;
			uint32_t	crc:1;
			uint32_t	ofol:1;
			uint32_t	fram:1;
			uint32_t	extra:1;
			uint32_t	l3_l4_sum:3;
			uint32_t	rend:1;
			uint32_t	err:1;
			uint32_t	own:1;
		} status_bits;
	} cntl_status;
} sum_rx_bd, *psum_rx_bd;
/*
 * Hot offload rx's bd which support 64bit access and
 * full-tcp hardware offload
 */
typedef struct _hot_rx_bd {
	uint32_t	host_buf_addr_hi;
	uint32_t	host_buf_addr_lo;
	uint32_t	sw_tag;
	union {
		uint32_t	cntl_val;
		struct {
			uint32_t	bcnt:14;
			uint32_t	resv14_29:16;
			uint32_t	inten:1;
			uint32_t	own:1;
		} control_bits;

		struct {
			uint32_t	bcnt:14;
			uint32_t	ctmach_rd:1;
			uint32_t	bam:1;
			uint32_t	mam:1;
			uint32_t	pam:1;
			uint32_t	runt:1;
			uint32_t	lcol:1;
			uint32_t	max:1;
			uint32_t	lfer:1;
			uint32_t	crc:1;
			uint32_t	ofol:1;
			uint32_t	fram:1;
			uint32_t	extra:1;
			uint32_t	l3_l4_sum:3;
			uint32_t	rend:1;
			uint32_t	err:1;
			uint32_t	own:1;
		} status_bits_legacy;
	} cntl_status;
} hot_rx_bd, *phot_rx_bd;

/*
 * Legacy tx's bd which does not support
 * any hardware offload
 */
typedef struct _legacy_tx_bd {
	uint32_t	host_buf_addr;
	union {
		uint32_t	cntl_val;
		struct {
			uint32_t	bcnt:16;
			uint32_t	end:1;
			uint32_t	resv17_23:7;
			uint32_t	inten:1;
			uint32_t	resv25_30:6;
			uint32_t	own:1;
		} control_bits;

		struct {
			uint32_t	bcnt:16;
			uint32_t	end:1;
			uint32_t	rtry:1;
			uint32_t	trc:4;
			uint32_t	inten:1;
			uint32_t	exdef:1;
			uint32_t	def:1;
			uint32_t	lcar:1;
			uint32_t	lcol:1;
			uint32_t	uflo:1;
			uint32_t	err:1;
			uint32_t	own:1;
		} status_bits;
	} cntl_status;
} legacy_tx_bd, *plegacy_tx_bd;

/*
 * Stand offload tx's bd which supports hareware checksum
 * for tcp/ip
 */
typedef struct _sum_tx_bd {
	uint32_t	host_buf_addr;
	union {
		uint32_t	cntl_val;
		struct {
			uint32_t	bcnt:14;
			uint32_t	resv14_25:12;
			uint32_t	tcp_hsum:1;
			uint32_t	ip_hsum:1;
			uint32_t	segen:1;
			uint32_t	end:1;
			uint32_t	inten:1;
			uint32_t	own:1;
		} control_sum_bits;

		struct {
			uint32_t	bcnt:14;
			uint32_t	mss:14;
			uint32_t	segen:1;
			uint32_t	end:1;
			uint32_t	inten:1;
			uint32_t	own:1;
		} control_tso_bits;

		struct {
			uint32_t	bcnt:14;
			uint32_t	resv14_17:4;
			uint32_t	rtry:1;
			uint32_t	trc:4;
			uint32_t	inten:1;
			uint32_t	exdef:1;
			uint32_t	def:1;
			uint32_t	lcar:1;
			uint32_t	lcol:1;
			uint32_t	uflo:1;
			uint32_t	end:1;
			uint32_t	err:1;
			uint32_t	own:1;
		} status_bits;
	} control_status;
} sum_tx_bd, *psum_tx_bd;

/*
 * Hot offload tx's bd which support 64bit access and
 * full-tcp hardware offload
 */

typedef struct _hot_tx_bd {
	uint32_t	host_buf_addr_hi;
	uint32_t	host_buf_addr_lo;
	union {
		uint32_t	parm_val;
		struct {
			uint32_t	resv0_15:16;
			uint32_t	resv16:1;
			uint32_t	resv17:1;
			uint32_t	resv18_31:14;
		} parm_bits;
	} hot_parms;

	union {
		uint32_t	cntl_val;
		struct {
			uint32_t	bcnt:14;
			uint32_t	resv14_25:12;
			uint32_t	tcp_hsum:1;
			uint32_t	ip_hsum:1;
			uint32_t	segen:1;
			uint32_t	end:1;
			uint32_t	inten:1;
			uint32_t	own:1;
		} control_sum_bits;

		struct {
			uint32_t	bcnt:14;
			uint32_t	mss:14;
			uint32_t	segen:1;
			uint32_t	end:1;
			uint32_t	inten:1;
			uint32_t	own:1;
		} control_tso_bits;

		struct {
			uint32_t	bcnt:14;
			uint32_t	resv14_17:4;
			uint32_t	rtry:1;
			uint32_t	trc:4;
			uint32_t	inten:1;
			uint32_t	exdef:1;
			uint32_t	def:1;
			uint32_t	lcar:1;
			uint32_t	lcol:1;
			uint32_t	uflo:1;
			uint32_t	end:1;
			uint32_t	err:1;
			uint32_t	own:1;
		} status_bits;
	} control_status;
} hot_tx_bd, *phot_tx_bd;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_NGE_CHIP_H */
