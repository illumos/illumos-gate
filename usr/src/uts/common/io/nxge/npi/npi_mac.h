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

#ifndef _NPI_MAC_H
#define	_NPI_MAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>
#include <nxge_mac_hw.h>
#include <nxge_mii.h>

typedef struct _npi_mac_addr {
	uint16_t	w0;
	uint16_t	w1;
	uint16_t	w2;
} npi_mac_addr_t;

typedef enum npi_mac_attr {
	MAC_PORT_MODE = 0,
	MAC_PORT_FRAME_SIZE,
	MAC_PORT_ADDR,
	MAC_PORT_ADDR_FILTER,
	MAC_PORT_ADDR_FILTER_MASK,
	XMAC_PORT_IPG,
	XMAC_10G_PORT_IPG,
	BMAC_PORT_MAX_BURST_SIZE,
	BMAC_PORT_PA_SIZE,
	BMAC_PORT_CTRL_TYPE
} npi_mac_attr_t;

/* MAC Mode options */

typedef enum npi_mac_mode_e {
	MAC_MII_MODE = 0,
	MAC_GMII_MODE,
	MAC_XGMII_MODE
} npi_mac_mode_t;

typedef enum npi_mac_reset_e {
	TX_MAC_RESET = 1,
	RX_MAC_RESET,
	XTX_MAC_REG_RESET,
	XRX_MAC_REG_RESET,
	XTX_MAC_LOGIC_RESET,
	XRX_MAC_LOGIC_RESET,
	XTX_MAC_RESET_ALL,
	XRX_MAC_RESET_ALL,
	BMAC_RESET_ALL,
	XMAC_RESET_ALL
} npi_mac_reset_t;

typedef enum xmac_tx_iconfig_e {
	ICFG_XMAC_TX_FRAME_XMIT 	= XMAC_TX_FRAME_XMIT,
	ICFG_XMAC_TX_UNDERRUN		= XMAC_TX_UNDERRUN,
	ICFG_XMAC_TX_MAX_PACKET_ERR	= XMAC_TX_MAX_PACKET_ERR,
	ICFG_XMAC_TX_OVERFLOW		= XMAC_TX_OVERFLOW,
	ICFG_XMAC_TX_FIFO_XFR_ERR	= XMAC_TX_FIFO_XFR_ERR,
	ICFG_XMAC_TX_BYTE_CNT_EXP	= XMAC_TX_BYTE_CNT_EXP,
	ICFG_XMAC_TX_FRAME_CNT_EXP	= XMAC_TX_FRAME_CNT_EXP,
	ICFG_XMAC_TX_ALL = (XMAC_TX_FRAME_XMIT | XMAC_TX_UNDERRUN |
				XMAC_TX_MAX_PACKET_ERR | XMAC_TX_OVERFLOW |
				XMAC_TX_FIFO_XFR_ERR |  XMAC_TX_BYTE_CNT_EXP |
				XMAC_TX_FRAME_CNT_EXP)
} xmac_tx_iconfig_t;

typedef enum xmac_rx_iconfig_e {
	ICFG_XMAC_RX_FRAME_RCVD		= XMAC_RX_FRAME_RCVD,
	ICFG_XMAC_RX_OVERFLOW		= XMAC_RX_OVERFLOW,
	ICFG_XMAC_RX_UNDERFLOW		= XMAC_RX_UNDERFLOW,
	ICFG_XMAC_RX_CRC_ERR_CNT_EXP	= XMAC_RX_CRC_ERR_CNT_EXP,
	ICFG_XMAC_RX_LEN_ERR_CNT_EXP	= XMAC_RX_LEN_ERR_CNT_EXP,
	ICFG_XMAC_RX_VIOL_ERR_CNT_EXP	= XMAC_RX_VIOL_ERR_CNT_EXP,
	ICFG_XMAC_RX_OCT_CNT_EXP	= XMAC_RX_OCT_CNT_EXP,
	ICFG_XMAC_RX_HST_CNT1_EXP	= XMAC_RX_HST_CNT1_EXP,
	ICFG_XMAC_RX_HST_CNT2_EXP	= XMAC_RX_HST_CNT2_EXP,
	ICFG_XMAC_RX_HST_CNT3_EXP	= XMAC_RX_HST_CNT3_EXP,
	ICFG_XMAC_RX_HST_CNT4_EXP	= XMAC_RX_HST_CNT4_EXP,
	ICFG_XMAC_RX_HST_CNT5_EXP	= XMAC_RX_HST_CNT5_EXP,
	ICFG_XMAC_RX_HST_CNT6_EXP	= XMAC_RX_HST_CNT6_EXP,
	ICFG_XMAC_RX_BCAST_CNT_EXP	= XMAC_RX_BCAST_CNT_EXP,
	ICFG_XMAC_RX_MCAST_CNT_EXP	= XMAC_RX_MCAST_CNT_EXP,
	ICFG_XMAC_RX_FRAG_CNT_EXP	= XMAC_RX_FRAG_CNT_EXP,
	ICFG_XMAC_RX_ALIGNERR_CNT_EXP	= XMAC_RX_ALIGNERR_CNT_EXP,
	ICFG_XMAC_RX_LINK_FLT_CNT_EXP	= XMAC_RX_LINK_FLT_CNT_EXP,
	ICFG_XMAC_RX_HST_CNT7_EXP	= XMAC_RX_HST_CNT7_EXP,
	ICFG_XMAC_RX_REMOTE_FLT_DET	= XMAC_RX_REMOTE_FLT_DET,
	ICFG_XMAC_RX_LOCAL_FLT_DET	= XMAC_RX_LOCAL_FLT_DET,
	ICFG_XMAC_RX_ALL = (XMAC_RX_FRAME_RCVD | XMAC_RX_OVERFLOW |
				XMAC_RX_UNDERFLOW | XMAC_RX_CRC_ERR_CNT_EXP |
				XMAC_RX_LEN_ERR_CNT_EXP |
				XMAC_RX_VIOL_ERR_CNT_EXP |
				XMAC_RX_OCT_CNT_EXP | XMAC_RX_HST_CNT1_EXP |
				XMAC_RX_HST_CNT2_EXP | XMAC_RX_HST_CNT3_EXP |
				XMAC_RX_HST_CNT4_EXP | XMAC_RX_HST_CNT5_EXP |
				XMAC_RX_HST_CNT6_EXP | XMAC_RX_BCAST_CNT_EXP |
				XMAC_RX_MCAST_CNT_EXP | XMAC_RX_FRAG_CNT_EXP |
				XMAC_RX_ALIGNERR_CNT_EXP |
				XMAC_RX_LINK_FLT_CNT_EXP |
				XMAC_RX_HST_CNT7_EXP |
				XMAC_RX_REMOTE_FLT_DET | XMAC_RX_LOCAL_FLT_DET)
} xmac_rx_iconfig_t;

typedef enum xmac_ctl_iconfig_e {
	ICFG_XMAC_CTRL_PAUSE_RCVD	= XMAC_CTRL_PAUSE_RCVD,
	ICFG_XMAC_CTRL_PAUSE_STATE	= XMAC_CTRL_PAUSE_STATE,
	ICFG_XMAC_CTRL_NOPAUSE_STATE	= XMAC_CTRL_NOPAUSE_STATE,
	ICFG_XMAC_CTRL_ALL = (XMAC_CTRL_PAUSE_RCVD | XMAC_CTRL_PAUSE_STATE |
				XMAC_CTRL_NOPAUSE_STATE)
} xmac_ctl_iconfig_t;


typedef enum bmac_tx_iconfig_e {
	ICFG_BMAC_TX_FRAME_SENT 	= MAC_TX_FRAME_XMIT,
	ICFG_BMAC_TX_UNDERFLOW		= MAC_TX_UNDERRUN,
	ICFG_BMAC_TX_MAXPKTSZ_ERR	= MAC_TX_MAX_PACKET_ERR,
	ICFG_BMAC_TX_BYTE_CNT_EXP	= MAC_TX_BYTE_CNT_EXP,
	ICFG_BMAC_TX_FRAME_CNT_EXP	= MAC_TX_FRAME_CNT_EXP,
	ICFG_BMAC_TX_ALL = (MAC_TX_FRAME_XMIT | MAC_TX_UNDERRUN |
				MAC_TX_MAX_PACKET_ERR | MAC_TX_BYTE_CNT_EXP |
				MAC_TX_FRAME_CNT_EXP)
} bmac_tx_iconfig_t;

typedef enum bmac_rx_iconfig_e {
	ICFG_BMAC_RX_FRAME_RCVD		= MAC_RX_FRAME_RECV,
	ICFG_BMAC_RX_OVERFLOW		= MAC_RX_OVERFLOW,
	ICFG_BMAC_RX_FRAME_CNT_EXP	= MAC_RX_FRAME_COUNT,
	ICFG_BMAC_RX_CRC_ERR_CNT_EXP	= MAC_RX_ALIGN_ERR,
	ICFG_BMAC_RX_LEN_ERR_CNT_EXP	= MAC_RX_CRC_ERR,
	ICFG_BMAC_RX_VIOL_ERR_CNT_EXP	= MAC_RX_LEN_ERR,
	ICFG_BMAC_RX_BYTE_CNT_EXP	= MAC_RX_VIOL_ERR,
	ICFG_BMAC_RX_ALIGNERR_CNT_EXP	= MAC_RX_BYTE_CNT_EXP,
	ICFG_BMAC_RX_ALL = (MAC_RX_FRAME_RECV | MAC_RX_OVERFLOW |
				MAC_RX_FRAME_COUNT | MAC_RX_ALIGN_ERR |
				MAC_RX_CRC_ERR | MAC_RX_LEN_ERR |
				MAC_RX_VIOL_ERR | MAC_RX_BYTE_CNT_EXP)
} bmac_rx_iconfig_t;

typedef enum bmac_ctl_iconfig_e {
	ICFG_BMAC_CTL_RCVPAUSE		= MAC_CTRL_PAUSE_RECEIVED,
	ICFG_BMAC_CTL_INPAUSE_ST	= MAC_CTRL_PAUSE_STATE,
	ICFG_BMAC_CTL_INNOTPAUSE_ST	= MAC_CTRL_NOPAUSE_STATE,
	ICFG_BMAC_CTL_ALL = (MAC_CTRL_PAUSE_RECEIVED | MAC_CTRL_PAUSE_STATE |
				MAC_CTRL_NOPAUSE_STATE)
} bmac_ctl_iconfig_t;

typedef	enum xmac_tx_config_e {
	CFG_XMAC_TX			= 0x00000001,
	CFG_XMAC_TX_STRETCH_MODE	= 0x00000002,
	CFG_XMAC_VAR_IPG		= 0x00000004,
	CFG_XMAC_TX_CRC			= 0x00000008,
	CFG_XMAC_TX_ALL			= 0x0000000F
} xmac_tx_config_t;

typedef enum xmac_rx_config_e {
	CFG_XMAC_RX			= 0x00000001,
	CFG_XMAC_RX_PROMISCUOUS		= 0x00000002,
	CFG_XMAC_RX_PROMISCUOUSGROUP	= 0x00000004,
	CFG_XMAC_RX_ERRCHK		= 0x00000008,
	CFG_XMAC_RX_CRC_CHK		= 0x00000010,
	CFG_XMAC_RX_RESV_MULTICAST	= 0x00000020,
	CFG_XMAC_RX_CODE_VIO_CHK	= 0x00000040,
	CFG_XMAC_RX_HASH_FILTER		= 0x00000080,
	CFG_XMAC_RX_ADDR_FILTER		= 0x00000100,
	CFG_XMAC_RX_STRIP_CRC		= 0x00000200,
	CFG_XMAC_RX_PAUSE		= 0x00000400,
	CFG_XMAC_RX_PASS_FC_FRAME	= 0x00000800,
	CFG_XMAC_RX_MAC2IPP_PKT_CNT	= 0x00001000,
	CFG_XMAC_RX_ALL			= 0x00001FFF
} xmac_rx_config_t;

typedef	enum xmac_xif_config_e {
	CFG_XMAC_XIF_LED_FORCE		= 0x00000001,
	CFG_XMAC_XIF_LED_POLARITY	= 0x00000002,
	CFG_XMAC_XIF_SEL_POR_CLK_SRC	= 0x00000004,
	CFG_XMAC_XIF_TX_OUTPUT		= 0x00000008,
	CFG_XMAC_XIF_LOOPBACK		= 0x00000010,
	CFG_XMAC_XIF_LFS		= 0x00000020,
	CFG_XMAC_XIF_XPCS_BYPASS	= 0x00000040,
	CFG_XMAC_XIF_1G_PCS_BYPASS	= 0x00000080,
	CFG_XMAC_XIF_SEL_CLK_25MHZ	= 0x00000100,
	CFG_XMAC_XIF_ALL		= 0x000001FF
} xmac_xif_config_t;

typedef	enum bmac_tx_config_e {
	CFG_BMAC_TX			= 0x00000001,
	CFG_BMAC_TX_CRC			= 0x00000002,
	CFG_BMAC_TX_ALL			= 0x00000003
} bmac_tx_config_t;

typedef enum bmac_rx_config_e {
	CFG_BMAC_RX			= 0x00000001,
	CFG_BMAC_RX_STRIP_PAD		= 0x00000002,
	CFG_BMAC_RX_STRIP_CRC		= 0x00000004,
	CFG_BMAC_RX_PROMISCUOUS		= 0x00000008,
	CFG_BMAC_RX_PROMISCUOUSGROUP	= 0x00000010,
	CFG_BMAC_RX_HASH_FILTER		= 0x00000020,
	CFG_BMAC_RX_ADDR_FILTER		= 0x00000040,
	CFG_BMAC_RX_DISCARD_ON_ERR	= 0x00000080,
	CFG_BMAC_RX_ALL			= 0x000000FF
} bmac_rx_config_t;

typedef	enum bmac_xif_config_e {
	CFG_BMAC_XIF_TX_OUTPUT		= 0x00000001,
	CFG_BMAC_XIF_LOOPBACK		= 0x00000002,
	CFG_BMAC_XIF_GMII_MODE		= 0x00000008,
	CFG_BMAC_XIF_LINKLED		= 0x00000020,
	CFG_BMAC_XIF_LED_POLARITY	= 0x00000040,
	CFG_BMAC_XIF_SEL_CLK_25MHZ	= 0x00000080,
	CFG_BMAC_XIF_ALL		= 0x000000FF
} bmac_xif_config_t;


typedef enum xmac_ipg_e {
	XGMII_IPG_12_15 = 0,
	XGMII_IPG_16_19,
	XGMII_IPG_20_23,
	MII_GMII_IPG_12,
	MII_GMII_IPG_13,
	MII_GMII_IPG_14,
	MII_GMII_IPG_15,
	MII_GMII_IPG_16
} xmac_ipg_t;

typedef	enum xpcs_reg_e {
	XPCS_REG_CONTROL1,
	XPCS_REG_STATUS1,
	XPCS_REG_DEVICE_ID,
	XPCS_REG_SPEED_ABILITY,
	XPCS_REG_DEVICE_IN_PKG,
	XPCS_REG_CONTROL2,
	XPCS_REG_STATUS2,
	XPCS_REG_PKG_ID,
	XPCS_REG_STATUS,
	XPCS_REG_TEST_CONTROL,
	XPCS_REG_CONFIG_VENDOR1,
	XPCS_REG_DIAG_VENDOR2,
	XPCS_REG_MASK1,
	XPCS_REG_PACKET_COUNTER,
	XPCS_REG_TX_STATEMACHINE,
	XPCS_REG_DESCWERR_COUNTER,
	XPCS_REG_SYMBOL_ERR_L0_1_COUNTER,
	XPCS_REG_SYMBOL_ERR_L2_3_COUNTER,
	XPCS_REG_TRAINING_VECTOR
} xpcs_reg_t;

#define	IS_XMAC_PORT_NUM_VALID(portn)\
	((portn == XMAC_PORT_0) || (portn == XMAC_PORT_1))

#define	IS_BMAC_PORT_NUM_VALID(portn)\
	((portn == BMAC_PORT_0) || (portn == BMAC_PORT_1))

#define	XMAC_REG_WR(handle, portn, reg, val)\
	NXGE_REG_WR64(handle, XMAC_REG_ADDR((portn), (reg)), (val))

#define	XMAC_REG_RD(handle, portn, reg, val_p)\
	NXGE_REG_RD64(handle, XMAC_REG_ADDR((portn), (reg)), (val_p))

#define	BMAC_REG_WR(handle, portn, reg, val)\
	NXGE_REG_WR64(handle, BMAC_REG_ADDR((portn), (reg)), (val))

#define	BMAC_REG_RD(handle, portn, reg, val_p)\
	NXGE_REG_RD64(handle, BMAC_REG_ADDR((portn), (reg)), (val_p))

#define	PCS_REG_WR(handle, portn, reg, val)\
	NXGE_REG_WR64(handle, PCS_REG_ADDR((portn), (reg)), (val))

#define	PCS_REG_RD(handle, portn, reg, val_p)\
	NXGE_REG_RD64(handle, PCS_REG_ADDR((portn), (reg)), (val_p))

#define	XPCS_REG_WR(handle, portn, reg, val)\
	NXGE_REG_WR64(handle, XPCS_ADDR((portn), (reg)), (val))

#define	XPCS_REG_RD(handle, portn, reg, val_p)\
	NXGE_REG_RD64(handle, XPCS_ADDR((portn), (reg)), (val_p))

#define	MIF_REG_WR(handle, reg, val)\
	NXGE_REG_WR64(handle, MIF_ADDR((reg)), (val))

#define	MIF_REG_RD(handle, reg, val_p)\
	NXGE_REG_RD64(handle, MIF_ADDR((reg)), (val_p))


/*
 * When MIF_REG_RD is called inside a poll loop and if the poll takes
 * very long time to complete, then each poll will print a rt_show_reg
 * result on the screen and the rtrace "register show" result may
 * become too messy to read.  The solution is to call MIF_REG_RD_NO_SHOW
 * instead of MIF_REG_RD in a polling loop. When COSIM or REG_SHOW is
 * not defined, this macro is the same as MIF_REG_RD.  When both COSIM
 * and REG_SHOW are defined, this macro calls NXGE_REG_RD64_NO_SHOW
 * which does not call rt_show_reg.
 */
#if defined(COSIM) && defined(REG_SHOW)
#define	MIF_REG_RD_NO_SHOW(handle, reg, val_p)\
	NXGE_REG_RD64_NO_SHOW(handle, MIF_ADDR((reg)), (val_p))
#else
	/*	If not COSIM or REG_SHOW, still show */
#define	MIF_REG_RD_NO_SHOW(handle, reg, val_p)\
	NXGE_REG_RD64(handle, MIF_ADDR((reg)), (val_p))
#endif

#define	ESR_REG_WR(handle, reg, val)\
	NXGE_REG_WR64(handle, ESR_ADDR((reg)), (val))

#define	ESR_REG_RD(handle, reg, val_p)\
	NXGE_REG_RD64(handle, ESR_ADDR((reg)), (val_p))

/* Macros to read/modify MAC attributes */

#define	SET_MAC_ATTR1(handle, p, portn, attr, val, stat) {\
	p.type = attr;\
	p.idata[0] = (uint32_t)val;\
	stat = npi_mac_port_attr(handle, OP_SET, portn, (npi_attr_t *)&p);\
}

#define	SET_MAC_ATTR2(handle, p, portn, attr, val0, val1, stat) {\
	p.type = attr;\
	p.idata[0] = (uint32_t)val0;\
	p.idata[1] = (uint32_t)val1;\
	stat = npi_mac_port_attr(handle, OP_SET, portn, (npi_attr_t *)&p);\
}

#define	SET_MAC_ATTR3(handle, p, portn, attr, val0, val1, val2, stat) {\
	p.type = attr;\
	p.idata[0] = (uint32_t)val0;\
	p.idata[1] = (uint32_t)val1;\
	p.idata[2] = (uint32_t)val2;\
	stat = npi_mac_port_attr(handle, OP_SET, portn, (npi_attr_t *)&p);\
}

#define	SET_MAC_ATTR4(handle, p, portn, attr, val0, val1, val2, val3, stat) {\
	p.type = attr;\
	p.idata[0] = (uint32_t)val0;\
	p.idata[1] = (uint32_t)val1;\
	p.idata[2] = (uint32_t)val2;\
	p.idata[3] = (uint32_t)val3;\
	stat = npi_mac_port_attr(handle, OP_SET, portn, (npi_attr_t *)&p);\
}

#define	GET_MAC_ATTR1(handle, p, portn, attr, val, stat) {\
	p.type = attr;\
	if ((stat = npi_mac_port_attr(handle, OP_GET, portn, \
					(npi_attr_t *)&p)) == NPI_SUCCESS) {\
		val = p.odata[0];\
	}\
}

#define	GET_MAC_ATTR2(handle, p, portn, attr, val0, val1, stat) {\
	p.type = attr;\
	if ((stat = npi_mac_port_attr(handle, OP_GET, portn, \
					(npi_attr_t *)&p)) == NPI_SUCCESS) {\
		val0 = p.odata[0];\
		val1 = p.odata[1];\
	}\
}

#define	GET_MAC_ATTR3(handle, p, portn, attr, val0, val1, \
			val2, stat) {\
	p.type = attr;\
	if ((stat = npi_mac_port_attr(handle, OP_GET, portn, \
					(npi_attr_t *)&p)) == NPI_SUCCESS) {\
		val0 = p.odata[0];\
		val1 = p.odata[1];\
		val2 = p.odata[2];\
	}\
}

#define	GET_MAC_ATTR4(handle, p, portn, attr, val0, val1, \
			val2, val3, stat) {\
	p.type = attr;\
	if ((stat = npi_mac_port_attr(handle, OP_GET, portn, \
					(npi_attr_t *)&p)) == NPI_SUCCESS) {\
		val0 = p.odata[0];\
		val1 = p.odata[1];\
		val2 = p.odata[2];\
		val3 = p.odata[3];\
	}\
}

/* MAC specific errors */

#define	MAC_PORT_ATTR_INVALID		0x50
#define	MAC_RESET_MODE_INVALID		0x51
#define	MAC_HASHTAB_ENTRY_INVALID	0x52
#define	MAC_HOSTINFO_ENTRY_INVALID	0x53
#define	MAC_ALT_ADDR_ENTRY_INVALID	0x54

/* MAC error return macros */

#define	NPI_MAC_PORT_INVALID(portn)	((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					PORT_INVALID | IS_PORT | (portn << 12))
#define	NPI_MAC_OPCODE_INVALID(portn)	((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					OPCODE_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_MAC_HASHTAB_ENTRY_INVALID(portn)\
					((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					MAC_HASHTAB_ENTRY_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_MAC_HOSTINFO_ENTRY_INVALID(portn)\
					((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					MAC_HOSTINFO_ENTRY_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_MAC_ALT_ADDR_ENTRY_INVALID(portn)\
					((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					MAC_ALT_ADDR_ENTRY_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_MAC_PORT_ATTR_INVALID(portn)\
					((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					MAC_PORT_ATTR_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_MAC_RESET_MODE_INVALID(portn)\
					((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					MAC_RESET_MODE_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_MAC_PCS_REG_INVALID(portn)	((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					REGISTER_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_TXMAC_RESET_FAILED(portn)	((TXMAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					RESET_FAILED | IS_PORT | (portn << 12))
#define	NPI_RXMAC_RESET_FAILED(portn)	((RXMAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					RESET_FAILED | IS_PORT | (portn << 12))
#define	NPI_MAC_CONFIG_INVALID(portn)	((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					CONFIG_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_MAC_REG_INVALID(portn)	((MAC_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					REGISTER_INVALID |\
					IS_PORT | (portn << 12))
#define	NPI_MAC_MII_READ_FAILED(portn)	((MIF_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					READ_FAILED | IS_PORT | (portn << 12))
#define	NPI_MAC_MII_WRITE_FAILED(portn)	((MIF_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
					WRITE_FAILED | IS_PORT | (portn << 12))

/* library functions prototypes */

/* general mac functions */
npi_status_t npi_mac_hashtab_entry(npi_handle_t, io_op_t,
				uint8_t, uint8_t, uint16_t *);
npi_status_t npi_mac_hostinfo_entry(npi_handle_t, io_op_t,
				uint8_t, uint8_t,
				hostinfo_t *);
npi_status_t npi_mac_altaddr_enable(npi_handle_t, uint8_t,
				uint8_t);
npi_status_t npi_mac_altaddr_disable(npi_handle_t, uint8_t,
				uint8_t);
npi_status_t npi_mac_altaddr_entry(npi_handle_t, io_op_t,
				uint8_t, uint8_t,
				npi_mac_addr_t *);
npi_status_t npi_mac_port_attr(npi_handle_t, io_op_t, uint8_t,
				npi_attr_t *);
npi_status_t npi_mac_get_link_status(npi_handle_t, uint8_t,
				boolean_t *);
npi_status_t npi_mac_get_10g_link_status(npi_handle_t, uint8_t,
				boolean_t *);
npi_status_t npi_mac_mif_mii_read(npi_handle_t, uint8_t,
				uint8_t, uint16_t *);
npi_status_t npi_mac_mif_mii_write(npi_handle_t, uint8_t,
				uint8_t, uint16_t);
npi_status_t npi_mac_mif_link_intr_enable(npi_handle_t, uint8_t,
				uint8_t, uint16_t);
npi_status_t npi_mac_mif_mdio_read(npi_handle_t, uint8_t,
				uint8_t, uint16_t,
				uint16_t *);
npi_status_t npi_mac_mif_mdio_write(npi_handle_t, uint8_t,
				uint8_t, uint16_t,
				uint16_t);
npi_status_t npi_mac_mif_mdio_link_intr_enable(npi_handle_t,
				uint8_t, uint8_t,
				uint16_t, uint16_t);
npi_status_t npi_mac_mif_link_intr_disable(npi_handle_t, uint8_t);
npi_status_t npi_mac_pcs_mii_read(npi_handle_t, uint8_t,
				uint8_t, uint16_t *);
npi_status_t npi_mac_pcs_mii_write(npi_handle_t, uint8_t,
				uint8_t, uint16_t);
npi_status_t npi_mac_pcs_link_intr_enable(npi_handle_t, uint8_t);
npi_status_t npi_mac_pcs_link_intr_disable(npi_handle_t, uint8_t);
npi_status_t npi_mac_pcs_reset(npi_handle_t, uint8_t);

/* xmac functions */
npi_status_t npi_xmac_reset(npi_handle_t, uint8_t,
				npi_mac_reset_t);
npi_status_t npi_xmac_xif_config(npi_handle_t, config_op_t,
				uint8_t, xmac_xif_config_t);
npi_status_t npi_xmac_tx_config(npi_handle_t, config_op_t,
				uint8_t, xmac_tx_config_t);
npi_status_t npi_xmac_rx_config(npi_handle_t, config_op_t,
				uint8_t, xmac_rx_config_t);
npi_status_t npi_xmac_tx_iconfig(npi_handle_t, config_op_t,
				uint8_t, xmac_tx_iconfig_t);
npi_status_t npi_xmac_rx_iconfig(npi_handle_t, config_op_t,
				uint8_t, xmac_rx_iconfig_t);
npi_status_t npi_xmac_ctl_iconfig(npi_handle_t, config_op_t,
				uint8_t, xmac_ctl_iconfig_t);
npi_status_t npi_xmac_tx_get_istatus(npi_handle_t, uint8_t,
				xmac_tx_iconfig_t *);
npi_status_t npi_xmac_rx_get_istatus(npi_handle_t, uint8_t,
				xmac_rx_iconfig_t *);
npi_status_t npi_xmac_ctl_get_istatus(npi_handle_t, uint8_t,
				xmac_ctl_iconfig_t *);
npi_status_t npi_xmac_xpcs_reset(npi_handle_t, uint8_t);
npi_status_t npi_xmac_xpcs_enable(npi_handle_t, uint8_t);
npi_status_t npi_xmac_xpcs_disable(npi_handle_t, uint8_t);
npi_status_t npi_xmac_xpcs_read(npi_handle_t, uint8_t,
				uint8_t, uint32_t *);
npi_status_t npi_xmac_xpcs_write(npi_handle_t, uint8_t,
				uint8_t, uint32_t);
npi_status_t npi_xmac_xpcs_link_intr_enable(npi_handle_t, uint8_t);
npi_status_t npi_xmac_xpcs_link_intr_disable(npi_handle_t,
				uint8_t);
npi_status_t npi_xmac_xif_led(npi_handle_t, uint8_t,
				boolean_t);
npi_status_t npi_xmac_zap_tx_counters(npi_handle_t, uint8_t);
npi_status_t npi_xmac_zap_rx_counters(npi_handle_t, uint8_t);

/* bmac functions */
npi_status_t npi_bmac_reset(npi_handle_t, uint8_t,
				npi_mac_reset_t mode);
npi_status_t npi_bmac_tx_config(npi_handle_t, config_op_t,
				uint8_t, bmac_tx_config_t);
npi_status_t npi_bmac_rx_config(npi_handle_t, config_op_t,
				uint8_t, bmac_rx_config_t);
npi_status_t npi_bmac_rx_iconfig(npi_handle_t, config_op_t,
				uint8_t, bmac_rx_iconfig_t);
npi_status_t npi_bmac_xif_config(npi_handle_t, config_op_t,
				uint8_t, bmac_xif_config_t);
npi_status_t npi_bmac_tx_iconfig(npi_handle_t, config_op_t,
				uint8_t, bmac_tx_iconfig_t);
npi_status_t npi_bmac_ctl_iconfig(npi_handle_t, config_op_t,
				uint8_t, bmac_ctl_iconfig_t);
npi_status_t npi_bmac_tx_get_istatus(npi_handle_t, uint8_t,
				bmac_tx_iconfig_t *);
npi_status_t npi_bmac_rx_get_istatus(npi_handle_t, uint8_t,
				bmac_rx_iconfig_t *);
npi_status_t npi_bmac_ctl_get_istatus(npi_handle_t, uint8_t,
				bmac_ctl_iconfig_t *);
npi_status_t npi_bmac_send_pause(npi_handle_t, uint8_t,
				uint16_t);
npi_status_t npi_mac_dump_regs(npi_handle_t, uint8_t);

/* MIF common functions */
void npi_mac_mif_set_indirect_mode(npi_handle_t, boolean_t);
void npi_mac_mif_set_atca_mode(npi_handle_t, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_MAC_H */
