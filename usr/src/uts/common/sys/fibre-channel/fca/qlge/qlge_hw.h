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
 * Copyright 2010 QLogic Corporation. All rights reserved.
 */

#ifndef _QLGE_HW_H
#define	_QLGE_HW_H

#ifdef __cplusplus
extern "C" {
#endif

#define	ISP_SCHULTZ 0x8000

#define	MB_REG_COUNT		8
#define	MB_DATA_REG_COUNT	(MB_REG_COUNT-1)


#define	QLA_SCHULTZ(qlge) ((qlge)->device_id == ISP_SCHULTZ)

/*
 * Data bit definitions.
 */
#define	BIT_0	0x1
#define	BIT_1	0x2
#define	BIT_2	0x4
#define	BIT_3	0x8
#define	BIT_4	0x10
#define	BIT_5	0x20
#define	BIT_6	0x40
#define	BIT_7	0x80
#define	BIT_8	0x100
#define	BIT_9	0x200
#define	BIT_10	0x400
#define	BIT_11	0x800
#define	BIT_12	0x1000
#define	BIT_13	0x2000
#define	BIT_14	0x4000
#define	BIT_15	0x8000
#define	BIT_16	0x10000
#define	BIT_17	0x20000
#define	BIT_18	0x40000
#define	BIT_19	0x80000
#define	BIT_20	0x100000
#define	BIT_21	0x200000
#define	BIT_22	0x400000
#define	BIT_23	0x800000
#define	BIT_24	0x1000000
#define	BIT_25	0x2000000
#define	BIT_26	0x4000000
#define	BIT_27	0x8000000
#define	BIT_28	0x10000000
#define	BIT_29	0x20000000
#define	BIT_30	0x40000000
#define	BIT_31	0x80000000

typedef struct ql_stats
{
	uint32_t	intr_type;
	/* software statics */
	uint32_t	intr;
	uint64_t	speed;
	uint32_t	duplex;
	uint32_t	media;
	/* TX */
	uint64_t	obytes;
	uint64_t	opackets;
	uint32_t	nocarrier;
	uint32_t	defer;
	/* RX */
	uint64_t	rbytes;
	uint64_t	rpackets;
	uint32_t	norcvbuf;
	uint32_t	frame_too_long;
	uint32_t	crc;
	ulong_t		multircv;
	ulong_t		brdcstrcv;
	uint32_t	errrcv;
	uint32_t	frame_too_short;
	/* statics by hw */
	uint32_t	errxmt;
	uint32_t	frame_err;
	ulong_t		multixmt;
	ulong_t		brdcstxmt;
	uint32_t	phy_addr;
	uint32_t	jabber_err;

}ql_stats_t;


#define	ETHERNET_CRC_SIZE	4

/*
 * Register Definitions...
 */
#define	MAILBOX_COUNT	16
/* System Register 0x00 */
#define	PROC_ADDR_RDY	BIT_31
#define	PROC_ADDR_R	BIT_30
#define	PROC_ADDR_ERR	BIT_29
#define	PROC_ADDR_DA	BIT_28
#define	PROC_ADDR_FUNC0_MBI	0x00001180
#define	PROC_ADDR_FUNC0_MBO	(PROC_ADDR_FUNC0_MBI + MAILBOX_COUNT)
#define	PROC_ADDR_FUNC0_CTL	0x000011a1
#define	PROC_ADDR_FUNC2_MBI	0x00001280
#define	PROC_ADDR_FUNC2_MBO	(PROC_ADDR_FUNC2_MBI + MAILBOX_COUNT)
#define	PROC_ADDR_FUNC2_CTL	0x000012a1
#define	PROC_ADDR_MPI_RISC	0x00000000
#define	PROC_ADDR_MDE		0x00010000
#define	PROC_ADDR_REGBLOCK	0x00020000
#define	PROC_ADDR_RISC_REG	0x00030000


/* System Register 0x08 */
#define	SYSTEM_EFE_FAE		0x3u
#define	SYSTEM_EFE_FAE_MASK	(SYSTEM_EFE_FAE<<16)
enum {
	SYS_EFE = (1 << 0),
	SYS_FAE = (1 << 1),
	SYS_MDC = (1 << 2),
	SYS_DST = (1 << 3),
	SYS_DWC = (1 << 4),
	SYS_EVW = (1 << 5),
	SYS_OMP_DLY_MASK = 0x3f000000,
	/*
	 * There are no values defined as of edit #15.
	 */
	SYS_ODI = (1 << 14)
};

/*
 * Reset/Failover Register (RST_FO) bit definitions.
 */

#define	RST_FO_TFO		(1 << 0)
#define	RST_FO_RR_MASK		0x00060000
#define	RST_FO_RR_CQ_CAM	0x00000000
#define	RST_FO_RR_DROP		0x00000001
#define	RST_FO_RR_DQ		0x00000002
#define	RST_FO_RR_RCV_FUNC_CQ	0x00000003
#define	RST_FO_FRB		BIT_12
#define	RST_FO_MOP		BIT_13
#define	RST_FO_REG		BIT_14
#define	RST_FO_FR		0x8000u

/*
 * Function Specific Control Register (FSC) bit definitions.
 */
enum {
	FSC_DBRST_MASK = 0x00070000,
	FSC_DBRST_256 = 0x00000000,
	FSC_DBRST_512 = 0x00000001,
	FSC_DBRST_768 = 0x00000002,
	FSC_DBRST_1024 = 0x00000003,
	FSC_DBL_MASK = 0x00180000,
	FSC_DBL_DBRST = 0x00000000,
	FSC_DBL_MAX_PLD = 0x00000008,
	FSC_DBL_MAX_BRST = 0x00000010,
	FSC_DBL_128_BYTES = 0x00000018,
	FSC_EC = (1 << 5),
	FSC_EPC_MASK = 0x00c00000,
	FSC_EPC_INBOUND = (1 << 6),
	FSC_EPC_OUTBOUND = (1 << 7),
	FSC_VM_PAGESIZE_MASK = 0x07000000,
	FSC_VM_PAGE_2K = 0x00000100,
	FSC_VM_PAGE_4K = 0x00000200,
	FSC_VM_PAGE_8K = 0x00000300,
	FSC_VM_PAGE_64K = 0x00000600,
	FSC_SH = (1 << 11),
	FSC_DSB = (1 << 12),
	FSC_STE = (1 << 13),
	FSC_FE = (1 << 15)
};

/*
 * Host Command Status Register (CSR) bit definitions.
 */
#define	CSR_ERR_STS_MASK	0x0000003f
/*
 * There are no valued defined as of edit #15.
 */
#define	CSR_RR			BIT_8
#define	CSR_HRI			BIT_9
#define	CSR_RP			BIT_10
#define	CSR_CMD_PARM_SHIFT	22
#define	CSR_CMD_NOP		0x00000000
#define	CSR_CMD_SET_RST		0x1000000
#define	CSR_CMD_CLR_RST		0x20000000
#define	CSR_CMD_SET_PAUSE	0x30000000
#define	CSR_CMD_CLR_PAUSE	0x40000000
#define	CSR_CMD_SET_H2R_INT	0x50000000
#define	CSR_CMD_CLR_H2R_INT	0x60000000
#define	CSR_CMD_PAR_EN		0x70000000
#define	CSR_CMD_SET_BAD_PAR	0x80000000u
#define	CSR_CMD_CLR_BAD_PAR	0x90000000u
#define	CSR_CMD_CLR_R2PCI_INT	0xa0000000u

/*
 * Configuration Register (CFG) bit definitions.
 */
enum {
	CFG_LRQ = (1 << 0),
	CFG_DRQ = (1 << 1),
	CFG_LR = (1 << 2),
	CFG_DR = (1 << 3),
	CFG_LE = (1 << 5),
	CFG_LCQ = (1 << 6),
	CFG_DCQ = (1 << 7),
	CFG_Q_SHIFT = 8,
	CFG_Q_MASK = 0x7f000000
};

/*
 *  Status Register (STS) bit definitions.
 */
enum {
	STS_FE = (1 << 0),
	STS_PI = (1 << 1),
	STS_PL0 = (1 << 2),
	STS_PL1 = (1 << 3),
	STS_PI0 = (1 << 4),
	STS_PI1 = (1 << 5),
	STS_FUNC_ID_MASK = 0x000000c0,
	STS_FUNC_ID_SHIFT = 6,
	STS_F0E = (1 << 8),
	STS_F1E = (1 << 9),
	STS_F2E = (1 << 10),
	STS_F3E = (1 << 11),
	STS_NFE = (1 << 12)
};

/*
 * Register (REV_ID) bit definitions.
 */
enum {
	REV_ID_MASK = 0x0000000f,
	REV_ID_NICROLL_SHIFT = 0,
	REV_ID_NICREV_SHIFT = 4,
	REV_ID_XGROLL_SHIFT = 8,
	REV_ID_XGREV_SHIFT = 12,
	REV_ID_CHIPREV_SHIFT = 28
};

/*
 *  Force ECC Error Register (FRC_ECC_ERR) bit definitions.
 */
enum {
	FRC_ECC_ERR_VW = (1 << 12),
	FRC_ECC_ERR_VB = (1 << 13),
	FRC_ECC_ERR_NI = (1 << 14),
	FRC_ECC_ERR_NO = (1 << 15),
	FRC_ECC_PFE_SHIFT = 16,
	FRC_ECC_ERR_DO = (1 << 18),
	FRC_ECC_P14 = (1 << 19)
};

/*
 * Error Status Register (ERR_STS) bit definitions.
 */
enum {
	ERR_STS_NOF = (1 << 0),
	ERR_STS_NIF = (1 << 1),
	ERR_STS_DRP = (1 << 2),
	ERR_STS_XGP = (1 << 3),
	ERR_STS_FOU = (1 << 4),
	ERR_STS_FOC = (1 << 5),
	ERR_STS_FOF = (1 << 6),
	ERR_STS_FIU = (1 << 7),
	ERR_STS_FIC = (1 << 8),
	ERR_STS_FIF = (1 << 9),
	ERR_STS_MOF = (1 << 10),
	ERR_STS_TA = (1 << 11),
	ERR_STS_MA = (1 << 12),
	ERR_STS_MPE = (1 << 13),
	ERR_STS_SCE = (1 << 14),
	ERR_STS_STE = (1 << 15),
	ERR_STS_FOW = (1 << 16),
	ERR_STS_UE = (1 << 17),
	ERR_STS_MCH = (1 << 26),
	ERR_STS_LOC_SHIFT = 27
};

/*
 * Semaphore Register (SEM) bit definitions.
 */
/*
 * Example:
 * reg = SEM_XGMAC0_MASK | (SEM_SET << SEM_XGMAC0_SHIFT)
 */
#define	SEM_CLEAR		0
#define	SEM_SET			1
#define	SEM_FORCE		3
#define	SEM_XGMAC0_SHIFT	0
#define	SEM_XGMAC1_SHIFT	2
#define	SEM_ICB_SHIFT		4
#define	SEM_MAC_ADDR_SHIFT	6
#define	SEM_FLASH_SHIFT		8
#define	SEM_PROBE_SHIFT		10
#define	SEM_RT_IDX_SHIFT	12
#define	SEM_PROC_REG_SHIFT	14
#define	SEM_XGMAC0_MASK		0x00030000
#define	SEM_XGMAC1_MASK		0x000c0000
#define	SEM_ICB_MASK		0x00300000
#define	SEM_MAC_ADDR_MASK	0x00c00000
#define	SEM_FLASH_MASK		0x03000000
#define	SEM_PROBE_MASK		0x0c000000
#define	SEM_RT_IDX_MASK		0x30000000
#define	SEM_PROC_REG_MASK	0xc0000000

/*
 * Stop CQ Processing Register (CQ_STOP) bit definitions.
 */
enum {
	CQ_STOP_QUEUE_MASK = (0x007f0000),
	CQ_STOP_TYPE_MASK = (0x03000000),
	CQ_STOP_TYPE_START = 0x00000100,
	CQ_STOP_TYPE_STOP = 0x00000200,
	CQ_STOP_TYPE_READ = 0x00000300,
	CQ_STOP_EN = (1 << 15)
};

/*
 * MAC Protocol Address Index Register (MAC_ADDR_IDX) bit definitions.
 */
#define	MAC_ADDR_IDX_SHIFT		4
#define	MAC_ADDR_TYPE_SHIFT		16
#define	MAC_ADDR_TYPE_MASK 		0x000f0000
#define	MAC_ADDR_TYPE_CAM_MAC		0x00000000
#define	MAC_ADDR_TYPE_MULTI_MAC		0x00010000
#define	MAC_ADDR_TYPE_VLAN		0x00020000
#define	MAC_ADDR_TYPE_MULTI_FLTR	0x00030000
#define	MAC_ADDR_TYPE_FC_MAC		0x00040000
#define	MAC_ADDR_TYPE_MGMT_MAC		0x00050000
#define	MAC_ADDR_TYPE_MGMT_VLAN		0x00060000
#define	MAC_ADDR_TYPE_MGMT_V4		0x00070000
#define	MAC_ADDR_TYPE_MGMT_V6		0x00080000
#define	MAC_ADDR_TYPE_MGMT_TU_DP	0x00090000
#define	MAC_ADDR_ADR			BIT_25
#define	MAC_ADDR_RS			BIT_26
#define	MAC_ADDR_E  			BIT_27
#define	MAC_ADDR_MR  			BIT_30
#define	MAC_ADDR_MW  			BIT_31
#define	MAX_MULTICAST_HW_SIZE		32

/*
 *  MAC Protocol Address Index Register (SPLT_HDR, 0xC0) bit definitions.
 */
#define	SPLT_HDR_EP	BIT_31

/*
 * NIC Receive Configuration Register (NIC_RCV_CFG) bit definitions.
 */
enum {
	NIC_RCV_CFG_PPE = (1 << 0),
	NIC_RCV_CFG_VLAN_MASK = 0x00060000,
	NIC_RCV_CFG_VLAN_ALL = 0x00000000,
	NIC_RCV_CFG_VLAN_MATCH_ONLY = 0x00000002,
	NIC_RCV_CFG_VLAN_MATCH_AND_NON = 0x00000004,
	NIC_RCV_CFG_VLAN_NONE_AND_NON = 0x00000006,
	NIC_RCV_CFG_RV = (1 << 3),
	NIC_RCV_CFG_DFQ_MASK = (0x7f000000),
	NIC_RCV_CFG_DFQ_SHIFT = 8,
	NIC_RCV_CFG_DFQ = 0	/* HARDCODE default queue to 0. */
};

/*
 * Routing Index Register (RT_IDX) bit definitions.
 */
#define	RT_IDX_IDX_SHIFT	8
#define	RT_IDX_TYPE_MASK	0x000f0000
#define	RT_IDX_TYPE_RT		0x00000000
#define	RT_IDX_TYPE_RT_INV	0x00010000
#define	RT_IDX_TYPE_NICQ	0x00020000
#define	RT_IDX_TYPE_NICQ_INV	0x00030000
#define	RT_IDX_DST_MASK		0x00700000
#define	RT_IDX_DST_RSS		0x00000000
#define	RT_IDX_DST_CAM_Q	0x00100000
#define	RT_IDX_DST_COS_Q	0x00200000
#define	RT_IDX_DST_DFLT_Q	0x00300000
#define	RT_IDX_DST_DEST_Q	0x00400000
#define	RT_IDX_RS		BIT_26
#define	RT_IDX_E		BIT_27
#define	RT_IDX_MR		BIT_30
#define	RT_IDX_MW		BIT_31

/* Nic Queue format - type 2 bits */
#define	RT_IDX_BCAST		1
#define	RT_IDX_MCAST		BIT_1
#define	RT_IDX_MCAST_MATCH	BIT_2
#define	RT_IDX_MCAST_REG_MATCH	BIT_3
#define	RT_IDX_MCAST_HASH_MATCH	BIT_4
#define	RT_IDX_FC_MACH		BIT_5
#define	RT_IDX_ETH_FCOE		BIT_6
#define	RT_IDX_CAM_HIT		BIT_7
#define	RT_IDX_CAM_BIT0		BIT_8
#define	RT_IDX_CAM_BIT1		BIT_9
#define	RT_IDX_VLAN_TAG		BIT_10
#define	RT_IDX_VLAN_MATCH	BIT_11
#define	RT_IDX_VLAN_FILTER	BIT_12
#define	RT_IDX_ETH_SKIP1	BIT_13
#define	RT_IDX_ETH_SKIP2	BIT_14
#define	RT_IDX_BCAST_MCAST_MATCH	BIT_15
#define	RT_IDX_802_3		BIT_16
#define	RT_IDX_LLDP		BIT_17
#define	RT_IDX_UNUSED018	BIT_18
#define	RT_IDX_UNUSED019	BIT_19
#define	RT_IDX_UNUSED20		BIT_20
#define	RT_IDX_UNUSED21		BIT_21
#define	RT_IDX_ERR		BIT_22
#define	RT_IDX_VALID		BIT_23
#define	RT_IDX_TU_CSUM_ERR	BIT_24
#define	RT_IDX_IP_CSUM_ERR	BIT_25
#define	RT_IDX_MAC_ERR		BIT_26
#define	RT_IDX_RSS_TCP6		BIT_27
#define	RT_IDX_RSS_TCP4		BIT_28
#define	RT_IDX_RSS_IPV6		BIT_29
#define	RT_IDX_RSS_IPV4		BIT_30
#define	RT_IDX_RSS_MATCH	BIT_31

/* Hierarchy for the NIC Queue Mask */
enum {
	RT_IDX_ALL_ERR_SLOT = 0,
	RT_IDX_MAC_ERR_SLOT = 0,
	RT_IDX_IP_CSUM_ERR_SLOT = 1,
	RT_IDX_TCP_UDP_CSUM_ERR_SLOT = 2,
	RT_IDX_BCAST_SLOT = 3,
	RT_IDX_MCAST_MATCH_SLOT = 4,
	RT_IDX_ALLMULTI_SLOT = 5,
	RT_IDX_UNUSED6_SLOT = 6,
	RT_IDX_UNUSED7_SLOT = 7,
	RT_IDX_RSS_MATCH_SLOT = 8,
	RT_IDX_RSS_IPV4_SLOT = 8,
	RT_IDX_RSS_IPV6_SLOT = 9,
	RT_IDX_RSS_TCP4_SLOT = 10,
	RT_IDX_RSS_TCP6_SLOT = 11,
	RT_IDX_CAM_HIT_SLOT = 12,
	RT_IDX_UNUSED013 = 13,
	RT_IDX_UNUSED014 = 14,
	RT_IDX_PROMISCUOUS_SLOT = 15,
	RT_IDX_MAX_SLOTS = 16
};

enum {
	CAM_OUT_ROUTE_FC = 0,
	CAM_OUT_ROUTE_NIC = 1,
	CAM_OUT_FUNC_SHIFT = 2,
	CAM_OUT_RV = (1 << 4),
	CAM_OUT_SH = (1 << 15),
	CAM_OUT_CQ_ID_SHIFT = 5
};

/* Reset/Failover Register 0C */
#define	FUNCTION_RESET		0x8000u
#define	FUNCTION_RESET_MASK	(FUNCTION_RESET<<16)

/* Function Specific Control Register 0x10 */
#define	FSC_MASK	(0x97ffu << 16)
#define	FSC_FE		0x8000

/* Configuration Register 0x28 */
#define	LOAD_LCQ	0x40
#define	LOAD_LCQ_MASK	(0x7F40u << 16)
#define	LOAD_ICB_ERR	0x20
#define	LOAD_LRQ	0x01
#define	LOAD_LRQ_MASK	(0x7F01u << 16)

#define	FN0_NET	0
#define	FN1_NET	1
#define	FN0_FC	2
#define	FN1_FC	3

/*
 * Semaphore Register (SEM) bit definitions.
 */
#define	SEM_CLEAR		0
#define	SEM_SET			1
#define	SEM_FORCE		3
#define	SEM_XGMAC0_SHIFT	0
#define	SEM_XGMAC1_SHIFT	2
#define	SEM_ICB_SHIFT		4
#define	SEM_MAC_ADDR_SHIFT	6
#define	SEM_FLASH_SHIFT		8
#define	SEM_PROBE_SHIFT		10
#define	SEM_RT_IDX_SHIFT	12
#define	SEM_PROC_REG_SHIFT	14
#define	SEM_XGMAC0_MASK		0x00030000
#define	SEM_XGMAC1_MASK		0x000c0000
#define	SEM_ICB_MASK		0x00300000
#define	SEM_MAC_ADDR_MASK	0x00c00000
#define	SEM_FLASH_MASK		0x03000000
#define	SEM_PROBE_MASK		0x0c000000
#define	SEM_RT_IDX_MASK		0x30000000
#define	SEM_PROC_REG_MASK	0xc0000000

/* System Register 0x08 */
#define	SYSTEM_EFE_FAE	0x3u
#define	SYSTEM_EFE_FAE_MASK	(SYSTEM_EFE_FAE<<16)

/* Interrupt Status Register-1		0x3C */
#define	CQ_0_NOT_EMPTY			BIT_0
#define	CQ_1_NOT_EMPTY			BIT_1
#define	CQ_2_NOT_EMPTY			BIT_2
#define	CQ_3_NOT_EMPTY			BIT_3
#define	CQ_4_NOT_EMPTY			BIT_4
#define	CQ_5_NOT_EMPTY			BIT_5
#define	CQ_6_NOT_EMPTY			BIT_6
#define	CQ_7_NOT_EMPTY			BIT_7
#define	CQ_8_NOT_EMPTY			BIT_8
#define	CQ_9_NOT_EMPTY			BIT_9
#define	CQ_10_NOT_EMPTY			BIT_10
#define	CQ_11_NOT_EMPTY			BIT_11
#define	CQ_12_NOT_EMPTY			BIT_12
#define	CQ_13_NOT_EMPTY			BIT_13
#define	CQ_14_NOT_EMPTY			BIT_14
#define	CQ_15_NOT_EMPTY			BIT_15
#define	CQ_16_NOT_EMPTY			BIT_16
/* Processor Address Register 0x00 */
#define	PROCESSOR_ADDRESS_RDY	(0x8000u<<16)
#define	PROCESSOR_ADDRESS_READ	(0x4000u<<16)
/* Host Command/Status Register 0x14 */
#define	HOST_CMD_SET_RISC_RESET			0x10000000u
#define	HOST_CMD_CLEAR_RISC_RESET		0x20000000u
#define	HOST_CMD_SET_RISC_PAUSE			0x30000000u
#define	HOST_CMD_RELEASE_RISC_PAUSE		0x40000000u
#define	HOST_CMD_SET_RISC_INTR			0x50000000u
#define	HOST_CMD_CLEAR_RISC_INTR		0x60000000u
#define	HOST_CMD_SET_PARITY_ENABLE		0x70000000u
#define	HOST_CMD_FORCE_BAD_PARITY		0x80000000u
#define	HOST_CMD_RELEASE_BAD_PARITY		0x90000000u
#define	HOST_CMD_CLEAR_RISC_TO_HOST_INTR	0xA0000000u
#define	HOST_TO_MPI_INTR_NOT_DONE		0x200

#define	RISC_RESET			BIT_8
#define	RISC_PAUSED			BIT_10
/* Semaphor Register 0x64 */
#define	QL_SEM_BITS_BASE_CODE		0x1u
#define	QL_PORT0_XGMAC_SEM_BITS		(QL_SEM_BITS_BASE_CODE)
#define	QL_PORT1_XGMAC_SEM_BITS		(QL_SEM_BITS_BASE_CODE << 2)
#define	QL_ICB_ACCESS_ADDRESS_SEM_BITS	(QL_SEM_BITS_BASE_CODE << 4)
#define	QL_MAC_PROTOCOL_SEM_BITS	(QL_SEM_BITS_BASE_CODE << 6)
#define	QL_FLASH_SEM_BITS		(QL_SEM_BITS_BASE_CODE << 8)
#define	QL_PROBE_MUX_SEM_BITS		(QL_SEM_BITS_BASE_CODE << 10)
#define	QL_ROUTING_INDEX_SEM_BITS	(QL_SEM_BITS_BASE_CODE << 12)
#define	QL_PROCESSOR_SEM_BITS		(QL_SEM_BITS_BASE_CODE << 14)
#define	QL_NIC_RECV_CONFIG_SEM_BITS	(QL_SEM_BITS_BASE_CODE << 14)

#define	QL_SEM_MASK_BASE_CODE		0x30000u
#define	QL_PORT0_XGMAC_SEM_MASK		(QL_SEM_MASK_BASE_CODE)
#define	QL_PORT1_XGMAC_SEM_MASK		(QL_SEM_MASK_BASE_CODE << 2)
#define	QL_ICB_ACCESS_ADDRESS_SEM_MASK	(QL_SEM_MASK_BASE_CODE << 4)
#define	QL_MAC_PROTOCOL_SEM_MASK	(QL_SEM_MASK_BASE_CODE << 6)
#define	QL_FLASH_SEM_MASK		(QL_SEM_MASK_BASE_CODE << 8)
#define	QL_PROBE_MUX_SEM_MASK		(QL_SEM_MASK_BASE_CODE << 10)
#define	QL_ROUTING_INDEX_SEM_MASK	(QL_SEM_MASK_BASE_CODE << 12)
#define	QL_PROCESSOR_SEM_MASK		(QL_SEM_MASK_BASE_CODE << 14)
#define	QL_NIC_RECV_CONFIG_SEM_MASK	(QL_SEM_MASK_BASE_CODE << 14)

/* XGMAC Address Register 0x78 */
#define	XGMAC_ADDRESS_RDY		(0x8000u<<16)
#define	XGMAC_ADDRESS_READ_TRANSACT	(0x4000u<<16)
#define	XGMAC_ADDRESS_ACCESS_ERROR	(0x2000u<<16)

/* XGMAC Register Set */
#define	REG_XGMAC_GLOBAL_CONFIGURATION	0x108
#define	GLOBAL_CONFIG_JUMBO_MODE	0x40

#define	REG_XGMAC_MAC_TX_CONFIGURATION	0x10C
#define	XGMAC_MAC_TX_ENABLE		0x02

#define	REG_XGMAC_MAC_RX_CONFIGURATION	0x110
#define	XGMAC_MAC_RX_ENABLE		0x02

#define	REG_XGMAC_FLOW_CONTROL		0x11C

#define	REG_XGMAC_MAC_TX_PARAM		0x134
#define	REG_XGMAC_MAC_RX_PARAM		0x138

#define	REG_XGMAC_MAC_TX_PKTS		0x200
#define	REG_XGMAC_MAC_TX_OCTETS		0x208
#define	REG_XGMAC_MAC_TX_MULTCAST_PKTS	0x210
#define	REG_XGMAC_MAC_TX_BROADCAST_PKTS	0x218
#define	REG_XGMAC_MAC_TX_PAUSE_PKTS	0x230

#define	REG_XGMAC_MAC_RX_OCTETS		0x300
#define	REG_XGMAC_MAC_RX_OCTETS_OK	0x308
#define	REG_XGMAC_MAC_RX_PKTS		0x310
#define	REG_XGMAC_MAC_RX_PKTS_OK	0x318
#define	REG_XGMAC_MAC_RX_BROADCAST_PKTS	0x320
#define	REG_XGMAC_MAC_RX_MULTCAST_PKTS	0x328
#define	REG_XGMAC_MAC_RX_JABBER_PKTS	0x348
#define	REG_XGMAC_MAC_FCS_ERR		0x360
#define	REG_XGMAC_MAC_ALIGN_ERR		0x368
#define	REG_XGMAC_MAC_RX_SYM_ERR	0x370
#define	REG_XGMAC_MAC_RX_INT_ERR	0x378
#define	REG_XGMAC_MAC_RX_PAUSE_PKTS	0x388
#define	REG_XGMAC_MAC_PHY_ADDR		0x430
#define	REG_XGMAC_MAC_RX_FIFO_DROPS	0x5B8


/* MAC Protocol Address Index Register Set 0xA8 */
#define	MAC_PROTOCOL_ADDRESS_INDEX_MW	(0x8000u<<16)
#define	MAC_PROTOCOL_ADDRESS_ENABLE	(1 << 27)
#define	MAC_PROTOCOL_TYPE_CAM_MAC	(0x0)
#define	MAC_PROTOCOL_TYPE_MULTICAST	(0x10000u)

/* NIC Receive Configuration Register 0xD4 */
#define	RECV_CONFIG_DEFAULT_Q_MASK	(0x7F000000u)
#define	RECV_CONFIG_VTAG_REMOVAL_MASK	(0x80000u)
#define	RECV_CONFIG_VTAG_RV		0x08

/*
 *  10G MAC Address  Register (XGMAC_ADDR) bit definitions.
 */
#define	XGMAC_ADDR_RDY	(1 << 31)
#define	XGMAC_ADDR_R	(1 << 30)
#define	XGMAC_ADDR_XME	(1 << 29)

#define	PAUSE_SRC_LO			0x00000100
#define	PAUSE_SRC_HI			0x00000104
#define	GLOBAL_CFG			0x00000108
#define	GLOBAL_CFG_RESET		(1 << 0)
#define	GLOBAL_CFG_JUMBO		(1 << 6)
#define	GLOBAL_CFG_TX_STAT_EN		(1 << 10)
#define	GLOBAL_CFG_RX_STAT_EN		(1 << 11)
#define	TX_CFG				0x0000010c
#define	TX_CFG_RESET			(1 << 0)
#define	TX_CFG_EN			(1 << 1)
#define	TX_CFG_PREAM			(1 << 2)
#define	RX_CFG				0x00000110
#define	RX_CFG_RESET			(1 << 0)
#define	RX_CFG_EN			(1 << 1)
#define	RX_CFG_PREAM			(1 << 2)
#define	FLOW_CTL			0x0000011c
#define	PAUSE_OPCODE			0x00000120
#define	PAUSE_TIMER			0x00000124
#define	PAUSE_FRM_DEST_LO		0x00000128
#define	PAUSE_FRM_DEST_HI		0x0000012c
#define	MAC_TX_PARAMS			0x00000134
#define	MAC_TX_PARAMS_JUMBO		(1 << 31)
#define	MAC_TX_PARAMS_SIZE_SHIFT	16
#define	MAC_RX_PARAMS			0x00000138
#define	MAC_SYS_INT			0x00000144
#define	MAC_SYS_INT_MASK		0x00000148
#define	MAC_MGMT_INT			0x0000014c
#define	MAC_MGMT_IN_MASK		0x00000150
#define	EXT_ARB_MODE			0x000001fc
#define	TX_PKTS				0x00000200
#define	TX_PKTS_LO			0x00000204
#define	TX_BYTES			0x00000208
#define	TX_BYTES_LO			0x0000020C
#define	TX_MCAST_PKTS			0x00000210
#define	TX_MCAST_PKTS_LO		0x00000214
#define	TX_BCAST_PKTS			0x00000218
#define	TX_BCAST_PKTS_LO		0x0000021C
#define	TX_UCAST_PKTS			0x00000220
#define	TX_UCAST_PKTS_LO		0x00000224
#define	TX_CTL_PKTS			0x00000228
#define	TX_CTL_PKTS_LO			0x0000022c
#define	TX_PAUSE_PKTS			0x00000230
#define	TX_PAUSE_PKTS_LO		0x00000234
#define	TX_64_PKT			0x00000238
#define	TX_64_PKT_LO			0x0000023c
#define	TX_65_TO_127_PKT		0x00000240
#define	TX_65_TO_127_PKT_LO		0x00000244
#define	TX_128_TO_255_PKT		0x00000248
#define	TX_128_TO_255_PKT_LO		0x0000024c
#define	TX_256_511_PKT			0x00000250
#define	TX_256_511_PKT_LO		0x00000254
#define	TX_512_TO_1023_PKT		0x00000258
#define	TX_512_TO_1023_PKT_LO		0x0000025c
#define	TX_1024_TO_1518_PKT		0x00000260
#define	TX_1024_TO_1518_PKT_LO		0x00000264
#define	TX_1519_TO_MAX_PKT		0x00000268
#define	TX_1519_TO_MAX_PKT_LO		0x0000026c
#define	TX_UNDERSIZE_PKT		0x00000270
#define	TX_UNDERSIZE_PKT_LO		0x00000274
#define	TX_OVERSIZE_PKT			0x00000278
#define	TX_OVERSIZE_PKT_LO		0x0000027c
#define	RX_HALF_FULL_DET		0x000002a0
#define	TX_HALF_FULL_DET_LO		0x000002a4
#define	RX_OVERFLOW_DET			0x000002a8
#define	TX_OVERFLOW_DET_LO		0x000002ac
#define	RX_HALF_FULL_MASK		0x000002b0
#define	TX_HALF_FULL_MASK_LO		0x000002b4
#define	RX_OVERFLOW_MASK		0x000002b8
#define	TX_OVERFLOW_MASK_LO		0x000002bc
#define	STAT_CNT_CTL			0x000002c0
#define	STAT_CNT_CTL_CLEAR_TX		(1 << 0)	/* Control */
#define	STAT_CNT_CTL_CLEAR_RX		(1 << 1)	/* Control */
#define	AUX_RX_HALF_FULL_DET		0x000002d0
#define	AUX_TX_HALF_FULL_DET		0x000002d4
#define	AUX_RX_OVERFLOW_DET		0x000002d8
#define	AUX_TX_OVERFLOW_DET		0x000002dc
#define	AUX_RX_HALF_FULL_MASK		0x000002f0
#define	AUX_TX_HALF_FULL_MASK		0x000002f4
#define	AUX_RX_OVERFLOW_MASK		0x000002f8
#define	AUX_TX_OVERFLOW_MASK		0x000002fc
#define	RX_BYTES			0x00000300
#define	RX_BYTES_LO			0x00000304
#define	RX_BYTES_OK			0x00000308
#define	RX_BYTES_OK_LO			0x0000030c
#define	RX_PKTS				0x00000310
#define	RX_PKTS_LO			0x00000314
#define	RX_PKTS_OK			0x00000318
#define	RX_PKTS_OK_LO			0x0000031c
#define	RX_BCAST_PKTS			0x00000320
#define	RX_BCAST_PKTS_LO		0x00000324
#define	RX_MCAST_PKTS			0x00000328
#define	RX_MCAST_PKTS_LO		0x0000032c
#define	RX_UCAST_PKTS			0x00000330
#define	RX_UCAST_PKTS_LO		0x00000334
#define	RX_UNDERSIZE_PKTS		0x00000338
#define	RX_UNDERSIZE_PKTS_LO		0x0000033c
#define	RX_OVERSIZE_PKTS		0x00000340
#define	RX_OVERSIZE_PKTS_LO		0x00000344
#define	RX_JABBER_PKTS			0x00000348
#define	RX_JABBER_PKTS_LO		0x0000034c
#define	RX_UNDERSIZE_FCERR_PKTS		0x00000350
#define	RX_UNDERSIZE_FCERR_PKTS_LO	0x00000354
#define	RX_DROP_EVENTS			0x00000358
#define	RX_DROP_EVENTS_LO		0x0000035c
#define	RX_FCERR_PKTS			0x00000360
#define	RX_FCERR_PKTS_LO		0x00000364
#define	RX_ALIGN_ERR			0x00000368
#define	RX_ALIGN_ERR_LO			0x0000036c
#define	RX_SYMBOL_ERR			0x00000370
#define	RX_SYMBOL_ERR_LO		0x00000374
#define	RX_MAC_ERR			0x00000378
#define	RX_MAC_ERR_LO			0x0000037c
#define	RX_CTL_PKTS			0x00000380
#define	RX_CTL_PKTS_LO			0x00000384
#define	RX_PAUSE_PKTS			0x00000388
#define	RX_PAUSE_PKTS_LO		0x0000038c
#define	RX_64_PKTS			0x00000390
#define	RX_64_PKTS_LO			0x00000394
#define	RX_65_TO_127_PKTS		0x00000398
#define	RX_65_TO_127_PKTS_LO		0x0000039c
#define	RX_128_255_PKTS			0x000003a0
#define	RX_128_255_PKTS_LO		0x000003a4
#define	RX_256_511_PKTS			0x000003a8
#define	RX_256_511_PKTS_LO		0x000003ac
#define	RX_512_TO_1023_PKTS		0x000003b0
#define	RX_512_TO_1023_PKTS_LO		0x000003b4
#define	RX_1024_TO_1518_PKTS		0x000003b8
#define	RX_1024_TO_1518_PKTS_LO		0x000003bc
#define	RX_1519_TO_MAX_PKTS		0x000003c0
#define	RX_1519_TO_MAX_PKTS_LO		0x000003c4
#define	RX_LEN_ERR_PKTS			0x000003c8
#define	RX_LEN_ERR_PKTS_LO		0x000003cc
#define	MDIO_TX_DATA			0x00000400
#define	MDIO_RX_DATA			0x00000410
#define	MDIO_CMD			0x00000420
#define	MDIO_PHY_ADDR			0x00000430
#define	MDIO_PORT			0x00000440
#define	MDIO_STATUS			0x00000450
#define	TX_CBFC_PAUSE_FRAMES0		0x00000500
#define	TX_CBFC_PAUSE_FRAMES0_LO	0x00000504
#define	TX_CBFC_PAUSE_FRAMES1		0x00000508
#define	TX_CBFC_PAUSE_FRAMES1_LO	0x0000050C
#define	TX_CBFC_PAUSE_FRAMES2		0x00000510
#define	TX_CBFC_PAUSE_FRAMES2_LO	0x00000514
#define	TX_CBFC_PAUSE_FRAMES3		0x00000518
#define	TX_CBFC_PAUSE_FRAMES3_LO	0x0000051C
#define	TX_CBFC_PAUSE_FRAMES4		0x00000520
#define	TX_CBFC_PAUSE_FRAMES4_LO	0x00000524
#define	TX_CBFC_PAUSE_FRAMES5		0x00000528
#define	TX_CBFC_PAUSE_FRAMES5_LO	0x0000052C
#define	TX_CBFC_PAUSE_FRAMES6		0x00000530
#define	TX_CBFC_PAUSE_FRAMES6_LO	0x00000534
#define	TX_CBFC_PAUSE_FRAMES7		0x00000538
#define	TX_CBFC_PAUSE_FRAMES7_LO	0x0000053C
#define	TX_FCOE_PKTS			0x00000540
#define	TX_FCOE_PKTS_LO			0x00000544
#define	TX_MGMT_PKTS			0x00000548
#define	TX_MGMT_PKTS_LO			0x0000054C
#define	RX_CBFC_PAUSE_FRAMES0		0x00000568
#define	RX_CBFC_PAUSE_FRAMES0_LO	0x0000056C
#define	RX_CBFC_PAUSE_FRAMES1		0x00000570
#define	RX_CBFC_PAUSE_FRAMES1_LO	0x00000574
#define	RX_CBFC_PAUSE_FRAMES2		0x00000578
#define	RX_CBFC_PAUSE_FRAMES2_LO	0x0000057C
#define	RX_CBFC_PAUSE_FRAMES3		0x00000580
#define	RX_CBFC_PAUSE_FRAMES3_LO	0x00000584
#define	RX_CBFC_PAUSE_FRAMES4		0x00000588
#define	RX_CBFC_PAUSE_FRAMES4_LO	0x0000058C
#define	RX_CBFC_PAUSE_FRAMES5		0x00000590
#define	RX_CBFC_PAUSE_FRAMES5_LO	0x00000594
#define	RX_CBFC_PAUSE_FRAMES6		0x00000598
#define	RX_CBFC_PAUSE_FRAMES6_LO	0x0000059C
#define	RX_CBFC_PAUSE_FRAMES7		0x000005A0
#define	RX_CBFC_PAUSE_FRAMES7_LO	0x000005A4
#define	RX_FCOE_PKTS			0x000005A8
#define	RX_FCOE_PKTS_LO			0x000005AC
#define	RX_MGMT_PKTS			0x000005B0
#define	RX_MGMT_PKTS_LO			0x000005B4
#define	RX_NIC_FIFO_DROP		0x000005B8
#define	RX_NIC_FIFO_DROP_LO		0x000005BC
#define	RX_FCOE_FIFO_DROP		0x000005C0
#define	RX_FCOE_FIFO_DROP_LO		0x000005C4
#define	RX_MGMT_FIFO_DROP		0x000005C8
#define	RX_MGMT_FIFO_DROP_LO		0x000005CC
#define	RX_PKTS_PRIORITY0		0x00000600
#define	RX_PKTS_PRIORITY0_LO		0x00000604
#define	RX_PKTS_PRIORITY1		0x00000608
#define	RX_PKTS_PRIORITY1_LO		0x0000060C
#define	RX_PKTS_PRIORITY2		0x00000610
#define	RX_PKTS_PRIORITY2_LO		0x00000614
#define	RX_PKTS_PRIORITY3		0x00000618
#define	RX_PKTS_PRIORITY3_LO		0x0000061C
#define	RX_PKTS_PRIORITY4		0x00000620
#define	RX_PKTS_PRIORITY4_LO		0x00000624
#define	RX_PKTS_PRIORITY5		0x00000628
#define	RX_PKTS_PRIORITY5_LO		0x0000062C
#define	RX_PKTS_PRIORITY6		0x00000630
#define	RX_PKTS_PRIORITY6_LO		0x00000634
#define	RX_PKTS_PRIORITY7		0x00000638
#define	RX_PKTS_PRIORITY7_LO		0x0000063C
#define	RX_OCTETS_PRIORITY0		0x00000640
#define	RX_OCTETS_PRIORITY0_LO		0x00000644
#define	RX_OCTETS_PRIORITY1		0x00000648
#define	RX_OCTETS_PRIORITY1_LO		0x0000064C
#define	RX_OCTETS_PRIORITY2		0x00000650
#define	RX_OCTETS_PRIORITY2_LO		0x00000654
#define	RX_OCTETS_PRIORITY3		0x00000658
#define	RX_OCTETS_PRIORITY3_LO		0x0000065C
#define	RX_OCTETS_PRIORITY4		0x00000660
#define	RX_OCTETS_PRIORITY4_LO		0x00000664
#define	RX_OCTETS_PRIORITY5		0x00000668
#define	RX_OCTETS_PRIORITY5_LO		0x0000066C
#define	RX_OCTETS_PRIORITY6		0x00000670
#define	RX_OCTETS_PRIORITY6_LO		0x00000674
#define	RX_OCTETS_PRIORITY7		0x00000678
#define	RX_OCTETS_PRIORITY7_LO		0x0000067C
#define	TX_PKTS_PRIORITY0		0x00000680
#define	TX_PKTS_PRIORITY0_LO		0x00000684
#define	TX_PKTS_PRIORITY1		0x00000688
#define	TX_PKTS_PRIORITY1_LO		0x0000068C
#define	TX_PKTS_PRIORITY2		0x00000690
#define	TX_PKTS_PRIORITY2_LO		0x00000694
#define	TX_PKTS_PRIORITY3		0x00000698
#define	TX_PKTS_PRIORITY3_LO		0x0000069C
#define	TX_PKTS_PRIORITY4		0x000006A0
#define	TX_PKTS_PRIORITY4_LO		0x000006A4
#define	TX_PKTS_PRIORITY5		0x000006A8
#define	TX_PKTS_PRIORITY5_LO		0x000006AC
#define	TX_PKTS_PRIORITY6		0x000006B0
#define	TX_PKTS_PRIORITY6_LO		0x000006B4
#define	TX_PKTS_PRIORITY7		0x000006B8
#define	TX_PKTS_PRIORITY7_LO		0x000006BC
#define	TX_OCTETS_PRIORITY0		0x000006C0
#define	TX_OCTETS_PRIORITY0_LO		0x000006C4
#define	TX_OCTETS_PRIORITY1		0x000006C8
#define	TX_OCTETS_PRIORITY1_LO		0x000006CC
#define	TX_OCTETS_PRIORITY2		0x000006D0
#define	TX_OCTETS_PRIORITY2_LO		0x000006D4
#define	TX_OCTETS_PRIORITY3		0x000006D8
#define	TX_OCTETS_PRIORITY3_LO		0x000006DC
#define	TX_OCTETS_PRIORITY4		0x000006E0
#define	TX_OCTETS_PRIORITY4_LO		0x000006E4
#define	TX_OCTETS_PRIORITY5		0x000006E8
#define	TX_OCTETS_PRIORITY5_LO		0x000006EC
#define	TX_OCTETS_PRIORITY6		0x000006F0
#define	TX_OCTETS_PRIORITY6_LO		0x000006F4
#define	TX_OCTETS_PRIORITY7		0x000006F8
#define	TX_OCTETS_PRIORITY7_LO		0x000006FC
#define	RX_DISCARD_PRIORITY0		0x00000700
#define	RX_DISCARD_PRIORITY0_LO		0x00000704
#define	RX_DISCARD_PRIORITY1		0x00000708
#define	RX_DISCARD_PRIORITY1_LO		0x0000070C
#define	RX_DISCARD_PRIORITY2		0x00000710
#define	RX_DISCARD_PRIORITY2_LO		0x00000714
#define	RX_DISCARD_PRIORITY3		0x00000718
#define	RX_DISCARD_PRIORITY3_LO		0x0000071C
#define	RX_DISCARD_PRIORITY4		0x00000720
#define	RX_DISCARD_PRIORITY4_LO		0x00000724
#define	RX_DISCARD_PRIORITY5		0x00000728
#define	RX_DISCARD_PRIORITY5_LO		0x0000072C
#define	RX_DISCARD_PRIORITY6		0x00000730
#define	RX_DISCARD_PRIORITY6_LO		0x00000734
#define	RX_DISCARD_PRIORITY7		0x00000738
#define	RX_DISCARD_PRIORITY7_LO		0x0000073C


#define	CQ0_ID				0x0
#define	NIC_CORE			0x1
/* Routing Index Register 0xE4 */
#define	ROUTING_INDEX_MW			BIT_31
#define	ROUTING_INDEX_DEFAULT_ENABLE_MASK	(0x8320000u)
#define	ROUTING_INDEX_DEFAULT_DISABLE_MASK	(0x0320000u)

/* Routing Data Register 0xE8 */
#define	ROUTE_AS_CAM_HIT		0x80
#define	ROUTE_AS_BCAST_MCAST_MATCH	0x8000u
#define	ROUTE_AS_VALID_PKT		0x800000u	/* promiscuous mode? */

enum {
	ROUTING_MASK_INDEX_CAM_HIT,
	ROUTING_MASK_INDEX_BCAST_MCAST_MATCH,
	ROUTING_MASK_INDEX_VALID_PKT,
	ROUTING_MASK_INDEX_TOTAL
};

#define	ROUTING_MASK_INDEX_MAX	16
/*
 * General definitions...
 */

/*
 * Below are a number compiler switches for controlling driver behavior.
 * Some are not supported under certain conditions and are notated as such.
 */

/* MTU & Frame Size stuff */
#define	JUMBO_MTU		9000
#define	NORMAL_FRAME_SIZE	2500	/* ETHERMTU,1500 */
#define	JUMBO_FRAME_SIZE	9600
#define	LRG_BUF_NORMAL_SIZE	NORMAL_FRAME_SIZE
#define	LRG_BUF_JUMBO_SIZE	JUMBO_FRAME_SIZE
#define	VLAN_ID_LEN		2
#define	VLAN_HEADER_LEN		sizeof (struct ether_vlan_header) /* 18 */
#define	ETHER_HEADER_LEN	sizeof (struct ether_header)	/* 14 */

#define	NUM_TX_RING_ENTRIES	(1024)
#define	NUM_RX_RING_ENTRIES	(1024)

#define	NUM_SMALL_BUFFERS	(1024)
#define	NUM_LARGE_BUFFERS	(1024)

#define	RX_TX_RING_SHADOW_SPACE	2	/* 1st one is wqicb and 2nd for cqicb */
#define	BUF_Q_PTR_SPACE		((((NUM_SMALL_BUFFERS * sizeof (uint64_t))  \
				    / VM_PAGE_SIZE) + 1) + \
				    (((NUM_LARGE_BUFFERS * sizeof (uint64_t))  \
				    / VM_PAGE_SIZE) + 1))

#define	MAX_CQ				128
#define	DFLT_RX_COALESCE_WAIT		90	/* usec wait for coalescing */
#define	DFLT_RX_INTER_FRAME_WAIT	30  	/* max interframe-wait for */
						/* coalescing */
#define	DFLT_TX_COALESCE_WAIT		90	/* usec wait for coalescing */
#define	DFLT_TX_INTER_FRAME_WAIT	30	/* max interframe-wait for */
						/* coalescing */
#define	DFLT_RX_COALESCE_WAIT_JUMBO	40	/* usec wait for coalescing */
#define	DFLT_RX_INTER_FRAME_WAIT_JUMBO	10  	/* max interframe-wait for */
						/* coalescing */
#define	DFLT_TX_COALESCE_WAIT_JUMBO	40	/* usec wait for coalescing */
#define	DFLT_TX_INTER_FRAME_WAIT_JUMBO	10	/* max interframe-wait for */
						/* coalescing */
#define	DFLT_PAYLOAD_COPY_THRESH	6	/* must be at least 6 usec */

#define	UDELAY_COUNT			3
#define	UDELAY_DELAY			10

#define	MAX_RX_RINGS			128
#define	MAX_TX_RINGS			16

/*
 * Large & Small Buffers for Receives
 */
struct lrg_buf_q_entry {
	uint32_t	addr0_lower;
#define	IAL_LAST_ENTRY	0x00000001
#define	IAL_CONT_ENTRY	0x00000002
#define	IAL_FLAG_MASK	0x00000003
	uint32_t	addr0_upper;
};

struct bufq_addr_element {
	uint32_t	addr_low;
	uint32_t	addr_high;
};

#define	QL_NO_RESET	0
#define	QL_DO_RESET	1

/* Link must be in one of these states */
enum link_state_t {
	LS_DOWN,
	LS_UP
};

/* qlge->flags definitions. */
#define	INTERRUPTS_ENABLED	BIT_0
#define	ADAPTER_ERROR		BIT_1

#define	ADAPTER_SUSPENDED	BIT_8

/*
 * ISP PCI Configuration Register Set structure definitions.
 */
typedef volatile struct
{
volatile uint16_t	vendor_id;
volatile uint16_t	device_id;
volatile uint16_t	command;
volatile uint16_t	status;
volatile uint8_t	revision;
volatile uint8_t	prog_class;
volatile uint8_t	sub_class;
volatile uint8_t	base_class;
volatile uint8_t	cache_line_size;
volatile uint8_t	latency_timer;
volatile uint8_t	header_type;
volatile uint32_t	io_base_address;
volatile uint32_t	pci_cntl_reg_set_mem_base_address_lower;
volatile uint32_t	pci_cntl_reg_set_mem_base_address_upper;
volatile uint32_t	pci_doorbell_mem_base_address_lower;
volatile uint32_t	pci_doorbell_mem_base_address_upper;

volatile uint16_t	sub_vendor_id;
volatile uint16_t	sub_device_id;
volatile uint32_t	expansion_rom;
volatile uint8_t	intr_line;
volatile uint8_t	intr_pin;
volatile uint8_t	min_grant;
volatile uint8_t	max_latency;
volatile uint16_t	pcie_device_control;
volatile uint16_t	link_status;
volatile uint16_t	msi_msg_control;
volatile uint16_t	msi_x_msg_control;

} pci_cfg_t;


/*
 *
 *      Schultz Control Registers Index
 *
 */
#define	REG_PROCESSOR_ADDR		0x00
#define	REG_PROCESSOR_DATA		0x04
#define	REG_SYSTEM			0x08
#define	REG_RESET_FAILOVER		0x0C
#define	REG_FUNCTION_SPECIFIC_CONTROL	0x10
#define	REG_HOST_CMD_STATUS		0x14
#define	REG_ICB_RID			0x1C
#define	REG_ICB_ACCESS_ADDRESS_LOWER	0x20
#define	REG_ICB_ACCESS_ADDRESS_UPPER	0x24
#define	REG_CONFIGURATION		0x28

#define	INTR_EN_INTR_MASK	0x007f0000
#define	INTR_EN_TYPE_MASK	0x03000000
#define	INTR_EN_TYPE_ENABLE	0x00000100
#define	INTR_EN_TYPE_DISABLE	0x00000200
#define	INTR_EN_TYPE_READ	0x00000300
#define	INTR_EN_IHD		0x00002000
#define	INTR_EN_IHD_MASK	(INTR_EN_IHD << 16)
#define	INTR_EN_EI		0x00004000
#define	INTR_EN_EN		0x00008000

#define	REG_STATUS				0x30
#define	REG_INTERRUPT_ENABLE			0x34
#define	REG_INTERRUPT_MASK			0x38
#define	REG_INTERRUPT_STATUS_1			0x3C

#define	REG_ERROR_STATUS			0x54

#define	REG_SEMAPHORE				0x64

#define	REG_XGMAC_ADDRESS			0x78
#define	REG_XGMAC_DATA				0x7C
#define	REG_NIC_ENHANCED_TX_SCHEDULE		0x80
#define	REG_CNA_ENHANCED_TX_SCHEDULE		0x84
#define	REG_FLASH_ADDRESS			0x88
#define	REG_FLASH_DATA				0x8C

#define	REG_STOP_CQ_PROCESSING			0x90
#define	REG_PAGE_TABLE_RID			0x94
#define	REG_WQ_PAGE_TABLE_BASE_ADDR_LOWER	0x98
#define	REG_WQ_PAGE_TABLE_BASE_ADDR_UPPER	0x9C
#define	REG_CQ_PAGE_TABLE_BASE_ADDR_LOWER	0xA0
#define	REG_CQ_PAGE_TABLE_BASE_ADDR_UPPER	0xA4
#define	REG_MAC_PROTOCOL_ADDRESS_INDEX		0xA8
#define	REG_MAC_PROTOCOL_DATA			0xAC
#define	REG_SPLIT_HEADER			0xC0
#define	REG_NIC_RECEIVE_CONFIGURATION		0xD4

#define	REG_MGMT_RCV_CFG			0xE0
#define	REG_ROUTING_INDEX			0xE4
#define	REG_ROUTING_DATA			0xE8
#define	REG_RSVD7				0xEC
#define	REG_XG_SERDES_ADDR			0xF0
#define	REG_XG_SERDES_DATA			0xF4
#define	REG_PRB_MX_ADDR				0xF8
#define	REG_PRB_MX_DATA				0xFC

#define	INTR_MASK_PI				0x00000001
#define	INTR_MASK_HL0				0x00000002
#define	INTR_MASK_LH0				0x00000004
#define	INTR_MASK_HL1				0x00000008
#define	INTR_MASK_LH1				0x00000010
#define	INTR_MASK_SE				0x00000020
#define	INTR_MASK_LSC				0x00000040
#define	INTR_MASK_MC				0x00000080
#define	INTR_MASK_LINK_IRQS = (INTR_MASK_LSC | INTR_MASK_SE | INTR_MASK_MC)

/* Interrupt Enable Register 0x34 */
#define	INTR_ENABLED		0x8000
#define	GLOBAL_ENABLE_INTR	0x4000
#define	ENABLE_MSI_MULTI_INTR	0x2000
#define	ONE_INTR_MASK		0x3FF0000u
#define	ENABLE_INTR		0x0100
#define	DISABLE_INTR		0x0200
#define	VERIFY_INTR_ENABLED	0x0300
#define	ISP_ENABLE_INTR(qlge)	ql_put32(qlge, \
				    REG_INTERRUPT_ENABLE,\
				    (ONE_INTR_MASK | ENABLE_INTR))
#define	ISP_DISABLE_INTR(qlge)	ql_put32(qlge, \
				    REG_INTERRUPT_ENABLE, \
				    (ONE_INTR_MASK | DISABLE_INTR))
#define	ISP_ENABLE_PI_INTR(qlge)	ql_put32(qlge, \
					    REG_INTERRUPT_MASK, (BIT_16|1))
#define	ISP_DISABLE_PI_INTR(qlge)	ql_put32(qlge, \
					    REG_INTERRUPT_MASK, BIT_16)

#define	ISP_ENABLE_GLOBAL_INTRS(qlge) { \
				ql_put32(qlge, REG_INTERRUPT_ENABLE, \
				    (0x40000000u | GLOBAL_ENABLE_INTR)); \
				qlge->flags |= INTERRUPTS_ENABLED; \
				}
#define	ISP_DISABLE_GLOBAL_INTRS(qlge) { \
				ql_put32(qlge, \
				    REG_INTERRUPT_ENABLE, (0x40000000u)); \
				qlge->flags &= ~INTERRUPTS_ENABLED; \
				}
#define	REQ_Q_VALID		0x10
#define	RSP_Q_VALID		0x10

/*
 * Mailbox Registers
 */
#define	MPI_REG				0x1002
#define	NUM_MAILBOX_REGS		16
#define	FUNC_0_IN_MAILBOX_0_REG_OFFSET	0x1180
#define	FUNC_0_OUT_MAILBOX_0_REG_OFFSET	0x1190
#define	FUNC_1_IN_MAILBOX_0_REG_OFFSET	0x1280
#define	FUNC_1_OUT_MAILBOX_0_REG_OFFSET	0x1290

/*
 * Control Register Set definitions.
 */
typedef volatile struct
{
volatile uint32_t	processor_address;	/* 0x00 */
volatile uint32_t	processor_data;		/* 0x04 */
volatile uint32_t	system_data;		/* 0x08 */
volatile uint32_t	reset_failover;		/* 0x0C */

volatile uint32_t	function_specific_control;	/* 0x10 */
volatile uint32_t	host_command_status;	/* 0x14 */
volatile uint32_t	led;			/* 0x18 */
volatile uint32_t	icb_rid;		/* 0x1c */

volatile uint32_t	idb_access_address_low;	/* 0x20 */
volatile uint32_t	idb_access_address_high; /* 0x24 */
volatile uint32_t	configuration;		/* 0x28 */
volatile uint32_t	bios_base;		/* 0x2C */

volatile uint32_t	status;			/* 0x30 */
volatile uint32_t	interrupt_enable;	/* 0x34 */
volatile uint32_t	interrupt_mask;		/* 0x38 */
volatile uint32_t	interrupt_status_1;	/* 0x3c */

volatile uint32_t	interrupt_status_2;	/* 0x40 */
volatile uint32_t	interrupt_status_3;	/* 0x44 */
volatile uint32_t	interrupt_status_4;	/* 0x48 */
volatile uint32_t	rev_id;			/* 0x4c */

volatile uint32_t	force_ecc_error;	/* 0x50 */
volatile uint32_t	error_status;		/* 0x54 */
volatile uint32_t	internal_ram_debug_address;	/* 0x58 */
volatile uint32_t	internal_ram_data;	/* 0x5c */

volatile uint32_t	correctable_ecc_error;	/* 0x60 */
volatile uint32_t	semaphore;		/* 0x64 */

volatile uint32_t	gpio1;			/* 0x68 */
volatile uint32_t	gpio2;			/* 0x6c */

volatile uint32_t	gpio3;			/* 0x70 */
volatile uint32_t	reserved1;		/* 0x74 */
volatile uint32_t	xgmac_address;		/* 0x78 */
volatile uint32_t	xgmac_data;		/* 0x7c */

volatile uint32_t	nic_enhanced_tx_schedule;	/* 0x80 */
volatile uint32_t	cna_enhanced_tx_schedule;	/* 0x84 */
volatile uint32_t	flash_address;			/* 0x88 */
volatile uint32_t	flash_data;			/* 0x8c */

volatile uint32_t	stop_cq;			/* 0x90 */
volatile uint32_t	page_table_rid;			/* 0x94 */
volatile uint32_t	wq_page_table_base_address_lower; /* 0x98 */
volatile uint32_t	wq_page_table_base_address_upper; /* 0x9c */

volatile uint32_t	cq_page_table_base_address_lower; /* 0xA0 */
volatile uint32_t	cq_page_table_base_address_upper; /* 0xA4 */
volatile uint32_t	mac_protocol_address_index;	/* 0xA8 */
volatile uint32_t	mac_protocol_data;		/* 0xAc */

volatile uint32_t	cos_default_cq_reg1;		/* 0xB0 */
volatile uint32_t	cos_default_cq_reg2;		/* 0xB4 */
volatile uint32_t	ethertype_skip_reg1;		/* 0xB8 */
volatile uint32_t	ethertype_skip_reg2;		/* 0xBC */

volatile uint32_t	split_header;			/* 0xC0 */
volatile uint32_t	fcoe_pause_threshold;		/* 0xC4 */
volatile uint32_t	nic_pause_threshold;		/* 0xC8 */
volatile uint32_t	fc_ethertype;			/* 0xCC */

volatile uint32_t	fcoe_recv_configuration;	/* 0xD0 */
volatile uint32_t	nic_recv_configuration;		/* 0xD4 */
volatile uint32_t	cos_tags_in_fcoe_fifo;		/* 0xD8 */
volatile uint32_t	cos_tags_in_nic_fifo;		/* 0xDc */

volatile uint32_t	mgmt_recv_configuration;	/* 0xE0 */
volatile uint32_t	routing_index;			/* 0xE4 */
volatile uint32_t	routing_data;			/* 0xE8 */
volatile uint32_t	reserved2;			/* 0xEc */

volatile uint32_t	xg_serdes_address;		/* 0xF0 */
volatile uint32_t	xg_serdes_data;			/* 0xF4 */
volatile uint32_t	probe_mux_address;		/* 0xF8 */
volatile uint32_t	probe_mux_read_data;		/* 0xFc */

#define	INTR_PENDING	(uint32_t)(CSR_COMPLETION_INTR)

} dev_reg_t;

typedef volatile struct
{
	volatile uint32_t	doorbell_reg_address[256];	/* 0x00 */
} dev_doorbell_reg_t;

#define	SET_RMASK(val)  ((val & 0xffff) | (val << 16))
#define	CLR_RMASK(val)  (0 | (val << 16))

/*
 * DMA registers read only
 */
typedef volatile struct
{
    volatile uint32_t req_q_out;
    volatile uint32_t rsp_q_in;

} iop_dmaregs_t;

#define	DMAREGS_SIZE	(sizeof (iop_dmaregs_t))
#define	DUMMY_SIZE	(32*1024)

#ifdef QL_DEBUG
typedef struct crash_record {
uint16_t	fw_major_version;	/* 00 - 01 */
uint16_t	fw_minor_version;	/* 02 - 03 */
uint16_t	fw_patch_version;	/* 04 - 05 */
uint16_t	fw_build_version;	/* 06 - 07 */

uint8_t		build_date[16];		/* 08 - 17 */
uint8_t		build_time[16];		/* 18 - 27 */
uint8_t		build_user[16];		/* 28 - 37 */
uint8_t		card_serial_num[16];	/* 38 - 47 */

uint32_t	time_of_crash_in_secs;	/* 48 - 4B */
uint32_t	time_of_crash_in_ms;	/* 4C - 4F */

uint16_t	outb_risc_sd_num_frames; /* 50 - 51 */
uint16_t	oap_sd_length;		/* 52 - 53 */
uint16_t	iap_sd_num_frames;	/* 54 - 55 */
uint16_t	inb_risc_sd_length;	/* 56 - 57 */

uint8_t		reserved[28];		/* 58 - 7F */

uint8_t		outb_risc_reg_dump[256]; /* 80 -17F */
uint8_t		inb_risc_reg_dump[256];	/* 180 -27F */
uint8_t		inb_outb_risc_stack_dump[1]; /* 280 - ??? */
} crash_record_t;
#endif

/*
 * I/O register access macros
 * #if QL_DEBUG & 1
 */

#define	RD_REG_BYTE(qlge, addr) \
    ddi_get8(qlge->dev_handle, (uint8_t *)addr)
#define	RD_REG_DWORD(qlge, addr) \
    ddi_get32(qlge->dev_handle, (uint32_t *)addr)
#define	WRT_REG_BYTE(qlge, addr, data) \
    ddi_put8(qlge->dev_handle, (uint8_t *)addr, data)
#define	WRT_REG_WORD(qlge, addr, data) \
    ddi_put16(qlge->dev_handle, (uint16_t *)addr, data)
#define	WRT_REG_DWORD(qlge, addr, data) \
    ddi_put32(qlge->dev_handle, (uint32_t *)addr, data)

/*
 * QLGE-specific ioctls ...
 */
#define	QLA_IOC			((((('Q' << 8) + 'L') << 8) + 'A') << 8)

/*
 * Definition of ioctls commands
 */
#define	QLA_PCI_STATUS			(QLA_IOC|1) /* Read all PCI registers */

#define	QLA_WRITE_REG			(QLA_IOC|3)
#define	QLA_READ_PCI_REG		(QLA_IOC|4)
#define	QLA_WRITE_PCI_REG		(QLA_IOC|5)
#define	QLA_GET_DBGLEAVEL		(QLA_IOC|6)
#define	QLA_SET_DBGLEAVEL		(QLA_IOC|7)
#define	QLA_READ_CONTRL_REGISTERS	(QLA_IOC|8)

#define	QLA_MANUAL_READ_FLASH		(QLA_IOC|9)
#define	QLA_MANUAL_WRITE_FLASH		(QLA_IOC|10)
#define	QLA_SUPPORTED_DUMP_TYPES	(QLA_IOC|11)
#define	QLA_GET_BINARY_CORE_DUMP	(QLA_IOC|12)
#define	QLA_TRIGGER_SYS_ERROR_EVENT	(QLA_IOC|13)

#define	QLA_READ_FLASH			(QLA_IOC|15)
#define	QLA_WRITE_FLASH			(QLA_IOC|16)
#define	QLA_READ_VPD			(QLA_IOC|17)
#define	QLA_GET_PROP			(QLA_IOC|18)
#define	QLA_SHOW_REGION			(QLA_IOC|19)
#define	QLA_LIST_ADAPTER_INFO		(QLA_IOC|20)
#define	QLA_READ_FW_IMAGE		(QLA_IOC|21)
#define	QLA_WRITE_FW_IMAGE_HEADERS	(QLA_IOC|22)

#define	QLA_CONTINUE_COPY_IN		(QLA_IOC|29)
#define	QLA_CONTINUE_COPY_OUT		(QLA_IOC|30)
#define	QLA_SOFT_RESET			(QLA_IOC|31)

#define	QLA_IOCTL_CMD_FIRST		QLA_PCI_STATUS
#define	QLA_IOCTL_CMD_LAST		QLA_SOFT_RESET

/* Solaris IOCTL can copy in&out up to 1024 bytes each time */
#define	IOCTL_BUFFER_SIZE		1024
#define	IOCTL_MAX_BUF_SIZE		(IOCTL_BUFFER_SIZE*512) /* 512k */

typedef struct ioctl_header_info {
uint8_t		version;
uint8_t		reserved;
uint8_t		option[2];
uint16_t	expected_trans_times;
uint16_t	payload_length;
uint32_t	total_length;
} ioctl_header_info_t;

#define	IOCTL_HEADER_LEN	sizeof (ioctl_header_info_t)
#define	IOCTL_MAX_DATA_LEN	(IOCTL_BUFFER_SIZE - IOCTL_HEADER_LEN)

struct ql_pci_reg {
uint16_t	addr;	/* register number [0..ff] */
uint16_t	value;	/* data to write/data read */
};

struct ql_device_reg {
uint32_t	addr;	/* address to write/data read	*/
uint32_t	value;	/* data to write/data read	*/
};

struct ql_flash_io_info {
uint32_t	addr;	/* register number [0..ff] */
uint32_t	size;	/* number of data to write/data read */
};

struct qlnic_mpi_version_info {
uint32_t fw_version;
uint32_t phy_version;
};

struct qlnic_link_status_info {
uint32_t link_status_info;
uint32_t additional_info;
uint32_t network_hw_info;
uint32_t dcbx_frame_counters_info;
uint32_t change_counters_info;
};

struct qlnic_prop_info {
struct qlnic_mpi_version_info	mpi_version;	/* MPI Version */
uint32_t			fw_state;	/* MPI state */
struct qlnic_link_status_info	link_status;	/* Link Status */
};

typedef struct ql_adapter_info {
uint32_t	pci_binding;	/* /bus/dev/func number per IEEE 1277 format */
uint16_t	vendor_id;
uint16_t	device_id;
uint16_t	sub_vendor_id;
uint16_t	sub_device_id;
struct ether_addr	cur_addr;
} ql_adapter_info_t;

#define	DUMP_DESCRIPTION_HEADER_SIGNATURE	0x42535451	/* "QTSB" */
typedef struct ql_dump_header {
uint32_t	signature;	/* QTSB */
uint8_t		version;
uint8_t		length;
uint8_t		num_dumps;
uint8_t		reserved;
uint32_t	time_stamp_lo;
uint32_t	time_stamp_hi;
} ql_dump_header_t;

#define	DUMP_IMAGE_HEADER_SIGNATURE	0x504D4451	/* "QDMP" */

typedef struct ql_dump_image_header {
uint32_t	signature;	/* QDMP */
uint8_t		version;
uint8_t		header_length;
uint16_t	checksum;
uint32_t	data_type;
#define	DUMP_TYPE_CORE_DUMP	1
#define	DUMP_TYPE_REGISTER_DUMP	2
#define	DUMP_TYPE_DRIVER_DUMP 	3
uint32_t	data_length;
} ql_dump_image_header_t;

/* utility request */
#define	DUMP_REQUEST_CORE 	BIT_1
#define	DUMP_REQUEST_REGISTER	BIT_2
#define	DUMP_REQUEST_DRIVER	BIT_3

#define	DUMP_REQUEST_ALL	BIT_7

#define	DUMP_DESCRIPTION_FOOTER_SIGNATURE	0x45535451	/* "QTSE" */
typedef struct ql_dump_footer {
uint32_t	signature;	/* QTSE */
uint8_t		version;
uint8_t		length;
uint16_t	reserved;
uint32_t	time_stamp_lo;
uint32_t	time_stamp_hi;
} ql_dump_footer_t;


/*
 * Solaris qlnic exit status.
 */
#define	QN_ERR_BASE		0x30000000
#define	QN_ERR_OK		QN_ERR_BASE | 0 /* Success		*/
#define	QN_ERR_NOT_SUPPORTED	QN_ERR_BASE | 1 /* Command not supported */
#define	QN_ERR_INVALID_PARAM	QN_ERR_BASE | 2 /* Invalid parameter	*/
#define	QN_ERR_WRONG_NO_PARAM	QN_ERR_BASE | 3 /* Wrong number of parameters */
#define	QN_ERR_FILE_NOT_FOUND	QN_ERR_BASE | 4 /* File not found	*/
#define	QN_ERR_FILE_READ_ERR	QN_ERR_BASE | 5 /* File read err	*/
#define	QN_ERR_FILE_WRITE_ERR	QN_ERR_BASE | 6 /* File write err	*/
#define	QN_ERR_NO_MEMORY	QN_ERR_BASE | 7 /* No Memory		*/

#define	FLT_REGION_FDT			0x1A
#define	ISP_8100_FDT_ADDR		0x360000
#define	ISP_8100_FDT_SIZE		0x80

#define	FLT_REGION_FLT			0x1C
#define	ISP_8100_FLT_ADDR		0x361000
#define	ISP_8100_FLT_SIZE		0x1000

#define	FLT_REGION_NIC_BOOT_CODE	0x2E
#define	ISP_8100_NIC_BOOT_CODE_ADDR	0x0
#define	ISP_8100_NIC_BOOT_CODE_SIZE	0x80000

#define	FLT_REGION_MPI_FW_USE		0x42
#define	ISP_8100_MPI_FW_USE_ADDR 	0xF0000
#define	ISP_8100_MPI_FW_USE_SIZE 	0x10000

#define	FLT_REGION_MPI_RISC_FW		0x40
#define	ISP_8100_MPI_RISC_FW_ADDR 	0x100000
#define	ISP_8100_MPI_RISC_FW_SIZE 	0x10000

#define	FLT_REGION_VPD0			0x2C
#define	ISP_8100_VPD0_ADDR		0x140000
#define	ISP_8100_VPD0_SIZE		0x200

#define	FLT_REGION_NIC_PARAM0		0x46
#define	ISP_8100_NIC_PARAM0_ADDR	0x140200
#define	ISP_8100_NIC_PARAM0_SIZE	0x200

#define	FLT_REGION_VPD1			0x2D
#define	ISP_8100_VPD1_ADDR		0x140400
#define	ISP_8100_VPD1_SIZE		0x200

#define	FLT_REGION_NIC_PARAM1		0x47
#define	ISP_8100_NIC_PARAM1_ADDR	0x140600
#define	ISP_8100_NIC_PARAM1_SIZE	0x200

#define	FLT_REGION_MPI_CFG		0x41
#define	ISP_8100_MPI_CFG_ADDR		0x150000
#define	ISP_8100_MPI_CFG_SIZE		0x10000

#define	FLT_REGION_EDC_PHY_FW		0x45
#define	ISP_8100_EDC_PHY_FW_ADDR	0x170000
#define	ISP_8100_EDC_PHY_FW_SIZE	0x20000

#define	FLT_REGION_FC_BOOT_CODE		0x07
#define	ISP_8100_FC_BOOT_CODE_ADDR	0x200000
#define	ISP_8100_FC_BOOT_CODE_SIZE	0x80000

#define	FLT_REGION_FC_FW		0x01
#define	ISP_8100_FC_FW_ADDR		0x280000
#define	ISP_8100_FC_FW_SIZE		0x80000

#define	FLT_REGION_FC_VPD0		0x14
#define	ISP_8100_FC_VPD0_ADDR		0x340000
#define	ISP_8100_FC_VPD0_SIZE		0x200

#define	FLT_REGION_FC_NVRAM0		0x15
#define	ISP_8100_FC_NVRAM0_ADDR		0x340200
#define	ISP_8100_FC_NVRAM0_SIZE		0x200

#define	FLT_REGION_FC_VPD1		0x16
#define	ISP_8100_FC_VPD1_ADDR		0x340400
#define	ISP_8100_FC_VPD1_SIZE		0x200

#define	FLT_REGION_FC_NVRAM1		0x17
#define	ISP_8100_FC_NVRAM1_ADDR		0x340600
#define	ISP_8100_FC_NVRAM1_SIZE		0x200

#define	FLT_REGION_FC_BOOT_CODE		0x07
#define	ISP_8100_FC_BOOT_CODE_ADDR	0x200000
#define	ISP_8100_FC_BOOT_CODE_SIZE	0x80000

#define	FLT_REGION_FC_FW		0x01
#define	ISP_8100_FC_FW_ADDR		0x280000
#define	ISP_8100_FC_FW_SIZE		0x80000

#define	FLT_REGION_TIME_STAMP		0x60

/* flash region for testing */
#define	FLT_REGION_WIN_FW_DUMP0		0x48
#define	ISP_8100_WIN_FW_DUMP0_ADDR	0x190000
#define	ISP_8100_WIN_FW_DUMP0_SIZE	0x30000

#define	ISP_8100_FLASH_TEST_REGION_ADDR		ISP_8100_WIN_FW_DUMP0_ADDR
#define	ISP_8100_FLASH_TEST_REGION_SIZE		0x10000

/* mailbox */
#define	QL_8XXX_SFP_SIZE	256

#define	MAILBOX_TOV		30	/* Default Timeout value. */
/*
 * ISP mailbox commands from Host
 */
#define	MBC_NO_OPERATION		0	/* No Operation. */
#define	MBC_LOAD_RAM			1	/* Load RAM. */
#define	MBC_EXECUTE_FIRMWARE		2	/* Execute firmware. */
#define	MBC_MAILBOX_REGISTER_TEST	6	/* Mailbox echo test */
#define	MBC_VERIFY_CHECKSUM		7	/* Verify checksum. */
#define	MBC_ABOUT_FIRMWARE		8	/* About Firmware. */
#define	MBC_RISC_MEMORY_COPY		0xA	/* Copy RISC memory. */
#define	MBC_LOAD_RISC_RAM		0xB	/* Load RISC RAM command. */
#define	MBC_DUMP_RISC_RAM		0xC	/* Dump RISC RAM command. */
#define	MBC_INIT_RISC_RAM		0xE
#define	MBC_READ_RAM_WORD		0xF	/* Read RAM  */
#define	MBC_STOP_FIRMWARE		0x14	/* Stop firmware */
#define	MBC_GENERATE_SYS_ERROR		0x2A	/* Generate System Error */
#define	MBC_WRITE_SFP			0x30	/* Write SFP. */
#define	MBC_READ_SFP			0x31	/* Read SFP. */
#define	MBC_INITIALIZE_FIRMWARE		0x60	/* Initialize firmware */
#define	MBC_GET_INIT_CTRL_BLOCK		0x61	/* Get Initialization CBLK */
#define	MBC_GET_FIRMWARE_STATE		0x69	/* Get firmware state. */
#define	MBC_IDC_REQUEST			0x100	/* IDC Request. */
#define	IDC_REQ_ALL_DEST_FUNC_MASK	BIT_4	/* Mailbox 1 */

#define	IDC_REQ_DEST_FUNC_0_MASK	BIT_0	/* Mailbox 2 */
#define	IDC_REQ_DEST_FUNC_1_MASK	BIT_1
#define	IDC_REQ_DEST_FUNC_2_MASK	BIT_2
#define	IDC_REQ_DEST_FUNC_3_MASK	BIT_3

enum IDC_REQ_DEST_FUNC {
IDC_REQ_DEST_FUNC_0,
IDC_REQ_DEST_FUNC_1,
IDC_REQ_DEST_FUNC_2,
IDC_REQ_DEST_FUNC_3,
IDC_REQ_DEST_FUNC_ALL = 0x0F
};

#define	IDC_REQ_TIMEOUT_MASK		0x01

#define	MBC_IDC_ACK			0x101	/* IDC Acknowledge. */
#define	MBC_IDC_TIME_EXTENDED		0x102	/* IDC Time Extended. */

#define	MBC_SET_WAKE_ON_LANE_MODE	0x110
#define	MBC_SET_WAKE_ON_LANE_FILTER	0x111
#define	MBC_CLEAR_WAKE_ON_LANE_FILTER	0x112
#define	MBC_SET_WAKE_ON_LANE_MAGIC_PKT	0x113
#define	MBC_CLEAR_WAKE_ON_LANE_MAGIC_PKT	0x114

#define	MBC_PORT_RESET			0x120
#define	MBC_SET_PORT_CONFIG		0x122
#define	MBC_GET_PORT_CONFIG		0x123
#define	ENABLE_JUMBO_FRAME_SIZE_MASK	BIT_16
#define	MBC_GET_LINK_STATUS		0x124

#define	MBC_SET_LED_CONFIG		0x125
#define	MBC_GET_LED_CONFIG		0x126

/*
 * ISP mailbox command complete status codes
 */
#define	MBS_COMMAND_COMPLETE		0x4000
#define	MBS_INVALID_COMMAND		0x4001
#define	MBS_HOST_INTERFACE_ERROR	0x4002
#define	MBS_TEST_FAILED			0x4003
#define	MBS_POST_ERROR			0x4004
#define	MBS_COMMAND_ERROR		0x4005
#define	MBS_COMMAND_PARAMETER_ERROR	0x4006
#define	MBS_PORT_ID_USED		0x4007
#define	MBS_LOOP_ID_USED		0x4008
#define	MBS_ALL_IDS_IN_USE		0x4009
#define	MBS_NOT_LOGGED_IN		0x400A
#define	MBS_LOOP_DOWN			0x400B
#define	MBS_LOOP_BACK_ERROR		0x400C
#define	MBS_CHECKSUM_ERROR		0x4010

/* Async Event Status */
#define	MBA_IDC_INTERMEDIATE_COMPLETE	0x1000
#define	MBA_ASYNC_EVENT			0x8000 /* Asynchronous event. */
#define	MBA_SYSTEM_ERR			0x8002
#define	MBA_LINK_UP			0x8011
enum {
	XFI_NETWORK_INTERFACE = 1,
	XAUI_NETWORK_INTERFACE,
	XFI_BACKPLANE_INTERFACE,
	XAUI_BACKPLANE_INTERFACE,
	EXT_10GBASE_T_PHY,
	EXT_EXT_EDC_PHY
};
#define	MBA_LINK_DOWN			0x8012
#define	MBA_IDC_COMPLETE		0x8100
#define	MBA_IDC_REQUEST_NOTIFICATION	0x8101
#define	MBA_IDC_TIME_EXTENDED		0x8102
#define	MBA_DCBX_CONFIG_CHANGE		0x8110
#define	MBA_NOTIFICATION_LOST		0x8120
#define	MBA_SFT_TRANSCEIVER_INSERTION	0x8130
#define	MBA_SFT_TRANSCEIVER_REMOVAL	0x8131
#define	MBA_FIRMWARE_INIT_COMPLETE	0x8400
#define	MBA_FIRMWARE_INIT_FAILED	0x8401

typedef struct firmware_version_info {
uint8_t	reserved;
uint8_t	major_version;
uint8_t	minor_version;
uint8_t	sub_minor_version;
} firmware_version_info_t;

typedef struct phy_firmware_version_info {
uint8_t	reserved;
uint8_t	major_version;
uint8_t	minor_version;
uint8_t	sub_minor_version;
} phy_firmware_version_info_t;

#define	ENABLE_JUMBO BIT_16
#define	STD_PAUSE 0x20
#define	PP_PAUSE 0x40
#define	DCBX_ENABLE 0x10
#define	LOOP_INTERNAL_PARALLEL	0x02
#define	LOOP_INTERNAL_SERIAL	0x04
#define	LOOP_EXTERNAL_PHY	0x06

typedef struct port_cfg_info {
uint32_t link_cfg;
uint32_t max_frame_size;
} port_cfg_info_t;

enum {
	PAUSE_MODE_DISABLED,
	PAUSE_MODE_STANDARD,	/* Standard Ethernet Pause */
	PAUSE_MODE_PER_PRIORITY	/* Class Based Pause */
};

/* Mailbox command parameter structure definition. */
typedef struct mbx_cmd {
uint32_t from_mpi;	/* number of Incomming from MPI to driver */
uint32_t mb[NUM_MAILBOX_REGS];
clock_t  timeout;	/* Timeout in seconds. */
} mbx_cmd_t;

/* Returned Mailbox registers. */
typedef struct mbx_data {
uint32_t from_mpi;	/* number of Incomming from MPI to driver */
uint32_t mb[NUM_MAILBOX_REGS];
} mbx_data_t;

/* Address/Length pairs for the coredump. */

#define	MPI_CORE_REGS_ADDR	0x00030000
#define	MPI_CORE_REGS_CNT	127
#define	MPI_CORE_SH_REGS_CNT	16
#define	TEST_REGS_ADDR		0x00001000
#define	TEST_REGS_CNT		23
#define	RMII_REGS_ADDR		0x00001040
#define	RMII_REGS_CNT		64
#define	FCMAC1_REGS_ADDR	0x00001080
#define	FCMAC2_REGS_ADDR	0x000010c0
#define	FCMAC_REGS_CNT		64
#define	FC1_MBX_REGS_ADDR	0x00001100
#define	FC2_MBX_REGS_ADDR	0x00001240
#define	FC_MBX_REGS_CNT		64
#define	IDE_REGS_ADDR		0x00001140
#define	IDE_REGS_CNT		64
#define	NIC1_MBX_REGS_ADDR	0x00001180
#define	NIC2_MBX_REGS_ADDR	0x00001280
#define	NIC_MBX_REGS_CNT	64
#define	SMBUS_REGS_ADDR		0x00001200
#define	SMBUS_REGS_CNT		64
#define	I2C_REGS_ADDR		0x00001fc0
#define	I2C_REGS_CNT		64
#define	MEMC_REGS_ADDR		0x00003000
#define	MEMC_REGS_CNT		256
#define	PBUS_REGS_ADDR		0x00007c00
#define	PBUS_REGS_CNT		256
#define	MDE_REGS_ADDR		0x00010000
#define	MDE_REGS_CNT		6
#define	CODE_RAM_ADDR		0x00020000
#define	CODE_RAM_CNT		0x2000
#define	MEMC_RAM_ADDR		0x00100000
#define	MEMC_RAM_CNT		0x2000

/* 64 probes, 8 bytes per probe + 4 bytes to list the probe ID */
#define	PROBE_DATA_LENGTH_WORDS		((64 * 2) + 1)
#define	NUMBER_OF_PROBES		34
#define	NUMBER_ROUTING_REG_ENTRIES	48
#define	WORDS_PER_ROUTING_REG_ENTRY	4
#define	MAC_PROTOCOL_REGISTER_WORDS	((512 * 3) + (32 * 2) + (4096 * 1) + \
					    (4096 * 1) + (4 * 2) + (8 * 2) + \
					    (16 * 1) + (4 * 1) + (4 * 4) + \
					    (4 * 1))
/* Save both the address and data register */
#define	WORDS_PER_MAC_PROT_ENTRY	2

#define	MPI_COREDUMP_COOKIE 0x5555aaaa
typedef struct mpi_coredump_global_header {
uint32_t	cookie;
char		id_string[16];
uint32_t	time_lo;
uint32_t	time_hi;
uint32_t	total_image_size;
uint32_t	global_header_size;
char		driver_info[0xE0];
}mpi_coredump_global_header_t;

typedef struct mpi_coredump_segment_header {
uint32_t	cookie;
uint32_t	seg_number;
uint32_t	seg_size;
uint32_t	extra;
char		description[16];
}mpi_coredump_segment_header_t;

typedef struct	ql_mpi_coredump {
mpi_coredump_global_header_t mpi_global_header;

mpi_coredump_segment_header_t core_regs_seg_hdr;
uint32_t	mpi_core_regs[MPI_CORE_REGS_CNT];
uint32_t	mpi_core_sh_regs[MPI_CORE_SH_REGS_CNT];

mpi_coredump_segment_header_t test_logic_regs_seg_hdr;
uint32_t	test_logic_regs[TEST_REGS_CNT];

mpi_coredump_segment_header_t rmii_regs_seg_hdr;
uint32_t	rmii_regs[RMII_REGS_CNT];

mpi_coredump_segment_header_t fcmac1_regs_seg_hdr;
uint32_t	fcmac1_regs[FCMAC_REGS_CNT];

mpi_coredump_segment_header_t fcmac2_regs_seg_hdr;
uint32_t	fcmac2_regs[FCMAC_REGS_CNT];

mpi_coredump_segment_header_t fc1_mbx_regs_seg_hdr;
uint32_t	fc1_mbx_regs[FC_MBX_REGS_CNT];

mpi_coredump_segment_header_t ide_regs_seg_hdr;
uint32_t	ide_regs[IDE_REGS_CNT];

mpi_coredump_segment_header_t nic1_mbx_regs_seg_hdr;
uint32_t	nic1_mbx_regs[NIC_MBX_REGS_CNT];

mpi_coredump_segment_header_t smbus_regs_seg_hdr;
uint32_t	smbus_regs[SMBUS_REGS_CNT];

mpi_coredump_segment_header_t fc2_mbx_regs_seg_hdr;
uint32_t	fc2_mbx_regs[FC_MBX_REGS_CNT];

mpi_coredump_segment_header_t nic2_mbx_regs_seg_hdr;
uint32_t	nic2_mbx_regs[NIC_MBX_REGS_CNT];

mpi_coredump_segment_header_t i2c_regs_seg_hdr;
uint32_t	i2c_regs[I2C_REGS_CNT];

mpi_coredump_segment_header_t memc_regs_seg_hdr;
uint32_t	memc_regs[MEMC_REGS_CNT];

mpi_coredump_segment_header_t pbus_regs_seg_hdr;
uint32_t	pbus_regs[PBUS_REGS_CNT];

mpi_coredump_segment_header_t mde_regs_seg_hdr;
uint32_t	mde_regs[MDE_REGS_CNT];

mpi_coredump_segment_header_t xaui_an_hdr;
uint32_t	serdes_xaui_an[14];

mpi_coredump_segment_header_t xaui_hss_pcs_hdr;
uint32_t	serdes_xaui_hss_pcs[33];

mpi_coredump_segment_header_t xfi_an_hdr;
uint32_t	serdes_xfi_an[14];

mpi_coredump_segment_header_t xfi_train_hdr;
uint32_t	serdes_xfi_train[12];

mpi_coredump_segment_header_t xfi_hss_pcs_hdr;
uint32_t	serdes_xfi_hss_pcs[15];

mpi_coredump_segment_header_t xfi_hss_tx_hdr;
uint32_t	serdes_xfi_hss_tx[32];

mpi_coredump_segment_header_t xfi_hss_rx_hdr;
uint32_t	serdes_xfi_hss_rx[32];

mpi_coredump_segment_header_t xfi_hss_pll_hdr;
uint32_t	serdes_xfi_hss_pll[32];

mpi_coredump_segment_header_t nic_regs_seg_hdr;
uint32_t	nic_regs[64];

/* one interrupt state for each CQ */
mpi_coredump_segment_header_t intr_states_seg_hdr;
uint32_t	intr_states[MAX_RX_RINGS];

mpi_coredump_segment_header_t xgmac_seg_hdr;
#define	XGMAC_REGISTER_END 0x740
uint32_t xgmac[XGMAC_REGISTER_END];

mpi_coredump_segment_header_t probe_dump_seg_hdr;
uint32_t probe_dump[PROBE_DATA_LENGTH_WORDS * NUMBER_OF_PROBES];

mpi_coredump_segment_header_t routing_reg_seg_hdr;
uint32_t routing_regs[NUMBER_ROUTING_REG_ENTRIES * WORDS_PER_ROUTING_REG_ENTRY];

mpi_coredump_segment_header_t mac_prot_reg_seg_hdr;
uint32_t mac_prot_regs[MAC_PROTOCOL_REGISTER_WORDS * WORDS_PER_MAC_PROT_ENTRY];


mpi_coredump_segment_header_t ets_seg_hdr;
uint32_t	ets[8+2];

mpi_coredump_segment_header_t code_ram_seg_hdr;
uint32_t	code_ram[CODE_RAM_CNT];

mpi_coredump_segment_header_t memc_ram_seg_hdr;
uint32_t	memc_ram[MEMC_RAM_CNT];

} ql_mpi_coredump_t;

#define	WCS_MPI_CODE_RAM_LENGTH		(0x2000*4)
#define	MEMC_MPI_RAM_LENGTH		(0x2000*4)

#define	XG_SERDES_ADDR_RDY	BIT_31
#define	XG_SERDES_ADDR_R	BIT_30

#define	CORE_SEG_NUM		1
#define	TEST_LOGIC_SEG_NUM	2
#define	RMII_SEG_NUM		3
#define	FCMAC1_SEG_NUM		4
#define	FCMAC2_SEG_NUM		5
#define	FC1_MBOX_SEG_NUM	6
#define	IDE_SEG_NUM		7
#define	NIC1_MBOX_SEG_NUM	8
#define	SMBUS_SEG_NUM		9
#define	FC2_MBOX_SEG_NUM	10
#define	NIC2_MBOX_SEG_NUM	11
#define	I2C_SEG_NUM		12
#define	MEMC_SEG_NUM		13
#define	PBUS_SEG_NUM		14
#define	MDE_SEG_NUM		15
#define	NIC1_CONTROL_SEG_NUM	16
#define	NIC2_CONTROL_SEG_NUM	17
#define	NIC1_XGMAC_SEG_NUM	18
#define	NIC2_XGMAC_SEG_NUM	19
#define	WCS_RAM_SEG_NUM		20
#define	MEMC_RAM_SEG_NUM	21
#define	XAUI_AN_SEG_NUM		22
#define	XAUI_HSS_PCS_SEG_NUM	23
#define	XFI_AN_SEG_NUM		24
#define	XFI_TRAIN_SEG_NUM	25
#define	XFI_HSS_PCS_SEG_NUM	26
#define	XFI_HSS_TX_SEG_NUM	27
#define	XFI_HSS_RX_SEG_NUM	28
#define	XFI_HSS_PLL_SEG_NUM	29
#define	INTR_STATES_SEG_NUM	31
#define	ETS_SEG_NUM		34
#define	PROBE_DUMP_SEG_NUM	35
#define	ROUTING_INDEX_SEG_NUM	36
#define	MAC_PROTOCOL_SEG_NUM	37

/* Force byte packing for the following structures */
#pragma pack(1)

/*
 * Work Queue (Request Queue) Initialization Control Block (WQICB)
 */

struct wqicb_t {
	uint16_t len;
#define	Q_LEN_V		(1 << 4)
#define	Q_LEN_CPP_CONT	0x0000
#define	Q_LEN_CPP_16	0x0001
#define	Q_LEN_CPP_32	0x0002
#define	Q_LEN_CPP_64	0x0003
#define	Q_LEN_CPP_512	0x0006
	uint16_t flags;
#define	Q_PRI_SHIFT	1
#define	Q_FLAGS_LC	0x1000
#define	Q_FLAGS_LB	0x2000
#define	Q_FLAGS_LI	0x4000
#define	Q_FLAGS_LO	0x8000
	uint16_t cq_id_rss;
#define	Q_CQ_ID_RSS_RV 0x8000
	uint16_t rid;
	uint32_t wq_addr_lo;
	uint32_t wq_addr_hi;
	uint32_t cnsmr_idx_addr_lo;
	uint32_t cnsmr_idx_addr_hi;
};

/*
 * Completion Queue (Response Queue) Initialization Control Block (CQICB)
 */

struct cqicb_t {
	uint8_t	msix_vect;
	uint8_t	reserved1;
	uint8_t	reserved2;
	uint8_t	flags;
#define	FLAGS_LV	0x08
#define	FLAGS_LS	0x10
#define	FLAGS_LL	0x20
#define	FLAGS_LI	0x40
#define	FLAGS_LC	0x80
	uint16_t	len;
#define	LEN_V		(1 << 4)
#define	LEN_CPP_CONT	0x0000
#define	LEN_CPP_32	0x0001
#define	LEN_CPP_64	0x0002
#define	LEN_CPP_128	0x0003
	uint16_t	rid;
	uint32_t	cq_base_addr_lo; /* completion queue base address */
	uint32_t	cq_base_addr_hi;
	uint32_t	prod_idx_addr_lo; /* completion queue host copy */
					/* producer index host shadow  */
	uint32_t	prod_idx_addr_hi;
	uint16_t	pkt_delay;
	uint16_t	irq_delay;
	uint32_t	lbq_addr_lo;
	uint32_t	lbq_addr_hi;
	uint16_t	lbq_buf_size;
	uint16_t	lbq_len;	/* entry count */
	uint32_t	sbq_addr_lo;
	uint32_t	sbq_addr_hi;
	uint16_t	sbq_buf_size;
	uint16_t	sbq_len;	/* entry count */
};

struct ricb {
	uint8_t		base_cq;
#define	RSS_L4K	0x80
	uint8_t		flags;
#define	RSS_L6K	0x01
#define	RSS_LI	0x02
#define	RSS_LB	0x04
#define	RSS_LM	0x08
#define	RSS_RI4	0x10
#define	RSS_RT4	0x20
#define	RSS_RI6	0x40
#define	RSS_RT6	0x80
	uint16_t	mask;
#define	RSS_HASH_CQ_ID_MAX	1024
	uint8_t		hash_cq_id[RSS_HASH_CQ_ID_MAX];
	uint32_t	ipv6_hash_key[10];
	uint32_t	ipv4_hash_key[4];
};

/*
 * Host Command IOCB Formats
 */

#define	OPCODE_OB_MAC_IOCB		0x01
#define	OPCODE_OB_MAC_OFFLOAD_IOCB 	0x02

#define	OPCODE_IB_MAC_IOCB		0x20
#define	OPCODE_IB_SYS_EVENT_IOCB	0x3f

/*
 * The following constants define control bits for buffer
 * length fields for all IOCB's.
 */
#define	OAL_LAST_ENTRY	0x80000000	/* Last valid buffer in list. */
#define	OAL_CONT_ENTRY	0x40000000	/* points to an OAL. (continuation) */

struct oal_entry {
uint32_t buf_addr_low;
uint32_t buf_addr_high;
uint32_t buf_len;
};

/* 32 words, 128 bytes */
#define	TX_DESC_PER_IOCB	8	/* Number of descs in one TX IOCB */

struct ob_mac_iocb_req {
	uint8_t opcode;
	uint8_t flag0;
#define	OB_MAC_IOCB_REQ_IPv6	0x80
#define	OB_MAC_IOCB_REQ_IPv4	0x40
#define	OB_MAC_IOCB_REQ_D	0x08	/* disable generation of comp. msg */
#define	OB_MAC_IOCB_REQ_I	0x02	/* disable generation of intr at comp */
	uint8_t flag1;
#define	OB_MAC_IOCB_REQ_TC	0x80	/* enable TCP checksum offload */
#define	OB_MAC_IOCB_REQ_UC	0x40	/* enable UDP checksum offload */
#define	OB_MAC_IOCB_REQ_LSO	0x20	/* enable LSO offload */
	uint8_t flag2;
#define	OB_MAC_IOCB_REQ_VLAN_OFFSET_MASK	0xF8 /* VLAN TCI insert */
#define	OB_MAC_IOCB_REQ_V	0x04	/* insert VLAN TCI */
#define	OB_MAC_IOCB_REQ_DFP	0x02	/* Drop for Failover port */
#define	OB_MAC_IOCB_REQ_IC	0x01	/* enable IP checksum offload */
	uint32_t unused;
	uint32_t reserved_cq_tag;
	uint32_t frame_len;		/* max 9000,for none LSO, 16M for LSO */
	uint32_t tid;
	uint32_t txq_idx;
	uint16_t protocol_hdr_len;
	uint16_t hdr_off;		/* tcp/udp hdr offset */
	uint16_t vlan_tci;
	uint16_t mss;

	struct oal_entry oal_entry[TX_DESC_PER_IOCB]; /* max FFFFF 1M bytes */

};
/* 16 words, 64 bytes */
struct ob_mac_iocb_rsp {
	uint8_t opcode;
	uint8_t flags1;
#define	OB_MAC_IOCB_RSP_OI	0x01	/* */
#define	OB_MAC_IOCB_RSP_I	0x02	/* */
#define	OB_MAC_IOCB_RSP_E	0x08	/* */
#define	OB_MAC_IOCB_RSP_S	0x10	/* too Short */
#define	OB_MAC_IOCB_RSP_L	0x20	/* too Large */
#define	OB_MAC_IOCB_RSP_P	0x40	/* Padded */

	uint8_t flags2;
	uint8_t flags3;

#define	OB_MAC_IOCB_RSP_B	0x80

	uint32_t tid;
	uint32_t txq_idx;

	uint32_t reserved[13];
};

#define	IB_MAC_IOCB_RSP_VLAN_MASK	0x0ffff

struct ib_mac_iocb_rsp {
	uint8_t	opcode;		/* 0x20 */
	uint8_t	flags1;
#define	IB_MAC_IOCB_RSP_OI	0x01	/* Overide intr delay */
#define	IB_MAC_IOCB_RSP_I	0x02	/* Disble Intr Generation */
#define	IB_MAC_IOCB_RSP_TE	0x04	/* Checksum error */
#define	IB_MAC_IOCB_RSP_NU	0x08	/* No checksum rcvd */
#define	IB_MAC_IOCB_RSP_IE	0x10	/* IPv4 checksum error */
#define	IB_MAC_IOCB_RSP_M_MASK	0x60	/* Multicast info */
#define	IB_MAC_IOCB_RSP_M_NONE	0x00	/* Not mcast frame */
#define	IB_MAC_IOCB_RSP_M_HASH	0x20	/* HASH mcast frame */
#define	IB_MAC_IOCB_RSP_M_REG 	0x40	/* Registered mcast frame */
#define	IB_MAC_IOCB_RSP_M_PROM 	0x60	/* Promiscuous mcast frame */
#define	IB_MAC_IOCB_RSP_B	0x80	/* Broadcast frame */
	uint8_t	flags2;
#define	IB_MAC_IOCB_RSP_P	0x01	/* Promiscuous frame */
#define	IB_MAC_IOCB_RSP_V	0x02	/* Vlan tag present */
#define	IB_MAC_IOCB_RSP_ERR_MASK	0x1c	/*  */
#define	IB_MAC_IOCB_RSP_ERR_CODE_ERR	0x04
#define	IB_MAC_IOCB_RSP_ERR_OVERSIZE	0x08
#define	IB_MAC_IOCB_RSP_ERR_UNDERSIZE	0x10
#define	IB_MAC_IOCB_RSP_ERR_PREAMBLE	0x14
#define	IB_MAC_IOCB_RSP_ERR_FRAME_LEN	0x18
#define	IB_MAC_IOCB_RSP_ERR_CRC		0x1c
#define	IB_MAC_IOCB_RSP_U	0x20	/* UDP packet */
#define	IB_MAC_IOCB_RSP_T	0x40	/* TCP packet */
#define	IB_MAC_IOCB_RSP_FO	0x80	/* Failover port */
	uint8_t	flags3;
#define	IB_MAC_IOCB_RSP_RSS_MASK	0x07	/* RSS mask */
#define	IB_MAC_IOCB_RSP_M_NONE	0x00	/* No RSS match */
#define	IB_MAC_IOCB_RSP_M_IPV4	0x04	/* IPv4 RSS match */
#define	IB_MAC_IOCB_RSP_M_IPV6	0x02	/* IPv6 RSS match */
#define	IB_MAC_IOCB_RSP_M_TCP_V4 	0x05	/* TCP with IPv4 */
#define	IB_MAC_IOCB_RSP_M_TCP_V6 	0x03	/* TCP with IPv6 */
#define	IB_MAC_IOCB_RSP_V4	0x08	/* IPV4 */
#define	IB_MAC_IOCB_RSP_V6	0x10	/* IPV6 */
#define	IB_MAC_IOCB_RSP_IH	0x20	/* Split after IP header */
#define	IB_MAC_IOCB_RSP_DS	0x40	/* data is in small buffer */
#define	IB_MAC_IOCB_RSP_DL	0x80	/* data is in large buffer */
	uint32_t	data_len;
	uint64_t	data_addr;
	uint32_t	rss;
	uint16_t	vlan_id;	/* 12 bits */
#define	IB_MAC_IOCB_RSP_VLAN_ID_MASK	0xFFF
#define	IB_MAC_IOCB_RSP_C		0x1000	/* VLAN CFI bit */
#define	IB_MAC_IOCB_RSP_COS_SHIFT	12	/* class of service value */

	uint16_t reserved1;
	uint32_t reserved2[6];
	uint8_t reserved3[3];
	uint8_t flags4;
#define	IB_MAC_IOCB_RSP_HV	0x20
#define	IB_MAC_IOCB_RSP_HS	0x40
#define	IB_MAC_IOCB_RSP_HL	0x80
	uint32_t hdr_len;
	uint64_t hdr_addr;
};

/* 16 words, 64 bytes */
struct ib_sys_event_iocb_rsp {
	uint8_t opcode;
	uint8_t flag0;
	uint8_t event_type;
	uint8_t q_id;
	uint32_t reserved[15];
};
#define	SYS_EVENT_PORT_LINK_UP		0x0
#define	SYS_EVENT_PORT_LINK_DOWN	0x1
#define	SYS_EVENT_MULTIPLE_CAM_HITS	0x6
#define	SYS_EVENT_SOFT_ECC_ERR		0x7
#define	SYS_EVENT_MGMT_FATAL_ERR	0x8	/* MPI_PROCESSOR */
#define	SYS_EVENT_MAC_INTERRUPT		0x9
#define	SYS_EVENT_PCI_ERR_READING_SML_LRG_BUF	0x40

/*
 *  Status Register (#define STATUS) bit definitions.
 */
#define	STATUS_FE	(1 << 0)
#define	STATUS_PI	(1 << 1)
#define	STATUS_PL0	(1 << 2),
#define	STATUS_PL1	(1 << 3)
#define	STATUS_PI0	(1 << 4)
#define	STATUS_PI1	(1 << 5)
#define	STATUS_FUNC_ID_MASK	0x000000c0
#define	STATUS_FUNC_ID_SHIFT	6
#define	STATUS_F0E	(1 << 8)
#define	STATUS_F1E	(1 << 9)
#define	STATUS_F2E	(1 << 10)
#define	STATUS_F3E	(1 << 11)
#define	STATUS_NFE	(1 << 12)

/*
 * Generic Response Queue IOCB Format which abstracts the difference between
 * IB_MAC, OB_MAC IOCBs
 */
struct net_rsp_iocb {
	uint8_t	opcode;
	uint8_t	flag0;
	uint8_t	flag1;
	uint8_t	flag2;
	uint32_t	reserved[15];
};

/* Restore original packing rules */
#pragma pack()

#define	RESPONSE_ENTRY_SIZE	(sizeof (struct net_rsp_iocb))
#define	REQUEST_ENTRY_SIZE	(sizeof (struct ob_mac_iocb_req))

/* flash */
/* Little endian machine correction defines. */
#ifdef _LITTLE_ENDIAN
#define	LITTLE_ENDIAN_16(x)
#define	LITTLE_ENDIAN_24(x)
#define	LITTLE_ENDIAN_32(x)
#define	LITTLE_ENDIAN_64(x)
#define	LITTLE_ENDIAN(bp, bytes)
#define	BIG_ENDIAN_16(x)	ql_change_endian((uint8_t *)x, 2)
#define	BIG_ENDIAN_24(x)	ql_change_endian((uint8_t *)x, 3)
#define	BIG_ENDIAN_32(x)	ql_change_endian((uint8_t *)x, 4)
#define	BIG_ENDIAN_64(x)	ql_change_endian((uint8_t *)x, 8)
#define	BIG_ENDIAN(bp, bytes)	ql_change_endian((uint8_t *)bp, bytes)
#endif /* _LITTLE_ENDIAN */

/* Big endian machine correction defines. */
#ifdef	_BIG_ENDIAN
#define	LITTLE_ENDIAN_16(x)		ql_change_endian((uint8_t *)x, 2)
#define	LITTLE_ENDIAN_24(x)		ql_change_endian((uint8_t *)x, 3)
#define	LITTLE_ENDIAN_32(x)		ql_change_endian((uint8_t *)x, 4)
#define	LITTLE_ENDIAN_64(x)		ql_change_endian((uint8_t *)x, 8)
#define	LITTLE_ENDIAN(bp, bytes)	ql_change_endian((uint8_t *)bp, bytes)
#define	BIG_ENDIAN_16(x)
#define	BIG_ENDIAN_24(x)
#define	BIG_ENDIAN_32(x)
#define	BIG_ENDIAN_64(x)
#define	BIG_ENDIAN(bp, bytes)
#endif	/* _BIG_ENDIAN */

void ql_change_endian(uint8_t *, size_t);

/* Flash Address Register 0x88 */
#define	FLASH_RDY_FLAG		BIT_31
#define	FLASH_R_FLAG		BIT_30
#define	FLASH_ERR_FLAG		BIT_29
#define	FLASH_CONF_ADDR		0x7D0000u
#define	FLASH_ADDR_MASK		0x7F0000

#define	FLASH_WRSR_CMD		0x01
#define	FLASH_PP_CMD		0x02
#define	FLASH_READ_CMD		0x03
#define	FLASH_WRDI_CMD		0x04
#define	FLASH_RDSR_CMD		0x05
#define	FLASH_WREN_CMD		0x06
#define	FLASH_RDID_CMD		0x9F
#define	FLASH_RES_CMD		0xAB

/*
 * Flash definitions.
 */
typedef struct ql_flash_info {
	uint32_t	type;		/* flash type */
	uint32_t	flash_size;	/* length in bytes of flash */
	uint32_t	sec_mask;	/* sector number mask */
	uint8_t		flash_manuf;	/* flash chip manufacturer id */
	uint8_t		flash_id;	/* flash chip id */
	uint8_t		flash_cap;	/* flash chip capacity */
} ql_flash_info_t;

/*
 * Flash Description Table
 */
#define	FLASH_DESC_VERSION	1
#define	FLASH_DESC_VAILD	0x44494C51	/* "QLID" */
typedef struct flash_desc {
	uint32_t	flash_valid;
	uint16_t	flash_version;
	uint16_t	flash_len; /* flash description table length */
	uint16_t	flash_checksum;
	uint16_t	flash_unused;
	uint8_t		flash_model[16];
	uint16_t	flash_manuf;
	uint16_t	flash_id;
	uint8_t		flash_flag;
	uint8_t		erase_cmd;
	uint8_t		alt_erase_cmd;
	uint8_t		write_enable_cmd;
	uint8_t		write_enable_bits;
	uint8_t		write_statusreg_cmd;
	uint8_t		unprotect_sector_cmd;
	uint8_t		read_manuf_cmd;
	uint32_t	block_size;
	uint32_t	alt_block_size;
	uint32_t	flash_size;
	uint32_t	write_enable_data;
	uint8_t		readid_address_len;
	uint8_t		write_disable_bits;
	uint8_t		read_device_id_len;
	uint8_t		chip_erase_cmd;
	uint16_t	read_timeout;
	uint8_t		protect_sector_cmd;
	uint8_t		exp_reserved[65];
} flash_desc_t;

/* flash manufacturer id's */
#define	AMD_FLASH		0x01	/* AMD / Spansion */
#define	ST_FLASH		0x20	/* ST Electronics */
#define	SST_FLASH		0xbf	/* SST Electronics */
#define	MXIC_FLASH		0xc2	/* Macronix (MXIC) */
#define	ATMEL_FLASH		0x1f	/* Atmel (AT26DF081A) */
#define	WINBOND_FLASH		0xef	/* Winbond (W25X16,W25X32) */
#define	INTEL_FLASH		0x89	/* Intel (QB25F016S33B8) */

/* flash id defines */
#define	AMD_FLASHID_128K	0x6e	/* 128k AMD flash chip */
#define	AMD_FLASHID_512K	0x4f	/* 512k AMD flash chip */
#define	AMD_FLASHID_512Kt	0xb9	/* 512k AMD flash chip - top boot blk */
#define	AMD_FLASHID_512Kb	0xba	/* 512k AMD flash chip - btm boot blk */
#define	AMD_FLASHID_1024K	0x38	/* 1 MB AMD flash chip */
#define	ST_FLASHID_128K		0x23	/* 128k ST flash chip */
#define	ST_FLASHID_512K		0xe3	/* 512k ST flash chip */
#define	ST_FLASHID_M25PXX	0x20	/* M25Pxx ST flash chip */
#define	SST_FLASHID_128K	0xd5	/* 128k SST flash chip */
#define	SST_FLASHID_1024K	0xd8	/* 1 MB SST flash chip */
#define	SST_FLASHID_1024K_A	0x80	/* 1 MB SST 25LF080A flash chip */
#define	SST_FLASHID_1024K_B	0x8e	/* 1 MB SST 25VF080B flash chip */
#define	SST_FLASHID_2048K	0x25	/* 2 MB SST 25VF016B flash chip */
#define	MXIC_FLASHID_512K	0x4f	/* 512k MXIC flash chip */
#define	MXIC_FLASHID_1024K	0x38	/* 1 MB MXIC flash chip */
#define	MXIC_FLASHID_25LXX	0x20	/* 25Lxx MXIC flash chip */
#define	ATMEL_FLASHID_1024K	0x45	/* 1 MB ATMEL flash chip */
#define	SPAN_FLASHID_2048K	0x02	/* 2 MB Spansion flash chip */
#define	WINBOND_FLASHID		0x30	/* Winbond W25Xxx flash chip */
#define	INTEL_FLASHID		0x89	/* Intel QB25F016S33B8 flash chip */

/* flash type defines */
#define	FLASH128	BIT_0
#define	FLASH512	BIT_1
#define	FLASH512S	BIT_2
#define	FLASH1024	BIT_3
#define	FLASH2048	BIT_4
#define	FLASH4096	BIT_5
#define	FLASH8192	BIT_6
#define	FLASH_PAGE	BIT_31
#define	FLASH_LEGACY	(FLASH128 | FLASH512S)

#define	FLASH_FIRMWARE_IMAGE_ADDR	0x100000 /* 1M */
typedef struct {
	uint8_t		signature[2];
	uint8_t		reserved[0x16];
	uint8_t		dataoffset[2];
	uint8_t		pad[6];
} pci_header_t;

typedef struct {
	uint8_t		 signature[4];
	uint8_t		 vid[2];
	uint8_t		 did[2];
	uint8_t		 reserved0[2];
	uint8_t		 pcidatalen[2];
	uint8_t		 pcidatarev;
	uint8_t		 classcode[3];
	uint8_t		 imagelength[2];	/* In sectors */
	uint8_t		 revisionlevel[2];
	uint8_t		 codetype;
	uint8_t		 indicator;
	uint8_t		 reserved1[2];
	uint8_t		 pad[8];
} pci_data_t;

#define	PCI_HEADER0		0x55
#define	PCI_HEADER1		0xAA
#define	PCI_DATASIG		"PCIR"
#define	PCI_SECTOR_SIZE		0x200
#define	PCI_CODE_X86PC		0
#define	PCI_CODE_FCODE		1
#define	PCI_CODE_HPPA		2
#define	PCI_CODE_EFI		3
#define	PCI_CODE_FW		0xfe
#define	PCI_IND_LAST_IMAGE	0x80
#define	SBUS_CODE_FCODE		0xf1

#define	FBUFSIZE	100
/* Flash Layout Table Data Structure(FLTDS) */
#define	FLASH_FLTDS_SIGNATURE	0x544C4651	/* "QFLT" */

typedef struct ql_fltds {
	uint32_t	signature;
	uint16_t	flt_addr_lo;
	uint16_t	flt_addr_hi;
	uint8_t		version;
	uint8_t		reserved;
	uint16_t	checksum;
} ql_fltds_t;
/* Image Layout Table Data Structure(ILTDS) */
#define	FLASH_ILTDS_SIGNATURE	0x4D494651	/* "QFIM" */
typedef struct ql_iltds_header {
	uint32_t	signature;
	uint16_t	table_version;	/* version of this structure */
	uint16_t	length;		/* length of the table */
	uint16_t	checksum;
	uint16_t	number_entries;	/* Number of type/len/size entries */
	uint16_t	reserved;
	uint16_t	version;	/* version of the image */
} ql_iltds_header_t;

#define	IMAGE_TABLE_HEADER_LEN	sizeof (ql_iltds_header_t)

#define	ILTDS_REGION_VERSION_LEN_NA	0	/* version not applicable */
typedef struct ql_iltds_img_entry {
	uint16_t	region_type;
	uint8_t		region_version_len;
	uint8_t		region_version[3];
	uint16_t	offset_lo;
	uint16_t	offset_hi;
	uint16_t	size_lo;
	uint16_t	size_hi;
	uint8_t		swap_mode;
#define	ILTDS_IMG_SWAP_NONE		0	/* no swap needed */
#define	ILTDS_IMG_SWAP_WORD		1

	uint8_t		card_type;
#define	ILTDS_IMG_CARD_TYPE_ALL		0	/* apply to all types */
#define	ILTDS_IMG_CARD_TYPE_SR		1	/* apply to SR/fc cards */
#define	ILTDS_IMG_CARD_TYPE_COPPER	2	/* apply to Copper cards */
#define	ILTDS_IMG_CARD_TYPE_MEZZ	4	/* apply to Mezz   cards */
} ql_iltds_img_entry_t;

#define	IMAGE_TABLE_ENTRY_LEN	sizeof (ql_iltds_img_entry_t)

typedef struct ql_iltds_time_stamp {
	uint16_t	region_type;
	uint8_t		region_version_len;
	uint8_t		region_version[3];
	uint8_t		year;
	uint8_t		month;
	uint8_t		day;
	uint8_t		hour;
	uint8_t		min;
	uint8_t		sec;
	uint32_t	reserved;
} ql_iltds_time_stamp_t;

#define	IMAGE_TABLE_TIME_STAMP_LEN	sizeof (ql_iltds_time_stamp_t)

#define	IMAGE_TABLE_IMAGE_DEFAULT_ENTRIES	5

typedef struct ql_iltds_description_header {
	ql_iltds_header_t 	iltds_table_header;
	ql_iltds_img_entry_t	img_entry[IMAGE_TABLE_IMAGE_DEFAULT_ENTRIES];
	ql_iltds_time_stamp_t	time_stamp;
}ql_iltds_description_header_t;

#define	ILTDS_DESCRIPTION_HEADERS_LEN	sizeof (ql_iltds_description_header_t)

/* flash layout table definition */
/* header */
typedef struct ql_flt_header {
	uint16_t	version;
	uint16_t	length;	/* length of the flt table,no table header */
	uint16_t	checksum;
	uint16_t	reserved;
} ql_flt_header_t;

/* table entry */
typedef struct ql_flt_entry {
	uint8_t		region;
	uint8_t		reserved0;
	uint8_t		attr;
#define	FLT_ATTR_READ_ONLY		BIT_0
#define	FLT_ATTR_NEED_FW_RESTART	BIT_1
#define	FLT_ATTR_NEED_DATA_REALOAD	BIT_2
	uint8_t		reserved1;
	uint32_t	size;
	uint32_t	begin_addr;
	uint32_t	end_addr;
} ql_flt_entry_t;

/* flt table */
typedef struct ql_flt {
	ql_flt_header_t	header;
	uint16_t	num_entries;
	ql_flt_entry_t	*ql_flt_entry_ptr;
} ql_flt_t;

/* Nic Configuration Table */
#define	FLASH_NIC_CONFIG_SIGNATURE	0x30303038	/* "8000" */

enum {
	DATA_TYPE_NONE,
	DATA_TYPE_FACTORY_MAC_ADDR,
	DATA_TYPE_CLP_MAC_ADDR,
	DATA_TYPE_CLP_VLAN_MAC_ADDR,
	DATA_TYPE_RESERVED,
	DATA_TYPE_LAST_ENTRY
};

typedef struct ql_nic_config {
	uint32_t	signature;
	uint16_t	version;
	uint16_t	size;
	uint16_t	checksum;
	uint16_t	reserved0;
	uint16_t	total_data_size;
	uint16_t	num_of_entries;
	uint8_t		factory_data_type;
	uint8_t		factory_data_type_size;
	uint8_t		factory_MAC[6];
	uint8_t		clp_data_type;
	uint8_t		clp_data_type_size;
	uint8_t		clp_MAC[6];
	uint8_t		clp_vlan_data_type;
	uint8_t		clp_vlan_data_type_size;
	uint16_t	vlan_id;
	uint8_t		last_data_type;
	uint8_t		last_data_type_size;
	uint16_t	last_entry;
	uint8_t		reserved1[464];
	uint16_t	subsys_vendor_id;
	uint16_t	subsys_device_id;
	uint8_t		reserved2[4];
} ql_nic_config_t;

#ifdef __cplusplus
}
#endif

#endif /* _QLGE_HW_H */
