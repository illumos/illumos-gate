/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_HW_H
#define	_EMLXS_HW_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_VPORTS			256	/* Max virtual ports per HBA */
						/* (includes physical port) */
#define	MAX_VPORTS_LIMITED		101

#define	FC_MAX_TRANSFER			0x40000	/* Max transfer size per */
						/* operation */

#define	MAX_RINGS_AVAILABLE		4	/* # rings available */
#define	MAX_RINGS			4	/* Max # rings used */

#define	PCB_SIZE			128

#define	SLIM_IOCB_CMD_R0_ENTRIES	128	/* SLI FCP cmd ring entries  */
#define	SLIM_IOCB_RSP_R0_ENTRIES	128	/* SLI FCP rsp ring entries */
#define	SLIM_IOCB_CMD_R1_ENTRIES	128	/* SLI IP cmd ring entries   */
#define	SLIM_IOCB_RSP_R1_ENTRIES	128	/* SLI IP rsp ring entries  */
#define	SLIM_IOCB_CMD_R2_ENTRIES	128	/* SLI ELS cmd ring entries  */
#define	SLIM_IOCB_RSP_R2_ENTRIES	128	/* SLI ELS rspe ring entries */
#define	SLIM_IOCB_CMD_R3_ENTRIES	128	/* SLI CT cmd ring entries   */
#define	SLIM_IOCB_RSP_R3_ENTRIES	128	/* SLI CT rsp ring entries  */

/*
 * Total: 184 Cmd's + 184 Rsp's = 368
 * Command and response entry counts are not required to be equal
 */

#define	SLIM_IOCB_CMD_ENTRIES		(SLIM_IOCB_CMD_R0_ENTRIES + \
					SLIM_IOCB_CMD_R1_ENTRIES + \
					SLIM_IOCB_CMD_R2_ENTRIES + \
					SLIM_IOCB_CMD_R3_ENTRIES)

#define	SLIM_IOCB_RSP_ENTRIES		(SLIM_IOCB_RSP_R0_ENTRIES + \
					SLIM_IOCB_RSP_R1_ENTRIES + \
					SLIM_IOCB_RSP_R2_ENTRIES + \
					SLIM_IOCB_RSP_R3_ENTRIES)

#define	SLIM_IOCB_ENTRIES		(SLIM_IOCB_CMD_ENTRIES + \
					SLIM_IOCB_RSP_ENTRIES)


/* SLI1 Definitions */
#define	SLI_SLIM1_SIZE			4096 /* Fixed size memory */


/* SLI2 Definitions */
#define	SLI2_IOCB_CMD_SIZE		32
#define	SLI2_IOCB_RSP_SIZE		32
#define	SLI2_IOCB_MAX_SIZE		((SLI2_IOCB_CMD_SIZE * \
					SLIM_IOCB_CMD_ENTRIES) + \
					(SLI2_IOCB_RSP_SIZE * \
					SLIM_IOCB_RSP_ENTRIES))
#define	SLI2_SLIM2_SIZE			(MBOX_SIZE + MBOX_EXTENSION_SIZE + \
					PCB_SIZE + SLI2_IOCB_MAX_SIZE)


/* SLI3 Definitions */
#define	SLI3_MAX_BDE			7
#define	SLI3_IOCB_CMD_SIZE		128
#define	SLI3_IOCB_RSP_SIZE		64
#define	SLI3_IOCB_MAX_SIZE		((SLI3_IOCB_CMD_SIZE * \
					SLIM_IOCB_CMD_ENTRIES) + \
					(SLI3_IOCB_RSP_SIZE * \
					SLIM_IOCB_RSP_ENTRIES))
#define	SLI3_SLIM2_SIZE			(MBOX_SIZE + MBOX_EXTENSION_SIZE + \
					PCB_SIZE + SLI3_IOCB_MAX_SIZE)

#define	SLI_SLIM2_SIZE			SLI3_SLIM2_SIZE
#define	SLI_IOCB_MAX_SIZE		SLI3_IOCB_MAX_SIZE


/* These two are defined to indicate FCP cmd or non FCP cmd */
#define	FC_FCP_CMD		0
#define	FC_FCT_CMD		0
#define	FC_IP_CMD		1
#define	FC_ELS_CMD		2
#define	FC_CT_CMD		3

#define	FC_NFCP_CMD		1	/* could be a bit mask */

#define	FC_MAXRETRY		3	/* max retries for ELS commands */
#define	FC_FCP_RING		0	/* use ring 0 for FCP initiator cmds */
#define	FC_FCT_RING		0	/* use ring 0 for FCP target cmds */

#define	FC_IP_RING		1	/* use ring 1 for IP commands */
#define	FC_ELS_RING		2	/* use ring 2 for ELS commands */
#define	FC_CT_RING		3	/* use ring 3 for CT commands */

#define	FF_DEF_EDTOV		2000	/* Default E_D_TOV (2000ms) */
#define	FF_DEF_ALTOV		15	/* Default AL_TIME (15ms) */
#define	FF_DEF_RATOV		2	/* Default RA_TOV (2s) */
#define	FF_DEF_ARBTOV		1900	/* Default ARB_TOV (1900ms) */
#define	MAX_MSG_DATA		28	/* max msg data in CMD_ADAPTER_MSG */
					/* iocb */
#define	FF_REG_AREA_SIZE	256	/* size, in bytes, of i/o register */
					/* area */

/*
 * Miscellaneous stuff....
 */

#define	MAX_NODE_THROTTLE	2048

/* HBA Mgmt */
#define	FDMI_DID		((uint32_t)0xfffffa)
#define	NAMESERVER_DID		((uint32_t)0xfffffc)
#define	SCR_DID			((uint32_t)0xfffffd)
#define	FABRIC_DID		((uint32_t)0xfffffe)
#define	BCAST_DID		((uint32_t)0xffffff)
#define	MASK_DID		((uint32_t)0xffffff)
#define	CT_DID_MASK		((uint32_t)0xffff00)
#define	FABRIC_DID_MASK		((uint32_t)0xfff000)
#define	WELL_KNOWN_DID_MASK	((uint32_t)0xfffff0)

#define	EMLXS_MENLO_DID		((uint32_t)0x00fc0e)

#define	OWN_CHIP	1	/* IOCB / Mailbox is owned by FireFly */
#define	OWN_HOST	0	/* IOCB / Mailbox is owned by Host */
#define	END_OF_CHAIN	0


/* defines for type field in fc header */
#define	EMLXS_MENLO_TYPE	0xFE

/* defines for rctl field in fc header */
#define	FC_DEV_DATA	0x0
#define	FC_UNSOL_CTL	0x2
#define	FC_SOL_CTL	0x3
#define	FC_UNSOL_DATA	0x4
#define	FC_FCP_CMND	0x6
#define	FC_ELS_REQ	0x22
#define	FC_ELS_RSP	0x23
#define	FC_NET_HDR	0x20	/* network headers for Dfctl field */

/*
 * Common Transport structures and definitions
 *
 */
#define	EMLXS_COMMAND	0
#define	EMLXS_RESPONSE	1

typedef union CtRevisionId
{
	/* Structure is in Big Endian format */
	struct
	{
		uint32_t	Revision:8;
		uint32_t	InId:24;
	} bits;
	uint32_t	word;
} CtRevisionId_t;

typedef union CtCommandResponse
{
	/* Structure is in Big Endian format */
	struct
	{
		uint32_t	CmdRsp:16;
		uint32_t	Size:16;
	} bits;
	uint32_t	word;
} CtCommandResponse_t;

typedef struct SliCtRequest
{
	/* Structure is in Big Endian format */
	CtRevisionId_t		RevisionId;
	uint8_t			FsType;
	uint8_t			FsSubType;
	uint8_t			Options;
	uint8_t			Rsrvd1;
	CtCommandResponse_t	CommandResponse;
	uint8_t			Rsrvd2;
	uint8_t			ReasonCode;
	uint8_t			Explanation;
	uint8_t			VendorUnique;

	union
	{
		uint32_t	data;
		uint32_t	PortID;

		struct gid
		{
			uint8_t	PortType;	/* for GID_PT requests */
			uint8_t	DomainScope;
			uint8_t	AreaScope;
			uint8_t	Fc4Type;	/* for GID_FT requests */
		} gid;
		struct rft
		{
			uint32_t	PortId;	/* For RFT_ID requests */
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	rsvd0:16;
			uint32_t	rsvd1:7;
			uint32_t	fcpReg:1;	/* Type 8 */
			uint32_t	rsvd2:2;
			uint32_t	ipReg:1;	/* Type 5 */
			uint32_t	rsvd3:5;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	rsvd0:16;
			uint32_t	fcpReg:1;	/* Type 8 */
			uint32_t	rsvd1:7;
			uint32_t	rsvd3:5;
			uint32_t	ipReg:1;	/* Type 5 */
			uint32_t	rsvd2:2;
#endif
			uint32_t	rsvd[7];
		} rft;

		struct rsnn
		{
			uint8_t		wwnn[8];
			uint8_t		snn_len;
			char		snn[256];
		} rsnn;

		struct rspn
		{
			uint32_t	PortId;
			uint8_t		spn_len;
			char		spn[256];
		} rspn;
	} un;
} SliCtRequest_t;
typedef SliCtRequest_t SLI_CT_REQUEST;

#define	SLI_CT_REVISION	1


/*
 * FsType Definitions
 */

#define	SLI_CT_MANAGEMENT_SERVICE		0xFA
#define	SLI_CT_TIME_SERVICE			0xFB
#define	SLI_CT_DIRECTORY_SERVICE		0xFC
#define	SLI_CT_FABRIC_CONTROLLER_SERVICE	0xFD

/*
 * Directory Service Subtypes
 */

#define	SLI_CT_DIRECTORY_NAME_SERVER	0x02

/*
 * Response Codes
 */

#define	SLI_CT_RESPONSE_FS_RJT	0x8001
#define	SLI_CT_RESPONSE_FS_ACC	0x8002

/*
 * Reason Codes
 */

#define	SLI_CT_NO_ADDITIONAL_EXPL		0x0
#define	SLI_CT_INVALID_COMMAND			0x01
#define	SLI_CT_INVALID_VERSION			0x02
#define	SLI_CT_LOGICAL_ERROR			0x03
#define	SLI_CT_INVALID_IU_SIZE			0x04
#define	SLI_CT_LOGICAL_BUSY			0x05
#define	SLI_CT_PROTOCOL_ERROR			0x07
#define	SLI_CT_UNABLE_TO_PERFORM_REQ		0x09
#define	SLI_CT_REQ_NOT_SUPPORTED		0x0b
#define	SLI_CT_HBA_INFO_NOT_REGISTERED		0x10
#define	SLI_CT_MULTIPLE_HBA_ATTR_OF_SAME_TYPE	0x11
#define	SLI_CT_INVALID_HBA_ATTR_BLOCK_LEN	0x12
#define	SLI_CT_HBA_ATTR_NOT_PRESENT		0x13
#define	SLI_CT_PORT_INFO_NOT_REGISTERED		0x20
#define	SLI_CT_MULTIPLE_PORT_ATTR_OF_SAME_TYPE	0x21
#define	SLI_CT_INVALID_PORT_ATTR_BLOCK_LEN	0x22
#define	SLI_CT_VENDOR_UNIQUE			0xff

/*
 * Name Server SLI_CT_UNABLE_TO_PERFORM_REQ Explanations
 */

#define	SLI_CT_NO_PORT_ID		0x01
#define	SLI_CT_NO_PORT_NAME		0x02
#define	SLI_CT_NO_NODE_NAME		0x03
#define	SLI_CT_NO_CLASS_OF_SERVICE	0x04
#define	SLI_CT_NO_IP_ADDRESS		0x05
#define	SLI_CT_NO_IPA			0x06
#define	SLI_CT_NO_FC4_TYPES		0x07
#define	SLI_CT_NO_SYMBOLIC_PORT_NAME	0x08
#define	SLI_CT_NO_SYMBOLIC_NODE_NAME	0x09
#define	SLI_CT_NO_PORT_TYPE		0x0A
#define	SLI_CT_ACCESS_DENIED		0x10
#define	SLI_CT_INVALID_PORT_ID		0x11
#define	SLI_CT_DATABASE_EMPTY		0x12

#ifdef EMLXS_BIG_ENDIAN
#define	CT_CMD_MASK	0xffff0000
#endif

#ifdef EMLXS_LITTLE_ENDIAN
#define	CT_CMD_MASK	0xffff
#endif

/*
 * Management Server Interface Command Codes
 */

#define	MS_GTIN		0x0100
#define	MS_GIEL		0x0101
#define	MS_GIET		0x0111
#define	MS_GDID		0x0112
#define	MS_GMID		0x0113
#define	MS_GFN		0x0114
#define	MS_GIELN	0x0115
#define	MS_GMAL		0x0116
#define	MS_GIEIL	0x0117
#define	MS_GPL		0x0118
#define	MS_GPT		0x0121
#define	MS_GPPN		0x0122
#define	MS_GAPNL	0x0124
#define	MS_GPS		0x0126
#define	MS_GPSC		0x0127
#define	MS_GATIN	0x0128
#define	MS_GSES		0x0130
#define	MS_GPLNL	0x0191
#define	MS_GPLT		0x0192
#define	MS_GPLML	0x0193
#define	MS_GPAB		0x0197
#define	MS_GNPL		0x01A1
#define	MS_GPNL		0x01A2
#define	MS_GPFCP	0x01A4
#define	MS_GPLI		0x01A5
#define	MS_GNID		0x01B1
#define	MS_RIELN	0x0215
#define	MS_RPL		0x0280
#define	MS_RPLN		0x0291
#define	MS_RPLT		0x0292
#define	MS_RPLM		0x0293
#define	MS_RPAB		0x0298
#define	MS_RPFCP	0x029A
#define	MS_RPLI		0x029B
#define	MS_DPL		0x0380
#define	MS_DPLN		0x0391
#define	MS_DPLM		0x0392
#define	MS_DPLML	0x0393
#define	MS_DPLI		0x0394
#define	MS_DPAB		0x0395
#define	MS_DPALL	0x039F

/*
 * Name Server Command Codes
 */
#define	SLI_CTNS_GA_NXT		0x0100
#define	SLI_CTNS_GPN_ID		0x0112
#define	SLI_CTNS_GNN_ID		0x0113
#define	SLI_CTNS_GCS_ID		0x0114
#define	SLI_CTNS_GFT_ID		0x0117
#define	SLI_CTNS_GSPN_ID	0x0118
#define	SLI_CTNS_GPT_ID		0x011A
#define	SLI_CTNS_GID_PN		0x0121
#define	SLI_CTNS_GID_NN		0x0131
#define	SLI_CTNS_GIP_NN		0x0135
#define	SLI_CTNS_GIPA_NN	0x0136
#define	SLI_CTNS_GSNN_NN	0x0139
#define	SLI_CTNS_GNN_IP		0x0153
#define	SLI_CTNS_GIPA_IP	0x0156
#define	SLI_CTNS_GID_FT		0x0171
#define	SLI_CTNS_GID_PT		0x01A1
#define	SLI_CTNS_RPN_ID		0x0212
#define	SLI_CTNS_RNN_ID		0x0213
#define	SLI_CTNS_RCS_ID		0x0214
#define	SLI_CTNS_RFT_ID		0x0217
#define	SLI_CTNS_RSPN_ID	0x0218
#define	SLI_CTNS_RPT_ID		0x021A
#define	SLI_CTNS_RIP_NN		0x0235
#define	SLI_CTNS_RIPA_NN	0x0236
#define	SLI_CTNS_RSNN_NN	0x0239
#define	SLI_CTNS_DA_ID		0x0300

#define	SLI_CT_LOOPBACK		0xFCFC


/*
 * Port Types
 */

#define	SLI_CTPT_N_PORT		0x01
#define	SLI_CTPT_NL_PORT	0x02
#define	SLI_CTPT_FNL_PORT	0x03
#define	SLI_CTPT_IP		0x04
#define	SLI_CTPT_FCP		0x08
#define	SLI_CTPT_NX_PORT	0x7F
#define	SLI_CTPT_F_PORT		0x81
#define	SLI_CTPT_FL_PORT	0x82
#define	SLI_CTPT_E_PORT		0x84

#define	SLI_CT_LAST_ENTRY	0x80000000

/* ===================================================================== */

/*
 * Start FireFly Register definitions
 */

/* PCI register offsets */
#define	MEM_ADDR_OFFSET	0x10	/* SLIM base memory address */
#define	MEMH_OFFSET	0x14	/* SLIM base memory high address */
#define	REG_ADDR_OFFSET	0x18	/* REGISTER base memory address */
#define	REGH_OFFSET	0x1c	/* REGISTER base memory high address */
#define	IO_ADDR_OFFSET	0x20	/* BIU I/O registers */
#define	REGIOH_OFFSET	0x24	/* REGISTER base io high address */

#define	CMD_REG_OFFSET	0x4	/* PCI command configuration */

/* General PCI Register Definitions */
/* Refer To The PCI Specification For Detailed Explanations */

#define	PCI_VENDOR_ID_REGISTER		0x00	/* PCI Vendor ID Reg */
#define	PCI_DEVICE_ID_REGISTER		0x02	/* PCI Device ID Reg */
#define	PCI_CONFIG_ID_REGISTER		0x00	/* PCI Configuration ID Reg */
#define	PCI_COMMAND_REGISTER		0x04	/* PCI Command Reg */
#define	PCI_STATUS_REGISTER		0x06	/* PCI Status Reg */
#define	PCI_REV_ID_REGISTER		0x08	/* PCI Revision ID Reg */
#define	PCI_CLASS_CODE_REGISTER		0x09	/* PCI Class Code Reg */
#define	PCI_CACHE_LINE_REGISTER		0x0C	/* PCI Cache Line Reg */
#define	PCI_LATENCY_TMR_REGISTER	0x0D	/* PCI Latency Timer Reg */
#define	PCI_HEADER_TYPE_REGISTER	0x0E	/* PCI Header Type Reg */
#define	PCI_BIST_REGISTER		0x0F	/* PCI Built-In SelfTest Reg */
#define	PCI_BAR_0_REGISTER		0x10	/* PCI Base Address Reg 0 */
#define	PCI_BAR_1_REGISTER		0x14	/* PCI Base Address Reg 1 */
#define	PCI_BAR_2_REGISTER		0x18	/* PCI Base Address Reg 2 */
#define	PCI_BAR_3_REGISTER		0x1C	/* PCI Base Address Reg 3 */
#define	PCI_BAR_4_REGISTER		0x20	/* PCI Base Address Reg 4 */
#define	PCI_BAR_5_REGISTER		0x24	/* PCI Base Address Reg 5 */
#define	PCI_SSID_REGISTER		0x2C
#define	PCI_SSVID_REGISTER		0x2C
#define	PCI_SSDID_REGISTER		0x2E
#define	PCI_EXPANSION_ROM		0x30	/* PCI Expansion ROM Base Reg */
#define	PCI_CAP_POINTER			0x34

/* PCI capatability registers are defined in pci.h */
#define	PCI_CAP_ID_SHIFT			0
#define	PCI_CAP_ID_MASK				0xff
#define	PCI_CAP_NEXT_PTR_SHIFT			8
#define	PCI_CAP_NEXT_PTR_MASK			0xff

/* PCI extended capatability registers are defined in pcie.h */
#define	PCI_EXT_CAP_MAX_PTR		0x30

#define	PCI_EXT_CAP_ID_MRIOV		0x0000 /* ??? */
#define	PCI_EXT_CAP_ID_SRIOV		0x0010
#define	PCI_EXT_CAP_ID_11		0x0011
#define	PCI_EXT_CAP_ID_12		0x0012
#define	PCI_EXT_CAP_ID_13		0x0013
#define	PCI_EXT_CAP_ID_14		0x0014
#define	PCI_EXT_CAP_ID_15		0x0015
#define	PCI_EXT_CAP_ID_16		0x0016
#define	PCI_EXT_CAP_ID_TPH		0x0017
#define	PCI_EXT_CAP_ID_18		0x0018
#define	PCI_EXT_CAP_ID_SEC_PCI		0x0019

/* Vendor Specific (VS) register */
#define	PCI_VS_SLI_INTF_OFFSET	4

/* PCI access methods */
#define	P_CONF_T1	1
#define	P_CONF_T2	2

/* max number of pci buses */
#define	MAX_PCI_BUSES	0xFF

/* number of PCI config bytes to access */
#define	PCI_BYTE	1
#define	PCI_WORD	2
#define	PCI_DWORD	4

/* PCI related constants */
#define	CMD_IO_ENBL	0x0001
#define	CMD_MEM_ENBL	0x0002
#define	CMD_BUS_MASTER	0x0004
#define	CMD_MWI		0x0010
#define	CMD_PARITY_CHK	0x0040
#define	CMD_SERR_ENBL	0x0100

#define	CMD_CFG_VALUE	0x156	/* mem enable, master, MWI, SERR, PERR */

/* PCI addresses */
#define	PCI_SPACE_ENABLE		0x0CF8
#define	CF1_CONFIG_ADDR_REGISTER	0x0CF8
#define	CF1_CONFIG_DATA_REGISTER	0x0CFC
#define	CF2_FORWARD_REGISTER		0x0CFA
#define	CF2_BASE_ADDRESS		0xC000


#define	DEFAULT_PCI_LATENCY_CLOCKS	0xf8	/* 0xF8 is a special value */
						/* for FF11.1N6 firmware. */
						/* Use 0x80 for pre-FF11.1N6 */
						/* &N7, etc */
#define	PCI_LATENCY_VALUE		0xf8



/* ==== Register Bit Definitions ==== */

/* Used by SBUS adapter */
/* SBUS Control Register */
#define	SBUS_CTRL_REG_OFFSET	0	/* Word offset from reg base addr */

#define	SBUS_CTRL_SBRST 	0x00000001	/* Bit  0 */
#define	SBUS_CTRL_BKOFF 	0x00000002	/* Bit  1 */
#define	SBUS_CTRL_ENP 		0x00000004	/* Bit  2 */
#define	SBUS_CTRL_EN64		0x00000008	/* Bit  3 */
#define	SBUS_CTRL_SIR_1 	0x00000010	/* Bit [6:4] IRL 1, */
						/* lowset priority */
#define	SBUS_CTRL_SIR_2 	0x00000020
#define	SBUS_CTRL_SIR_3 	0x00000030
#define	SBUS_CTRL_SIR_4 	0x00000040
#define	SBUS_CTRL_SIR_5 	0x00000050
#define	SBUS_CTRL_SIR_6 	0x00000060
#define	SBUS_CTRL_SIR_7 	0x00000070	/* IRL 7, highest priority */

/* SBUS Status Register */
#define	SBUS_STAT_REG_OFFSET	1	/* Word offset from reg base addr */
#define	SBUS_STAT_IP		0x00000001	/* Bit  0 */
#define	SBUS_STAT_LERR		0x00000002	/* Bit  1 */
#define	SBUS_STAT_SBPE		0x00000004	/* Bit  2 */
#define	SBUS_STAT_TE		0x00000008	/* Bit  3 */
#define	SBUS_STAT_WPE		0x00000010	/* Bit  4 */
#define	SBUS_STAT_PERR		0x00000020	/* Bit  5 */
#define	SBUS_STAT_SERR		0x00000040	/* Bit  6 */
#define	SBUS_STAT_PTA		0x00000080	/* Bit  7 */

/* SBUS Update Register */
#define	SBUS_UPDATE_REG_OFFSET	2	/* Word offfset from reg base addr */

#define	SBUS_UPDATE_DATA	0x00000001	/* Bit  0 */
#define	SBUS_UPDATE_SPCLK	0x00000002	/* Bit  1 */
#define	SBUS_UPDATE_SPCE	0x00000004	/* Bit  2 */
#define	SBUS_UPDATE_SPRST	0x00000008	/* Bit  3 */
#define	SBUS_UPDATE_SPWE	0x00000010	/* Bit  4 */
#define	SBUS_UPDATE_LDFPGA	0x00000080	/* Bit  7 */

/* Host Attention Register */

#define	HA_REG_OFFSET  0	/* Word offset from register base address */

#define	HA_R0RE_REQ	0x00000001	/* Bit  0 */
#define	HA_R0CE_RSP	0x00000002	/* Bit  1 */
#define	HA_R0ATT	0x00000008	/* Bit  3 */
#define	HA_R1RE_REQ	0x00000010	/* Bit  4 */
#define	HA_R1CE_RSP	0x00000020	/* Bit  5 */
#define	HA_R1ATT	0x00000080	/* Bit  7 */
#define	HA_R2RE_REQ	0x00000100	/* Bit  8 */
#define	HA_R2CE_RSP	0x00000200	/* Bit  9 */
#define	HA_R2ATT	0x00000800	/* Bit 11 */
#define	HA_R3RE_REQ	0x00001000	/* Bit 12 */
#define	HA_R3CE_RSP	0x00002000	/* Bit 13 */
#define	HA_R3ATT	0x00008000	/* Bit 15 */
#define	HA_LATT		0x20000000	/* Bit 29 */
#define	HA_MBATT	0x40000000	/* Bit 30 */
#define	HA_ERATT	0x80000000	/* Bit 31 */


#ifdef MSI_SUPPORT


/* Host attention interrupt map */
#define	EMLXS_MSI_MAP8	{0, HA_R0ATT, HA_R1ATT, HA_R2ATT, \
	HA_R3ATT, HA_LATT, HA_MBATT, HA_ERATT}
#define	EMLXS_MSI_MAP4	{0, HA_R0ATT, HA_R1ATT, HA_R2ATT, 0, 0, 0, 0}
#define	EMLXS_MSI_MAP2	{0, HA_R0ATT, 0, 0, 0, 0, 0, 0}
#define	EMLXS_MSI_MAP1	{0, 0, 0, 0, 0, 0, 0, 0}

/* MSI 0 interrupt mask */
#define	EMLXS_MSI0_MASK8	0
#define	EMLXS_MSI0_MASK4	(HC_R3INT_ENA|HC_MBINT_ENA|HC_LAINT_ENA| \
				HC_ERINT_ENA)
#define	EMLXS_MSI0_MASK2	(HC_R1INT_ENA|HC_R2INT_ENA|HC_R3INT_ENA| \
				HC_MBINT_ENA|HC_LAINT_ENA|HC_ERINT_ENA)
#define	EMLXS_MSI0_MASK1	(HC_R0INT_ENA|HC_R1INT_ENA|HC_R2INT_ENA| \
				HC_R3INT_ENA|HC_MBINT_ENA|HC_LAINT_ENA| \
				HC_ERINT_ENA)


#define	EMLXS_MSI_MAX_INTRS	8

#define	EMLXS_MSI_MODE1		0
#define	EMLXS_MSI_MODE2		1
#define	EMLXS_MSI_MODE4		2
#define	EMLXS_MSI_MODE8		3
#define	EMLXS_MSI_MODES		4

#endif	/* MSI_SUPPORT */


#define	IO_THROTTLE_RESERVE	12




/* Chip Attention Register */

#define	CA_REG_OFFSET	1	/* Word offset from register base address */

#define	CA_R0CE_REQ	0x00000001	/* Bit  0 */
#define	CA_R0RE_RSP	0x00000002	/* Bit  1 */
#define	CA_R0ATT	0x00000008	/* Bit  3 */
#define	CA_R1CE_REQ	0x00000010	/* Bit  4 */
#define	CA_R1RE_RSP	0x00000020	/* Bit  5 */
#define	CA_R1ATT	0x00000080	/* Bit  7 */
#define	CA_R2CE_REQ	0x00000100	/* Bit  8 */
#define	CA_R2RE_RSP	0x00000200	/* Bit  9 */
#define	CA_R2ATT	0x00000800	/* Bit 11 */
#define	CA_R3CE_REQ	0x00001000	/* Bit 12 */
#define	CA_R3RE_RSP	0x00002000	/* Bit 13 */
#define	CA_R3ATT	0x00008000	/* Bit 15 */
#define	CA_MBATT	0x40000000	/* Bit 30 */

/* Host Status Register */

#define	HS_REG_OFFSET	2	/* Word offset from register base address */

#define	HS_OVERTEMP	0x00000100	/* Bit 8 */
#define	HS_MBRDY	0x00400000	/* Bit 22 */
#define	HS_FFRDY	0x00800000	/* Bit 23 */
#define	HS_FFER8	0x01000000	/* Bit 24 */
#define	HS_FFER7	0x02000000	/* Bit 25 */
#define	HS_FFER6	0x04000000	/* Bit 26 */
#define	HS_FFER5	0x08000000	/* Bit 27 */
#define	HS_FFER4	0x10000000	/* Bit 28 */
#define	HS_FFER3	0x20000000	/* Bit 29 */
#define	HS_FFER2	0x40000000	/* Bit 30 */
#define	HS_FFER1	0x80000000	/* Bit 31 */
#define	HS_FFERM	0xFF000000	/* Mask for error bits 31:24 */

/* Host Control Register */

#define	HC_REG_OFFSET	3	/* Word offset from register base address */

#define	HC_MBINT_ENA	0x00000001	/* Bit  0 */
#define	HC_R0INT_ENA	0x00000002	/* Bit  1 */
#define	HC_R1INT_ENA	0x00000004	/* Bit  2 */
#define	HC_R2INT_ENA	0x00000008	/* Bit  3 */
#define	HC_R3INT_ENA	0x00000010	/* Bit  4 */
#define	HC_INITHBI	0x02000000	/* Bit 25 */
#define	HC_INITMB	0x04000000	/* Bit 26 */
#define	HC_INITFF	0x08000000	/* Bit 27 */
#define	HC_LAINT_ENA	0x20000000	/* Bit 29 */
#define	HC_ERINT_ENA	0x80000000	/* Bit 31 */

/* BIU Configuration Register */

#define	BC_REG_OFFSET	4	/* Word offset from register base address */

#define	BC_BSE		0x00000001	/* Bit 0 */
#define	BC_BSE_SWAP	0x01000000	/* Bit 0 - swapped */

/*
 * End FireFly Register definitions
 */

/*
 * Start SLI 4 section.
 */

/* PCI Config Register offsets */
#define	PCICFG_UE_STATUS_LO_OFFSET	0xA0	/* Error Indication - low */
#define	PCICFG_UE_STATUS_HI_OFFSET	0xA4	/* Error Indication - high */
#define	PCICFG_UE_MASK_LO_OFFSET	0xA8	/* Error mask - low */
#define	PCICFG_UE_MASK_HI_OFFSET	0xAC	/* Error mask - high */
#define	PCICFG_UE_STATUS_ONLINE1	0xB0	/* Error status1 */
#define	PCICFG_UE_STATUS_ONLINE2	0xB4	/* Error status2 */

/* BAR1 and BAR2 register offsets */

/* BAR1 offsets for principal registers */
#define	CSR_ISR0_OFFSET		0x0C18	/* CSR for EQ interrupt indications */
#define	CSR_IMR0_OFFSET		0x0C48	/* CSR for EQ interrupt masking */
#define	CSR_ISCR0_OFFSET	0x0C78	/* CSR for EQ interrupt clearing */

#define	ISR0_EQ0_INDC	0x00000001	/* Indication bit for EQ0 */
#define	ISR0_EQ1_INDC	0x00000002	/* Indication bit for EQ1 */
#define	ISR0_EQ2_INDC	0x00000004	/* Indication bit for EQ2 */
#define	ISR0_EQ3_INDC	0x00000008	/* Indication bit for EQ3 */
#define	ISR0_EQ4_INDC	0x00000010	/* Indication bit for EQ4 */
#define	ISR0_EQ5_INDC	0x00000020	/* Indication bit for EQ5 */
#define	ISR0_EQ6_INDC	0x00000040	/* Indication bit for EQ6 */
#define	ISR0_EQ7_INDC	0x00000080	/* Indication bit for EQ7 */

/* MPU EP Semaphore register (ARM POST) */
#define	CSR_MPU_EP_SEMAPHORE_OFFSET	0x00AC

/* SLI Status register */
#define	SLI_STATUS_ERROR		0x80000000
#define	SLI_STATUS_BE			0x40000000
#define	SLI_STATUS_OTI			0x20000000
#define	SLI_STATUS_DUMP_LOCATION	0x04000000
#define	SLI_STATUS_DUMP_IMAGE_PRESENT	0x02000000
#define	SLI_STATUS_RESET_NEEDED		0x01000000
#define	SLI_STATUS_READY		0x00800000
#define	SLI_STATUS_INTERRUPT_DISABLE	0x00400000

/* SLI Control register */
#define	SLI_CNTL_BE		0x40000000
#define	SLI_CNTL_INIT_PORT	0x08000000

/* SLI PHYDEV Control register */
#define	SLI_PHYDEV_RERROR	0x80000000
#define	SLI_PHYDEV_INP		0x40000000
#define	SLI_PHYDEV_IPLD		0x00008000
#define	SLI_PHYDEV_GPC		0x00004000
#define	SLI_PHYDEV_GP		0x00002000

#define	SLI_PHYDEV_RC_MASK	0x00000700
#define	SLI_PHYDEV_RC_UNKNOWN	0x00000000
#define	SLI_PHYDEV_RC_PROFILE	0x00000100
#define	SLI_PHYDEV_RC_FACTORY	0x00000200

#define	SLI_PHYDEV_FRL_MASK	0x000000F0
#define	SLI_PHYDEV_FRL_ALL	0x00000000
#define	SLI_PHYDEV_FRL_FCOE	0x00000010

#define	SLI_PHYDEV_LC		0x00000008
#define	SLI_PHYDEV_DD		0x00000004
#define	SLI_PHYDEV_FRST		0x00000002
#define	SLI_PHYDEV_DRST		0x00000001

/* POST Stages of interest */
#define	ARM_POST_FATAL	0x80000000
#define	ARM_POST_READY	0xc000
#define	ARM_POST_MASK	0xffff
#define	ARM_UNRECOVERABLE_ERROR	0xf000

#define	MPU_EP_DL	0x04000000	/* Driverloadedbitmask */
#define	MPU_EP_ORI	0x08000000	/* OptionROMinstalledbitmask */
#define	MPU_EP_IPC	0x10000000	/* IPaddressconflictmask */
#define	MPU_EP_NIP	0x20000000	/* NoIPaddressmask */
#define	MPU_EP_BFW	0x40000000	/* BackupFWinusemask */
#define	MPU_EP_ERR	0x80000000	/* POSTfatalerrormask */

/* BAR2 offsets for principal doorbell registers */

#define	PD_RQ_DB_OFFSET	0x00A0	/* Doorbell notify of posted RQEs */
#define	PD_WQ_DB_OFFSET	0x0040	/* Doorbell notify of posted WQEs */
#define	PD_CQ_DB_OFFSET	0x0120	/* Doorbell notify of processed CQEs or EQEs */
#define	PD_MQ_DB_OFFSET	0x0140	/* Doorbell notify of posted MQEs */
#define	PD_MB_DB_OFFSET	0x0160	/* Doorbell Bootstrap Mailbox */

#define	SLIPORT_SEMAPHORE_OFFSET	0x0400
#define	SLIPORT_STATUS_OFFSET		0x0404
#define	SLIPORT_CONTROL_OFFSET		0x0408
#define	SLIPORT_ERROR1_OFFSET		0x040C
#define	SLIPORT_ERROR2_OFFSET		0x0410
#define	PHYSDEV_CONTROL_OFFSET		0x0414


/* Doorbell definitions */

/* Defines for MQ doorbell */
#define	MQ_DB_POP_SHIFT 16		/* shift for entries popped */
#define	MQ_DB_POP_MASK  0x1FFF0000	/* Mask for number of entries popped */

/* Defines for CQ doorbell */
#define	CQ_DB_POP_SHIFT 16		/* shift for entries popped */
#define	CQ_DB_POP_MASK  0x1FFF0000	/* Mask for number of entries popped */
#define	CQ_DB_REARM	0x20000000	/* Bit 29, rearm */

/* Defines for EQ doorbell */
#define	EQ_DB_CLEAR	0x00000200	/* Bit 9, designates clear EQ ISR */
#define	EQ_DB_EVENT	0x00000400	/* Bit 10, designates EQ */
#define	EQ_DB_POP_SHIFT 16		/* shift for entries popped */
#define	EQ_DB_POP_MASK  0x1FFF0000	/* Mask for number of entries popped */
#define	EQ_DB_REARM	0x20000000	/* Bit 29, rearm */

/* bootstrap mailbox doorbell defines */
#define	BMBX_READY	0x00000001	/* Mask for Port Ready bit */
#define	BMBX_ADDR_HI	0x00000002	/* Mask for Addr Hi bit */
#define	BMBX_ADDR	0xFFFFFFFA	/* Mask for Addr bits */

/* Sizeof bootstrap mailbox */
#define	EMLXS_BOOTSTRAP_MB_SIZE	256

#define	FW_INITIALIZE_WORD0	0xFF1234FF /* Initialize bootstrap wd 0 */
#define	FW_INITIALIZE_WORD1	0xFF5678FF /* Initialize bootstrap wd 1 */

#define	FW_DEINITIALIZE_WORD0	0xFFAABBFF /* DeInitialize bootstrap wd 0 */
#define	FW_DEINITIALIZE_WORD1	0xFFCCDDFF /* DeInitialize bootstrap wd 1 */

/* ===================================================================== */

/*
 * Start of FCP specific structures
 */

typedef struct emlxs_fcp_rsp
{
	uint32_t	rspRsvd1;	/* FC Word 0, byte 0:3 */
	uint32_t	rspRsvd2;	/* FC Word 1, byte 0:3 */

	uint8_t		rspStatus0;	/* FCP_STATUS byte 0 (reserved) */
	uint8_t		rspStatus1;	/* FCP_STATUS byte 1 (reserved) */
	uint8_t		rspStatus2;	/* FCP_STATUS byte 2 field validity */
#define	RSP_LEN_VALID	0x01	/* bit 0 */
#define	SNS_LEN_VALID	0x02	/* bit 1 */
#define	RESID_OVER	0x04	/* bit 2 */
#define	RESID_UNDER	0x08	/* bit 3 */

	uint8_t		rspStatus3;	/* FCP_STATUS byte 3 SCSI status byte */
#define	SCSI_STAT_GOOD		0x00
#define	SCSI_STAT_CHECK_COND	0x02
#define	SCSI_STAT_COND_MET	0x04
#define	SCSI_STAT_BUSY		0x08
#define	SCSI_STAT_INTERMED	0x10
#define	SCSI_STAT_INTERMED_CM	0x14
#define	SCSI_STAT_RES_CNFLCT	0x18
#define	SCSI_STAT_CMD_TERM	0x22
#define	SCSI_STAT_QUE_FULL	0x28
#define	SCSI_STAT_ACA_ACTIVE	0x30
#define	SCSI_STAT_TASK_ABORT	0x40

	uint32_t	rspResId;	/* Residual xfer if RESID_xxxx set */
					/* in fcpStatus2. */
					/* Received in Big Endian format */
	uint32_t	rspSnsLen;	/* Length of sense data in fcpSnsInfo */
					/* Received in Big Endian format */
	uint32_t	rspRspLen;	/* Length of FCP response data */
					/* in fcpRspInfo */
					/* Received in Big Endian format */

	uint8_t		rspInfo0;	/* FCP_RSP_INFO byte 0 (reserved) */
	uint8_t		rspInfo1;	/* FCP_RSP_INFO byte 1 (reserved) */
	uint8_t		rspInfo2;	/* FCP_RSP_INFO byte 2 (reserved) */
	uint8_t		rspInfo3;	/* FCP_RSP_INFO RSP_CODE byte 3 */

#define	RSP_NO_FAILURE		0x00
#define	RSP_DATA_BURST_ERR	0x01
#define	RSP_CMD_FIELD_ERR	0x02
#define	RSP_RO_MISMATCH_ERR	0x03
#define	RSP_TM_NOT_SUPPORTED	0x04	/* Task mgmt function not supported */
#define	RSP_TM_NOT_COMPLETED	0x05	/* Task mgmt function not performed */

	uint32_t	rspInfoRsvd;	/* FCP_RSP_INFO bytes 4-7 (reserved) */

	/*
	 * Define maximum size of SCSI Sense buffer.
	 * Seagate never issues more than 18 bytes of Sense data
	 */
#define	MAX_FCP_SNS	128
	uint8_t		rspSnsInfo[MAX_FCP_SNS];
} emlxs_fcp_rsp;
typedef emlxs_fcp_rsp FCP_RSP;


typedef struct emlxs_fcp_cmd
{
	uint32_t	fcpLunMsl;	/* most significant lun word */
	uint32_t	fcpLunLsl;	/* least significant lun word */

	/*
	 * # of bits to shift lun id to end up in right payload word,
	 * little endian = 8, big = 16.
	 */
#ifdef EMLXS_LITTLE_ENDIAN
#define	FC_LUN_SHIFT		8
#define	FC_ADDR_MODE_SHIFT	0
#endif
#ifdef EMLXS_BIG_ENDIAN
#define	FC_LUN_SHIFT		16
#define	FC_ADDR_MODE_SHIFT	24
#endif

	uint8_t		fcpCntl0;	/* FCP_CNTL byte 0 (reserved) */
	uint8_t		fcpCntl1;	/* FCP_CNTL byte 1 task codes */
#define	SIMPLE_Q	0x00
#define	HEAD_OF_Q	0x01
#define	ORDERED_Q	0x02
#define	ACA_Q		0x04
#define	UNTAGGED	0x05

	uint8_t		fcpCntl2;	/* FCP_CTL byte 2 task management */
					/* codes */
#define	ABORT_TASK_SET	0x02	/* Bit 1 */
#define	CLEAR_TASK_SET	0x04	/* bit 2 */
#define	LUN_RESET	0x10	/* bit 4 */
#define	TARGET_RESET	0x20	/* bit 5 */
#define	CLEAR_ACA	0x40	/* bit 6 */
#define	TERMINATE_TASK	0x80	/* bit 7 */

	uint8_t		fcpCntl3;
#define	WRITE_DATA	0x01	/* Bit 0 */
#define	READ_DATA	0x02	/* Bit 1 */

	uint8_t		fcpCdb[16];	/* SRB cdb field is copied here */
	uint32_t	fcpDl;	/* Total transfer length */
} emlxs_fcp_cmd_t;
typedef emlxs_fcp_cmd_t FCP_CMND;




/* SCSI INQUIRY Command Structure */

typedef struct emlxs_inquiryDataType
{
	uint8_t		DeviceType:5;
	uint8_t		DeviceTypeQualifier:3;

	uint8_t		DeviceTypeModifier:7;
	uint8_t		RemovableMedia:1;

	uint8_t		Versions;
	uint8_t		ResponseDataFormat;
	uint8_t		AdditionalLength;
	uint8_t		Reserved[2];

	uint8_t		SoftReset:1;
	uint8_t		CommandQueue:1;
	uint8_t		Reserved2:1;
	uint8_t		LinkedCommands:1;
	uint8_t		Synchronous:1;
	uint8_t		Wide16Bit:1;
	uint8_t		Wide32Bit:1;
	uint8_t		RelativeAddressing:1;

	uint8_t		VendorId[8];
	uint8_t		ProductId[16];
	uint8_t		ProductRevisionLevel[4];
	uint8_t		VendorSpecific[20];
	uint8_t		Reserved3[40];
} emlxs_inquiry_data_type_t;
typedef emlxs_inquiry_data_type_t INQUIRY_DATA_DEF;


typedef struct emlxs_read_capacity_data
{
	uint32_t	LogicalBlockAddress;
	uint32_t	BytesPerBlock;
} emlxs_read_capacity_data_t;
typedef emlxs_read_capacity_data_t READ_CAPACITY_DATA_DEF;


/* SCSI CDB command codes */
#define	FCP_SCSI_FORMAT_UNIT			0x04
#define	FCP_SCSI_INQUIRY			0x12
#define	FCP_SCSI_MODE_SELECT			0x15
#define	FCP_SCSI_MODE_SENSE			0x1A
#define	FCP_SCSI_PAUSE_RESUME			0x4B
#define	FCP_SCSI_PLAY_AUDIO			0x45
#define	FCP_SCSI_PLAY_AUDIO_EXT			0xA5
#define	FCP_SCSI_PLAY_AUDIO_MSF			0x47
#define	FCP_SCSI_PLAY_AUDIO_TRK_INDX		0x48
#define	FCP_SCSI_PREVENT_ALLOW_REMOVAL		0x1E
#define	FCP_SCSI_READ_CMD			0x08
#define	FCP_SCSI_READ_BUFFER			0x3C
#define	FCP_SCSI_READ_CAPACITY			0x25
#define	FCP_SCSI_READ_DEFECT_LIST		0x37
#define	FCP_SCSI_READ_EXTENDED			0x28
#define	FCP_SCSI_READ_HEADER			0x44
#define	FCP_SCSI_READ_LONG			0xE8
#define	FCP_SCSI_READ_SUB_CHANNEL		0x42
#define	FCP_SCSI_READ_TOC			0x43
#define	FCP_SCSI_REASSIGN_BLOCK			0x07
#define	FCP_SCSI_RECEIVE_DIAGNOSTIC_RESULTS	0x1C
#define	FCP_SCSI_RELEASE_UNIT			0x17
#define	FCP_SCSI_REPORT_LUNS			0xa0
#define	FCP_SCSI_REQUEST_SENSE			0x03
#define	FCP_SCSI_RESERVE_UNIT			0x16
#define	FCP_SCSI_REZERO_UNIT			0x01
#define	FCP_SCSI_SEEK				0x0B
#define	FCP_SCSI_SEEK_EXTENDED			0x2B
#define	FCP_SCSI_SEND_DIAGNOSTIC		0x1D
#define	FCP_SCSI_START_STOP_UNIT		0x1B
#define	FCP_SCSI_TEST_UNIT_READY		0x00
#define	FCP_SCSI_VERIFY				0x2F
#define	FCP_SCSI_WRITE_CMD			0x0A
#define	FCP_SCSI_WRITE_AND_VERIFY		0x2E
#define	FCP_SCSI_WRITE_BUFFER			0x3B
#define	FCP_SCSI_WRITE_EXTENDED			0x2A
#define	FCP_SCSI_WRITE_LONG			0xEA
#define	FCP_SCSI_RELEASE_LUNR			0xBB
#define	FCP_SCSI_RELEASE_LUNV			0xBF

#define	HPVA_SETPASSTHROUGHMODE			0x27
#define	HPVA_EXECUTEPASSTHROUGH			0x29
#define	HPVA_CREATELUN				0xE2
#define	HPVA_SETLUNSECURITYLIST			0xED
#define	HPVA_SETCLOCK				0xF9
#define	HPVA_RECOVER				0xFA
#define	HPVA_GENERICSERVICEOUT			0xFD

#define	DMEP_EXPORT_IN				0x85
#define	DMEP_EXPORT_OUT				0x89

#define	MDACIOCTL_DIRECT_CMD			0x22
#define	MDACIOCTL_STOREIMAGE			0x2C
#define	MDACIOCTL_WRITESIGNATURE		0xA6
#define	MDACIOCTL_SETREALTIMECLOCK		0xAC
#define	MDACIOCTL_PASS_THRU_CDB			0xAD
#define	MDACIOCTL_PASS_THRU_INITIATE		0xAE
#define	MDACIOCTL_CREATENEWCONF			0xC0
#define	MDACIOCTL_ADDNEWCONF			0xC4
#define	MDACIOCTL_MORE				0xC6
#define	MDACIOCTL_SETPHYSDEVPARAMETER		0xC8
#define	MDACIOCTL_SETLOGDEVPARAMETER		0xCF
#define	MDACIOCTL_SETCONTROLLERPARAMETER	0xD1
#define	MDACIOCTL_WRITESANMAP			0xD4
#define	MDACIOCTL_SETMACADDRESS			0xD5

/*
 * End of FCP specific structures
 */

#define	FL_ALPA		0x00	/* AL_PA of FL_Port */

/* Fibre Channel Service Parameter definitions */

#define	FC_PH_4_0	6	/* FC-PH version 4.0 */
#define	FC_PH_4_1	7	/* FC-PH version 4.1 */
#define	FC_PH_4_2	8	/* FC-PH version 4.2 */
#define	FC_PH_4_3	9	/* FC-PH version 4.3 */

#define	FC_PH_LOW	8	/* Lowest supported FC-PH version */
#define	FC_PH_HIGH	9	/* Highest supported FC-PH version */
#define	FC_PH3		0x20	/* FC-PH-3 version */

#define	FF_FRAME_SIZE	2048


typedef struct emlxs_rings
{
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	crReserved:16;
	uint32_t	crBegin:8;
	uint32_t	crEnd:8;	/* Low order bit first word */
	uint32_t	rrReserved:16;
	uint32_t	rrBegin:8;
	uint32_t	rrEnd:8;	/* Low order bit second word */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	crEnd:8;	/* Low order bit first word */
	uint32_t	crBegin:8;
	uint32_t	crReserved:16;
	uint32_t	rrEnd:8;	/* Low order bit second word */
	uint32_t	rrBegin:8;
	uint32_t	rrReserved:16;
#endif
} emlxs_rings_t;
typedef emlxs_rings_t RINGS;


typedef struct emlxs_ring_def
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	offCiocb;
	uint16_t	numCiocb;
	uint16_t	offRiocb;
	uint16_t	numRiocb;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	numCiocb;
	uint16_t	offCiocb;
	uint16_t	numRiocb;
	uint16_t	offRiocb;
#endif
} emlxs_ring_def_t;
typedef emlxs_ring_def_t RING_DEF;

/*
 * The following F.C. frame stuctures are defined in Big Endian format.
 */

typedef struct emlxs_name_type
{
#ifdef EMLXS_BIG_ENDIAN
	uint8_t		nameType:4;	/* FC Word 0, bit 28:31 */
	uint8_t		IEEEextMsn:4;	/* FC Word 0, bit 24:27, bit 8:11 */
					/* of IEEE ext */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		IEEEextMsn:4;	/* FC Word 0, bit 24:27, bit 8:11 */
					/* of IEEE ext */
	uint8_t		nameType:4;	/* FC Word 0, bit 28:31 */
#endif
#define	NAME_IEEE		0x1	/* IEEE name - nameType */
#define	NAME_IEEE_EXT		0x2	/* IEEE extended name */
#define	NAME_FC_TYPE		0x3	/* FC native name type */
#define	NAME_IP_TYPE		0x4	/* IP address */
#define	NAME_CCITT_TYPE		0xC
#define	NAME_CCITT_GR_TYPE	0xE
	uint8_t		IEEEextLsb;	/* FC Word 0, bit 16:23, */
					/* IEEE extended Lsb */
	uint8_t		IEEE[6];	/* FC IEEE address */
} emlxs_name_type_t;
typedef emlxs_name_type_t NAME_TYPE;


/*
 * Word 1 Bit 31 in common service parameter is overloaded.
 * Word 1 Bit 31 in FLOGI/FDISC request is multiple NPort request
 * Word 1 Bit 31 in FLOGI/FDISC response is clean address bit
 */
#define	CLEAN_ADDRESS_BIT reqMultipleNPort /* Word 1, bit 31 */

typedef struct emlxs_csp
{
	uint8_t		fcphHigh;		/* FC Word 0, byte 0 */
	uint8_t		fcphLow;
	uint8_t		bbCreditMsb;
	uint8_t		bbCreditlsb;		/* FC Word 0, byte 3 */
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	reqMultipleNPort:1;	/* FC Word 1, bit 31 */
	uint16_t	randomOffset:1;		/* FC Word 1, bit 30 */
	uint16_t	rspMultipleNPort:1;	/* FC Word 1, bit 29 */
	uint16_t	fPort:1;		/* FC Word 1, bit 28 */
	uint16_t	altBbCredit:1;		/* FC Word 1, bit 27 */
	uint16_t	edtovResolution:1;	/* FC Word 1, bit 26 */
	uint16_t	multicast:1;		/* FC Word 1, bit 25 */
	uint16_t	broadcast:1;		/* FC Word 1, bit 24 */

	uint16_t	huntgroup:1;		/* FC Word 1, bit 23 */
	uint16_t	simplex:1;		/* FC Word 1, bit 22 */

	uint16_t	fcsp_support:1;		/* FC Word 1, bit 21 */
	uint16_t	word1Reserved20:1;	/* FC Word 1, bit 20 */
	uint16_t	word1Reserved19:1;	/* FC Word 1, bit 19 */

	uint16_t	dhd:1;			/* FC Word 1, bit 18 */
	uint16_t	contIncSeqCnt:1;	/* FC Word 1, bit 17 */
	uint16_t	payloadlength:1;	/* FC Word 1, bit 16 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	broadcast:1;		/* FC Word 1, bit 24 */
	uint16_t	multicast:1;		/* FC Word 1, bit 25 */
	uint16_t	edtovResolution:1;	/* FC Word 1, bit 26 */
	uint16_t	altBbCredit:1;		/* FC Word 1, bit 27 */
	uint16_t	fPort:1;		/* FC Word 1, bit 28 */
	uint16_t	rspMultipleNPort:1;	/* FC Word 1, bit 29 */
	uint16_t	randomOffset:1;		/* FC Word 1, bit 30 */
	uint16_t	reqMultipleNPort:1;	/* FC Word 1, bit 31 */

	uint16_t	payloadlength:1;	/* FC Word 1, bit 16 */
	uint16_t	contIncSeqCnt:1;	/* FC Word 1, bit 17 */
	uint16_t	dhd:1;			/* FC Word 1, bit 18 */

	uint16_t	word1Reserved19:1;	/* FC Word 1, bit 19 */
	uint16_t	word1Reserved20:1;	/* FC Word 1, bit 20 */
	uint16_t	fcsp_support:1;		/* FC Word 1, bit 21 */

	uint16_t	simplex:1;		/* FC Word 1, bit 22 */
	uint16_t	huntgroup:1;		/* FC Word 1, bit 23 */
#endif
	uint8_t		bbRcvSizeMsb;		/* Upper nibble is reserved */
	uint8_t		bbRcvSizeLsb;		/* FC Word 1, byte 3 */
	union
	{
		struct
		{
			uint8_t	word2Reserved1;	/* FC Word 2 byte 0 */

			uint8_t	totalConcurrSeq; /* FC Word 2 byte 1 */
			uint8_t	roByCategoryMsb; /* FC Word 2 byte 2 */

			uint8_t	roByCategoryLsb; /* FC Word 2 byte 3 */
		} nPort;
		uint32_t	r_a_tov;	/* R_A_TOV must be in Big */
						/* Endian format */
	} w2;

	uint32_t	e_d_tov;		/* E_D_TOV must be in Big */
						/* Endian format */
} emlxs_csp_t;
typedef emlxs_csp_t CSP;


typedef struct emlxs_class_parms
{
#ifdef EMLXS_BIG_ENDIAN
	uint8_t	classValid:1;		/* FC Word 0, bit 31 */
	uint8_t	intermix:1;		/* FC Word 0, bit 30 */
	uint8_t	stackedXparent:1;	/* FC Word 0, bit 29 */
	uint8_t	stackedLockDown:1;	/* FC Word 0, bit 28 */
	uint8_t	seqDelivery:1;		/* FC Word 0, bit 27 */
	uint8_t	word0Reserved1:3;	/* FC Word 0, bit 24:26 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t	word0Reserved1:3;	/* FC Word 0, bit 24:26 */
	uint8_t	seqDelivery:1;		/* FC Word 0, bit 27 */
	uint8_t	stackedLockDown:1;	/* FC Word 0, bit 28 */
	uint8_t	stackedXparent:1;	/* FC Word 0, bit 29 */
	uint8_t	intermix:1;		/* FC Word 0, bit 30 */
	uint8_t	classValid:1;		/* FC Word 0, bit 31 */

#endif
	uint8_t	word0Reserved2;		/* FC Word 0, bit 16:23 */
#ifdef EMLXS_BIG_ENDIAN
	uint8_t	iCtlXidReAssgn:2;	/* FC Word 0, Bit 14:15 */
	uint8_t	iCtlInitialPa:2;	/* FC Word 0, bit 12:13 */
	uint8_t	iCtlAck0capable:1;	/* FC Word 0, bit 11 */
	uint8_t	iCtlAckNcapable:1;	/* FC Word 0, bit 10 */
	uint8_t	word0Reserved3:2;	/* FC Word 0, bit  8: 9 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t	word0Reserved3:2;	/* FC Word 0, bit  8: 9 */
	uint8_t	iCtlAckNcapable:1;	/* FC Word 0, bit 10 */
	uint8_t	iCtlAck0capable:1;	/* FC Word 0, bit 11 */
	uint8_t	iCtlInitialPa:2;	/* FC Word 0, bit 12:13 */
	uint8_t	iCtlXidReAssgn:2;	/* FC Word 0, Bit 14:15 */
#endif
	uint8_t	word0Reserved4;		/* FC Word 0, bit  0: 7 */
#ifdef EMLXS_BIG_ENDIAN
	uint8_t	rCtlAck0capable:1;	/* FC Word 1, bit 31 */
	uint8_t	rCtlAckNcapable:1;	/* FC Word 1, bit 30 */
	uint8_t	rCtlXidInterlck:1;	/* FC Word 1, bit 29 */
	uint8_t	rCtlErrorPolicy:2;	/* FC Word 1, bit 27:28 */
	uint8_t	word1Reserved1:1;	/* FC Word 1, bit 26 */
	uint8_t	rCtlCatPerSeq:2;	/* FC Word 1, bit 24:25 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t	rCtlCatPerSeq:2;	/* FC Word 1, bit 24:25 */
	uint8_t	word1Reserved1:1;	/* FC Word 1, bit 26 */
	uint8_t	rCtlErrorPolicy:2;	/* FC Word 1, bit 27:28 */
	uint8_t	rCtlXidInterlck:1;	/* FC Word 1, bit 29 */
	uint8_t	rCtlAckNcapable:1;	/* FC Word 1, bit 30 */
	uint8_t	rCtlAck0capable:1;	/* FC Word 1, bit 31 */
#endif
	uint8_t	word1Reserved2;		/* FC Word 1, bit 16:23 */
	uint8_t	rcvDataSizeMsb;		/* FC Word 1, bit  8:15 */
	uint8_t	rcvDataSizeLsb;		/* FC Word 1, bit  0: 7 */

	uint8_t	concurrentSeqMsb;	/* FC Word 2, bit 24:31 */
	uint8_t	concurrentSeqLsb;	/* FC Word 2, bit 16:23 */
	uint8_t	EeCreditSeqMsb;		/* FC Word 2, bit  8:15 */
	uint8_t	EeCreditSeqLsb;		/* FC Word 2, bit  0: 7 */

	uint8_t	openSeqPerXchgMsb;	/* FC Word 3, bit 24:31 */
	uint8_t	openSeqPerXchgLsb;	/* FC Word 3, bit 16:23 */
	uint8_t	word3Reserved1;		/* Fc Word 3, bit  8:15 */
	uint8_t	word3Reserved2;		/* Fc Word 3, bit  0: 7 */
} emlxs_class_parms_t;
typedef emlxs_class_parms_t CLASS_PARMS;


typedef struct emlxs_serv_parms
{ /* Structure is in Big Endian format */
	CSP		cmn;
	NAME_TYPE	portName;
	NAME_TYPE	nodeName;
	CLASS_PARMS	cls1;
	CLASS_PARMS	cls2;
	CLASS_PARMS	cls3;
	CLASS_PARMS	cls4;
	uint8_t		vendorVersion[16];
} emlxs_serv_parms_t;
typedef emlxs_serv_parms_t SERV_PARM;

typedef struct
{
	union
	{
		uint32_t	word0;
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd0:8;	/* Word 0, Byte 3 */
			uint32_t oui:24;	/* Elx Organization */
						/* Unique ID (0000C9) */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t oui:24;	/* Elx Organization */
						/* Unique ID (0000C9) */
			uint32_t rsvd0:8;	/* Word 0, Byte 3 */
#endif
		} w0;
	} un0;
	union
	{
		uint32_t	word1;
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t vport:1;	/* Word 1, Bit 31 */
			uint32_t rsvd1:31;	/* Word 1, Bit 0-30 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t rsvd1:31;	/* Word 1, Bit 0-30 */
			uint32_t vport:1;	/* Word 1, Bit 31 */
#endif
		} w1;
	} un1;
	uint8_t		rsvd2[8];
} emlxs_vvl_fmt_t;

#define	VALID_VENDOR_VERSION	cmn.rspMultipleNPort



/*
 * Extended Link Service LS_COMMAND codes (Payload BYTE 0)
 */
#ifdef EMLXS_BIG_ENDIAN
#define	ELS_CMD_SHIFT	24
#define	ELS_CMD_MASK	0xff000000
#define	ELS_RSP_MASK	0xff000000
#define	ELS_CMD_LS_RJT	0x01000000
#define	ELS_CMD_ACC	0x02000000
#define	ELS_CMD_PLOGI	0x03000000
#define	ELS_CMD_FLOGI	0x04000000
#define	ELS_CMD_LOGO	0x05000000
#define	ELS_CMD_ABTX	0x06000000
#define	ELS_CMD_RCS	0x07000000
#define	ELS_CMD_RES	0x08000000
#define	ELS_CMD_RSS	0x09000000
#define	ELS_CMD_RSI	0x0A000000
#define	ELS_CMD_ESTS	0x0B000000
#define	ELS_CMD_ESTC	0x0C000000
#define	ELS_CMD_ADVC	0x0D000000
#define	ELS_CMD_RTV	0x0E000000
#define	ELS_CMD_RLS	0x0F000000
#define	ELS_CMD_ECHO	0x10000000
#define	ELS_CMD_TEST	0x11000000
#define	ELS_CMD_RRQ	0x12000000
#define	ELS_CMD_REC	0x13000000
#define	ELS_CMD_PRLI	0x20000000
#define	ELS_CMD_PRLO	0x21000000
#define	ELS_CMD_SCN	0x22000000
#define	ELS_CMD_TPLS	0x23000000
#define	ELS_CMD_GPRLO	0x24000000
#define	ELS_CMD_GAID	0x30000000
#define	ELS_CMD_FACT	0x31000000
#define	ELS_CMD_FDACT	0x32000000
#define	ELS_CMD_NACT	0x33000000
#define	ELS_CMD_NDACT	0x34000000
#define	ELS_CMD_QoSR	0x40000000
#define	ELS_CMD_RVCS	0x41000000
#define	ELS_CMD_PDISC	0x50000000
#define	ELS_CMD_FDISC	0x51000000
#define	ELS_CMD_ADISC	0x52000000
#define	ELS_CMD_FARP	0x54000000
#define	ELS_CMD_FARPR	0x55000000
#define	ELS_CMD_FAN	0x60000000
#define	ELS_CMD_RSCN	0x61000000
#define	ELS_CMD_SCR	0x62000000
#define	ELS_CMD_LINIT	0x70000000
#define	ELS_CMD_RNID	0x78000000
#define	ELS_CMD_AUTH	0x90000000
#endif

#ifdef EMLXS_LITTLE_ENDIAN
#define	ELS_CMD_SHIFT	0
#define	ELS_CMD_MASK	0xff
#define	ELS_RSP_MASK	0xff
#define	ELS_CMD_LS_RJT	0x01
#define	ELS_CMD_ACC	0x02
#define	ELS_CMD_PLOGI	0x03
#define	ELS_CMD_FLOGI	0x04
#define	ELS_CMD_LOGO	0x05
#define	ELS_CMD_ABTX	0x06
#define	ELS_CMD_RCS	0x07
#define	ELS_CMD_RES	0x08
#define	ELS_CMD_RSS	0x09
#define	ELS_CMD_RSI	0x0A
#define	ELS_CMD_ESTS	0x0B
#define	ELS_CMD_ESTC	0x0C
#define	ELS_CMD_ADVC	0x0D
#define	ELS_CMD_RTV	0x0E
#define	ELS_CMD_RLS	0x0F
#define	ELS_CMD_ECHO	0x10
#define	ELS_CMD_TEST	0x11
#define	ELS_CMD_RRQ	0x12
#define	ELS_CMD_REC	0x13
#define	ELS_CMD_PRLI	0x20
#define	ELS_CMD_PRLO	0x21
#define	ELS_CMD_SCN	0x22
#define	ELS_CMD_TPLS	0x23
#define	ELS_CMD_GPRLO	0x24
#define	ELS_CMD_GAID	0x30
#define	ELS_CMD_FACT	0x31
#define	ELS_CMD_FDACT	0x32
#define	ELS_CMD_NACT	0x33
#define	ELS_CMD_NDACT	0x34
#define	ELS_CMD_QoSR	0x40
#define	ELS_CMD_RVCS	0x41
#define	ELS_CMD_PDISC	0x50
#define	ELS_CMD_FDISC	0x51
#define	ELS_CMD_ADISC	0x52
#define	ELS_CMD_FARP	0x54
#define	ELS_CMD_FARPR	0x55
#define	ELS_CMD_FAN	0x60
#define	ELS_CMD_RSCN	0x61
#define	ELS_CMD_SCR	0x62
#define	ELS_CMD_LINIT	0x70
#define	ELS_CMD_RNID	0x78
#define	ELS_CMD_AUTH	0x90
#endif


/*
 * LS_RJT Payload Definition
 */

typedef struct _LS_RJT
{ /* Structure is in Big Endian format */
	union
	{
		uint32_t	lsRjtError;
		struct
		{
			uint8_t	lsRjtRsvd0;	/* FC Word 0, */
						/* bit 24:31 */

			uint8_t	lsRjtRsnCode;	/* FC Word 0, */
						/* bit 16:23 */
			/* LS_RJT reason codes */
#define	LSRJT_INVALID_CMD	0x01
#define	LSRJT_LOGICAL_ERR	0x03
#define	LSRJT_LOGICAL_BSY	0x05
#define	LSRJT_PROTOCOL_ERR	0x07
#define	LSRJT_UNABLE_TPC	0x09	/* Unable to perform command */
#define	LSRJT_CMD_UNSUPPORTED	0x0B
#define	LSRJT_VENDOR_UNIQUE	0xFF	/* See Byte 3 */

			uint8_t	lsRjtRsnCodeExp;	/* FC Word 0, */
							/* bit 8:15 */
			/* LS_RJT reason explanation */
#define	LSEXP_NOTHING_MORE	0x00
#define	LSEXP_SPARM_OPTIONS	0x01
#define	LSEXP_SPARM_ICTL	0x03
#define	LSEXP_SPARM_RCTL	0x05
#define	LSEXP_SPARM_RCV_SIZE	0x07
#define	LSEXP_SPARM_CONCUR_SEQ	0x09
#define	LSEXP_SPARM_CREDIT	0x0B
#define	LSEXP_INVALID_PNAME	0x0D
#define	LSEXP_INVALID_NNAME	0x0E
#define	LSEXP_INVALID_CSP	0x0F
#define	LSEXP_INVALID_ASSOC_HDR	0x11
#define	LSEXP_ASSOC_HDR_REQ	0x13
#define	LSEXP_INVALID_O_SID	0x15
#define	LSEXP_INVALID_OX_RX	0x17
#define	LSEXP_CMD_IN_PROGRESS	0x19
#define	LSEXP_INVALID_NPORT_ID	0x1F
#define	LSEXP_INVALID_SEQ_ID	0x21
#define	LSEXP_INVALID_XCHG	0x23
#define	LSEXP_INACTIVE_XCHG	0x25
#define	LSEXP_RQ_REQUIRED	0x27
#define	LSEXP_OUT_OF_RESOURCE	0x29
#define	LSEXP_CANT_GIVE_DATA	0x2A
#define	LSEXP_REQ_UNSUPPORTED	0x2C
			uint8_t	vendorUnique;	/* FC Word 0, bit  0: 7 */
		} b;
	} un;
} LS_RJT;


/*
 * N_Port Login (FLOGO/PLOGO Request) Payload Definition
 */

typedef struct _LOGO
{ /* Structure is in Big Endian format */
	union
	{
		uint32_t	nPortId32;	/* Access nPortId as a word */
		struct
		{
			uint8_t	word1Reserved1;	/* FC Word 1, bit 31:24 */
			uint8_t	nPortIdByte0;	/* N_port  ID bit 16:23 */
			uint8_t	nPortIdByte1;	/* N_port  ID bit  8:15 */
			uint8_t	nPortIdByte2;	/* N_port  ID bit  0: 7 */
		} b;
	} un;
	NAME_TYPE		portName;	/* N_port name field */
} LOGO;


/*
 * FCP Login (PRLI Request / ACC) Payload Definition
 */

#define	PRLX_PAGE_LEN	0x10
#define	TPRLO_PAGE_LEN	0x14

typedef struct _PRLI
{ /* Structure is in Big Endian format */
	uint8_t		prliType;		/* FC Parm Word 0, bit 24:31 */

#define	PRLI_FCP_TYPE 0x08
	uint8_t		word0Reserved1;		/* FC Parm Word 0, bit 16:23 */

#ifdef EMLXS_BIG_ENDIAN
	uint8_t		origProcAssocV:1;	/* FC Parm Word 0, bit 15 */
	uint8_t		respProcAssocV:1;	/* FC Parm Word 0, bit 14 */
	uint8_t		estabImagePair:1;	/* FC Parm Word 0, bit 13 */

	/* ACC = imagePairEstablished */
	uint8_t		word0Reserved2:1;	/* FC Parm Word 0, bit 12 */
	uint8_t		acceptRspCode:4;	/* FC Parm Word 0, bit 8:11, */
						/* ACC ONLY */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		acceptRspCode:4;	/* FC Parm Word 0, bit 8:11, */
						/* ACC ONLY */
	uint8_t		word0Reserved2:1;	/* FC Parm Word 0, bit 12 */
	uint8_t		estabImagePair:1;	/* FC Parm Word 0, bit 13 */
	uint8_t		respProcAssocV:1;	/* FC Parm Word 0, bit 14 */
	uint8_t		origProcAssocV:1;	/* FC Parm Word 0, bit 15 */
	/* ACC = imagePairEstablished */
#endif
#define	PRLI_REQ_EXECUTED	0x1		/* acceptRspCode */
#define	PRLI_NO_RESOURCES	0x2
#define	PRLI_INIT_INCOMPLETE	0x3
#define	PRLI_NO_SUCH_PA		0x4
#define	PRLI_PREDEF_CONFIG	0x5
#define	PRLI_PARTIAL_SUCCESS	0x6
#define	PRLI_INVALID_PAGE_CNT	0x7
	uint8_t		word0Reserved3;		/* FC Parm Word 0, bit 0:7 */

	uint32_t	origProcAssoc;		/* FC Parm Word 1, bit 0:31 */

	uint32_t	respProcAssoc;		/* FC Parm Word 2, bit 0:31 */

	uint8_t		word3Reserved1;		/* FC Parm Word 3, bit 24:31 */
	uint8_t		word3Reserved2;		/* FC Parm Word 3, bit 16:23 */
#ifdef EMLXS_BIG_ENDIAN
	uint16_t	Word3bit15Resved:1;	/* FC Parm Word 3, bit 15 */
	uint16_t	Word3bit14Resved:1;	/* FC Parm Word 3, bit 14 */
	uint16_t	Word3bit13Resved:1;	/* FC Parm Word 3, bit 13 */
	uint16_t	Word3bit12Resved:1;	/* FC Parm Word 3, bit 12 */
	uint16_t	Word3bit11Resved:1;	/* FC Parm Word 3, bit 11 */
	uint16_t	Word3bit10Resved:1;	/* FC Parm Word 3, bit 10 */
	uint16_t	TaskRetryIdReq:1;	/* FC Parm Word 3, bit  9 */
	uint16_t	Retry:1;		/* FC Parm Word 3, bit  8 */
	uint16_t	ConfmComplAllowed:1;	/* FC Parm Word 3, bit  7 */
	uint16_t	dataOverLay:1;		/* FC Parm Word 3, bit  6 */
	uint16_t	initiatorFunc:1;	/* FC Parm Word 3, bit  5 */
	uint16_t	targetFunc:1;		/* FC Parm Word 3, bit  4 */
	uint16_t	cmdDataMixEna:1;	/* FC Parm Word 3, bit  3 */
	uint16_t	dataRspMixEna:1;	/* FC Parm Word 3, bit  2 */
	uint16_t	readXferRdyDis:1;	/* FC Parm Word 3, bit  1 */
	uint16_t	writeXferRdyDis:1;	/* FC Parm Word 3, bit  0 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t	Retry:1;		/* FC Parm Word 3, bit  8 */
	uint16_t	TaskRetryIdReq:1;	/* FC Parm Word 3, bit  9 */
	uint16_t	Word3bit10Resved:1;	/* FC Parm Word 3, bit 10 */
	uint16_t	Word3bit11Resved:1;	/* FC Parm Word 3, bit 11 */
	uint16_t	Word3bit12Resved:1;	/* FC Parm Word 3, bit 12 */
	uint16_t	Word3bit13Resved:1;	/* FC Parm Word 3, bit 13 */
	uint16_t	Word3bit14Resved:1;	/* FC Parm Word 3, bit 14 */
	uint16_t	Word3bit15Resved:1;	/* FC Parm Word 3, bit 15 */
	uint16_t	writeXferRdyDis:1;	/* FC Parm Word 3, bit  0 */
	uint16_t	readXferRdyDis:1;	/* FC Parm Word 3, bit  1 */
	uint16_t	dataRspMixEna:1;	/* FC Parm Word 3, bit  2 */
	uint16_t	cmdDataMixEna:1;	/* FC Parm Word 3, bit  3 */
	uint16_t	targetFunc:1;		/* FC Parm Word 3, bit  4 */
	uint16_t	initiatorFunc:1;	/* FC Parm Word 3, bit  5 */
	uint16_t	dataOverLay:1;		/* FC Parm Word 3, bit  6 */
	uint16_t	ConfmComplAllowed:1;	/* FC Parm Word 3, bit  7 */
#endif
} PRLI;

/*
 * FCP Logout (PRLO Request / ACC) Payload Definition
 */

typedef struct _PRLO
{ /* Structure is in Big Endian format */
	uint8_t		prloType;	/* FC Parm Word 0, bit 24:31 */

#define	PRLO_FCP_TYPE	0x08
	uint8_t		word0Reserved1;	/* FC Parm Word 0, bit 16:23 */

#ifdef EMLXS_BIG_ENDIAN
	uint8_t		origProcAssocV:1;	/* FC Parm Word 0, bit 15 */
	uint8_t		respProcAssocV:1;	/* FC Parm Word 0, bit 14 */
	uint8_t		word0Reserved2:2;	/* FC Parm Word 0, bit 12:13 */
	uint8_t		acceptRspCode:4;	/* FC Parm Word 0, bit 8:11, */
						/* ACC ONLY */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t		acceptRspCode:4;	/* FC Parm Word 0, bit 8:11, */
						/* ACC ONLY */
	uint8_t		word0Reserved2:2;	/* FC Parm Word 0, bit 12:13 */
	uint8_t		respProcAssocV:1;	/* FC Parm Word 0, bit 14 */
	uint8_t		origProcAssocV:1;	/* FC Parm Word 0, bit 15 */
#endif
#define	PRLO_REQ_EXECUTED	0x1		/* acceptRspCode */
#define	PRLO_NO_SUCH_IMAGE	0x4
#define	PRLO_INVALID_PAGE_CNT	0x7

	uint8_t		word0Reserved3;		/* FC Parm Word 0, bit 0:7 */
	uint32_t	origProcAssoc;		/* FC Parm Word 1, bit 0:31 */
	uint32_t	respProcAssoc;		/* FC Parm Word 2, bit 0:31 */
	uint32_t	word3Reserved1;		/* FC Parm Word 3, bit 0:31 */
} PRLO;


typedef struct _ADISC
{ /* Structure is in Big Endian format */
	uint32_t	hardAL_PA;
	NAME_TYPE	portName;
	NAME_TYPE	nodeName;
	uint32_t	DID;
} ADISC;


typedef struct _FARP
{ /* Structure is in Big Endian format */
	uint32_t	Mflags:8;
	uint32_t	Odid:24;
#define	FARP_NO_ACTION	0	/* FARP information enclosed, no action */
#define	FARP_MATCH_PORT	0x1	/* Match on Responder Port Name */
#define	FARP_MATCH_NODE	0x2	/* Match on Responder Node Name */
#define	FARP_MATCH_IP	0x4	/* Match on IP address, not supported */
#define	FARP_MATCH_IPV4	0x5	/* Match on IPV4 address, not supported */
#define	FARP_MATCH_IPV6	0x6	/* Match on IPV6 address, not supported */
	uint32_t	Rflags:8;
	uint32_t	Rdid:24;
#define	FARP_REQUEST_PLOGI	0x1	/* Request for PLOGI */
#define	FARP_REQUEST_FARPR	0x2	/* Request for FARP Response */
	NAME_TYPE	OportName;
	NAME_TYPE	OnodeName;
	NAME_TYPE	RportName;
	NAME_TYPE	RnodeName;
	uint8_t		Oipaddr[16];
	uint8_t		Ripaddr[16];
} FARP;

typedef struct _FAN
{ /* Structure is in Big Endian format */
	uint32_t	Fdid;
	NAME_TYPE	FportName;
	NAME_TYPE	FnodeName;
} FAN;

typedef struct _SCR
{ /* Structure is in Big Endian format */
	uint8_t		resvd1;
	uint8_t		resvd2;
	uint8_t		resvd3;
	uint8_t		Function;
#define	SCR_FUNC_FABRIC	0x01
#define	SCR_FUNC_NPORT	0x02
#define	SCR_FUNC_FULL	0x03
#define	SCR_CLEAR	0xff
} SCR;

typedef struct _RNID_TOP_DISC
{
	NAME_TYPE	portName;
	uint8_t		resvd[8];
	uint32_t	unitType;
#define	RNID_HBA	0x7
#define	RNID_HOST	0xa
#define	RNID_DRIVER	0xd
	uint32_t	physPort;
	uint32_t	attachedNodes;
	uint16_t	ipVersion;
#define	RNID_IPV4	0x1
#define	RNID_IPV6	0x2
	uint16_t	UDPport;
	uint8_t		ipAddr[16];
	uint16_t	resvd1;
	uint16_t	flags;
#define	RNID_TD_SUPPORT	0x1
#define	RNID_LP_VALID	0x2
} RNID_TOP_DISC;

typedef struct _RNID
{ /* Structure is in Big Endian format */
	uint8_t		Format;
#define	RNID_TOPOLOGY_DISC  0xdf
	uint8_t		CommonLen;
	uint8_t		resvd1;
	uint8_t		SpecificLen;
	NAME_TYPE	portName;
	NAME_TYPE	nodeName;
	union
	{
		RNID_TOP_DISC topologyDisc;	/* topology disc (0xdf) */
	} un;
} RNID;

typedef struct _RRQ
{ /* Structure is in Big Endian format */
	uint32_t	SID;
	uint16_t	Oxid;
	uint16_t	Rxid;
	uint8_t		resv[32];	/* optional association hdr */
} RRQ;


/* This is used for RSCN command */
typedef struct _D_ID
{ /* Structure is in Big Endian format */
	union
	{
		uint32_t	word;
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint8_t	resv;
			uint8_t	domain;
			uint8_t	area;
			uint8_t	id;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint8_t	id;
			uint8_t	area;
			uint8_t	domain;
			uint8_t	resv;
#endif
		} b;
	} un;
} D_ID;

/*
 * Structure to define	all ELS Payload types
 */

typedef struct _ELS_PKT
{ /* Structure is in Big Endian format */
	uint8_t		elsCode;		/* FC Word 0, bit 24:31 */
	uint8_t		elsByte1;
	uint8_t		elsByte2;
	uint8_t		elsByte3;
	union
	{
		LS_RJT		lsRjt;		/* Payload for LS_RJT */
		SERV_PARM	logi;		/* Payload for PLOGI, FLOGI */
						/* PDISC, ACC */
		LOGO		logo;		/* Payload for PLOGO, FLOGO */
						/* ACC */
		PRLI		prli;		/* Payload for PRLI/ACC */
		PRLO		prlo;		/* Payload for PRLO/ACC */
		ADISC		adisc;		/* Payload for ADISC/ACC */
		FARP		farp;		/* Payload for FARP/ACC */
		FAN		fan;		/* Payload for FAN */
		SCR		scr;		/* Payload for SCR/ACC */
		RRQ		rrq;		/* Payload for RRQ */
		RNID		rnid;		/* Payload for RNID */
		uint8_t		pad[128 - 4];	/* Pad out to payload of */
						/* 128 bytes */
	} un;
} ELS_PKT;


typedef struct
{
	uint32_t	bdeAddress;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	bdeReserved:4;
	uint32_t	bdeAddrHigh:4;
	uint32_t	bdeSize:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	bdeSize:24;
	uint32_t	bdeAddrHigh:4;
	uint32_t	bdeReserved:4;
#endif
} ULP_BDE;

typedef struct ULP_BDE_64
{ /* SLI-2 */
	union ULP_BDE_TUS
	{
		uint32_t	w;
		struct
		{
#ifdef EMLXS_BIG_ENDIAN
			uint32_t	bdeFlags:8;	/* BDE Flags 0 IS A */
							/* SUPPORTED VALUE !! */
			uint32_t	bdeSize:24;	/* buff size in bytes */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t	bdeSize:24;	/* buff size in bytes */
			uint32_t	bdeFlags:8;	/* BDE Flags 0 IS A */
							/* SUPPORTED VALUE !! */
#endif
#define	BUFF_USE_RSVD		0x01	/* bdeFlags */
#define	BUFF_USE_INTRPT		0x02	/* Not Implemented with LP6000 */
#define	BUFF_USE_CMND		0x04	/* Optional, 1=cmd/rsp 0=data buffer */
#define	BUFF_USE_RCV		0x08	/* ""  "", 1=rcv buffer, */
					/* 0=xmit buffer */
#define	BUFF_TYPE_32BIT		0x10	/* ""  "", 1=32 bit addr */
					/* 0=64 bit addr */
#define	BUFF_TYPE_SPECIAL	0x20	/* Not Implemented with LP6000  */
#define	BUFF_TYPE_BDL		0x40	/* Optional,  may be set in BDL */
#define	BUFF_TYPE_INVALID	0x80	/* ""  "" */
		} f;
	} tus;
	uint32_t	addrLow;
	uint32_t	addrHigh;
} ULP_BDE64;

#define	BDE64_SIZE_WORD	0
#define	BPL64_SIZE_WORD	0x40

/*  ULP  */
typedef struct ULP_BPL_64
{
	ULP_BDE64	fccmd_payload;
	ULP_BDE64	fcrsp_payload;
	ULP_BDE64	fcdat_payload;
	ULP_BDE64	pat0;
} ULP_BPL64;

typedef struct ULP_BDL
{ /* SLI-2 */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	bdeFlags:8;	/* BDL Flags */
	uint32_t	bdeSize:24;	/* Size of BDL array in host */
					/* memory (bytes) */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	bdeSize:24;	/* Size of BDL array in host */
					/* memory (bytes) */
	uint32_t	bdeFlags:8;	/* BDL Flags */
#endif
	uint32_t	addrLow;	/* Address 0:31 */
	uint32_t	addrHigh;	/* Address 32:63 */
	uint32_t	ulpIoTag32;	/* Can be used for 32 bit I/O Tag */
} ULP_BDL;

typedef struct ULP_SGE_64
{ /* SLI-4 */
	uint32_t	addrHigh;	/* Address 32:63 */
	uint32_t	addrLow;	/* Address 0:31 */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t	last:1;		/* Last entry in SGL */
	uint32_t	type:4;
	uint32_t	offset:27;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t	offset:27;
	uint32_t	type:4;
	uint32_t	last:1;		/* Last entry in SGL */
#endif
#define	EMLXS_SGE_TYPE_DATA	0x0
#define	EMLXS_SGE_TYPE_DIF	0x4
#define	EMLXS_SGE_TYPE_LSP	0x5
#define	EMLXS_SGE_TYPE_ENC_DIF	0x6
#define	EMLXS_SGE_TYPE_ENC_SEED	0x7
#define	EMLXS_SGE_TYPE_SEED	0x8
#define	EMLXS_SGE_TYPE_ENC	0x9
#define	EMLXS_SGE_TYPE_SKIP	0xC

	uint32_t	length;
#define	EMLXS_MAX_SGE_SIZE	0x10000	/* 64K max length */
} ULP_SGE64;

#define	EMLXS_XFER_RDY_SIZE	12  /* Payload size of a FCP Transfer Ready */

typedef	struct _BE_PHYS_ADDR
{
	uint32_t	addrLow;
	uint32_t	addrHigh;
} BE_PHYS_ADDR;


typedef struct
{
	void		*fc_mptr;
	struct emlxs_memseg *segment;	/* Parent segment */

	void		*virt;		/* virtual address ptr */
	uint64_t	phys;		/* mapped address */
	uint32_t	size;

	void		*data_handle;
	void		*dma_handle;
	uint32_t	tag;
	uint32_t	flag;
#define	MAP_POOL_ALLOCATED	0x00000001
#define	MAP_BUF_ALLOCATED	0x00000002
#define	MAP_TABLE_ALLOCATED	0x00000004

#ifdef SFCT_SUPPORT
	void		*fct_private;
#endif /* SFCT_SUPPORT */
} MATCHMAP;


/*
 * This file defines the Header File for the FDMI HBA Management Service
 */

/*
 * FDMI HBA MAnagement Operations Command Codes
 */
#define	SLI_MGMT_GRHL	0x100	/* Get registered HBA list */
#define	SLI_MGMT_GHAT	0x101	/* Get HBA attributes */
#define	SLI_MGMT_GRPL	0x102	/* Get registered Port list */
#define	SLI_MGMT_GPAT	0x110	/* Get Port attributes */
#define	SLI_MGMT_RHBA	0x200	/* Register HBA */
#define	SLI_MGMT_RHAT	0x201	/* Register HBA atttributes */
#define	SLI_MGMT_RPRT	0x210	/* Register Port */
#define	SLI_MGMT_RPA	0x211	/* Register Port attributes */
#define	SLI_MGMT_DHBA	0x300	/* De-register HBA */
#define	SLI_MGMT_DPRT	0x310	/* De-register Port */

/*
 * Management Service Subtypes
 */
#define	SLI_CT_FDMI_SUBTYPES	0x10


/*
 * HBA Management Service Reject Code
 */
#define	REJECT_CODE		0x9	/* Unable to perform command request */

/*
 * HBA Management Service Reject Reason Code
 * Please refer to the Reason Codes above
 */

/*
 * HBA Attribute Types
 */
#define	NODE_NAME		0x1
#define	MANUFACTURER		0x2
#define	SERIAL_NUMBER		0x3
#define	MODEL			0x4
#define	MODEL_DESCRIPTION	0x5
#define	HARDWARE_VERSION	0x6
#define	DRIVER_VERSION		0x7
#define	OPTION_ROM_VERSION	0x8
#define	FIRMWARE_VERSION	0x9
#define	VENDOR_SPECIFIC		0xa
#define	DRV_NAME		0xb
#define	OS_NAME_VERSION		0xc
#define	MAX_CT_PAYLOAD_LEN	0xd

/*
 * Port Attrubute Types
 */
#define	SUPPORTED_FC4_TYPES	0x1
#define	SUPPORTED_SPEED		0x2
#define	PORT_SPEED		0x3
#define	MAX_FRAME_SIZE		0x4
#define	OS_DEVICE_NAME		0x5

union AttributesDef
{
	/* Structure is in Big Endian format */
	struct
	{
		uint32_t	AttrType:16;
		uint32_t	AttrLen:16;
	} bits;
	uint32_t	word;
};

/*
 * HBA Attribute Entry (8 - 260 bytes)
 */
typedef struct
{
	union AttributesDef	ad;
	union
	{
		uint32_t	VendorSpecific;
		uint32_t	SupportSpeed;
		uint32_t	PortSpeed;
		uint32_t	MaxFrameSize;
		uint32_t	MaxCTPayloadLen;
		uint8_t		SupportFC4Types[32];
		uint8_t		OsDeviceName[256];
		uint8_t		Manufacturer[64];
		uint8_t		SerialNumber[64];
		uint8_t		Model[256];
		uint8_t		ModelDescription[256];
		uint8_t		HardwareVersion[256];
		uint8_t		DriverVersion[256];
		uint8_t		OptionROMVersion[256];
		uint8_t		FirmwareVersion[256];
		uint8_t		DriverName[256];
		NAME_TYPE	NodeName;
	} un;
} ATTRIBUTE_ENTRY, *PATTRIBUTE_ENTRY;


/*
 * HBA Attribute Block
 */
typedef struct
{
	uint32_t	EntryCnt;	/* Number of HBA attribute entries */
	ATTRIBUTE_ENTRY	Entry;		/* Variable-length array */
} ATTRIBUTE_BLOCK, *PATTRIBUTE_BLOCK;


/*
 * Port Entry
 */
typedef struct
{
	NAME_TYPE	PortName;
} PORT_ENTRY, *PPORT_ENTRY;

/*
 * HBA Identifier
 */
typedef struct
{
	NAME_TYPE	PortName;
} HBA_IDENTIFIER, *PHBA_IDENTIFIER;

/*
 * Registered Port List Format
 */
typedef struct
{
	uint32_t	EntryCnt;
	PORT_ENTRY	pe;	/* Variable-length array */
} REG_PORT_LIST, *PREG_PORT_LIST;

/*
 * Register HBA(RHBA)
 */
typedef struct
{
	HBA_IDENTIFIER	hi;
	REG_PORT_LIST	rpl;	/* variable-length array */
} REG_HBA, *PREG_HBA;

/*
 * Register HBA Attributes (RHAT)
 */
typedef struct
{
	NAME_TYPE	HBA_PortName;
	ATTRIBUTE_BLOCK	ab;
} REG_HBA_ATTRIBUTE, *PREG_HBA_ATTRIBUTE;

/*
 * Register Port Attributes (RPA)
 */
typedef struct
{
	NAME_TYPE	HBA_PortName;
	NAME_TYPE	PortName;
	ATTRIBUTE_BLOCK	ab;
} REG_PORT_ATTRIBUTE, *PREG_PORT_ATTRIBUTE;

/*
 * Get Registered HBA List (GRHL) Accept Payload Format
 */
typedef struct
{
	uint32_t	HBA__Entry_Cnt;	/* Number of Registered HBA Ids */
	NAME_TYPE	HBA_PortName;	/* Variable-length array */
} GRHL_ACC_PAYLOAD, *PGRHL_ACC_PAYLOAD;

/*
 * Get Registered Port List (GRPL) Accept Payload Format
 */
typedef struct
{
	uint32_t	RPL_Entry_Cnt;		/* No of Reg Port Entries */
	PORT_ENTRY	eg_Port_Entry[1];	/* Variable-length array */
} GRPL_ACC_PAYLOAD, *PGRPL_ACC_PAYLOAD;

/*
 * Get Port Attributes (GPAT) Accept Payload Format
 */

typedef struct
{
	ATTRIBUTE_BLOCK	pab;
} GPAT_ACC_PAYLOAD, *PGPAT_ACC_PAYLOAD;

/*
 * Use for Firmware DownLoad
 */

/* download.h */

#define	REDUCED_SRAM_CFG	0x7FFFC	/* 9802DC */
#define	FULL_SRAM_CFG		0x13FFFC	/* 9802   */

#define	SLI_FW_TYPE_SHIFT(x) ((x << 20))
#define	SLI_FW_ADAPTER_TYPE_MASK   0x00f00000
#define	SLI_FW_TYPE_6000  SLI_FW_TYPE_SHIFT(0)
#define	SLI_FW_TYPE_7000  SLI_FW_TYPE_SHIFT(1)
#define	SLI_FW_TYPE_8000  SLI_FW_TYPE_SHIFT(2)
#define	SLI_FW_TYPE_850   SLI_FW_TYPE_SHIFT(3)
#define	SLI_FW_TYPE_9000  SLI_FW_TYPE_SHIFT(4)
#define	SLI_FW_TYPE_950   SLI_FW_TYPE_SHIFT(5)
#define	SLI_FW_TYPE_9802  SLI_FW_TYPE_SHIFT(6)	/* [022702] */
#define	SLI_FW_TYPE_982   SLI_FW_TYPE_SHIFT(7)
#define	SLI_FW_TYPE_10000 SLI_FW_TYPE_SHIFT(8)
#define	SLI_FW_TYPE_1050  SLI_FW_TYPE_SHIFT(9)
#define	SLI_FW_TYPE_X1000 SLI_FW_TYPE_SHIFT(0xa)
#define	SLI_FW_TYPE_101   SLI_FW_TYPE_SHIFT(0xb)	/* LP101 */


enum emlxs_prog_type
{
	TEST_PROGRAM,	/* 0 */
	UTIL_PROGRAM,	/* 1 */
	FUNC_FIRMWARE,	/* 2 */
	BOOT_BIOS,	/* 3 */
	CONFIG_DATA,	/* 4 */
	SEQUENCER_CODE,	/* 5 */
	SLI1_OVERLAY,	/* 6 */
	SLI2_OVERLAY,	/* 7 */
	GASKET,		/* 8 */
	HARDWARE_IMAGE,	/* 9 */
	SBUS_FCODE,	/* A */
	SLI3_OVERLAY,	/* B */
	RESERVED_C,
	RESERVED_D,
	SLI4_OVERLAY,	/* E */
	KERNEL_CODE,	/* F */
	MAX_PROG_TYPES
} emlxs_prog_type_t;


typedef struct emlxs_fw_file
{
	uint32_t	version;
	uint32_t	revcomp;
	char		label[16];
	uint32_t	offset;
} emlxs_fw_file_t;

typedef struct emlxs_fw_image
{
	emlxs_fw_file_t awc;
	emlxs_fw_file_t bwc;
	emlxs_fw_file_t dwc;
	emlxs_fw_file_t prog[MAX_PROG_TYPES];
} emlxs_fw_image_t;



#define	NOP_IMAGE_TYPE		0xe1a00000

#define	FLASH_BASE_ADR		0x01400000
#define	DL_FROM_SLIM_OFFSET	MBOX_EXTENSION_OFFSET

#ifdef MBOX_EXT_SUPPORT
#define	DL_SLIM_SEG_BYTE_COUNT	MBOX_EXTENSION_SIZE
#else
#define	DL_SLIM_SEG_BYTE_COUNT	128
#endif /* MBOX_EXT_SUPPORT */

#define	SLI_CKSUM_LENGTH	4
#define	SLI_CKSUM_SEED		0x55555555
#define	SLI_CKSUM_ERR		0x1982abcd

#define	AIF_NOOP		0xe1a00000
#define	AIF_BLAL		0xeb000000
#define	OS_EXIT			0xef000011
#define	OS_GETENV		0xef000010
#define	AIF_IMAGEBASE		0x00008000
#define	AIF_BLZINIT		0xeb00000c
#define	DEBUG_TASK		0xef041d41
#define	AIF_DBG_SRC		2
#define	AIF_DBG_LL		1
#define	AIF_DATABASAT		0x100

#define	JEDEC_ID_ADDRESS	0x0080001c
#define	MAX_RBUS_SRAM_SIZE_ADR	0x788
#define	MAX_IBUS_SRAM_SIZE_ADR	0x78c
#define	FULL_RBUS_SRAM_CFG	0x7fffc
#define	FULL_IBUS_SRAM_CFG	0x187fffc
#define	REDUCED_RBUS_SRAM_CFG	0x5fffc
#define	REDUCED_IBUS_SRAM_CFG	0x183fffc

#define	FULL_SRAM_CFG_PROG_ID		1
#define	REDUCED_SRAM_CFG_PROG_ID	2
#define	OTHER_SRAM_CFG_PROG_ID		3

#define	NO_FLASH_MEM_AVAIL	0xf1

#define	PROG_TYPE_MASK		0xff000000
#define	PROG_TYPE_SHIFT		24

#define	FLASH_LOAD_LIST_ADR	0x79c
#define	RAM_LOAD_ENTRY_SIZE	9
#define	FLASH_LOAD_ENTRY_SIZE	6
#define	RAM_LOAD_ENTRY_TYPE	0
#define	FLASH_LOAD_ENTRY_TYPE	1

#define	CFG_DATA_NO_REGION	-3

#define	SLI_IMAGE_START		0x20080
#define	SLI_VERSION_LOC		0x270


#define	SLI_HW_REVISION_CHECK(x, y)	((x & 0xf0) == y)
#define	SLI_FCODE_REVISION_CHECK(x, y)	(x == y)


/* ************ OBJ firmware ************** */
#define	OBJ_MAX_XFER_SIZE	32768


/* ************ BladeEngine ************** */
#define	BE_SIGNATURE		"ServerEngines"
#define	BE_DIR_SIGNATURE	"*** SE FLAS"
#define	BE_BUILD_SIZE		24
#define	BE_VERSION_SIZE		32
#define	BE_COOKIE_SIZE		32
#define	BE_CONTROLLER_SIZE	8
#define	BE_FLASH_ENTRIES	32
#define	BE_MAX_XFER_SIZE	32768 /* 4K aligned */

/* ************** BE3 **************** */
#define	BE3_SIGNATURE_SIZE	52
#define	BE3_MAX_IMAGE_HEADERS	32

typedef struct emlxs_be3_image_header
{
	uint32_t id;
#define	UFI_BE3_FLASH_ID	0x01

	uint32_t offset;
	uint32_t length;
	uint32_t checksum;
	uint8_t version[BE_VERSION_SIZE];

} emlxs_be3_image_header_t;

typedef struct emlxs_be3_ufi_header
{
	char signature[BE3_SIGNATURE_SIZE];
	uint32_t ufi_version;
	uint32_t file_length;
	uint32_t checksum;
	uint32_t antidote;
	uint32_t image_cnt;
	char build[BE_BUILD_SIZE];
	uint8_t resv1[32];

} emlxs_be3_ufi_header_t;

typedef struct emlxs_be3_ufi_controller
{
	uint32_t vendor_id;
	uint32_t device_id;
	uint32_t sub_vendor_id;
	uint32_t sub_device_id;

} emlxs_be3_ufi_controller_t;

typedef struct emlxs_be3_flash_header
{
	uint32_t format_rev;
	uint32_t checksum;
	uint32_t antidote;
	uint32_t entry_count;
	emlxs_be3_ufi_controller_t controller[BE_CONTROLLER_SIZE];
	uint32_t resv0;
	uint32_t resv1;
	uint32_t resv2;
	uint32_t resv3;
} emlxs_be3_flash_header_t;

typedef struct emlxs_be3_flash_entry
{
	uint32_t type;
	uint32_t offset;
	uint32_t block_size;
	uint32_t image_size;
	uint32_t checksum;
	uint32_t entry_point;
	uint32_t resv0;
	uint32_t resv1;
	char version[BE_VERSION_SIZE];

} emlxs_be3_flash_entry_t;

typedef struct emlxs_be3_flash_dir
{
	char cookie[BE_COOKIE_SIZE];
	emlxs_be3_flash_header_t header;
	emlxs_be3_flash_entry_t entry[BE_FLASH_ENTRIES];

} emlxs_be3_flash_dir_t;

typedef struct emlxs_be3_ncsi_header {
	uint32_t magic;
	uint8_t hdr_len;
	uint8_t type;
	uint16_t hdr_ver;
	uint16_t rsvd0;
	uint16_t load_offset;
	uint32_t len;
	uint32_t flash_offset;
	uint8_t ver[16];
	uint8_t name[24];
	uint32_t img_cksum;
	uint32_t rsvd1;
	uint32_t hdr_cksum;
} emlxs_be3_ncsi_header_t;


/* ************** BE2 **************** */
#define	BE2_SIGNATURE_SIZE	32


typedef struct emlxs_be2_ufi_controller
{
	uint32_t vendor_id;
	uint32_t device_id;
	uint32_t sub_vendor_id;
	uint32_t sub_device_id;

} emlxs_be2_ufi_controller_t;

typedef struct emlxs_be2_ufi_header
{
	char signature[BE2_SIGNATURE_SIZE];
	uint32_t checksum;
	uint32_t antidote;
	emlxs_be2_ufi_controller_t  controller;
	uint32_t file_length;
	uint32_t chunk_num;
	uint32_t chunk_cnt;
	uint32_t image_cnt;
	char build[BE_BUILD_SIZE];

} emlxs_be2_ufi_header_t;

typedef struct emlxs_be2_flash_header /* 96 bytes */
{
	uint32_t format_rev;
	uint32_t checksum;
	uint32_t antidote;
	uint32_t build_num;
	emlxs_be2_ufi_controller_t controller[BE_CONTROLLER_SIZE];
	uint32_t active_entry_mask;
	uint32_t valid_entry_mask;
	uint32_t orig_content_mask;
	uint32_t resv0;
	uint32_t resv1;
	uint32_t resv2;
	uint32_t resv3;
	uint32_t resv4;

} emlxs_be2_flash_header_t;

typedef struct emlxs_be2_flash_entry
{
	uint32_t type;
	uint32_t offset;
	uint32_t pad_size;
	uint32_t image_size;
	uint32_t checksum;
	uint32_t entry_point;
	uint32_t resv0;
	uint32_t resv1;
	char version[BE_VERSION_SIZE];

} emlxs_be2_flash_entry_t;

typedef struct emlxs_be2_flash_dir
{
	char cookie[BE_COOKIE_SIZE];
	emlxs_be2_flash_header_t header;
	emlxs_be2_flash_entry_t entry[BE_FLASH_ENTRIES];

} emlxs_be2_flash_dir_t;


/* FLASH ENTRY TYPES */
#define	BE_FLASHTYPE_NCSI_FIRMWARE		0x10 /* BE3 */
#define	BE_FLASHTYPE_PXE_BIOS			0x20
#define	BE_FLASHTYPE_FCOE_BIOS			0x21
#define	BE_FLASHTYPE_ISCSI_BIOS			0x22
#define	BE_FLASHTYPE_FLASH_ISM			0x30 /* BE3 */
#define	BE_FLASHTYPE_ISCSI_FIRMWARE		0xA0
#define	BE_FLASHTYPE_ISCSI_FIRMWARE_COMP	0xA1
#define	BE_FLASHTYPE_FCOE_FIRMWARE		0xA2
#define	BE_FLASHTYPE_FCOE_FIRMWARE_COMP		0xA3
#define	BE_FLASHTYPE_ISCSI_BACKUP		0xB0
#define	BE_FLASHTYPE_ISCSI_BACKUP_COMP		0xB1
#define	BE_FLASHTYPE_FCOE_BACKUP		0xB2
#define	BE_FLASHTYPE_FCOE_BACKUP_COMP		0xB3
#define	BE_FLASHTYPE_PHY_FIRMWARE		0xC0 /* 10Base-T */
#define	BE_FLASHTYPE_REDBOOT			0xE0

/* Flash types in download order */
typedef enum emlxs_be_flashtypes
{
	PHY_FIRMWARE_FLASHTYPE,
	NCSI_FIRMWARE_FLASHTYPE,
	ISCSI_FIRMWARE_FLASHTYPE,
	ISCSI_BACKUP_FLASHTYPE,
	FCOE_FIRMWARE_FLASHTYPE,
	FCOE_BACKUP_FLASHTYPE,
	ISCSI_BIOS_FLASHTYPE,
	FCOE_BIOS_FLASHTYPE,
	PXE_BIOS_FLASHTYPE,
	REDBOOT_FLASHTYPE,
	BE_MAX_FLASHTYPES

} emlxs_be_flashtypes_t;

/* Driver level constructs */
typedef struct emlxs_be_fw_file
{
	uint32_t 	be_version;
	uint32_t	ufi_plus;

	uint32_t	type;
	uint32_t	image_offset;
	uint32_t	image_size;
	uint32_t	block_size;
	uint32_t	block_crc;
	uint32_t	load_address; /* BE3 */
	char		label[BE_VERSION_SIZE];
} emlxs_be_fw_file_t;

typedef struct emlxs_be_fw_image
{
	uint32_t 	be_version;
	uint32_t	ufi_plus;

	uint32_t fcoe_version;
	char fcoe_label[BE_VERSION_SIZE];

	uint32_t iscsi_version;
	char iscsi_label[BE_VERSION_SIZE];

	emlxs_be_fw_file_t file[BE_MAX_FLASHTYPES];
} emlxs_be_fw_image_t;


typedef struct emlxs_obj_header
{
	uint32_t 	FileSize;

#ifdef EMLXS_BIG_ENDIAN
	uint16_t 	MagicNumHi;
	uint16_t 	MagicNumLo;

	uint32_t 	FileType:8;
	uint32_t 	Id:8;
	uint32_t 	rsvd0:16;
#endif

#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t 	MagicNumLo;
	uint16_t 	MagicNumHi;

	uint32_t 	rsvd0:16;
	uint32_t 	Id:8;
	uint32_t 	FileType:8;
#endif

#define	OBJ_MAGIC_NUM_HI		0xFEAA
#define	OBJ_MAGIC_NUM_LO		0x0001

#define	OBJ_GRP_FILE_TYPE		0xF7

#define	OBJ_LANCER_ID			0xA2

	char		RevName[128];
	char		Date[12];
	char		Revision[32];
} emlxs_obj_header_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_HW_H */
