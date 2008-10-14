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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_HW_H
#define	_EMLXS_HW_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef NPIV_SUPPORT
/* Maximum virtual ports per HBA (includes physical port) */
#define	MAX_VPORTS			256

#define	MAX_VPORTS_LIMITED		101
#else
/* Maximum virtual ports per HBA (includes physical port) */
#define	MAX_VPORTS			1
#define	MAX_VPORTS_LIMITED		1
#endif	/* NPIV_SUPPORT */


/* Maximum transfer size per operation */
#define	FC_MAX_TRANSFER			0x40000

#define	MAX_RINGS_AVAILABLE		4	/* # rings available */
#define	MAX_RINGS			4	/* Max # rings used */


#define	PCB_SIZE			128
#define	MBOX_SIZE			256
#define	MBOX_EXTENSION_OFFSET		MBOX_SIZE


#ifdef MBOX_EXT_SUPPORT
#define	MBOX_EXTENSION_SIZE		1024
#else
#define	MBOX_EXTENSION_SIZE		0
#endif	/* MBOX_EXT_SUPPORT */


#define	SLIM_IOCB_CMD_R0_ENTRIES	128	/* SLI FCP cmd ring entries  */
#define	SLIM_IOCB_RSP_R0_ENTRIES	128	/* SLI FCP rsp ring entries */
#define	SLIM_IOCB_CMD_R1_ENTRIES	32	/* SLI IP cmd ring entries */
#define	SLIM_IOCB_RSP_R1_ENTRIES	32	/* SLI IP rsp ring entries */
#define	SLIM_IOCB_CMD_R2_ENTRIES	16	/* SLI ELS cmd ring entries */
#define	SLIM_IOCB_RSP_R2_ENTRIES	16	/* SLI ELS rsp ring entries */
#define	SLIM_IOCB_CMD_R3_ENTRIES	8	/* SLI CT cmd ring entries */
#define	SLIM_IOCB_RSP_R3_ENTRIES	8	/* SLI CT rsp ring entries */
/* ------------------------------------------------------------------------- */
/* Total:	184 Cmd's + 184 Rsp's = 368	*/
/* Command and response entry counts are not required to be equal */

#define	SLIM_IOCB_CMD_ENTRIES \
	(SLIM_IOCB_CMD_R0_ENTRIES + SLIM_IOCB_CMD_R1_ENTRIES + \
	SLIM_IOCB_CMD_R2_ENTRIES + SLIM_IOCB_CMD_R3_ENTRIES)

#define	SLIM_IOCB_RSP_ENTRIES \
	(SLIM_IOCB_RSP_R0_ENTRIES + SLIM_IOCB_RSP_R1_ENTRIES + \
	SLIM_IOCB_RSP_R2_ENTRIES + SLIM_IOCB_RSP_R3_ENTRIES)

#define	SLIM_IOCB_ENTRIES \
	(SLIM_IOCB_CMD_ENTRIES + SLIM_IOCB_RSP_ENTRIES)


/* SLI1 Definitions */
#define	SLI_SLIM1_SIZE			4096	/* Fixed size memory */


/* SLI2 Definitions */
#define	SLI2_IOCB_CMD_SIZE		32
#define	SLI2_IOCB_RSP_SIZE		32
#define	SLI2_IOCB_MAX_SIZE \
	((SLI2_IOCB_CMD_SIZE * SLIM_IOCB_CMD_ENTRIES)+ \
	(SLI2_IOCB_RSP_SIZE * SLIM_IOCB_RSP_ENTRIES))
#define	SLI2_SLIM2_SIZE \
	(MBOX_SIZE + MBOX_EXTENSION_SIZE + PCB_SIZE + SLI2_IOCB_MAX_SIZE)

/* SLI3 Definitions */
#define	SLI3_MAX_BDE			7
#define	SLI3_IOCB_CMD_SIZE		128
#define	SLI3_IOCB_RSP_SIZE		64
#define	SLI3_IOCB_MAX_SIZE \
	((SLI3_IOCB_CMD_SIZE * SLIM_IOCB_CMD_ENTRIES) + \
	(SLI3_IOCB_RSP_SIZE * SLIM_IOCB_RSP_ENTRIES))
#define	SLI3_SLIM2_SIZE \
	(MBOX_SIZE + MBOX_EXTENSION_SIZE + PCB_SIZE + SLI3_IOCB_MAX_SIZE)


#ifdef SLI3_SUPPORT
#define	SLI_SLIM2_SIZE			SLI3_SLIM2_SIZE
#define	SLI_IOCB_MAX_SIZE		SLI3_IOCB_MAX_SIZE
#else	/* SLI2_SUPPORT */
#define	SLI_SLIM2_SIZE			SLI2_SLIM2_SIZE
#define	SLI_IOCB_MAX_SIZE		SLI2_IOCB_MAX_SIZE
#endif	/* SLI3_SUPPORT */



#define	FC_MAXRETRY		3	/* max retries for ELS commands */
#define	FC_FCP_RING		0	/* use ring 0 for FCP initiator cmd */
#define	FC_FCT_RING		0	/* use ring 0 for FCP target cmd */

#define	FC_IP_RING		1	/* use ring 1 for IP commands */
#define	FC_ELS_RING		2	/* use ring 2 for ELS commands */
#define	FC_CT_RING		3	/* use ring 3 for CT commands */

#define	FF_DEF_EDTOV		2000	/* Default E_D_TOV (2000ms) */
#define	FF_DEF_ALTOV		15	/* Default AL_TIME (15ms) */
#define	FF_DEF_RATOV		2	/* Default RA_TOV (2s) */
#define	FF_DEF_ARBTOV		1900	/* Default ARB_TOV (1900ms) */

/* max msg data in CMD_ADAPTER_MSG iocb */
#define	MAX_MSG_DATA		28

#define	FF_REG_AREA_SIZE	256	/* size in bytes of i/o reg area */

/*
 * Miscellaneous stuff....
 */
/* HBA Mgmt */
#define	FDMI_DID		((uint32_t)0xfffffa)
#define	NameServer_DID		((uint32_t)0xfffffc)
#define	SCR_DID			((uint32_t)0xfffffd)
#define	Fabric_DID		((uint32_t)0xfffffe)
#define	Bcast_DID		((uint32_t)0xffffff)
#define	Mask_DID		((uint32_t)0xffffff)
#define	CT_DID_MASK		((uint32_t)0xffff00)
#define	Fabric_DID_MASK		((uint32_t)0xfff000)
#define	WELL_KNOWN_DID_MASK	((uint32_t)0xfffff0)

#define	EMLXS_MENLO_DID		((uint32_t)0x00fc0e)


#define	PT2PT_LocalID   ((uint32_t)1)
#define	PT2PT_RemoteID  ((uint32_t)2)

#define	OWN_CHIP	1	/* IOCB / Mailbox is owned by FireFly */
#define	OWN_HOST	0	/* IOCB / Mailbox is owned by Host */
#define	END_OF_CHAIN    0



/* defines for type field in fc header */
#define	FC_ELS_DATA		0x01
#define	FC_LLC_SNAP		0x05
#define	FC_FCP_DATA		0x08
#define	FC_CT_TYPE		0x20
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

typedef union CtRevisionId {
	/* Structure is in Big Endian format */
	struct {
		uint32_t Revision:8;
		uint32_t InId:24;
	} bits;
	uint32_t word;

} CtRevisionId_t;

typedef union CtCommandResponse {
	/* Structure is in Big Endian format */
	struct {
		uint32_t CmdRsp:16;
		uint32_t Size:16;
	} bits;
	uint32_t word;

} CtCommandResponse_t;

typedef struct SliCtRequest {
	/* Structure is in Big Endian format */
	CtRevisionId_t RevisionId;
	uint8_t FsType;
	uint8_t FsSubType;
	uint8_t Options;
	uint8_t Rsrvd1;
	CtCommandResponse_t CommandResponse;
	uint8_t Rsrvd2;
	uint8_t ReasonCode;
	uint8_t Explanation;
	uint8_t VendorUnique;

	union {
		uint32_t data;
		uint32_t PortID;

		struct gid {
			uint8_t PortType;	/* for GID_PT requests */
			uint8_t DomainScope;
			uint8_t AreaScope;
			uint8_t Fc4Type;	/* for GID_FT requests */
		} gid;
		struct rft {
			uint32_t PortId;	/* For RFT_ID requests */
#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd0:16;
			uint32_t rsvd1:7;
			uint32_t fcpReg:1;	/* Type 8 */
			uint32_t rsvd2:2;
			uint32_t ipReg:1;	/* Type 5 */
			uint32_t rsvd3:5;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t rsvd0:16;
			uint32_t fcpReg:1;	/* Type 8 */
			uint32_t rsvd1:7;
			uint32_t rsvd3:5;
			uint32_t ipReg:1;	/* Type 5 */
			uint32_t rsvd2:2;
#endif
			uint32_t rsvd[7];
		} rft;

		struct rsnn {
			uint8_t wwnn[8];
			uint8_t snn_len;
			char snn[256];
		} rsnn;

		struct rspn {
			uint32_t PortId;
			uint8_t spn_len;
			char spn[256];
		} rspn;

	} un;


} SliCtRequest_t;
typedef SliCtRequest_t SLI_CT_REQUEST;

#define	SLI_CT_REVISION		1


/*
 * FsType Definitions
 */

#define	 SLI_CT_MANAGEMENT_SERVICE		0xFA
#define	 SLI_CT_TIME_SERVICE			0xFB
#define	 SLI_CT_DIRECTORY_SERVICE		0xFC
#define	 SLI_CT_FABRIC_CONTROLLER_SERVICE	0xFD

/*
 * Directory Service Subtypes
 */

#define	 SLI_CT_DIRECTORY_NAME_SERVER	0x02

/*
 * Response Codes
 */

#define	 SLI_CT_RESPONSE_FS_RJT		0x8001
#define	 SLI_CT_RESPONSE_FS_ACC		0x8002

/*
 * Reason Codes
 */

#define	 SLI_CT_NO_ADDITIONAL_EXPL		0x0
#define	 SLI_CT_INVALID_COMMAND			0x01
#define	 SLI_CT_INVALID_VERSION			0x02
#define	 SLI_CT_LOGICAL_ERROR			0x03
#define	 SLI_CT_INVALID_IU_SIZE			0x04
#define	 SLI_CT_LOGICAL_BUSY			0x05
#define	 SLI_CT_PROTOCOL_ERROR			0x07
#define	 SLI_CT_UNABLE_TO_PERFORM_REQ		0x09
#define	 SLI_CT_REQ_NOT_SUPPORTED		0x0b
#define	 SLI_CT_HBA_INFO_NOT_REGISTERED		0x10
#define	 SLI_CT_MULTIPLE_HBA_ATTR_OF_SAME_TYPE	0x11
#define	 SLI_CT_INVALID_HBA_ATTR_BLOCK_LEN	0x12
#define	 SLI_CT_HBA_ATTR_NOT_PRESENT		0x13
#define	 SLI_CT_PORT_INFO_NOT_REGISTERED	0x20
#define	 SLI_CT_MULTIPLE_PORT_ATTR_OF_SAME_TYPE	0x21
#define	 SLI_CT_INVALID_PORT_ATTR_BLOCK_LEN	0x22
#define	 SLI_CT_VENDOR_UNIQUE			0xff

/*
 * Name Server SLI_CT_UNABLE_TO_PERFORM_REQ Explanations
 */

#define	 SLI_CT_NO_PORT_ID		0x01
#define	 SLI_CT_NO_PORT_NAME		0x02
#define	 SLI_CT_NO_NODE_NAME		0x03
#define	 SLI_CT_NO_CLASS_OF_SERVICE	0x04
#define	 SLI_CT_NO_IP_ADDRESS		0x05
#define	 SLI_CT_NO_IPA			0x06
#define	 SLI_CT_NO_FC4_TYPES		0x07
#define	 SLI_CT_NO_SYMBOLIC_PORT_NAME	0x08
#define	 SLI_CT_NO_SYMBOLIC_NODE_NAME	0x09
#define	 SLI_CT_NO_PORT_TYPE		0x0A
#define	 SLI_CT_ACCESS_DENIED		0x10
#define	 SLI_CT_INVALID_PORT_ID		0x11
#define	 SLI_CT_DATABASE_EMPTY		0x12

#ifdef EMLXS_BIG_ENDIAN
#define	CT_CMD_MASK	0xffff0000
#endif

#ifdef EMLXS_LITTLE_ENDIAN
#define	CT_CMD_MASK	0xffff
#endif

/*
 * Management Server Interface Command Codes
 */

#define	 MS_GTIN		0x0100
#define	 MS_GIEL		0x0101
#define	 MS_GIET		0x0111
#define	 MS_GDID		0x0112
#define	 MS_GMID		0x0113
#define	 MS_GFN			0x0114
#define	 MS_GIELN		0x0115
#define	 MS_GMAL		0x0116
#define	 MS_GIEIL		0x0117
#define	 MS_GPL			0x0118
#define	 MS_GPT			0x0121
#define	 MS_GPPN		0x0122
#define	 MS_GAPNL		0x0124
#define	 MS_GPS			0x0126
#define	 MS_GPSC		0x0127
#define	 MS_GATIN		0x0128
#define	 MS_GSES		0x0130
#define	 MS_GPLNL		0x0191
#define	 MS_GPLT		0x0192
#define	 MS_GPLML		0x0193
#define	 MS_GPAB		0x0197
#define	 MS_GNPL		0x01A1
#define	 MS_GPNL		0x01A2
#define	 MS_GPFCP		0x01A4
#define	 MS_GPLI		0x01A5
#define	 MS_GNID		0x01B1
#define	 MS_RIELN		0x0215
#define	 MS_RPL			0x0280
#define	 MS_RPLN		0x0291
#define	 MS_RPLT		0x0292
#define	 MS_RPLM		0x0293
#define	 MS_RPAB		0x0298
#define	 MS_RPFCP		0x029A
#define	 MS_RPLI		0x029B
#define	 MS_DPL			0x0380
#define	 MS_DPLN		0x0391
#define	 MS_DPLM		0x0392
#define	 MS_DPLML		0x0393
#define	 MS_DPLI		0x0394
#define	 MS_DPAB		0x0395
#define	 MS_DPALL		0x039F


/*
 * Name Server Command Codes
 */
#define	 SLI_CTNS_GA_NXT	0x0100
#define	 SLI_CTNS_GPN_ID	0x0112
#define	 SLI_CTNS_GNN_ID	0x0113
#define	 SLI_CTNS_GCS_ID	0x0114
#define	 SLI_CTNS_GFT_ID	0x0117
#define	 SLI_CTNS_GSPN_ID	0x0118
#define	 SLI_CTNS_GPT_ID	0x011A
#define	 SLI_CTNS_GID_PN	0x0121
#define	 SLI_CTNS_GID_NN	0x0131
#define	 SLI_CTNS_GIP_NN	0x0135
#define	 SLI_CTNS_GIPA_NN	0x0136
#define	 SLI_CTNS_GSNN_NN	0x0139
#define	 SLI_CTNS_GNN_IP	0x0153
#define	 SLI_CTNS_GIPA_IP	0x0156
#define	 SLI_CTNS_GID_FT	0x0171
#define	 SLI_CTNS_GID_PT	0x01A1
#define	 SLI_CTNS_RPN_ID	0x0212
#define	 SLI_CTNS_RNN_ID	0x0213
#define	 SLI_CTNS_RCS_ID	0x0214
#define	 SLI_CTNS_RFT_ID	0x0217
#define	 SLI_CTNS_RSPN_ID	0x0218
#define	 SLI_CTNS_RPT_ID	0x021A
#define	 SLI_CTNS_RIP_NN	0x0235
#define	 SLI_CTNS_RIPA_NN	0x0236
#define	 SLI_CTNS_RSNN_NN	0x0239
#define	 SLI_CTNS_DA_ID		0x0300

#define	 SLI_CT_LOOPBACK	0xFCFC


/*
 * Port Types
 */

#define	 SLI_CTPT_N_PORT	0x01
#define	 SLI_CTPT_NL_PORT	0x02
#define	 SLI_CTPT_FNL_PORT	0x03
#define	 SLI_CTPT_IP		0x04
#define	 SLI_CTPT_FCP		0x08
#define	 SLI_CTPT_NX_PORT	0x7F
#define	 SLI_CTPT_F_PORT	0x81
#define	 SLI_CTPT_FL_PORT	0x82
#define	 SLI_CTPT_E_PORT	0x84

#define	SLI_CT_LAST_ENTRY	0x80000000

/* ===================================================================== */

/*
 * Start FireFly Register definitions
 */

/* PCI register offsets */
#define	MEM_ADDR_OFFSET 0x10	/* SLIM base memory address */
#define	MEMH_OFFSET	0x14	/* SLIM base memory high address */
#define	REG_ADDR_OFFSET 0x18	/* REGISTER base memory address */
#define	REGH_OFFSET	0x1c	/* REGISTER base memory high address */
#define	IO_ADDR_OFFSET  0x20	/* BIU I/O registers */
#define	REGIOH_OFFSET   0x24	/* REGISTER base io high address */

#define	CMD_REG_OFFSET  0x4	/* PCI command configuration */

/* General PCI Register Definitions */
/* Refer To The PCI Specification For Detailed Explanations */

/* Register Offsets in little endian format */
#define	PCI_VENDOR_ID_REGISTER		0x00	/* PCI Vendor ID Register */
#define	PCI_DEVICE_ID_REGISTER		0x02	/* PCI Device ID Register */
#define	PCI_CONFIG_ID_REGISTER		0x00	/* PCI Configuration ID Reg */
#define	PCI_COMMAND_REGISTER		0x04	/* PCI Command Register */
#define	PCI_STATUS_REGISTER		0x06	/* PCI Status Register */
#define	PCI_REV_ID_REGISTER		0x08	/* PCI Revision ID Register */
#define	PCI_CLASS_CODE_REGISTER		0x09	/* PCI Class Code Register */
#define	PCI_CACHE_LINE_REGISTER		0x0C	/* PCI Cache Line Register */
#define	PCI_LATENCY_TMR_REGISTER	0x0D	/* PCI Latency Timer Register */
#define	PCI_HEADER_TYPE_REGISTER	0x0E	/* PCI Header Type Register */
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
#define	PCI_INTR_LINE_REGISTER		0x3C	/* PCI Interrupt Line Reg */
#define	PCI_INTR_PIN_REGISTER		0x3D	/* PCI Interrupt Pin Register */
#define	PCI_MIN_GNT_REGISTER		0x3E	/* PCI Min-Gnt Register */
#define	PCI_MAX_LAT_REGISTER		0x3F	/* PCI Max_Lat Register */
#define	PCI_NODE_ADDR_REGISTER		0x40	/* PCI Node Address Register */

#define	PCI_PM_CONTROL_REGISTER		0x50	/* PCI Power Mgmt Ctrl Reg */

/* PCIe adapters only */
#define	PCIe_MSI_CONTROL_REG0		0x60	/* MSI Control */
#define	PCIe_MSI_CONTROL_REG1		0x62	/* MSI Control */

/* Power management command states */
#define	PCI_PM_D0_STATE			0x00	/* Power up state */
#define	PCI_PM_D3_STATE			0x03	/* Power down state */


/* PCI access methods */
#define	P_CONF_T1	1
#define	P_CONF_T2	2

/* max number of pci buses */
#define	MAX_PCI_BUSES   0xFF

/* number of PCI config bytes to access */
#define	PCI_BYTE	1
#define	PCI_WORD	2
#define	PCI_DWORD	4

/* PCI related constants */
#define	CMD_IO_ENBL	0x0001
#define	CMD_MEM_ENBL    0x0002
#define	CMD_BUS_MASTER  0x0004
#define	CMD_MWI		0x0010
#define	CMD_PARITY_CHK  0x0040
#define	CMD_SERR_ENBL   0x0100

#define	CMD_CFG_VALUE   0x156	/* mem enable, master, MWI, SERR, PERR */

/* PCI addresses */
#define	PCI_SPACE_ENABLE		0x0CF8
#define	CF1_CONFIG_ADDR_REGISTER	0x0CF8
#define	CF1_CONFIG_DATA_REGISTER	0x0CFC
#define	CF2_FORWARD_REGISTER		0x0CFA
#define	CF2_BASE_ADDRESS		0xC000


/*
 * 0xF8 is a special value for FF11.1N6 firmware.
 * Use 0x80 for pre-FF11.1N6 &N7, etc
 */
#define	DEFAULT_PCI_LATENCY_CLOCKS	0xf8
#define	PCI_LATENCY_VALUE		0xf8



/* ==== Register Bit Definitions ==== */

/* Used by SBUS adapter */
/* SBUS Control Register */
#define	SBUS_CTRL_REG_OFFSET	0	/* Word offset from reg base addr */

#define	SBUS_CTRL_SBRST 	0x00000001	/* Bit  0 */
#define	SBUS_CTRL_BKOFF 	0x00000002	/* Bit  1 */
#define	SBUS_CTRL_ENP 		0x00000004	/* Bit  2 */
#define	SBUS_CTRL_EN64		0x00000008	/* Bit  3 */
/* Bit [6:4] IRL 1, lowset priority */
#define	SBUS_CTRL_SIR_1 	0x00000010

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
#define	EMLXS_MSI_MAP8 \
	{0, HA_R0ATT, HA_R1ATT, HA_R2ATT, HA_R3ATT, HA_LATT, HA_MBATT, HA_ERATT}
#define	EMLXS_MSI_MAP4 \
	{0, HA_R0ATT, HA_R1ATT, HA_R2ATT, 0, 0, 0, 0}
#define	EMLXS_MSI_MAP2		{0, HA_R0ATT, 0, 0, 0, 0, 0, 0}
#define	EMLXS_MSI_MAP1		{0, 0, 0, 0, 0, 0, 0, 0}

/* MSI 0 interrupt mask */
#define	EMLXS_MSI0_MASK8    0
#define	EMLXS_MSI0_MASK4   (HC_R3INT_ENA|HC_MBINT_ENA|HC_LAINT_ENA|HC_ERINT_ENA)
#define	EMLXS_MSI0_MASK2 \
	(HC_R1INT_ENA|HC_R2INT_ENA|HC_R3INT_ENA|HC_MBINT_ENA| \
	HC_LAINT_ENA|HC_ERINT_ENA)
#define	EMLXS_MSI0_MASK1 \
	(HC_R0INT_ENA|HC_R1INT_ENA|HC_R2INT_ENA|HC_R3INT_ENA| \
	HC_MBINT_ENA|HC_LAINT_ENA|HC_ERINT_ENA)


#define	EMLXS_MSI_MAX_INTRS		8

#define	EMLXS_MSI_MODE1			0
#define	EMLXS_MSI_MODE2			1
#define	EMLXS_MSI_MODE4			2
#define	EMLXS_MSI_MODE8			3
#define	EMLXS_MSI_MODES			4

#endif	/* MSI_SUPPORT */


#define	IO_THROTTLE_RESERVE		12




/* Chip Attention Register */

#define	CA_REG_OFFSET  1	/* Word offset from register base address */

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

#define	HS_REG_OFFSET  2	/* Word offset from register base address */

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

#define	HC_REG_OFFSET  3	/* Word offset from register base address */

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

#define	BC_REG_OFFSET  4	/* Word offset from register base address */

#define	BC_BSE		0x00000001	/* Bit 0 */
#define	BC_BSE_SWAP	0x01000000	/* Bit 0 - swapped */


/*
 * End FireFly Register definitions
 */

/* ===================================================================== */

/*
 * Start of FCP specific structures
 */

typedef struct emlxs_fcp_rsp {
	uint32_t rspRsvd1;	/* FC Word 0, byte 0:3 */
	uint32_t rspRsvd2;	/* FC Word 1, byte 0:3 */

	uint8_t rspStatus0;	/* FCP_STATUS byte 0 (reserved) */
	uint8_t rspStatus1;	/* FCP_STATUS byte 1 (reserved) */
	uint8_t rspStatus2;	/* FCP_STATUS byte 2 field validity */
#define	RSP_LEN_VALID	0x01	/* bit 0 */
#define	SNS_LEN_VALID	0x02	/* bit 1 */
#define	RESID_OVER	0x04	/* bit 2 */
#define	RESID_UNDER	0x08	/* bit 3 */
	uint8_t rspStatus3;	/* FCP_STATUS byte 3 SCSI status byte */
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

	uint32_t rspResId;	/* Resid xfer if RESID_xxxx set in fcpStatus2 */
	/* Received in Big Endian format */
	uint32_t rspSnsLen;	/* Length of sense data in fcpSnsInfo */
	/* Received in Big Endian format */
	uint32_t rspRspLen;	/* Length of FCP response data in fcpRspInfo */
	/* Received in Big Endian format */

	uint8_t rspInfo0;	/* FCP_RSP_INFO byte 0 (reserved) */
	uint8_t rspInfo1;	/* FCP_RSP_INFO byte 1 (reserved) */
	uint8_t rspInfo2;	/* FCP_RSP_INFO byte 2 (reserved) */
	uint8_t rspInfo3;	/* FCP_RSP_INFO RSP_CODE byte 3 */

#define	RSP_NO_FAILURE		0x00
#define	RSP_DATA_BURST_ERR	0x01
#define	RSP_CMD_FIELD_ERR	0x02
#define	RSP_RO_MISMATCH_ERR	0x03
#define	RSP_TM_NOT_SUPPORTED	0x04	/* Task mgmt function not supported */
#define	RSP_TM_NOT_COMPLETED	0x05	/* Task mgmt function not performed */

	uint32_t rspInfoRsvd;	/* FCP_RSP_INFO bytes 4-7 (reserved) */

	/*
	 * Define maximum size of SCSI Sense buffer. Seagate never issues
	 * more than 18 bytes of Sense data
	 */
#define	MAX_FCP_SNS  128
	uint8_t rspSnsInfo[MAX_FCP_SNS];

} emlxs_fcp_rsp;
typedef emlxs_fcp_rsp FCP_RSP;


typedef struct emlxs_fcp_cmd {
	uint32_t fcpLunMsl;	/* most  significant lun word (32 bits) */
	uint32_t fcpLunLsl;	/* least significant lun word (32 bits) */

	/*
	 * # of bits to shift lun id to end up in right payload word, little
	 * endian = 8, big = 16.
	 */
#ifdef EMLXS_LITTLE_ENDIAN
#define	FC_LUN_SHIFT		8
#define	FC_ADDR_MODE_SHIFT	0
#endif
#ifdef EMLXS_BIG_ENDIAN
#define	FC_LUN_SHIFT		16
#define	FC_ADDR_MODE_SHIFT	24
#endif

	uint8_t fcpCntl0;	/* FCP_CNTL byte 0 (reserved) */
	uint8_t fcpCntl1;	/* FCP_CNTL byte 1 task codes */
#define	 SIMPLE_Q	0x00
#define	 HEAD_OF_Q	0x01
#define	 ORDERED_Q	0x02
#define	 ACA_Q		0x04
#define	 UNTAGGED	0x05
	uint8_t fcpCntl2;	/* FCP_CTL byte 2 task management codes */
#define	 ABORT_TASK_SET	0x02	/* Bit 1 */
#define	 CLEAR_TASK_SET	0x04	/* bit 2 */
#define	 LUN_RESET	0x10	/* bit 4 */
#define	 TARGET_RESET	0x20	/* bit 5 */
#define	 CLEAR_ACA	0x40	/* bit 6 */
#define	 TERMINATE_TASK	0x80	/* bit 7 */
	uint8_t fcpCntl3;
#define	 WRITE_DATA	0x01	/* Bit 0 */
#define	 READ_DATA	0x02	/* Bit 1 */

	uint8_t fcpCdb[16];	/* SRB cdb field is copied here */
	uint32_t fcpDl;	/* Total transfer length */

} emlxs_fcp_cmd_t;
typedef emlxs_fcp_cmd_t FCP_CMND;










/* SCSI INQUIRY Command Structure */

typedef struct emlxs_inquiryDataType {
	uint8_t DeviceType:5;
	uint8_t DeviceTypeQualifier:3;

	uint8_t DeviceTypeModifier:7;
	uint8_t RemovableMedia:1;

	uint8_t Versions;
	uint8_t ResponseDataFormat;
	uint8_t AdditionalLength;
	uint8_t Reserved[2];

	uint8_t SoftReset:1;
	uint8_t CommandQueue:1;
	uint8_t Reserved2:1;
	uint8_t LinkedCommands:1;
	uint8_t Synchronous:1;
	uint8_t Wide16Bit:1;
	uint8_t Wide32Bit:1;
	uint8_t RelativeAddressing:1;

	uint8_t VendorId[8];
	uint8_t ProductId[16];
	uint8_t ProductRevisionLevel[4];
	uint8_t VendorSpecific[20];
	uint8_t Reserved3[40];

} emlxs_inquiry_data_type_t;
typedef emlxs_inquiry_data_type_t INQUIRY_DATA_DEF;


typedef struct emlxs_read_capacity_data {
	uint32_t LogicalBlockAddress;
	uint32_t BytesPerBlock;

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

#define	FL_ALPA    0x00	/* AL_PA of FL_Port */

/* Fibre Channel Service Parameter definitions */

#define	FC_PH_4_0   6	/* FC-PH version 4.0 */
#define	FC_PH_4_1   7	/* FC-PH version 4.1 */
#define	FC_PH_4_2   8	/* FC-PH version 4.2 */
#define	FC_PH_4_3   9	/* FC-PH version 4.3 */

#define	FC_PH_LOW   8	/* Lowest supported FC-PH version */
#define	FC_PH_HIGH  9	/* Highest supported FC-PH version */
#define	FC_PH3   0x20	/* FC-PH-3 version */

#define	FF_FRAME_SIZE		2048


/* ==== Mailbox Commands ==== */
#define	MBX_SHUTDOWN		0x00	/* terminate testing */
#define	MBX_LOAD_SM		0x01
#define	MBX_READ_NV		0x02
#define	MBX_WRITE_NV		0x03
#define	MBX_RUN_BIU_DIAG	0x04
#define	MBX_INIT_LINK		0x05
#define	MBX_DOWN_LINK		0x06
#define	MBX_CONFIG_LINK		0x07
#define	MBX_PART_SLIM		0x08
#define	MBX_CONFIG_RING		0x09
#define	MBX_RESET_RING		0x0A
#define	MBX_READ_CONFIG		0x0B
#define	MBX_READ_RCONFIG	0x0C
#define	MBX_READ_SPARM		0x0D
#define	MBX_READ_STATUS		0x0E
#define	MBX_READ_RPI		0x0F
#define	MBX_READ_XRI		0x10
#define	MBX_READ_REV		0x11
#define	MBX_READ_LNK_STAT	0x12
#define	MBX_REG_LOGIN		0x13
#define	MBX_UNREG_LOGIN		0x14
#define	MBX_READ_LA		0x15
#define	MBX_CLEAR_LA		0x16
#define	MBX_DUMP_MEMORY		0x17
#define	MBX_DUMP_CONTEXT	0x18
#define	MBX_RUN_DIAGS		0x19
#define	MBX_RESTART		0x1A
#define	MBX_UPDATE_CFG		0x1B
#define	MBX_DOWN_LOAD		0x1C
#define	MBX_DEL_LD_ENTRY	0x1D
#define	MBX_RUN_PROGRAM		0x1E
#define	MBX_SET_MASK		0x20
#define	MBX_SET_VARIABLE	0x21
#define	MBX_UNREG_D_ID		0x23
#define	MBX_KILL_BOARD		0x24
#define	MBX_CONFIG_FARP		0x25
#define	MBX_BEACON		0x2A
#define	MBX_CONFIG_MSIX		0x30
#define	MBX_HEARTBEAT		0x31
#define	MBX_WRITE_VPARMS	0x32
#define	MBX_ASYNC_EVENT		0x33

#define	MBX_READ_EVENT_LOG_STATUS	0x37
#define	MBX_READ_EVENT_LOG	0x38
#define	MBX_WRITE_EVENT_LOG	0x39
#define	MBX_NV_LOG			0x3A


#define	MBX_CONFIG_HBQ		0x7C	/* SLI3 */
#define	MBX_LOAD_AREA		0x81
#define	MBX_RUN_BIU_DIAG64	0x84
#define	MBX_GET_DEBUG		0x86
#define	MBX_CONFIG_PORT		0x88
#define	MBX_READ_SPARM64	0x8D
#define	MBX_READ_RPI64		0x8F
#define	MBX_CONFIG_MSI		0x90
#define	MBX_REG_LOGIN64		0x93
#define	MBX_READ_LA64		0x95
#define	MBX_REG_VPI		0x96	/* NPIV */
#define	MBX_UNREG_VPI		0x97	/* NPIV */
#define	MBX_FLASH_WR_ULA	0x98
#define	MBX_SET_DEBUG		0x99
#define	MBX_LOAD_EXP_ROM	0x9C
#define	MBX_MAX_CMDS		0x9D
#define	MBX_SLI2_CMD_MASK	0x80


/* ==== IOCB Commands ==== */

#define	CMD_RCV_SEQUENCE_CX	0x01
#define	CMD_XMIT_SEQUENCE_CR    0x02
#define	CMD_XMIT_SEQUENCE_CX    0x03
#define	CMD_XMIT_BCAST_CN	0x04
#define	CMD_XMIT_BCAST_CX	0x05
#define	CMD_QUE_RING_BUF_CN	0x06
#define	CMD_QUE_XRI_BUF_CX	0x07
#define	CMD_IOCB_CONTINUE_CN    0x08
#define	CMD_RET_XRI_BUF_CX	0x09
#define	CMD_ELS_REQUEST_CR	0x0A
#define	CMD_ELS_REQUEST_CX	0x0B
#define	CMD_RCV_ELS_REQ_CX	0x0D
#define	CMD_ABORT_XRI_CN	0x0E
#define	CMD_ABORT_XRI_CX	0x0F
#define	CMD_CLOSE_XRI_CN	0x10
#define	CMD_CLOSE_XRI_CX	0x11
#define	CMD_CREATE_XRI_CR	0x12
#define	CMD_CREATE_XRI_CX	0x13
#define	CMD_GET_RPI_CN		0x14
#define	CMD_XMIT_ELS_RSP_CX	0x15
#define	CMD_GET_RPI_CR		0x16
#define	CMD_XRI_ABORTED_CX	0x17
#define	CMD_FCP_IWRITE_CR	0x18
#define	CMD_FCP_IWRITE_CX	0x19
#define	CMD_FCP_IREAD_CR	0x1A
#define	CMD_FCP_IREAD_CX	0x1B
#define	CMD_FCP_ICMND_CR	0x1C
#define	CMD_FCP_ICMND_CX	0x1D
#define	CMD_FCP_TSEND_CX	0x1F	/* FCP_TARGET_MODE */
#define	CMD_ADAPTER_MSG		0x20
#define	CMD_FCP_TRECEIVE_CX	0x21	/* FCP_TARGET_MODE */
#define	CMD_ADAPTER_DUMP	0x22
#define	CMD_FCP_TRSP_CX		0x23	/* FCP_TARGET_MODE */
#define	CMD_FCP_AUTO_TRSP_CX	0x29	/* FCP_TARGET_MODE */

/* LP3000 gasket IOCB Command Set */

#define	CMD_BPL_IWRITE_CR	0x48
#define	CMD_BPL_IWRITE_CX	0x49
#define	CMD_BPL_IREAD_CR	0x4A
#define	CMD_BPL_IREAD_CX	0x4B
#define	CMD_BPL_ICMND_CR	0x4C
#define	CMD_BPL_ICMND_CX	0x4D

#define	CMD_ASYNC_STATUS	0x7C

/* SLI_2 IOCB Command Set */
#define	CMD_RCV_SEQUENCE64_CX   0x81
#define	CMD_XMIT_SEQUENCE64_CR  0x82
#define	CMD_XMIT_SEQUENCE64_CX  0x83
#define	CMD_XMIT_BCAST64_CN	0x84
#define	CMD_XMIT_BCAST64_CX	0x85
#define	CMD_QUE_RING_BUF64_CN   0x86
#define	CMD_QUE_XRI_BUF64_CX    0x87
#define	CMD_IOCB_CONTINUE64_CN  0x88
#define	CMD_RET_XRI_BUF64_CX    0x89
#define	CMD_ELS_REQUEST64_CR    0x8A
#define	CMD_ELS_REQUEST64_CX    0x8B
#define	CMD_RCV_ELS_REQ64_CX    0x8D
#define	CMD_XMIT_ELS_RSP64_CX   0x95
#define	CMD_FCP_IWRITE64_CR	0x98
#define	CMD_FCP_IWRITE64_CX	0x99
#define	CMD_FCP_IREAD64_CR	0x9A
#define	CMD_FCP_IREAD64_CX	0x9B
#define	CMD_FCP_ICMND64_CR	0x9C
#define	CMD_FCP_ICMND64_CX	0x9D
#define	CMD_FCP_TSEND64_CX	0x9F	/* FCP_TARGET_MODE */
#define	CMD_FCP_TRECEIVE64_CX   0xA1	/* FCP_TARGET_MODE */
#define	CMD_FCP_TRSP64_CX	0xA3	/* FCP_TARGET_MODE */
#define	CMD_RCV_SEQ64_CX	0xB5	/* SLI3 */
#define	CMD_RCV_ELS64_CX	0xB7	/* SLI3 */
#define	CMD_RCV_CONT64_CX	0xBB	/* SLI3 */
#define	CMD_RCV_SEQ_LIST64_CX   0xC1
#define	CMD_GEN_REQUEST64_CR	0xC2
#define	CMD_GEN_REQUEST64_CX	0xC3
#define	CMD_QUE_RING_LIST64_CN  0xC6

/*
 * Define Status
 */
#define	MBX_SUCCESS			0
#define	MBX_FAILURE			1
#define	MBXERR_NUM_IOCBS		2
#define	MBXERR_IOCBS_EXCEEDED		3
#define	MBXERR_BAD_RING_NUMBER		4
#define	MBXERR_MASK_ENTRIES_RANGE	5
#define	MBXERR_MASKS_EXCEEDED		6
#define	MBXERR_BAD_PROFILE		7
#define	MBXERR_BAD_DEF_CLASS		8
#define	MBXERR_BAD_MAX_RESPONDER	9
#define	MBXERR_BAD_MAX_ORIGINATOR	0xA
#define	MBXERR_RPI_REGISTERED		0xB
#define	MBXERR_RPI_FULL			0xC
#define	MBXERR_NO_RESOURCES		0xD
#define	MBXERR_BAD_RCV_LENGTH		0xE
#define	MBXERR_DMA_ERROR		0xF
#define	MBXERR_NOT_SUPPORTED		0x10
#define	MBXERR_UNSUPPORTED_FEATURE	0x11
#define	MBXERR_UNKNOWN_COMMAND		0x12

/* Driver special codes */
#define	MBX_OVERTEMP_ERROR		0xFA
#define	MBX_HARDWARE_ERROR		0xFB
#define	MBX_DRVR_ERROR			0xFC
#define	MBX_BUSY			0xFD
#define	MBX_TIMEOUT			0xFE
#define	MBX_NOT_FINISHED		0xFF


/*
 * flags for emlxs_mb_issue_cmd()
 */
#define	MBX_POLL	0x01	/* poll mbx till cmd done, then return */
#define	MBX_SLEEP	0x02	/* sleep till mbx intr cmpl wakes thread up */
#define	MBX_WAIT	0x03	/* wait for comand done, then return */
#define	MBX_NOWAIT	0x04	/* issue command then return immediately */

typedef struct emlxs_rings {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t crReserved:16;
	uint32_t crBegin:8;
	uint32_t crEnd:8;	/* Low order bit first word */
	uint32_t rrReserved:16;
	uint32_t rrBegin:8;
	uint32_t rrEnd:8;	/* Low order bit second word */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t crEnd:8;	/* Low order bit first word */
	uint32_t crBegin:8;
	uint32_t crReserved:16;
	uint32_t rrEnd:8;	/* Low order bit second word */
	uint32_t rrBegin:8;
	uint32_t rrReserved:16;
#endif
} emlxs_rings_t;
typedef emlxs_rings_t RINGS;


typedef struct emlxs_ring_def {
#ifdef EMLXS_BIG_ENDIAN
	uint16_t offCiocb;
	uint16_t numCiocb;
	uint16_t offRiocb;
	uint16_t numRiocb;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t numCiocb;
	uint16_t offCiocb;
	uint16_t numRiocb;
	uint16_t offRiocb;
#endif
} emlxs_ring_def_t;
typedef emlxs_ring_def_t RING_DEF;


/*
 * The following F.C. frame stuctures are defined in Big Endian format.
 */

typedef struct emlxs_name_type {
#ifdef EMLXS_BIG_ENDIAN
	uint8_t nameType:4;	/* FC Word 0, bit 28:31 */
	uint8_t IEEEextMsn:4;	/* FC Word 0, bit 24:27, bit 8:11 of IEEE ext */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t IEEEextMsn:4;	/* FC Word 0, bit 24:27, bit 8:11 of IEEE ext */
	uint8_t nameType:4;	/* FC Word 0, bit 28:31 */
#endif
#define	NAME_IEEE		0x1	/* IEEE name - nameType */
#define	NAME_IEEE_EXT		0x2	/* IEEE extended name */
#define	NAME_FC_TYPE		0x3	/* FC native name type */
#define	NAME_IP_TYPE		0x4	/* IP address */
#define	NAME_CCITT_TYPE		0xC
#define	NAME_CCITT_GR_TYPE	0xE
	uint8_t IEEEextLsb;	/* FC Word 0, bit 16:23, IEEE extended Lsb */
	uint8_t IEEE[6];	/* FC IEEE address */

} emlxs_name_type_t;
typedef emlxs_name_type_t NAME_TYPE;


typedef struct emlxs_csp {
	uint8_t fcphHigh;	/* FC Word 0, byte 0 */
	uint8_t fcphLow;
	uint8_t bbCreditMsb;
	uint8_t bbCreditlsb;	/* FC Word 0, byte 3 */
#ifdef EMLXS_BIG_ENDIAN
	uint16_t reqMultipleNPort:1;	/* FC Word 1, bit 31 */
	uint16_t randomOffset:1;	/* FC Word 1, bit 30 */
	uint16_t rspMultipleNPort:1;	/* FC Word 1, bit 29 */
	uint16_t fPort:1;	/* FC Word 1, bit 28 */
	uint16_t altBbCredit:1;	/* FC Word 1, bit 27 */
	uint16_t edtovResolution:1;	/* FC Word 1, bit 26 */
	uint16_t multicast:1;	/* FC Word 1, bit 25 */
	uint16_t broadcast:1;	/* FC Word 1, bit 24 */

	uint16_t huntgroup:1;	/* FC Word 1, bit 23 */
	uint16_t simplex:1;	/* FC Word 1, bit 22 */

	uint16_t fcsp_support:1;	/* FC Word 1, bit 21 */
	uint16_t word1Reserved20:1;	/* FC Word 1, bit 20 */
	uint16_t word1Reserved19:1;	/* FC Word 1, bit 19 */

	uint16_t dhd:1;	/* FC Word 1, bit 18 */
	uint16_t contIncSeqCnt:1;	/* FC Word 1, bit 17 */
	uint16_t payloadlength:1;	/* FC Word 1, bit 16 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t broadcast:1;	/* FC Word 1, bit 24 */
	uint16_t multicast:1;	/* FC Word 1, bit 25 */
	uint16_t edtovResolution:1;	/* FC Word 1, bit 26 */
	uint16_t altBbCredit:1;	/* FC Word 1, bit 27 */
	uint16_t fPort:1;	/* FC Word 1, bit 28 */
	uint16_t rspMultipleNPort:1;	/* FC Word 1, bit 29 */
	uint16_t randomOffset:1;	/* FC Word 1, bit 30 */
	uint16_t reqMultipleNPort:1;	/* FC Word 1, bit 31 */

	uint16_t payloadlength:1;	/* FC Word 1, bit 16 */
	uint16_t contIncSeqCnt:1;	/* FC Word 1, bit 17 */
	uint16_t dhd:1;	/* FC Word 1, bit 18 */

	uint16_t word1Reserved19:1;	/* FC Word 1, bit 19 */
	uint16_t word1Reserved20:1;	/* FC Word 1, bit 20 */
	uint16_t fcsp_support:1;	/* FC Word 1, bit 21 */

	uint16_t simplex:1;	/* FC Word 1, bit 22 */
	uint16_t huntgroup:1;	/* FC Word 1, bit 23 */
#endif
	uint8_t bbRcvSizeMsb;	/* Upper nibble is reserved */
	uint8_t bbRcvSizeLsb;	/* FC Word 1, byte 3 */
	union {
		struct {
			uint8_t word2Reserved1;	/* FC Word 2 byte 0 */

			uint8_t totalConcurrSeq;	/* FC Word 2 byte 1 */
			uint8_t roByCategoryMsb;	/* FC Word 2 byte 2 */

			uint8_t roByCategoryLsb;	/* FC Word 2 byte 3 */
		} nPort;
		uint32_t r_a_tov;	/* R_A_TOV must be in B.E. format */
	} w2;

	uint32_t e_d_tov;	/* E_D_TOV must be in B.E. format */

} emlxs_csp_t;
typedef emlxs_csp_t CSP;


typedef struct emlxs_class_parms {
#ifdef EMLXS_BIG_ENDIAN
	uint8_t classValid:1;	/* FC Word 0, bit 31 */
	uint8_t intermix:1;	/* FC Word 0, bit 30 */
	uint8_t stackedXparent:1;	/* FC Word 0, bit 29 */
	uint8_t stackedLockDown:1;	/* FC Word 0, bit 28 */
	uint8_t seqDelivery:1;	/* FC Word 0, bit 27 */
	uint8_t word0Reserved1:3;	/* FC Word 0, bit 24:26 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t word0Reserved1:3;	/* FC Word 0, bit 24:26 */
	uint8_t seqDelivery:1;	/* FC Word 0, bit 27 */
	uint8_t stackedLockDown:1;	/* FC Word 0, bit 28 */
	uint8_t stackedXparent:1;	/* FC Word 0, bit 29 */
	uint8_t intermix:1;	/* FC Word 0, bit 30 */
	uint8_t classValid:1;	/* FC Word 0, bit 31 */

#endif
	uint8_t word0Reserved2;	/* FC Word 0, bit 16:23 */
#ifdef EMLXS_BIG_ENDIAN
	uint8_t iCtlXidReAssgn:2;	/* FC Word 0, Bit 14:15 */
	uint8_t iCtlInitialPa:2;	/* FC Word 0, bit 12:13 */
	uint8_t iCtlAck0capable:1;	/* FC Word 0, bit 11 */
	uint8_t iCtlAckNcapable:1;	/* FC Word 0, bit 10 */
	uint8_t word0Reserved3:2;	/* FC Word 0, bit  8: 9 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t word0Reserved3:2;	/* FC Word 0, bit  8: 9 */
	uint8_t iCtlAckNcapable:1;	/* FC Word 0, bit 10 */
	uint8_t iCtlAck0capable:1;	/* FC Word 0, bit 11 */
	uint8_t iCtlInitialPa:2;	/* FC Word 0, bit 12:13 */
	uint8_t iCtlXidReAssgn:2;	/* FC Word 0, Bit 14:15 */
#endif
	uint8_t word0Reserved4;	/* FC Word 0, bit  0: 7 */
#ifdef EMLXS_BIG_ENDIAN
	uint8_t rCtlAck0capable:1;	/* FC Word 1, bit 31 */
	uint8_t rCtlAckNcapable:1;	/* FC Word 1, bit 30 */
	uint8_t rCtlXidInterlck:1;	/* FC Word 1, bit 29 */
	uint8_t rCtlErrorPolicy:2;	/* FC Word 1, bit 27:28 */
	uint8_t word1Reserved1:1;	/* FC Word 1, bit 26 */
	uint8_t rCtlCatPerSeq:2;	/* FC Word 1, bit 24:25 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t rCtlCatPerSeq:2;	/* FC Word 1, bit 24:25 */
	uint8_t word1Reserved1:1;	/* FC Word 1, bit 26 */
	uint8_t rCtlErrorPolicy:2;	/* FC Word 1, bit 27:28 */
	uint8_t rCtlXidInterlck:1;	/* FC Word 1, bit 29 */
	uint8_t rCtlAckNcapable:1;	/* FC Word 1, bit 30 */
	uint8_t rCtlAck0capable:1;	/* FC Word 1, bit 31 */
#endif
	uint8_t word1Reserved2;	/* FC Word 1, bit 16:23 */
	uint8_t rcvDataSizeMsb;	/* FC Word 1, bit  8:15 */
	uint8_t rcvDataSizeLsb;	/* FC Word 1, bit  0: 7 */

	uint8_t concurrentSeqMsb;	/* FC Word 2, bit 24:31 */
	uint8_t concurrentSeqLsb;	/* FC Word 2, bit 16:23 */
	uint8_t EeCreditSeqMsb;	/* FC Word 2, bit  8:15 */
	uint8_t EeCreditSeqLsb;	/* FC Word 2, bit  0: 7 */

	uint8_t openSeqPerXchgMsb;	/* FC Word 3, bit 24:31 */
	uint8_t openSeqPerXchgLsb;	/* FC Word 3, bit 16:23 */
	uint8_t word3Reserved1;	/* Fc Word 3, bit  8:15 */
	uint8_t word3Reserved2;	/* Fc Word 3, bit  0: 7 */

} emlxs_class_parms_t;
typedef emlxs_class_parms_t CLASS_PARMS;


typedef struct emlxs_serv_parms {	/* Structure is in Big Endian format */
	CSP cmn;
	NAME_TYPE portName;
	NAME_TYPE nodeName;
	CLASS_PARMS cls1;
	CLASS_PARMS cls2;
	CLASS_PARMS cls3;
	CLASS_PARMS cls4;
	uint8_t vendorVersion[16];

} emlxs_serv_parms_t;
typedef emlxs_serv_parms_t SERV_PARM;

typedef struct {
	union {
		uint32_t word0;
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd0:8;	/* Word 0, Byte 3 */
			/* Emulex Organization Unique ID (00-00-C9) */
			uint32_t oui:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			/* Emulex Organization Unique ID (00-00-C9) */
			uint32_t oui:24;
			uint32_t rsvd0:8;	/* Word 0, Byte 3 */
#endif
		} w0;
	} un0;
	union {
		uint32_t word1;
		struct {
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
	uint8_t rsvd2[8];
} emlxs_vvl_fmt_t;

#define	valid_vendor_version	cmn.rspMultipleNPort



/*
 * Extended Link Service LS_COMMAND codes (Payload BYTE 0)
 */
#ifdef EMLXS_BIG_ENDIAN
#define	ELS_CMD_SHIFT		24
#define	ELS_CMD_MASK		0xff000000
#define	ELS_RSP_MASK		0xff000000
#define	ELS_CMD_LS_RJT		0x01000000
#define	ELS_CMD_ACC		0x02000000
#define	ELS_CMD_PLOGI		0x03000000
#define	ELS_CMD_FLOGI		0x04000000
#define	ELS_CMD_LOGO		0x05000000
#define	ELS_CMD_ABTX		0x06000000
#define	ELS_CMD_RCS		0x07000000
#define	ELS_CMD_RES		0x08000000
#define	ELS_CMD_RSS		0x09000000
#define	ELS_CMD_RSI		0x0A000000
#define	ELS_CMD_ESTS		0x0B000000
#define	ELS_CMD_ESTC		0x0C000000
#define	ELS_CMD_ADVC		0x0D000000
#define	ELS_CMD_RTV		0x0E000000
#define	ELS_CMD_RLS		0x0F000000
#define	ELS_CMD_ECHO		0x10000000
#define	ELS_CMD_TEST		0x11000000
#define	ELS_CMD_RRQ		0x12000000
#define	ELS_CMD_PRLI		0x20000000
#define	ELS_CMD_PRLO		0x21000000
#define	ELS_CMD_SCN		0x22000000
#define	ELS_CMD_TPLS		0x23000000
#define	ELS_CMD_GPRLO		0x24000000
#define	ELS_CMD_GAID		0x30000000
#define	ELS_CMD_FACT		0x31000000
#define	ELS_CMD_FDACT		0x32000000
#define	ELS_CMD_NACT		0x33000000
#define	ELS_CMD_NDACT		0x34000000
#define	ELS_CMD_QoSR		0x40000000
#define	ELS_CMD_RVCS		0x41000000
#define	ELS_CMD_PDISC		0x50000000
#define	ELS_CMD_FDISC		0x51000000
#define	ELS_CMD_ADISC		0x52000000
#define	ELS_CMD_FARP		0x54000000
#define	ELS_CMD_FARPR		0x55000000
#define	ELS_CMD_FAN		0x60000000
#define	ELS_CMD_RSCN		0x61000000
#define	ELS_CMD_SCR		0x62000000
#define	ELS_CMD_LINIT		0x70000000
#define	ELS_CMD_RNID		0x78000000
#define	ELS_CMD_AUTH		0x90000000
#endif

#ifdef EMLXS_LITTLE_ENDIAN
#define	ELS_CMD_SHIFT		0
#define	ELS_CMD_MASK		0xff
#define	ELS_RSP_MASK		0xff
#define	ELS_CMD_LS_RJT		0x01
#define	ELS_CMD_ACC		0x02
#define	ELS_CMD_PLOGI		0x03
#define	ELS_CMD_FLOGI		0x04
#define	ELS_CMD_LOGO		0x05
#define	ELS_CMD_ABTX		0x06
#define	ELS_CMD_RCS		0x07
#define	ELS_CMD_RES		0x08
#define	ELS_CMD_RSS		0x09
#define	ELS_CMD_RSI		0x0A
#define	ELS_CMD_ESTS		0x0B
#define	ELS_CMD_ESTC		0x0C
#define	ELS_CMD_ADVC		0x0D
#define	ELS_CMD_RTV		0x0E
#define	ELS_CMD_RLS		0x0F
#define	ELS_CMD_ECHO		0x10
#define	ELS_CMD_TEST		0x11
#define	ELS_CMD_RRQ		0x12
#define	ELS_CMD_PRLI		0x20
#define	ELS_CMD_PRLO		0x21
#define	ELS_CMD_SCN		0x22
#define	ELS_CMD_TPLS		0x23
#define	ELS_CMD_GPRLO		0x24
#define	ELS_CMD_GAID		0x30
#define	ELS_CMD_FACT		0x31
#define	ELS_CMD_FDACT		0x32
#define	ELS_CMD_NACT		0x33
#define	ELS_CMD_NDACT		0x34
#define	ELS_CMD_QoSR		0x40
#define	ELS_CMD_RVCS		0x41
#define	ELS_CMD_PDISC		0x50
#define	ELS_CMD_FDISC		0x51
#define	ELS_CMD_ADISC		0x52
#define	ELS_CMD_FARP		0x54
#define	ELS_CMD_FARPR		0x55
#define	ELS_CMD_FAN		0x60
#define	ELS_CMD_RSCN		0x61
#define	ELS_CMD_SCR		0x62
#define	ELS_CMD_LINIT		0x70
#define	ELS_CMD_RNID		0x78
#define	ELS_CMD_AUTH		0x90
#endif


/*
 * LS_RJT Payload Definition
 */

typedef struct _LS_RJT {	/* Structure is in Big Endian format */
	union {
		uint32_t lsRjtError;
		struct {
			uint8_t lsRjtRsvd0;	/* FC Word 0, bit 24:31 */

			uint8_t lsRjtRsnCode;	/* FC Word 0, bit 16:23 */
			/* LS_RJT reason codes */
#define	LSRJT_INVALID_CMD	0x01
#define	LSRJT_LOGICAL_ERR	0x03
#define	LSRJT_LOGICAL_BSY	0x05
#define	LSRJT_PROTOCOL_ERR	0x07
#define	LSRJT_UNABLE_TPC	0x09	/* Unable to perform command */
#define	LSRJT_CMD_UNSUPPORTED	0x0B
#define	LSRJT_VENDOR_UNIQUE	0xFF	/* See Byte 3 */

			uint8_t lsRjtRsnCodeExp;    /* FC Word 0, bit  8:15 */
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
#define	LSEXP_REQ_UNSUPPORTED   0x2C
			uint8_t vendorUnique;	/* FC Word 0, bit  0: 7 */
		} b;
	} un;
} LS_RJT;


/*
 * N_Port Login (FLOGO/PLOGO Request) Payload Definition
 */

typedef struct _LOGO {	/* Structure is in Big Endian format */
	union {
		uint32_t nPortId32;	/* Access nPortId as a word */
		struct {
			uint8_t word1Reserved1;	/* FC Word 1, bit 31:24 */
			uint8_t nPortIdByte0;	/* N_port  ID bit 16:23 */
			uint8_t nPortIdByte1;	/* N_port  ID bit  8:15 */
			uint8_t nPortIdByte2;	/* N_port  ID bit  0: 7 */
		} b;
	} un;
	NAME_TYPE portName;	/* N_port name field */
} LOGO;


/*
 * FCP Login (PRLI Request / ACC) Payload Definition
 */

#define	PRLX_PAGE_LEN   0x10
#define	TPRLO_PAGE_LEN  0x14

typedef struct _PRLI {	/* Structure is in Big Endian format */
	uint8_t prliType;	/* FC Parm Word 0, bit 24:31 */

#define	PRLI_FCP_TYPE 0x08
	uint8_t word0Reserved1;	/* FC Parm Word 0, bit 16:23 */

#ifdef EMLXS_BIG_ENDIAN
	uint8_t origProcAssocV:1;	/* FC Parm Word 0, bit 15 */
	uint8_t respProcAssocV:1;	/* FC Parm Word 0, bit 14 */
	uint8_t estabImagePair:1;	/* FC Parm Word 0, bit 13 */

	/* ACC = imagePairEstablished */
	uint8_t word0Reserved2:1;	/* FC Parm Word 0, bit 12 */
	uint8_t acceptRspCode:4;	/* FC Parm Word 0, bit 8:11, ACC ONLY */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t acceptRspCode:4;	/* FC Parm Word 0, bit 8:11, ACC ONLY */
	uint8_t word0Reserved2:1;	/* FC Parm Word 0, bit 12 */
	uint8_t estabImagePair:1;	/* FC Parm Word 0, bit 13 */
	uint8_t respProcAssocV:1;	/* FC Parm Word 0, bit 14 */
	uint8_t origProcAssocV:1;	/* FC Parm Word 0, bit 15 */
	/* ACC = imagePairEstablished */
#endif
#define	PRLI_REQ_EXECUTED	0x1	/* acceptRspCode */
#define	PRLI_NO_RESOURCES	0x2
#define	PRLI_INIT_INCOMPLETE	0x3
#define	PRLI_NO_SUCH_PA		0x4
#define	PRLI_PREDEF_CONFIG	0x5
#define	PRLI_PARTIAL_SUCCESS	0x6
#define	PRLI_INVALID_PAGE_CNT	0x7
	uint8_t word0Reserved3;	/* FC Parm Word 0, bit 0:7 */

	uint32_t origProcAssoc;	/* FC Parm Word 1, bit 0:31 */

	uint32_t respProcAssoc;	/* FC Parm Word 2, bit 0:31 */

	uint8_t word3Reserved1;	/* FC Parm Word 3, bit 24:31 */
	uint8_t word3Reserved2;	/* FC Parm Word 3, bit 16:23 */
#ifdef EMLXS_BIG_ENDIAN
	uint16_t Word3bit15Resved:1;	/* FC Parm Word 3, bit 15 */
	uint16_t Word3bit14Resved:1;	/* FC Parm Word 3, bit 14 */
	uint16_t Word3bit13Resved:1;	/* FC Parm Word 3, bit 13 */
	uint16_t Word3bit12Resved:1;	/* FC Parm Word 3, bit 12 */
	uint16_t Word3bit11Resved:1;	/* FC Parm Word 3, bit 11 */
	uint16_t Word3bit10Resved:1;	/* FC Parm Word 3, bit 10 */
	uint16_t TaskRetryIdReq:1;	/* FC Parm Word 3, bit  9 */
	uint16_t Retry:1;	/* FC Parm Word 3, bit  8 */
	uint16_t ConfmComplAllowed:1;	/* FC Parm Word 3, bit  7 */
	uint16_t dataOverLay:1;	/* FC Parm Word 3, bit  6 */
	uint16_t initiatorFunc:1;	/* FC Parm Word 3, bit  5 */
	uint16_t targetFunc:1;	/* FC Parm Word 3, bit  4 */
	uint16_t cmdDataMixEna:1;	/* FC Parm Word 3, bit  3 */
	uint16_t dataRspMixEna:1;	/* FC Parm Word 3, bit  2 */
	uint16_t readXferRdyDis:1;	/* FC Parm Word 3, bit  1 */
	uint16_t writeXferRdyDis:1;	/* FC Parm Word 3, bit  0 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t Retry:1;	/* FC Parm Word 3, bit  8 */
	uint16_t TaskRetryIdReq:1;	/* FC Parm Word 3, bit  9 */
	uint16_t Word3bit10Resved:1;	/* FC Parm Word 3, bit 10 */
	uint16_t Word3bit11Resved:1;	/* FC Parm Word 3, bit 11 */
	uint16_t Word3bit12Resved:1;	/* FC Parm Word 3, bit 12 */
	uint16_t Word3bit13Resved:1;	/* FC Parm Word 3, bit 13 */
	uint16_t Word3bit14Resved:1;	/* FC Parm Word 3, bit 14 */
	uint16_t Word3bit15Resved:1;	/* FC Parm Word 3, bit 15 */
	uint16_t writeXferRdyDis:1;	/* FC Parm Word 3, bit  0 */
	uint16_t readXferRdyDis:1;	/* FC Parm Word 3, bit  1 */
	uint16_t dataRspMixEna:1;	/* FC Parm Word 3, bit  2 */
	uint16_t cmdDataMixEna:1;	/* FC Parm Word 3, bit  3 */
	uint16_t targetFunc:1;	/* FC Parm Word 3, bit  4 */
	uint16_t initiatorFunc:1;	/* FC Parm Word 3, bit  5 */
	uint16_t dataOverLay:1;	/* FC Parm Word 3, bit  6 */
	uint16_t ConfmComplAllowed:1;	/* FC Parm Word 3, bit  7 */
#endif
} PRLI;

/*
 * FCP Logout (PRLO Request / ACC) Payload Definition
 */

typedef struct _PRLO {	/* Structure is in Big Endian format */
	uint8_t prloType;	/* FC Parm Word 0, bit 24:31 */

#define	PRLO_FCP_TYPE  0x08
	uint8_t word0Reserved1;	/* FC Parm Word 0, bit 16:23 */

#ifdef EMLXS_BIG_ENDIAN
	uint8_t origProcAssocV:1;	/* FC Parm Word 0, bit 15 */
	uint8_t respProcAssocV:1;	/* FC Parm Word 0, bit 14 */
	uint8_t word0Reserved2:2;	/* FC Parm Word 0, bit 12:13 */
	uint8_t acceptRspCode:4;	/* FC Parm Word 0, bit 8:11, ACC ONLY */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t acceptRspCode:4;	/* FC Parm Word 0, bit 8:11, ACC ONLY */
	uint8_t word0Reserved2:2;	/* FC Parm Word 0, bit 12:13 */
	uint8_t respProcAssocV:1;	/* FC Parm Word 0, bit 14 */
	uint8_t origProcAssocV:1;	/* FC Parm Word 0, bit 15 */
#endif
#define	PRLO_REQ_EXECUTED	0x1	/* acceptRspCode */
#define	PRLO_NO_SUCH_IMAGE	0x4
#define	PRLO_INVALID_PAGE_CNT	0x7

	uint8_t word0Reserved3;	/* FC Parm Word 0, bit 0:7 */

	uint32_t origProcAssoc;	/* FC Parm Word 1, bit 0:31 */

	uint32_t respProcAssoc;	/* FC Parm Word 2, bit 0:31 */

	uint32_t word3Reserved1;	/* FC Parm Word 3, bit 0:31 */
} PRLO;


typedef struct _ADISC {	/* Structure is in Big Endian format */
	uint32_t hardAL_PA;
	NAME_TYPE portName;
	NAME_TYPE nodeName;
	uint32_t DID;
} ADISC;


typedef struct _FARP {	/* Structure is in Big Endian format */
	uint32_t Mflags:8;
	uint32_t Odid:24;
#define	FARP_NO_ACTION		0	/* FARP info enclosed, no action */
#define	FARP_MATCH_PORT		0x1	/* Match on Responder Port Name */
#define	FARP_MATCH_NODE		0x2	/* Match on Responder Node Name */
#define	FARP_MATCH_IP		0x4	/* Match on IP address, not supported */
#define	FARP_MATCH_IPV4		0x5	/* Match on IPV4 addr, not supported */
#define	FARP_MATCH_IPV6		0x6	/* Match on IPV6 addr, not supported */
	uint32_t Rflags:8;
	uint32_t Rdid:24;
#define	FARP_REQUEST_PLOGI	0x1	/* Request for PLOGI */
#define	FARP_REQUEST_FARPR	0x2	/* Request for FARP Response */
	NAME_TYPE OportName;
	NAME_TYPE OnodeName;
	NAME_TYPE RportName;
	NAME_TYPE RnodeName;
	uint8_t Oipaddr[16];
	uint8_t Ripaddr[16];
} FARP;

typedef struct _FAN {	/* Structure is in Big Endian format */
	uint32_t Fdid;
	NAME_TYPE FportName;
	NAME_TYPE FnodeName;
} FAN;

typedef struct _SCR {	/* Structure is in Big Endian format */
	uint8_t resvd1;
	uint8_t resvd2;
	uint8_t resvd3;
	uint8_t Function;
#define	 SCR_FUNC_FABRIC	0x01
#define	 SCR_FUNC_NPORT		0x02
#define	 SCR_FUNC_FULL		0x03
#define	 SCR_CLEAR		0xff
} SCR;

typedef struct _RNID_TOP_DISC {
	NAME_TYPE portName;
	uint8_t resvd[8];
	uint32_t unitType;
#define	RNID_HBA		0x7
#define	RNID_HOST		0xa
#define	RNID_DRIVER		0xd
	uint32_t physPort;
	uint32_t attachedNodes;
	uint16_t ipVersion;
#define	RNID_IPV4		0x1
#define	RNID_IPV6		0x2
	uint16_t UDPport;
	uint8_t ipAddr[16];
	uint16_t resvd1;
	uint16_t flags;
#define	RNID_TD_SUPPORT		0x1
#define	RNID_LP_VALID		0x2
} RNID_TOP_DISC;

typedef struct _RNID {	/* Structure is in Big Endian format */
	uint8_t Format;
#define	RNID_TOPOLOGY_DISC  0xdf
	uint8_t CommonLen;
	uint8_t resvd1;
	uint8_t SpecificLen;
	NAME_TYPE portName;
	NAME_TYPE nodeName;
	union {
		RNID_TOP_DISC topologyDisc;	/* topology disc (0xdf) */
	} un;
} RNID;

typedef struct _RRQ {	/* Structure is in Big Endian format */
	uint32_t SID;
	uint16_t Oxid;
	uint16_t Rxid;
	uint8_t resv[32];	/* optional association hdr */
} RRQ;


/* This is used for RSCN command */
typedef struct _D_ID {	/* Structure is in Big Endian format */
	union {
		uint32_t word;
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint8_t resv;
			uint8_t domain;
			uint8_t area;
			uint8_t id;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint8_t id;
			uint8_t area;
			uint8_t domain;
			uint8_t resv;
#endif
		} b;
	} un;
} D_ID;

/*
 * Structure to define all ELS Payload types
 */

typedef struct _ELS_PKT {	/* Structure is in Big Endian format */
	uint8_t elsCode;	/* FC Word 0, bit 24:31 */
	uint8_t elsByte1;
	uint8_t elsByte2;
	uint8_t elsByte3;
	union {
		LS_RJT lsRjt;	/* Payload for LS_RJT ELS response */
		SERV_PARM logi;	/* Payload for PLOGI/FLOGI/PDISC/ACC */
		LOGO logo;	/* Payload for PLOGO/FLOGO/ACC */
		PRLI prli;	/* Payload for PRLI/ACC */
		PRLO prlo;	/* Payload for PRLO/ACC */
		ADISC adisc;	/* Payload for ADISC/ACC */
		FARP farp;	/* Payload for FARP/ACC */
		FAN fan;	/* Payload for FAN */
		SCR scr;	/* Payload for SCR/ACC */
		RRQ rrq;	/* Payload for RRQ */
		RNID rnid;	/* Payload for RNID */
		uint8_t pad[128 - 4];	/* Pad out to payload of 128 bytes */
	} un;
} ELS_PKT;


/*
 * Begin Structure Definitions for Mailbox Commands
 */

typedef struct revcompat {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t ldflag:1;	/* Set in SRAM descriptor */
	uint32_t ldcount:7;	/* For use by program load */
	uint32_t kernel:4;	/* Kernel ID */
	uint32_t kver:4;	/* Kernel compatibility version */
	uint32_t SMver:4;	/* Sequence Manager version, 0 if none */
	uint32_t ENDECver:4;	/* ENDEC+ version, 0 if none */
	uint32_t BIUtype:4;	/* PCI = 0 */
	uint32_t BIUver:4;	/* BIU version, 0 if none */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t BIUver:4;	/* BIU version, 0 if none */
	uint32_t BIUtype:4;	/* PCI = 0 */
	uint32_t ENDECver:4;	/* ENDEC+ version, 0 if none */
	uint32_t SMver:4;	/* Sequence Manager version, 0 if none */
	uint32_t kver:4;	/* Kernel compatibility version */
	uint32_t kernel:4;	/* Kernel ID */
	uint32_t ldcount:7;	/* For use by program load */
	uint32_t ldflag:1;	/* Set in SRAM descriptor */
#endif
} REVCOMPAT;

typedef struct id_word {
#ifdef EMLXS_BIG_ENDIAN
	uint8_t Type;
	uint8_t Id;
	uint8_t Ver;
	uint8_t Rev;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t Rev;
	uint8_t Ver;
	uint8_t Id;
	uint8_t Type;
#endif
	union {
		REVCOMPAT cp;
		uint32_t revcomp;
	} un;
} PROG_ID;

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint8_t tval;
	uint8_t tmask;
	uint8_t rval;
	uint8_t rmask;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t rmask;
	uint8_t rval;
	uint8_t tmask;
	uint8_t tval;
#endif
} RR_REG;

typedef struct {
	uint32_t bdeAddress;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t bdeReserved:4;
	uint32_t bdeAddrHigh:4;
	uint32_t bdeSize:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t bdeSize:24;
	uint32_t bdeAddrHigh:4;
	uint32_t bdeReserved:4;
#endif
} ULP_BDE;

typedef struct ULP_BDE_64 {	/* SLI-2 */
	union ULP_BDE_TUS {
		uint32_t w;
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t bdeFlags:8;	/* BDE Flags 0 IS SUPPORTED */
			uint32_t bdeSize:24;	/* Size of buffer (in bytes) */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t bdeSize:24;	/* Size of buffer (in bytes) */
			uint32_t bdeFlags:8;	/* BDE Flags 0 IS SUPPORTED */
#endif
#define	BUFF_USE_RSVD		0x01	/* bdeFlags */
#define	BUFF_USE_INTRPT		0x02	/* Not Implemented with LP6000 */
#define	BUFF_USE_CMND		0x04	/* Optional, 1=cmd/rsp 0=data buf */
#define	BUFF_USE_RCV		0x08	/* "" "", 1=rcv buf, 0=xmit buf */
#define	BUFF_TYPE_32BIT		0x10	/* "" "", 1=32 bit addr 0=64 bit addr */
#define	BUFF_TYPE_SPECIAL	0x20	/* Not Implemented with LP6000  */
#define	BUFF_TYPE_BDL		0x40	/* Optional,  may be set in BDL */
#define	BUFF_TYPE_INVALID	0x80	/* ""  "" */

		} f;
	} tus;
	uint32_t addrLow;
	uint32_t addrHigh;
} ULP_BDE64;

#define	BDE64_SIZE_WORD 0
#define	BPL64_SIZE_WORD 0x40

/* ULP */
typedef struct ULP_BPL_64 {
	ULP_BDE64 fccmd_payload;
	ULP_BDE64 fcrsp_payload;
	ULP_BDE64 fcdat_payload;
	ULP_BDE64 pat0;
} ULP_BPL64;

typedef struct ULP_BDL {	/* SLI-2 */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t bdeFlags:8;	/* BDL Flags */
	uint32_t bdeSize:24;	/* Size of BDL array in host memory (bytes) */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t bdeSize:24;	/* Size of BDL array in host memory (bytes) */
	uint32_t bdeFlags:8;	/* BDL Flags */
#endif
	uint32_t addrLow;	/* Address 0:31 */
	uint32_t addrHigh;	/* Address 32:63 */
	uint32_t ulpIoTag32;	/* Can be used for 32 bit I/O Tag */
} ULP_BDL;

typedef struct {
	uint8_t *fc_mptr;
	uint8_t *virt;	/* virtual address ptr */
	uint64_t phys;	/* mapped address */
	uint32_t size;
	void *data_handle;
	void *dma_handle;
	uint32_t tag;
	uint32_t flag;

#define	MAP_POOL_ALLOCATED   0x00000001
#define	MAP_BUF_ALLOCATED    0x00000002
#define	MAP_TABLE_ALLOCATED  0x00000004

} MATCHMAP;

/* Structure used for a HBQ entry */
typedef struct {
	ULP_BDE64 bde;
	union UN_TAG {
		uint32_t w;
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t HBQ_tag:4;
			uint32_t HBQE_tag:28;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t HBQE_tag:28;
			uint32_t HBQ_tag:4;
#endif
		} ext;
	} unt;

} HBQE_t;

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint8_t tmatch;
	uint8_t tmask;
	uint8_t rctlmatch;
	uint8_t rctlmask;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t rctlmask;
	uint8_t rctlmatch;
	uint8_t tmask;
	uint8_t tmatch;
#endif
} HBQ_MASK;

#define	EMLXS_MAX_HBQ_BUFFERS	4096

typedef struct {
	uint32_t HBQ_num_mask;	/* number of mask entries in prt array */
	uint32_t HBQ_recvNotify;	/* Receive buffer notification */
	uint32_t HBQ_numEntries;	/* # of entries in HBQ */
	uint32_t HBQ_headerLen;	/* 0 if not profile 4 or 5 */
	uint32_t HBQ_logEntry;	/* Set to 1 if this HBQ used for LogEntry */
	uint32_t HBQ_profile;	/* Selection profile 0=all, 7=logentry */
	uint32_t HBQ_ringMask;	/* Binds HBQ to a ring e.g. ring2=b0100 */
	uint32_t HBQ_id;	/* index of this hbq in ring .HBQs[] */
	uint32_t HBQ_PutIdx_next;	/* Index to next HBQ slot to use */
	uint32_t HBQ_PutIdx;	/* HBQ slot to use */
	uint32_t HBQ_GetIdx;	/* Local copy of Get index from Port */
	uint16_t HBQ_PostBufCnt;	/* Current number of entries in list */
	MATCHMAP *HBQ_PostBufs[EMLXS_MAX_HBQ_BUFFERS];
	MATCHMAP HBQ_host_buf;	/* HBQ host buffer for HBQEs */
	HBQ_MASK HBQ_Masks[6];

	union {
		uint32_t allprofiles[12];

		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t seqlenoff:16;
			uint32_t maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t maxlen:16;
			uint32_t seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd1:28;
			uint32_t seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t seqlenbcnt:4;
			uint32_t rsvd1:28;
#endif
			uint32_t rsvd[10];
		} profile2;

		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t seqlenoff:16;
			uint32_t maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t maxlen:16;
			uint32_t seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t cmdcodeoff:28;
			uint32_t rsvd1:12;
			uint32_t seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t seqlenbcnt:4;
			uint32_t rsvd1:12;
			uint32_t cmdcodeoff:28;
#endif
			uint32_t cmdmatch[8];

			uint32_t rsvd[2];
		} profile3;

		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t seqlenoff:16;
			uint32_t maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t maxlen:16;
			uint32_t seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t cmdcodeoff:28;
			uint32_t rsvd1:12;
			uint32_t seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t seqlenbcnt:4;
			uint32_t rsvd1:12;
			uint32_t cmdcodeoff:28;
#endif
			uint32_t cmdmatch[8];

			uint32_t rsvd[2];
		} profile5;

	} profiles;

} HBQ_INIT_t;



/* Structure for MB Command LOAD_SM and DOWN_LOAD */


typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd2:25;
	uint32_t acknowledgment:1;
	uint32_t version:1;
	uint32_t erase_or_prog:1;
	uint32_t update_flash:1;
	uint32_t update_ram:1;
	uint32_t method:1;
	uint32_t load_cmplt:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t load_cmplt:1;
	uint32_t method:1;
	uint32_t update_ram:1;
	uint32_t update_flash:1;
	uint32_t erase_or_prog:1;
	uint32_t version:1;
	uint32_t acknowledgment:1;
	uint32_t rsvd2:25;
#endif

#define	DL_FROM_BDE	0	/* method */
#define	DL_FROM_SLIM	1

#define	PROGRAM_FLASH   0	/* erase_or_prog */
#define	ERASE_FLASH	1

	uint32_t dl_to_adr;
	uint32_t dl_len;
	union {
		uint32_t dl_from_slim_offset;
		ULP_BDE dl_from_bde;
		ULP_BDE64 dl_from_bde64;
		PROG_ID prog_id;
	} un;

} LOAD_SM_VAR;


/* Structure for MB Command READ_NVPARM (02) */

typedef struct {
	uint32_t rsvd1[3];	/* Read as all one's */
	uint32_t rsvd2;	/* Read as all zero's */
	uint32_t portname[2];	/* N_PORT name */
	uint32_t nodename[2];	/* NODE name */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t pref_DID:24;
	uint32_t hardAL_PA:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t hardAL_PA:8;
	uint32_t pref_DID:24;
#endif
	uint32_t rsvd3[21];	/* Read as all one's */
} READ_NV_VAR;


/* Structure for MB Command WRITE_NVPARMS (03) */

typedef struct {
	uint32_t rsvd1[3];	/* Must be all one's */
	uint32_t rsvd2;	/* Must be all zero's */
	uint32_t portname[2];	/* N_PORT name */
	uint32_t nodename[2];	/* NODE name */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t pref_DID:24;
	uint32_t hardAL_PA:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t hardAL_PA:8;
	uint32_t pref_DID:24;
#endif
	uint32_t rsvd3[21];	/* Must be all one's */
} WRITE_NV_VAR;


/* Structure for MB Command RUN_BIU_DIAG (04) */
/* Structure for MB Command RUN_BIU_DIAG64 (0x84) */

typedef struct {
	uint32_t rsvd1;
	union {
		struct {
			ULP_BDE xmit_bde;
			ULP_BDE rcv_bde;
		} s1;
		struct {
			ULP_BDE64 xmit_bde64;
			ULP_BDE64 rcv_bde64;
		} s2;
	} un;
} BIU_DIAG_VAR;


/* Structure for MB Command INIT_LINK (05) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd1:24;
	uint32_t lipsr_AL_PA:8;	/* AL_PA to issue Lip Selective Reset to */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t lipsr_AL_PA:8;	/* AL_PA to issue Lip Selective Reset to */
	uint32_t rsvd1:24;
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint8_t fabric_AL_PA;	/* If using a Fabric Assigned AL_PA */
	uint8_t rsvd2;
	uint16_t link_flags;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t link_flags;
	uint8_t rsvd2;
	uint8_t fabric_AL_PA;	/* If using a Fabric Assigned AL_PA */
#endif
/* link_flags (=1) ENDEC loopback */
#define	FLAGS_LOCAL_LB			0x01
#define	FLAGS_TOPOLOGY_MODE_LOOP_PT	0x00	/* Attempt loop then pt-pt */
#define	FLAGS_TOPOLOGY_MODE_PT_PT	0x02	/* Attempt pt-pt only */
#define	FLAGS_TOPOLOGY_MODE_LOOP	0x04	/* Attempt loop only */
#define	FLAGS_TOPOLOGY_MODE_PT_LOOP	0x06	/* Attempt pt-pt then loop */
#define	FLAGS_LIRP_LILP			0x80	/* LIRP / LILP is disabled */

#define	FLAGS_TOPOLOGY_FAILOVER		0x0400	/* Bit 10 */
#define	FLAGS_LINK_SPEED		0x0800	/* Bit 11 */
#define	FLAGS_PREABORT_RETURN		0x4000	/* Bit 14 */

	uint32_t link_speed;	/* NEW_FEATURE */
#define	LINK_SPEED_AUTO 0	/* Auto selection */
#define	LINK_SPEED_1G   1	/* 1 Gigabaud */
#define	LINK_SPEED_2G   2	/* 2 Gigabaud */

} INIT_LINK_VAR;


/* Structure for MB Command DOWN_LINK (06) */

typedef struct {
	uint32_t rsvd1;
} DOWN_LINK_VAR;


/* Structure for MB Command CONFIG_LINK (07) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t cr:1;
	uint32_t ci:1;
	uint32_t cr_delay:6;
	uint32_t cr_count:8;
	uint32_t rsvd1:8;
	uint32_t MaxBBC:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t MaxBBC:8;
	uint32_t rsvd1:8;
	uint32_t cr_count:8;
	uint32_t cr_delay:6;
	uint32_t ci:1;
	uint32_t cr:1;
#endif
	uint32_t myId;
	uint32_t rsvd2;
	uint32_t edtov;
	uint32_t arbtov;
	uint32_t ratov;
	uint32_t rttov;
	uint32_t altov;
	uint32_t crtov;
	uint32_t citov;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rrq_enable:1;
	uint32_t rrq_immed:1;
	uint32_t rsvd4:29;
	uint32_t ack0_enable:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t ack0_enable:1;
	uint32_t rsvd4:29;
	uint32_t rrq_immed:1;
	uint32_t rrq_enable:1;
#endif
} CONFIG_LINK;


/* Structure for MB Command PART_SLIM (08) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t unused1:24;
	uint32_t numRing:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t numRing:8;
	uint32_t unused1:24;
#endif
	emlxs_ring_def_t ringdef[4];
	uint32_t hbainit;
} PART_SLIM_VAR;


/* Structure for MB Command CONFIG_RING (09) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t unused2:6;
	uint32_t recvSeq:1;
	uint32_t recvNotify:1;
	uint32_t numMask:8;
	uint32_t profile:8;
	uint32_t unused1:4;
	uint32_t ring:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t ring:4;
	uint32_t unused1:4;
	uint32_t profile:8;
	uint32_t numMask:8;
	uint32_t recvNotify:1;
	uint32_t recvSeq:1;
	uint32_t unused2:6;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint16_t maxRespXchg;
	uint16_t maxOrigXchg;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t maxOrigXchg;
	uint16_t maxRespXchg;
#endif
	RR_REG rrRegs[6];
} CONFIG_RING_VAR;


/* Structure for MB Command RESET_RING (10) */

typedef struct {
	uint32_t ring_no;
} RESET_RING_VAR;


/* Structure for MB Command READ_CONFIG (11) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t cr:1;
	uint32_t ci:1;
	uint32_t cr_delay:6;
	uint32_t cr_count:8;
	uint32_t InitBBC:8;
	uint32_t MaxBBC:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t MaxBBC:8;
	uint32_t InitBBC:8;
	uint32_t cr_count:8;
	uint32_t cr_delay:6;
	uint32_t ci:1;
	uint32_t cr:1;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint32_t topology:8;
	uint32_t myDid:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t myDid:24;
	uint32_t topology:8;
#endif
	/* Defines for topology (defined previously) */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t AR:1;
	uint32_t IR:1;
	uint32_t rsvd1:29;
	uint32_t ack0:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t ack0:1;
	uint32_t rsvd1:29;
	uint32_t IR:1;
	uint32_t AR:1;
#endif
	uint32_t edtov;
	uint32_t arbtov;
	uint32_t ratov;
	uint32_t rttov;
	uint32_t altov;
	uint32_t lmt;

#define	LMT_1GB_CAPABLE   0x0004
#define	LMT_2GB_CAPABLE	  0x0008
#define	LMT_4GB_CAPABLE	  0x0040
#define	LMT_8GB_CAPABLE	  0x0080
#define	LMT_10GB_CAPABLE  0x0100
/* E2E supported on adapters >= 8GB */
#define	LMT_E2E_CAPABLE   (LMT_8GB_CAPABLE|LMT_10GB_CAPABLE)

	uint32_t rsvd2;
	uint32_t rsvd3;
	uint32_t max_xri;
	uint32_t max_iocb;
	uint32_t max_rpi;
	uint32_t avail_xri;
	uint32_t avail_iocb;
	uint32_t avail_rpi;

#ifdef SLI3_SUPPORT
	uint32_t max_vpi;
	uint32_t max_alpa;
	uint32_t rsvd4;
	uint32_t avail_vpi;
#else
	uint32_t default_rpi;
#endif	/* SLI3_SUPPORT */

} READ_CONFIG_VAR;


/* Structure for MB Command READ_RCONFIG (12) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd2:7;
	uint32_t recvNotify:1;
	uint32_t numMask:8;
	uint32_t profile:8;
	uint32_t rsvd1:4;
	uint32_t ring:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t ring:4;
	uint32_t rsvd1:4;
	uint32_t profile:8;
	uint32_t numMask:8;
	uint32_t recvNotify:1;
	uint32_t rsvd2:7;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint16_t maxResp;
	uint16_t maxOrig;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t maxOrig;
	uint16_t maxResp;
#endif
	RR_REG rrRegs[6];
#ifdef EMLXS_BIG_ENDIAN
	uint16_t cmdRingOffset;
	uint16_t cmdEntryCnt;
	uint16_t rspRingOffset;
	uint16_t rspEntryCnt;
	uint16_t nextCmdOffset;
	uint16_t rsvd3;
	uint16_t nextRspOffset;
	uint16_t rsvd4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t cmdEntryCnt;
	uint16_t cmdRingOffset;
	uint16_t rspEntryCnt;
	uint16_t rspRingOffset;
	uint16_t rsvd3;
	uint16_t nextCmdOffset;
	uint16_t rsvd4;
	uint16_t nextRspOffset;
#endif
} READ_RCONF_VAR;


/* Structure for MB Command READ_SPARM (13) */
/* Structure for MB Command READ_SPARM64 (0x8D) */

typedef struct {
	uint32_t rsvd1;
	uint32_t rsvd2;
	union {
		ULP_BDE sp;	/* This BDE points to SERV_PARM structure */
		ULP_BDE64 sp64;
	} un;
} READ_SPARM_VAR;


/* Structure for MB Command READ_STATUS (14) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd1:31;
	uint32_t clrCounters:1;
	uint16_t activeXriCnt;
	uint16_t activeRpiCnt;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t clrCounters:1;
	uint32_t rsvd1:31;
	uint16_t activeRpiCnt;
	uint16_t activeXriCnt;
#endif
	uint32_t xmitByteCnt;
	uint32_t rcvByteCnt;
	uint32_t xmitFrameCnt;
	uint32_t rcvFrameCnt;
	uint32_t xmitSeqCnt;
	uint32_t rcvSeqCnt;
	uint32_t totalOrigExchanges;
	uint32_t totalRespExchanges;
	uint32_t rcvPbsyCnt;
	uint32_t rcvFbsyCnt;
} READ_STATUS_VAR;


/* Structure for MB Command READ_RPI (15) */
/* Structure for MB Command READ_RPI64 (0x8F) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint16_t nextRpi;
	uint16_t reqRpi;
	uint32_t rsvd2:8;
	uint32_t DID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t reqRpi;
	uint16_t nextRpi;
	uint32_t DID:24;
	uint32_t rsvd2:8;
#endif
	union {
		ULP_BDE sp;
		ULP_BDE64 sp64;
	} un;

} READ_RPI_VAR;


/* Structure for MB Command READ_XRI (16) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint16_t nextXri;
	uint16_t reqXri;
	uint16_t rsvd1;
	uint16_t rpi;
	uint32_t rsvd2:8;
	uint32_t DID:24;
	uint32_t rsvd3:8;
	uint32_t SID:24;
	uint32_t rsvd4;
	uint8_t seqId;
	uint8_t rsvd5;
	uint16_t seqCount;
	uint16_t oxId;
	uint16_t rxId;
	uint32_t rsvd6:30;
	uint32_t si:1;
	uint32_t exchOrig:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t reqXri;
	uint16_t nextXri;
	uint16_t rpi;
	uint16_t rsvd1;
	uint32_t DID:24;
	uint32_t rsvd2:8;
	uint32_t SID:24;
	uint32_t rsvd3:8;
	uint32_t rsvd4;
	uint16_t seqCount;
	uint8_t rsvd5;
	uint8_t seqId;
	uint16_t rxId;
	uint16_t oxId;
	uint32_t exchOrig:1;
	uint32_t si:1;
	uint32_t rsvd6:30;
#endif
} READ_XRI_VAR;


/* Structure for MB Command READ_REV (17) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t cv:1;
	uint32_t rr:1;
	uint32_t co:1;
	uint32_t rp:1;
	uint32_t cv3:1;
	uint32_t rf3:1;
	uint32_t rsvd1:10;
	uint32_t offset:14;
	uint32_t rv:2;
#endif
#ifdef EMLXS_LITTLE_ENDIAN

	uint32_t rv:2;
	uint32_t offset:14;
	uint32_t rsvd1:10;
	uint32_t rf3:1;
	uint32_t cv3:1;
	uint32_t rp:1;
	uint32_t co:1;
	uint32_t rr:1;
	uint32_t cv:1;
#endif
	uint32_t biuRev;
	uint32_t smRev;
	union {
		uint32_t smFwRev;
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint8_t ProgType;
			uint8_t ProgId;
			uint16_t ProgVer:4;
			uint16_t ProgRev:4;
			uint16_t ProgFixLvl:2;
			uint16_t ProgDistType:2;
			uint16_t DistCnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t DistCnt:4;
			uint16_t ProgDistType:2;
			uint16_t ProgFixLvl:2;
			uint16_t ProgRev:4;
			uint16_t ProgVer:4;
			uint8_t ProgId;
			uint8_t ProgType;
#endif
		} b;
	} un;
	uint32_t endecRev;
#ifdef EMLXS_BIG_ENDIAN
	uint8_t feaLevelHigh;
	uint8_t feaLevelLow;
	uint8_t fcphHigh;
	uint8_t fcphLow;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t fcphLow;
	uint8_t fcphHigh;
	uint8_t feaLevelLow;
	uint8_t feaLevelHigh;
#endif
	uint32_t postKernRev;
	uint32_t opFwRev;
	uint8_t opFwName[16];

	uint32_t sliFwRev1;
	uint8_t sliFwName1[16];
	uint32_t sliFwRev2;
	uint8_t sliFwName2[16];

} READ_REV_VAR;

#define	rxSeqRev postKernRev
#define	txSeqRev opFwRev

/* Structure for MB Command READ_LINK_STAT (18) */

typedef struct {
	uint32_t rsvd1;
	uint32_t linkFailureCnt;
	uint32_t lossSyncCnt;

	uint32_t lossSignalCnt;
	uint32_t primSeqErrCnt;
	uint32_t invalidXmitWord;
	uint32_t crcCnt;
	uint32_t primSeqTimeout;
	uint32_t elasticOverrun;
	uint32_t arbTimeout;

	uint32_t rxBufCredit;
	uint32_t rxBufCreditCur;

	uint32_t txBufCredit;
	uint32_t txBufCreditCur;

	uint32_t EOFaCnt;
	uint32_t EOFdtiCnt;
	uint32_t EOFniCnt;
	uint32_t SOFfCnt;

} READ_LNK_VAR;


/* Structure for MB Command REG_LOGIN (19) */
/* Structure for MB Command REG_LOGIN64 (0x93) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint16_t rsvd1;
	uint16_t rpi;
	uint32_t rsvd2:8;
	uint32_t did:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t rpi;
	uint16_t rsvd1;
	uint32_t did:24;
	uint32_t rsvd2:8;
#endif
	union {
		ULP_BDE sp;
		ULP_BDE64 sp64;
	} un;

#ifdef SLI3_SUPPORT
#ifdef EMLXS_BIG_ENDIAN
	uint16_t rsvd6;
	uint16_t vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t vpi;
	uint16_t rsvd6;
#endif
#endif	/* SLI3_SUPPORT */

} REG_LOGIN_VAR;

/* Word 30 contents for REG_LOGIN */
typedef union {
	struct {
#ifdef EMLXS_BIG_ENDIAN
		uint16_t rsvd1:12;
		uint16_t class:4;
		uint16_t xri;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
		uint16_t xri;
		uint16_t class:4;
		uint16_t rsvd1:12;
#endif
	} f;
	uint32_t word;
} REG_WD30;


/* Structure for MB Command UNREG_LOGIN (20) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint16_t rsvd1;
	uint16_t rpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t rpi;
	uint16_t rsvd1;
#endif

#ifdef SLI3_SUPPORT
	uint32_t rsvd2;
	uint32_t rsvd3;
	uint32_t rsvd4;
	uint32_t rsvd5;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t rsvd6;
	uint16_t vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t vpi;
	uint16_t rsvd6;
#endif
#endif	/* SLI3_SUPPORT */

} UNREG_LOGIN_VAR;


/* Structure for MB Command UNREG_D_ID (0x23) */

typedef struct {
	uint32_t did;

#ifdef SLI3_SUPPORT
	uint32_t rsvd2;
	uint32_t rsvd3;
	uint32_t rsvd4;
	uint32_t rsvd5;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t rsvd6;
	uint16_t vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t vpi;
	uint16_t rsvd6;
#endif
#endif	/* SLI3_SUPPORT */

} UNREG_D_ID_VAR;


/* Structure for MB Command READ_LA (21) */
/* Structure for MB Command READ_LA64 (0x95) */

typedef struct {
	uint32_t eventTag;	/* Event tag */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd2:19;
	uint32_t fa:1;
	uint32_t mm:1;
	uint32_t tc:1;
	uint32_t pb:1;
	uint32_t il:1;
	uint32_t attType:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t attType:8;
	uint32_t il:1;
	uint32_t pb:1;
	uint32_t tc:1;
	uint32_t mm:1;
	uint32_t fa:1;
	uint32_t rsvd2:19;
#endif
#define	AT_RESERVED	0x00	/* Reserved - attType */
#define	AT_LINK_UP	0x01	/* Link is up */
#define	AT_LINK_DOWN	0x02	/* Link is down */
#ifdef EMLXS_BIG_ENDIAN
	uint8_t granted_AL_PA;
	uint8_t lipAlPs;
	uint8_t lipType;
	uint8_t topology;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t topology;
	uint8_t lipType;
	uint8_t lipAlPs;
	uint8_t granted_AL_PA;
#endif

	/* lipType */
/* An L_PORT initing (F7, AL_PS) - lipType */
#define	LT_PORT_INIT			0x00

/* Err @L_PORT rcv'er (F8, AL_PS) */
#define	LT_PORT_ERR			0x01

/* Lip Reset of some other port */
#define	LT_RESET_APORT			0x02

#define	LT_RESET_MYPORT			0x03	/* Lip Reset of my port */

	/* topology */
/* Topology is pt-pt pt-fabric */
#define	TOPOLOGY_PT_PT			0x01
/* Topology is FC-AL (private) */
#define	TOPOLOGY_LOOP			0x02

	union {
		/* This BDE points to a 128 byte buffer to */
		ULP_BDE lilpBde;
		/* store the LILP AL_PA position map into */
		ULP_BDE64 lilpBde64;
	} un;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t Dlu:1;
	uint32_t Dtf:1;
	uint32_t Drsvd2:14;
	uint32_t DlnkSpeed:8;
	uint32_t DnlPort:4;
	uint32_t Dtx:2;
	uint32_t Drx:2;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t Drx:2;
	uint32_t Dtx:2;
	uint32_t DnlPort:4;
	uint32_t DlnkSpeed:8;
	uint32_t Drsvd2:14;
	uint32_t Dtf:1;
	uint32_t Dlu:1;
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint32_t Ulu:1;
	uint32_t Utf:1;
	uint32_t Ursvd2:14;
	uint32_t UlnkSpeed:8;
	uint32_t UnlPort:4;
	uint32_t Utx:2;
	uint32_t Urx:2;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t Urx:2;
	uint32_t Utx:2;
	uint32_t UnlPort:4;
	uint32_t UlnkSpeed:8;
	uint32_t Ursvd2:14;
	uint32_t Utf:1;
	uint32_t Ulu:1;
#endif

#define	LA_1GHZ_LINK   0x04	/* lnkSpeed */
#define	LA_2GHZ_LINK   0x08	/* lnkSpeed */
#define	LA_4GHZ_LINK   0x10	/* lnkSpeed */
#define	LA_8GHZ_LINK   0x20	/* lnkSpeed */
#define	LA_10GHZ_LINK  0x40	/* lnkSpeed */

} READ_LA_VAR;


/* Structure for MB Command CLEAR_LA (22) */

typedef struct {
	uint32_t eventTag;	/* Event tag */
	uint32_t rsvd1;
} CLEAR_LA_VAR;

/* Structure for MB Command DUMP */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd:25;
	uint32_t ra:1;
	uint32_t co:1;
	uint32_t cv:1;
	uint32_t type:4;

	uint32_t entry_index:16;
	uint32_t region_id:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t type:4;
	uint32_t cv:1;
	uint32_t co:1;
	uint32_t ra:1;
	uint32_t rsvd:25;

	uint32_t region_id:16;
	uint32_t entry_index:16;
#endif
	uint32_t base_adr;
	uint32_t word_cnt;
	uint32_t resp_offset;
} DUMP_VAR;

/*
 * Dump type
 */
#define	 DMP_MEM_REG		0x1
#define	 DMP_NV_PARAMS		0x2

/*
 * Dump region ID
 */
#define	 NODE_CFG_A_REGION_ID		0
#define	 NODE_CFG_B_REGION_ID		1
#define	 NODE_CFG_C_REGION_ID		2
#define	 NODE_CFG_D_REGION_ID		3
#define	 WAKE_UP_PARMS_REGION_ID	4
#define	 DEF_PCI_CFG_REGION_ID		5
#define	 PCI_CFG_1_REGION_ID		6
#define	 PCI_CFG_2_REGION_ID		7
#define	 RSVD1_REGION_ID		8
#define	 RSVD2_REGION_ID		9
#define	 RSVD3_REGION_ID		10
#define	 RSVD4_REGION_ID		11
#define	 RSVD5_REGION_ID		12
#define	 RSVD6_REGION_ID		13
#define	 RSVD7_REGION_ID		14
#define	 DIAG_TRACE_REGION_ID		15
#define	 WWN_REGION_ID			16

#define	 DMP_VPD_REGION			0xe
#define	 DMP_VPD_SIZE			1024
#define	 DMP_VPD_DUMP_WCOUNT		25



/* Structure for MB Command UPDATE_CFG */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd2:16;
	uint32_t proc_type:8;
	uint32_t rsvd1:1;
	uint32_t Abit:1;
	uint32_t Obit:1;
	uint32_t Vbit:1;
	uint32_t req_type:4;
#define	 INIT_REGION		1
#define	 UPDATE_DATA		2
#define	 CLEAN_UP_CFG		3
	uint32_t entry_len:16;
	uint32_t region_id:16;
#endif

#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t req_type:4;
#define	 INIT_REGION		1
#define	 UPDATE_DATA		2
#define	 CLEAN_UP_CFG		3
	uint32_t Vbit:1;
	uint32_t Obit:1;
	uint32_t Abit:1;
	uint32_t rsvd1:1;
	uint32_t proc_type:8;
	uint32_t rsvd2:16;

	uint32_t region_id:16;
	uint32_t entry_len:16;
#endif

	uint32_t rsp_info;
	uint32_t byte_len;
	uint32_t cfg_data;

} UPDATE_CFG_VAR;

/* Structure for MB Command DEL_LD_ENTRY (29) */

typedef struct {
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t list_req:2;
	uint32_t list_rsp:2;
	uint32_t rsvd:28;
#else
	uint32_t rsvd:28;
	uint32_t list_rsp:2;
	uint32_t list_req:2;
#endif

#define	 FLASH_LOAD_LIST	1
#define	 RAM_LOAD_LIST		2
#define	 BOTH_LISTS		3

	PROG_ID prog_id;

} DEL_LD_ENTRY_VAR;

/* Structure for MB Command LOAD_AREA (81) */
typedef struct {
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t load_cmplt:1;
	uint32_t method:1;
	uint32_t rsvd1:1;
	uint32_t update_flash:1;
	uint32_t erase_or_prog:1;
	uint32_t version:1;
	uint32_t rsvd2:2;
	uint32_t progress:8;
	uint32_t step:8;
	uint32_t area_id:8;
#else
	uint32_t area_id:8;
	uint32_t step:8;
	uint32_t progress:8;
	uint32_t rsvd2:2;
	uint32_t version:1;
	uint32_t erase_or_prog:1;
	uint32_t update_flash:1;
	uint32_t rsvd1:1;
	uint32_t method:1;
	uint32_t load_cmplt:1;
#endif
	uint32_t dl_to_adr;
	uint32_t dl_len;
	union {
		uint32_t dl_from_slim_offset;
		ULP_BDE dl_from_bde;
		ULP_BDE64 dl_from_bde64;
		PROG_ID prog_id;
	} un;
} LOAD_AREA_VAR;

/* Structure for MB Command LOAD_EXP_ROM (9C) */
typedef struct {
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t rsvd1:8;
	uint32_t progress:8;
	uint32_t step:8;
	uint32_t rsvd2:8;
#else
	uint32_t rsvd2:8;
	uint32_t step:8;
	uint32_t progress:8;
	uint32_t rsvd1:8;
#endif
	uint32_t dl_to_adr;
	uint32_t rsvd3;
	union {
		uint32_t word[2];
		PROG_ID prog_id;
	} un;
} LOAD_EXP_ROM_VAR;


/* Structure for MB Command CONFIG_HBQ (7C) */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd1:7;
	uint32_t recvNotify:1;	/* Receive Notification */
	uint32_t numMask:8;	/* # Mask Entries */
	uint32_t profile:8;	/* Selection Profile    */
	uint32_t rsvd2:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t rsvd2:8;
	uint32_t profile:8;	/* Selection Profile    */
	uint32_t numMask:8;	/* # Mask Entries */
	uint32_t recvNotify:1;	/* Receive Notification */
	uint32_t rsvd1:7;
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t hbqId:16;
	uint32_t rsvd3:12;
	uint32_t ringMask:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t ringMask:4;
	uint32_t rsvd3:12;
	uint32_t hbqId:16;
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t numEntries:16;
	uint32_t rsvd4:8;
	uint32_t headerLen:8;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t headerLen:8;
	uint32_t rsvd4:8;
	uint32_t numEntries:16;
#endif

	uint32_t hbqaddrLow;
	uint32_t hbqaddrHigh;

#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd5:31;
	uint32_t logEntry:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t logEntry:1;
	uint32_t rsvd5:31;
#endif

	uint32_t rsvd6;	/* w7 */
	uint32_t rsvd7;	/* w8 */
	uint32_t rsvd8;	/* w9 */

	HBQ_MASK hbqMasks[6];

	union {
		uint32_t allprofiles[12];

		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t seqlenoff:16;
			uint32_t maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t maxlen:16;
			uint32_t seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t rsvd1:28;
			uint32_t seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t seqlenbcnt:4;
			uint32_t rsvd1:28;
#endif
			uint32_t rsvd[10];
		} profile2;

		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t seqlenoff:16;
			uint32_t maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t maxlen:16;
			uint32_t seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t cmdcodeoff:28;
			uint32_t rsvd1:12;
			uint32_t seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t seqlenbcnt:4;
			uint32_t rsvd1:12;
			uint32_t cmdcodeoff:28;
#endif
			uint32_t cmdmatch[8];

			uint32_t rsvd[2];
		} profile3;

		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t seqlenoff:16;
			uint32_t maxlen:16;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t maxlen:16;
			uint32_t seqlenoff:16;
#endif
#ifdef EMLXS_BIG_ENDIAN
			uint32_t cmdcodeoff:28;
			uint32_t rsvd1:12;
			uint32_t seqlenbcnt:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t seqlenbcnt:4;
			uint32_t rsvd1:12;
			uint32_t cmdcodeoff:28;
#endif
			uint32_t cmdmatch[8];

			uint32_t rsvd[2];
		} profile5;

	} profiles;

} CONFIG_HBQ_VAR;


/* Structure for MB Command REG_VPI(0x96) */
typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd1;
	uint32_t rsvd2:8;
	uint32_t sid:24;
	uint32_t rsvd3;
	uint32_t rsvd4;
	uint32_t rsvd5;
	uint16_t rsvd6;
	uint16_t vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t rsvd1;
	uint32_t sid:24;
	uint32_t rsvd2:8;
	uint32_t rsvd3;
	uint32_t rsvd4;
	uint32_t rsvd5;
	uint16_t vpi;
	uint16_t rsvd6;
#endif
} REG_VPI_VAR;

/* Structure for MB Command UNREG_VPI (0x97) */
typedef struct {
	uint32_t rsvd1;
	uint32_t rsvd2;
	uint32_t rsvd3;
	uint32_t rsvd4;
	uint32_t rsvd5;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t rsvd6;
	uint16_t vpi;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t vpi;
	uint16_t rsvd6;
#endif

} UNREG_VPI_VAR;


typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t read_log:1;
	uint32_t clear_log:1;
	uint32_t mbox_rsp:1;
	uint32_t resv:28;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t resv:28;
	uint32_t mbox_rsp:1;
	uint32_t clear_log:1;
	uint32_t read_log:1;
#endif

	uint32_t offset;

	union {
		ULP_BDE sp;
		ULP_BDE64 sp64;
	} un;

} READ_EVT_LOG_VAR;


/* Structure for MB Command CONFIG_PORT (0x88) */


#ifdef SLI3_SUPPORT

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t cBE:1;
	uint32_t cET:1;
	uint32_t cHpcb:1;
	uint32_t rMA:1;
	uint32_t sli_mode:4;
	uint32_t pcbLen:24;	/* bit 23:0 of memory based port cfg block */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t pcbLen:24;	/* bit 23:0  of memory based port cfg block */
	uint32_t sli_mode:4;
	uint32_t rMA:1;
	uint32_t cHpcb:1;
	uint32_t cET:1;
	uint32_t cBE:1;
#endif

	uint32_t pcbLow;	/* bit 31:0  of memory based port cfg block */
	uint32_t pcbHigh;	/* bit 63:32 of memory based port cfg block */
	uint32_t hbainit[5];

#ifdef EMLXS_BIG_ENDIAN
	uint32_t hps:1;	/* Host pointers in SLIM */
	uint32_t rsvd:31;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t rsvd:31;
	uint32_t hps:1;	/* Host pointers in SLIM */
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd1:24;
	uint32_t cmv:1;	/* Configure Max VPIs */
	uint32_t ccrp:1;	/* Config Command Ring Polling */
	uint32_t csah:1;	/* Configure Synchronous Abort Handling */
	uint32_t chbs:1;	/* Cofigure Host Backing store */
	uint32_t cinb:1;	/* Enable Interrupt Notification Block  */
	uint32_t cerbm:1;	/* Configure Enhanced Receive Buf Mgmt  */
	uint32_t cmx:1;	/* Configure Max XRIs */
	uint32_t cmr:1;	/* Configure Max RPIs */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t cmr:1;	/* Configure Max RPIs */
	uint32_t cmx:1;	/* Configure Max XRIs */
	uint32_t cerbm:1;	/* Configure Enhanced Receive Buf Mgmt  */
	uint32_t cinb:1;	/* Enable Interrupt Notification Block  */
	uint32_t chbs:1;	/* Cofigure Host Backing store */
	uint32_t csah:1;	/* Configure Synchronous Abort Handling */
	uint32_t ccrp:1;	/* Config Command Ring Polling */
	uint32_t cmv:1;	/* Configure Max VPIs */
	uint32_t rsvd1:24;	/* Reserved */
#endif
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd2:24;	/* Reserved */
	uint32_t gmv:1;	/* Grant Max VPIs */
	uint32_t gcrp:1;	/* Grant Command Ring Polling */
	uint32_t gsah:1;	/* Grant Synchronous Abort Handling */
	uint32_t ghbs:1;	/* Grant Host Backing Store */
	uint32_t ginb:1;	/* Grant Interrupt Notification Block   */
	uint32_t gerbm:1;	/* Grant ERBM Request */
	uint32_t gmx:1;	/* Grant Max XRIs */
	uint32_t gmr:1;	/* Grant Max RPIs */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t gmr:1;	/* Grant Max RPIs */
	uint32_t gmx:1;	/* Grant Max XRIs */
	uint32_t gerbm:1;	/* Grant ERBM Request */
	uint32_t ginb:1;	/* Grant Interrupt Notification Block   */
	uint32_t ghbs:1;	/* Grant Host Backing Store */
	uint32_t gsah:1;	/* Grant Synchronous Abort Handling */
	uint32_t gcrp:1;	/* Grant Command Ring Polling */
	uint32_t gmv:1;	/* Grant Max VPIs */
	uint32_t rsvd2:24;	/* Reserved */
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t max_rpi:16;	/* Max RPIs Port should configure */
	uint32_t max_xri:16;	/* Max XRIs Port should configure */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t max_xri:16;	/* Max XRIs Port should configure */
	uint32_t max_rpi:16;	/* Max RPIs Port should configure */
#endif

#ifdef EMLXS_BIG_ENDIAN
	uint32_t max_hbq:16;	/* Max HBQs Host expect to configure    */
	uint32_t rsvd3:16;	/* Max HBQs Host expect to configure    */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t rsvd3:16;	/* Max HBQs Host expect to configure    */
	uint32_t max_hbq:16;	/* Max HBQs Host expect to configure    */
#endif

	uint32_t rsvd4;	/* Reserved */

#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd5:16;	/* Reserved */
	uint32_t vpi_max:16;	/* Max number of virt N-Ports */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t vpi_max:16;	/* Max number of virt N-Ports */
	uint32_t rsvd5:16;	/* Reserved */
#endif

} CONFIG_PORT_VAR;

#else	/* !SLI3_SUPPORT */

typedef struct {
	uint32_t pcbLen;
	uint32_t pcbLow;	/* bit 31:0  of memory based port cfg block */
	uint32_t pcbHigh;	/* bit 63:32 of memory based port cfg block */
	uint32_t hbainit;
} CONFIG_PORT_VAR;

#endif	/* SLI3_SUPPORT */



/* SLI-2 Port Control Block */

/* SLIM POINTER */
#define	SLIMOFF	0x30	/* WORD */

typedef struct _SLI2_RDSC {
	uint32_t cmdEntries;
	uint32_t cmdAddrLow;
	uint32_t cmdAddrHigh;

	uint32_t rspEntries;
	uint32_t rspAddrLow;
	uint32_t rspAddrHigh;
} SLI2_RDSC;

typedef struct _PCB {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t type:8;
#define	TYPE_NATIVE_SLI2	0x01;
	uint32_t feature:8;
#define	FEATURE_INITIAL_SLI2	0x01;
	uint32_t rsvd:12;
	uint32_t maxRing:4;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t maxRing:4;
	uint32_t rsvd:12;
	uint32_t feature:8;
#define	FEATURE_INITIAL_SLI2	0x01;
	uint32_t type:8;
#define	TYPE_NATIVE_SLI2	0x01;
#endif

	uint32_t mailBoxSize;
	uint32_t mbAddrLow;
	uint32_t mbAddrHigh;

	uint32_t hgpAddrLow;
	uint32_t hgpAddrHigh;

	uint32_t pgpAddrLow;
	uint32_t pgpAddrHigh;
	SLI2_RDSC rdsc[MAX_RINGS_AVAILABLE];
} PCB;

/* NEW_FEATURE */
typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd0:27;
	uint32_t discardFarp:1;
	uint32_t IPEnable:1;
	uint32_t nodeName:1;
	uint32_t portName:1;
	uint32_t filterEnable:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t filterEnable:1;
	uint32_t portName:1;
	uint32_t nodeName:1;
	uint32_t IPEnable:1;
	uint32_t discardFarp:1;
	uint32_t rsvd:27;
#endif
	NAME_TYPE portname;
	NAME_TYPE nodename;
	uint32_t rsvd1;
	uint32_t rsvd2;
	uint32_t rsvd3;
	uint32_t IPAddress;
} CONFIG_FARP_VAR;


/* NEW_FEATURE */
typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t defaultMessageNumber:16;
	uint32_t rsvd1:3;
	uint32_t nid:5;
	uint32_t rsvd2:5;
	uint32_t defaultPresent:1;
	uint32_t addAssociations:1;
	uint32_t reportAssociations:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t reportAssociations:1;
	uint32_t addAssociations:1;
	uint32_t defaultPresent:1;
	uint32_t rsvd2:5;
	uint32_t nid:5;
	uint32_t rsvd1:3;
	uint32_t defaultMessageNumber:16;
#endif
	uint32_t attConditions;
	uint8_t attentionId[16];
	uint16_t messageNumberByHA[32];
	uint16_t messageNumberByID[16];
	uint32_t rsvd3;
} CONFIG_MSI_VAR;


/* NEW_FEATURE */
typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint32_t defaultMessageNumber:8;
	uint32_t rsvd1:11;
	uint32_t nid:5;
	uint32_t rsvd2:5;
	uint32_t defaultPresent:1;
	uint32_t addAssociations:1;
	uint32_t reportAssociations:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t reportAssociations:1;
	uint32_t addAssociations:1;
	uint32_t defaultPresent:1;
	uint32_t rsvd2:5;
	uint32_t nid:5;
	uint32_t rsvd1:11;
	uint32_t defaultMessageNumber:8;
#endif
	uint32_t attConditions1;
	uint32_t attConditions2;
	uint8_t attentionId[16];
	uint8_t messageNumberByHA[64];
	uint8_t messageNumberByID[16];
	uint32_t autoClearByHA1;
	uint32_t autoClearByHA2;
	uint32_t autoClearByID;
	uint32_t resv3;

} CONFIG_MSIX_VAR;


/* Union of all Mailbox Command types */

typedef union {
	uint32_t varWords[31];
	LOAD_SM_VAR varLdSM;	/* cmd =  1 (LOAD_SM) */
	READ_NV_VAR varRDnvp;	/* cmd =  2 (READ_NVPARMS)   */
	WRITE_NV_VAR varWTnvp;	/* cmd =  3 (WRITE_NVPARMS)  */
	BIU_DIAG_VAR varBIUdiag;	/* cmd =  4 (RUN_BIU_DIAG)   */
	INIT_LINK_VAR varInitLnk;	/* cmd =  5 (INIT_LINK) */
	DOWN_LINK_VAR varDwnLnk;	/* cmd =  6 (DOWN_LINK) */
	CONFIG_LINK varCfgLnk;	/* cmd =  7 (CONFIG_LINK)    */
	PART_SLIM_VAR varSlim;	/* cmd =  8 (PART_SLIM) */
	CONFIG_RING_VAR varCfgRing;	/* cmd =  9 (CONFIG_RING)    */
	RESET_RING_VAR varRstRing;	/* cmd = 10 (RESET_RING) */
	READ_CONFIG_VAR varRdConfig;	/* cmd = 11 (READ_CONFIG)    */
	READ_RCONF_VAR varRdRConfig;	/* cmd = 12 (READ_RCONFIG)   */
	READ_SPARM_VAR varRdSparm;	/* cmd = 13 (READ_SPARM(64)) */
	READ_STATUS_VAR varRdStatus;	/* cmd = 14 (READ_STATUS)    */
	READ_RPI_VAR varRdRPI;	/* cmd = 15 (READ_RPI(64))   */
	READ_XRI_VAR varRdXRI;	/* cmd = 16 (READ_XRI) */
	READ_REV_VAR varRdRev;	/* cmd = 17 (READ_REV) */
	READ_LNK_VAR varRdLnk;	/* cmd = 18 (READ_LNK_STAT)  */
	REG_LOGIN_VAR varRegLogin;	/* cmd = 19 (REG_LOGIN(64))  */
	UNREG_LOGIN_VAR varUnregLogin;	/* cmd = 20 (UNREG_LOGIN)    */
	READ_LA_VAR varReadLA;	/* cmd = 21 (READ_LA(64))    */
	CLEAR_LA_VAR varClearLA;	/* cmd = 22 (CLEAR_LA) */
	DUMP_VAR varDmp;	/* Warm Start DUMP mbx cmd   */
	UPDATE_CFG_VAR varUpdateCfg;	/* cmd = 0x1b Warm Start UPDATE_CFG */
	DEL_LD_ENTRY_VAR varDelLdEntry;	/* cmd = 0x1d (DEL_LD_ENTRY) */
	UNREG_D_ID_VAR varUnregDID;	/* cmd = 0x23 (UNREG_D_ID)   */
	CONFIG_FARP_VAR varCfgFarp;	/* cmd = 0x25 (CONFIG_FARP)  */
	CONFIG_MSI_VAR varCfgMSI;	/* cmd = 0x90 (CONFIG_MSI)   */
	CONFIG_MSIX_VAR varCfgMSIX;	/* cmd = 0x30 (CONFIG_MSIX)   */
	CONFIG_HBQ_VAR varCfgHbq;	/* cmd = 0x7C (CONFIG_HBQ)   */
	LOAD_AREA_VAR varLdArea;	/* cmd = 0x81 (LOAD_AREA)    */
	CONFIG_PORT_VAR varCfgPort;	/* cmd = 0x88 (CONFIG_PORT)  */
	LOAD_EXP_ROM_VAR varLdExpRom;	/* cmd = 0x9C (LOAD_XP_ROM)  */
	REG_VPI_VAR varRegVpi;	/* cmd = 0x96 (REG_VPI) */
	UNREG_VPI_VAR varUnregVpi;	/* cmd = 0x97 (UNREG_VPI)    */
	READ_EVT_LOG_VAR varRdEvtLog;	/* cmd = 0x38 (READ_EVENT_LOG)  */

} MAILVARIANTS;

#define	MAILBOX_CMD_BSIZE    128
#define	MAILBOX_CMD_WSIZE    32


/*
 * SLI-2 specific structures
 */

typedef struct _SLI1_DESC {
	emlxs_rings_t mbxCring[4];
	uint32_t mbxUnused[24];
} SLI1_DESC;	/* 128 bytes */

typedef struct {
	uint32_t cmdPutInx;
	uint32_t rspGetInx;
} HGP;

typedef struct {
	uint32_t cmdGetInx;
	uint32_t rspPutInx;
} PGP;

#ifdef SLI3_SUPPORT
typedef struct _SLI2_DESC {
	HGP host[4];
	PGP port[4];
	uint32_t HBQ_PortGetIdx[16];
} SLI2_DESC;	/* 128 bytes */
#else
typedef struct _SLI2_DESC {
	HGP host[4];	/* 8 words */
	uint32_t unused[16];
	PGP port[4];	/* 8 words */
} SLI2_DESC;	/* 128 bytes */
#endif	/* SLI3_SUPPORT */

typedef union {
	SLI1_DESC s1;	/* 32 words, 128 bytes */
	SLI2_DESC s2;	/* 32 words, 128 bytes */
} SLI_VAR;

typedef volatile struct {
#ifdef EMLXS_BIG_ENDIAN
	uint16_t mbxStatus;
	uint8_t mbxCommand;
	uint8_t mbxReserved:6;
	uint8_t mbxHc:1;
	uint8_t mbxOwner:1;	/* Low order bit first word */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t mbxOwner:1;	/* Low order bit first word */
	uint8_t mbxHc:1;
	uint8_t mbxReserved:6;
	uint8_t mbxCommand;
	uint16_t mbxStatus;
#endif
	MAILVARIANTS un;	/* 124 bytes */
	SLI_VAR us;	/* 128 bytes */

} MAILBOX;	/* 256 bytes */

/*
 * End Structure Definitions for Mailbox Commands
 */


/*
 * Begin Structure Definitions for IOCB Commands
 */

typedef struct {
#ifdef EMLXS_BIG_ENDIAN
	uint8_t statAction;
	uint8_t statRsn;
	uint8_t statBaExp;
	uint8_t statLocalError;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint8_t statLocalError;
	uint8_t statBaExp;
	uint8_t statRsn;
	uint8_t statAction;
#endif
	/* statAction  FBSY reason codes */
#define	FBSY_RSN_MASK   0xF0	/* Rsn stored in upper nibble */
#define	FBSY_FABRIC_BSY 0x10	/* F_bsy due to Fabric BSY */
#define	FBSY_NPORT_BSY  0x30	/* F_bsy due to N_port BSY */

	/* statAction  PBSY action codes */
#define	PBSY_ACTION1    0x01	/* Sequence terminated - retry */
#define	PBSY_ACTION2    0x02	/* Sequence active - retry */

	/* statAction  P/FRJT action codes */
#define	RJT_RETRYABLE   0x01	/* Retryable class of error */
#define	RJT_NO_RETRY    0x02	/* Non-Retryable class of error */

	/* statRsn  LS_RJT reason codes defined in LS_RJT structure */

	/* statRsn  P_BSY reason codes */
#define	PBSY_NPORT_BSY  0x01	/* Physical N_port BSY */
#define	PBSY_RESRCE_BSY 0x03	/* N_port resource BSY */
#define	PBSY_VU_BSY	0xFF	/* See VU field for rsn */

	/* statRsn  P/F_RJT reason codes */
#define	RJT_BAD_D_ID		0x01	/* Invalid D_ID field */
#define	RJT_BAD_S_ID		0x02	/* Invalid S_ID field */
#define	RJT_UNAVAIL_TEMP	0x03	/* N_Port unavailable temp. */
#define	RJT_UNAVAIL_PERM	0x04	/* N_Port unavailable perm. */
#define	RJT_UNSUP_CLASS		0x05	/* Class not supported */
#define	RJT_DELIM_ERR		0x06	/* Delimiter usage error */
#define	RJT_UNSUP_TYPE		0x07	/* Type not supported */
#define	RJT_BAD_CONTROL		0x08	/* Invalid link conrtol */
#define	RJT_BAD_RCTL		0x09	/* R_CTL invalid */
#define	RJT_BAD_FCTL		0x0A	/* F_CTL invalid */
#define	RJT_BAD_OXID		0x0B	/* OX_ID invalid */
#define	RJT_BAD_RXID		0x0C	/* RX_ID invalid */
#define	RJT_BAD_SEQID		0x0D	/* SEQ_ID invalid */
#define	RJT_BAD_DFCTL		0x0E	/* DF_CTL invalid */
#define	RJT_BAD_SEQCNT		0x0F	/* SEQ_CNT invalid */
#define	RJT_BAD_PARM		0x10	/* Param. field invalid */
#define	RJT_XCHG_ERR		0x11	/* Exchange error */
#define	RJT_PROT_ERR		0x12	/* Protocol error */
#define	RJT_BAD_LENGTH		0x13	/* Invalid Length */
#define	RJT_UNEXPECTED_ACK	0x14	/* Unexpected ACK */
#define	RJT_LOGIN_REQUIRED	0x16	/* Login required */
#define	RJT_TOO_MANY_SEQ	0x17	/* Excessive sequences */
#define	RJT_XCHG_NOT_STRT	0x18	/* Exchange not started */
#define	RJT_UNSUP_SEC_HDR	0x19	/* Security hdr not supported */
#define	RJT_UNAVAIL_PATH	0x1A	/* Fabric Path not available */
#define	RJT_VENDOR_UNIQUE	0xFF	/* Vendor unique error */

	/* statRsn  BA_RJT reason codes */
#define	BARJT_BAD_CMD_CODE	0x01	/* Invalid command code */
#define	BARJT_LOGICAL_ERR	0x03	/* Logical error */
#define	BARJT_LOGICAL_BSY	0x05	/* Logical busy */
#define	BARJT_PROTOCOL_ERR	0x07	/* Protocol error */
#define	BARJT_VU_ERR		0xFF	/* Vendor unique error */

	/* LS_RJT reason explanation defined in LS_RJT structure */

	/* BA_RJT reason explanation */
#define	BARJT_EXP_INVALID_ID  0x01	/* Invalid OX_ID/RX_ID */
#define	BARJT_EXP_ABORT_SEQ   0x05	/* Abort SEQ, no more info */

	/* Local Reject errors */
#define	IOERR_SUCCESS					0x00
#define	IOERR_MISSING_CONTINUE			0x01
#define	IOERR_SEQUENCE_TIMEOUT			0x02
#define	IOERR_INTERNAL_ERROR			0x03
#define	IOERR_INVALID_RPI				0x04
#define	IOERR_NO_XRI					0x05
#define	IOERR_ILLEGAL_COMMAND			0x06
#define	IOERR_XCHG_DROPPED				0x07
#define	IOERR_ILLEGAL_FIELD				0x08
/* RESERVED 0x09 */
/* RESERVED 0x0A */
#define	IOERR_RCV_BUFFER_WAITING		0x0B
/* RESERVED 0x0C */
#define	IOERR_TX_DMA_FAILED				0x0D
#define	IOERR_RX_DMA_FAILED				0x0E
#define	IOERR_ILLEGAL_FRAME				0x0F

/* RESERVED 0x10 */
#define	IOERR_NO_RESOURCES				0x11
/* RESERVED 0x12 */
#define	IOERR_ILLEGAL_LENGTH			0x13
#define	IOERR_UNSUPPORTED_FEATURE		0x14
#define	IOERR_ABORT_IN_PROGRESS			0x15
#define	IOERR_ABORT_REQUESTED			0x16
#define	IOERR_RCV_BUFFER_TIMEOUT		0x17
#define	IOERR_LOOP_OPEN_FAILURE			0x18
#define	IOERR_RING_RESET				0x19
#define	IOERR_LINK_DOWN					0x1A
#define	IOERR_CORRUPTED_DATA			0x1B
#define	IOERR_CORRUPTED_RPI				0x1C
#define	IOERR_OUT_OF_ORDER_DATA			0x1D
#define	IOERR_OUT_OF_ORDER_ACK			0x1E
#define	IOERR_DUP_FRAME					0x1F

#define	IOERR_LINK_CONTROL_FRAME		0x20	/* ACK_N received */
#define	IOERR_BAD_HOST_ADDRESS			0x21
#define	IOERR_RCV_HDRBUF_WAITING		0x22
#define	IOERR_MISSING_HDR_BUFFER		0x23
#define	IOERR_MSEQ_CHAIN_CORRUPTED		0x24
#define	IOERR_ABORTMULT_REQUESTED		0x25
/* RESERVED 0x26 */
/* RESERVED 0x27 */
#define	IOERR_BUFFER_SHORTAGE			0x28
#define	IOERR_XRIBUF_WAITING			0x29
/* RESERVED 0x2A */
#define	IOERR_MISSING_HBQ_ENTRY			0x2B
#define	IOERR_ABORT_EXT_REQ				0x2C
#define	IOERR_CLOSE_EXT_REQ				0x2D
/* RESERVED 0x2E */
/* RESERVED 0x2F */

#define	IOERR_XRIBUF_MISSING			0x30
#define	IOERR_ASSI_RSP_SUPPRESSED		0x31
/* RESERVED 0x32 - 0x3F */

#define	IOERR_ROFFSET_INVAL				0x40
#define	IOERR_ROFFSET_MISSING			0x41
#define	IOERR_INSUF_BUFFER				0x42
#define	IOERR_MISSING_SI				0x43
#define	IOERR_MISSING_ES				0x44
#define	IOERR_INCOMP_XFER				0x45
/* RESERVED 0x46 - 0xFF */

	/* Driver defined */
#define	IOERR_ABORT_TIMEOUT				0xF0

} PARM_ERR;

typedef union {
	struct {
#ifdef EMLXS_BIG_ENDIAN
		uint8_t Rctl;	/* R_CTL field */
		uint8_t Type;	/* TYPE field */
		uint8_t Dfctl;	/* DF_CTL field */
		uint8_t Fctl;	/* Bits 0-7 of IOCB word 5 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
		uint8_t Fctl;	/* Bits 0-7 of IOCB word 5 */
		uint8_t Dfctl;	/* DF_CTL field */
		uint8_t Type;	/* TYPE field */
		uint8_t Rctl;	/* R_CTL field */
#endif
#define	FCP_RTYPE  0x08	/* FCP_TARGET_MODE Type - Rctl */

#define	BC	0x02	/* Broadcast Received  - Fctl */
#define	SI	0x04	/* Sequence Initiative */
#define	LA	0x08	/* Ignore Link Attention state */
#define	FSEQ	0x40	/* First Sequence */
#define	LSEQ	0x80	/* Last Sequence */
	} hcsw;
	uint32_t reserved;
} WORD5;


/* IOCB Command template for a generic response */
typedef struct {
	uint32_t reserved[4];
	PARM_ERR perr;
} GENERIC_RSP;


/* IOCB Command template for XMIT / XMIT_BCAST / RCV_SEQUENCE / XMIT_ELS */
typedef struct {
	ULP_BDE xrsqbde[2];
	uint32_t xrsqRo;	/* Starting Relative Offset */
	WORD5 w5;	/* Header control/status word */
} XR_SEQ_FIELDS;

/* IOCB Command template for ELS_REQUEST */
typedef struct {
	ULP_BDE elsReq;
	ULP_BDE elsRsp;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t word4Rsvd:7;
	uint32_t fl:1;
	uint32_t myID:24;
	uint32_t word5Rsvd:8;
	uint32_t remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t myID:24;
	uint32_t fl:1;
	uint32_t word4Rsvd:7;
	uint32_t remoteID:24;
	uint32_t word5Rsvd:8;
#endif
} ELS_REQUEST;

/* IOCB Command template for RCV_ELS_REQ */
typedef struct {
	ULP_BDE elsReq[2];
	uint32_t parmRo;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t word5Rsvd:8;
	uint32_t remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t remoteID:24;
	uint32_t word5Rsvd:8;
#endif
} RCV_ELS_REQ;

/* IOCB Command template for ABORT / CLOSE_XRI */
typedef struct {
	uint32_t rsvd[3];
	uint32_t abortType;
#define	ABORT_TYPE_ABTX  0x00000000
#define	ABORT_TYPE_ABTS  0x00000001
	uint32_t parm;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t abortContextTag;	/* ulpContext from cmd to abort/close */
	uint16_t abortIoTag;	/* ulpIoTag from cmd to abort/close */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t abortIoTag;	/* ulpIoTag from cmd to abort/close */
	uint16_t abortContextTag;	/* ulpContext from cmd to abort/close */
#endif
} AC_XRI;

/* IOCB Command template for GET_RPI */
typedef struct {
	uint32_t rsvd[4];
	uint32_t parmRo;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t word5Rsvd:8;
	uint32_t remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t remoteID:24;
	uint32_t word5Rsvd:8;
#endif
} GET_RPI;

/* IOCB Command template for all FCP Initiator commands */
typedef struct {
	ULP_BDE fcpi_cmnd;	/* FCP_CMND payload descriptor */
	ULP_BDE fcpi_rsp;	/* Rcv buffer */
	uint32_t fcpi_parm;
	uint32_t fcpi_XRdy;	/* transfer ready for IWRITE */
} FCPI_FIELDS;

/* IOCB Command template for all FCP Target commands */
typedef struct {
	ULP_BDE fcpt_Buffer[2];	/* FCP_CMND payload descriptor */
	uint32_t fcpt_Offset;
	uint32_t fcpt_Length;	/* transfer ready for IWRITE */
} FCPT_FIELDS;

/* SLI-2 IOCB structure definitions */

/* IOCB Command template for 64 bit XMIT / XMIT_BCAST / XMIT_ELS */
typedef struct {
	ULP_BDL bdl;
	uint32_t xrsqRo;	/* Starting Relative Offset */
	WORD5 w5;	/* Header control/status word */
} XMT_SEQ_FIELDS64;


/* IOCB Command template for 64 bit RCV_SEQUENCE64 */
typedef struct {
	ULP_BDE64 rcvBde;
	uint32_t rsvd1;
	uint32_t xrsqRo;	/* Starting Relative Offset */
	WORD5 w5;	/* Header control/status word */
} RCV_SEQ_FIELDS64;

/* IOCB Command template for ELS_REQUEST64 */
typedef struct {
	ULP_BDL bdl;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t word4Rsvd:7;
	uint32_t fl:1;
	uint32_t myID:24;

	uint32_t word5Rsvd:8;
	uint32_t remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t myID:24;
	uint32_t fl:1;
	uint32_t word4Rsvd:7;

	uint32_t remoteID:24;
	uint32_t word5Rsvd:8;
#endif
} ELS_REQUEST64;


/* IOCB Command template for ASYNC_STATUS */
typedef struct {
	ULP_BDL resv;
	uint32_t parameter;
#ifdef EMLXS_BIG_ENDIAN
	uint16_t EventCode;
	uint16_t SubContext;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t SubContext;
	uint16_t EventCode;
#endif
} ASYNC_STATUS;


/* IOCB Command template for QUE_RING_LIST64 */
typedef struct {
	ULP_BDL bdl;
	uint32_t rsvd1;
	uint32_t rsvd2;
} QUE_RING_LIST64;


/* IOCB Command template for GEN_REQUEST64 */
typedef struct {
	ULP_BDL bdl;
	uint32_t param;	/* Starting Relative Offset */
	WORD5 w5;	/* Header control/status word */
} GEN_REQUEST64;

/* IOCB Command template for RCV_ELS_REQ64 */
typedef struct {
	ULP_BDE64 elsReq;
	uint32_t rcvd1;
	uint32_t parmRo;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t word5Rsvd:8;
	uint32_t remoteID:24;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t remoteID:24;
	uint32_t word5Rsvd:8;
#endif
} RCV_ELS_REQ64;

/* IOCB Command template for all 64 bit FCP Initiator commands */
typedef struct {
	ULP_BDL bdl;
	uint32_t fcpi_parm;
	uint32_t fcpi_XRdy;	/* transfer ready for IWRITE */
} FCPI_FIELDS64;

/* IOCB Command template for all 64 bit FCP Target commands */
typedef struct {
	ULP_BDL bdl;
	uint32_t fcpt_Offset;
	uint32_t fcpt_Length;	/* transfer ready for IWRITE */
} FCPT_FIELDS64;

/* IOCB Command template for all 64 bit FCP Target commands */
typedef struct {
	uint32_t rsp_length;
	uint32_t rsvd1;
	uint32_t rsvd2;
	uint32_t iotag32;
	uint32_t status;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t rsvd:30;
	uint32_t lnk:1;
#endif	/* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t lnk:1;
	uint32_t rsvd:30;
#endif	/* EMLXS_LITTLE_ENDIAN */

} AUTO_TRSP;


typedef struct {
	uint32_t io_tag64_low;	/* Word 8 */
	uint32_t io_tag64_high;	/* Word 9 */
#ifdef EMLXS_BIG_ENDIAN
	uint32_t cs_ctl:8;	/* Word 10, bit 31:24 */
	uint32_t cs_en:1;	/* Word 10, bit 23    */
	uint32_t rsv:15;	/* Word 10, bit 22:8  */
	uint32_t ebde_count:8;	/* Word 10, bit 7:0   */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t ebde_count:8;	/* Word 10, bit 7:0   */
	uint32_t rsv:15;	/* Word 10, bit 22:8  */
	uint32_t cs_en:1;	/* Word 10, bit 23    */
	uint32_t cs_ctl:8;	/* Word 10, bit 31:24 */
#endif
	uint32_t rsplen;	/* Word 11 */
	ULP_BDE64 ebde1;	/* Word 12:14 */
	ULP_BDE64 ebde2;	/* Word 15:17 */
	ULP_BDE64 ebde3;	/* Word 18:20 */
	ULP_BDE64 ebde4;	/* Word 21:23 */
	ULP_BDE64 ebde5;	/* Word 24:26 */
	ULP_BDE64 ebde6;	/* Word 27:29 */

} GENERIC_EXT_IOCB;

/*
 * IOCB Command Extension template for CMD_RCV_ELS64_CX (0xB7)
 * or CMD_RCV_SEQ64_CX (0xB5)
 */

typedef struct {
	uint32_t hdr3;	/* word 8 */
#ifdef EMLXS_BIG_ENDIAN
	uint16_t vpi;	/* word 9 */
	uint16_t buddy_xri;

	uint32_t ccp:8;	/* word 10 */
	uint32_t ccpe:1;
	uint32_t rsvd:23;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t buddy_xri;	/* word 9 */
	uint16_t vpi;

	uint32_t rsvd:23;	/* word 10 */
	uint32_t ccpe:1;
	uint32_t ccp:8;
#endif
	uint32_t seq_len;	/* received sequence length */
	ULP_BDL bde2;	/* total 4 words */

} RCV_SEQ_ELS_64_SLI3_EXT;



typedef volatile struct emlxs_iocb {	/* IOCB structure */
	union {
		GENERIC_RSP grsp;	/* Generic response */
		XR_SEQ_FIELDS xrseq;	/* XMIT / BCAST / RCV_SEQUENCE cmd */
		ULP_BDE cont[3];	/* up to 3 continuation bdes */
		ELS_REQUEST elsreq;	/* ELS_REQUEST template */
		RCV_ELS_REQ rcvels;	/* RCV_ELS_REQ template */
		AC_XRI acxri;	/* ABORT / CLOSE_XRI template */
		GET_RPI getrpi;	/* GET_RPI template */
		FCPI_FIELDS fcpi;	/* FCP Initiator template */
		FCPT_FIELDS fcpt;	/* FCP target template */

		/* SLI-2 structures */

		ULP_BDE64 cont64[2];	/* up to 2 64 bit cont bde_64s */
		ELS_REQUEST64 elsreq64;	/* ELS_REQUEST template */
		QUE_RING_LIST64 qringlist64;	/* QUE RING LIST64 template */
		GEN_REQUEST64 genreq64;	/* GEN_REQUEST template */
		RCV_ELS_REQ64 rcvels64;	/* RCV_ELS_REQ template */
		XMT_SEQ_FIELDS64 xseq64;	/* XMIT / BCAST cmd */
		FCPI_FIELDS64 fcpi64;	/* FCP 64 bit Initiator template */
		FCPT_FIELDS64 fcpt64;	/* FCP 64 bit target template */
		AUTO_TRSP atrsp;	/* FCP 64 bit target template */

		RCV_SEQ_FIELDS64 rcvseq64;
		ASYNC_STATUS astat;

		uint32_t ulpWord[6];	/* generic 6 'words' */
	} un;
	union {
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint16_t ulpContext;	/* High order bits word6 */
			uint16_t ulpIoTag;	/* Low  order bits word6 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t ulpIoTag;	/* Low  order bits word6 */
			uint16_t ulpContext;	/* High order bits word6 */
#endif
		} t1;
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint16_t ulpContext;	/* High order bits word6 */
			uint16_t ulpIoTag1:2;	/* Low  order bits word6 */
			uint16_t ulpIoTag0:14;	/* Low  order bits word6 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint16_t ulpIoTag0:14;	/* Low  order bits word6 */
			uint16_t ulpIoTag1:2;	/* Low  order bits word6 */
			uint16_t ulpContext;	/* High order bits word6 */
#endif
		} t2;
	} un1;
#define	ulpContext	un1.t1.ulpContext
#define	ulpIoTag	un1.t1.ulpIoTag
#define	ulpIoTag0	un1.t2.ulpIoTag0
#define	ulpDelayXmit	un1.t2.ulpIoTag1

#define	IOCB_DELAYXMIT_MSK 0x3000


	union {
		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t ulpRsvdByte:8;
			uint32_t ulpXS:1;
			uint32_t ulpFCP2Rcvy:1;
			uint32_t ulpPU:2;
			uint32_t ulpIr:1;
			uint32_t ulpClass:3;
			uint32_t ulpCommand:8;
			uint32_t ulpStatus:4;
			uint32_t ulpBdeCount:2;
			uint32_t ulpLe:1;
			uint32_t ulpOwner:1;	/* Low order bit word 7 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t ulpOwner:1;	/* Low order bit word 7 */
			uint32_t ulpLe:1;
			uint32_t ulpBdeCount:2;
			uint32_t ulpStatus:4;
			uint32_t ulpCommand:8;
			uint32_t ulpClass:3;
			uint32_t ulpIr:1;
			uint32_t ulpPU:2;
			uint32_t ulpFCP2Rcvy:1;
			uint32_t ulpXS:1;
			uint32_t ulpRsvdByte:8;
#endif
		} t1;

		struct {
#ifdef EMLXS_BIG_ENDIAN
			uint32_t ulpRsvdByte:8;
			uint32_t ulpCT:2;
			uint32_t ulpPU:2;
			uint32_t ulpIr:1;
			uint32_t ulpClass:3;
			uint32_t ulpCommand:8;
			uint32_t ulpStatus:4;
			uint32_t ulpBdeCount:2;
			uint32_t ulpLe:1;
			uint32_t ulpOwner:1;	/* Low order bit word 7 */
#endif
#ifdef EMLXS_LITTLE_ENDIAN
			uint32_t ulpOwner:1;	/* Low order bit word 7 */
			uint32_t ulpLe:1;
			uint32_t ulpBdeCount:2;
			uint32_t ulpStatus:4;
			uint32_t ulpCommand:8;
			uint32_t ulpClass:3;
			uint32_t ulpIr:1;
			uint32_t ulpPU:2;
			uint32_t ulpCT:2;
			uint32_t ulpRsvdByte:8;
#endif
		} t2;

	} un2;

#define	ulpCT			un2.t2.ulpCT
#define	ulpRsvdByte		un2.t1.ulpRsvdByte
#define	ulpXS			un2.t1.ulpXS
#define	ulpFCP2Rcvy		un2.t1.ulpFCP2Rcvy
#define	ulpPU			un2.t1.ulpPU
#define	ulpIr			un2.t1.ulpIr
#define	ulpClass		un2.t1.ulpClass
#define	ulpCommand		un2.t1.ulpCommand
#define	ulpStatus		un2.t1.ulpStatus
#define	ulpBdeCount		un2.t1.ulpBdeCount
#define	ulpLe			un2.t1.ulpLe
#define	ulpOwner		un2.t1.ulpOwner
	/* 32 bytes at this point */

#ifdef SLI3_SUPPORT
	union {
		GENERIC_EXT_IOCB ext_iocb;
		RCV_SEQ_ELS_64_SLI3_EXT ext_rcv;
		uint32_t sli3Words[24];	/* 96 extra bytes for SLI-3 */
	} unsli3;
	/* 128 bytes at this point */
#endif	/* SLI3_SUPPORT */

#define	IOCB_FCP	1	/* IOCB is used for FCP ELS cmds - ulpRsvByte */
#define	IOCB_IP		2	/* IOCB is used for IP ELS cmds */
#define	PARM_UNUSED	0	/* PU field (Word 4) not used */
#define	PARM_REL_OFF	1	/* PU field (Word 4) = R. O. */
#define	PARM_READ_CHECK	2	/* PU field (Word 4) = Data Transfer Length */
#define	CLASS1		0	/* Class 1 */
#define	CLASS2		1	/* Class 2 */
#define	CLASS3		2	/* Class 3 */
#define	CLASS_FCP_INTERMIX 7	/* FCP Data->Cls 1, all else->Cls 2 */

#define	IOSTAT_SUCCESS				0x0	/* ulpStatus */
#define	IOSTAT_FCP_RSP_ERROR		0x1
#define	IOSTAT_REMOTE_STOP			0x2
#define	IOSTAT_LOCAL_REJECT			0x3
#define	IOSTAT_NPORT_RJT			0x4
#define	IOSTAT_FABRIC_RJT			0x5
#define	IOSTAT_NPORT_BSY			0x6
#define	IOSTAT_FABRIC_BSY			0x7
#define	IOSTAT_INTERMED_RSP			0x8
#define	IOSTAT_LS_RJT				0x9
#define	IOSTAT_RESERVED_A			0xA
#define	IOSTAT_CMD_REJECT			0xB
#define	IOSTAT_FCP_TGT_LENCHK		0xC
#define	IOSTAT_NEED_BUF_ENTRY		0xD
#define	IOSTAT_RESERVED_E			0xE
#define	IOSTAT_ILLEGAL_FRAME_RCVD	0xF

/* Special error codes */
#define	IOSTAT_DATA_OVERRUN    0x10	/* Added for resid handling */
#define	IOSTAT_DATA_UNDERRUN   0x11	/* Added for resid handling */

} emlxs_iocb_t;
typedef emlxs_iocb_t IOCB;


typedef struct emlxs_iocbq {
	emlxs_iocb_t iocb;
	struct emlxs_iocbq *next;

	uint8_t *bp;	/* ptr to data buffer structure */
	void *port;	/* Board info pointer */
	void *ring;	/* Ring pointer */
	void *node;	/* Node pointer */
	void *sbp;	/* Pkt pointer */
	uint32_t flag;

#define	IOCB_POOL_ALLOCATED	0x00000001
#define	IOCB_PRIORITY		0x00000002
#define	IOCB_SPECIAL		0x00000004

} emlxs_iocbq_t;
typedef emlxs_iocbq_t IOCBQ;


typedef struct emlxs_mbq {
	volatile uint32_t mbox[MAILBOX_CMD_WSIZE];
	struct emlxs_mbq *next;

	/* Defferred handling pointers */
	uint8_t *bp;	/* ptr to data buffer structure */
	uint8_t *sbp;	/* ptr to emlxs_buf_t structure */
	uint8_t *ubp;	/* ptr to fc_unsol_buf_t structure */
	uint8_t *iocbq;	/* ptr to IOCBQ structure */
	uint32_t flag;

#define	MBQ_POOL_ALLOCATED	0x00000001
#define	MBQ_PASSTHRU		0x00000002
#define	MBQ_COMPLETED		0x00010000	/* Used for MBX_SLEEP */
#define	MBQ_INIT_MASK		0x0000ffff

#ifdef MBOX_EXT_SUPPORT
	uint8_t *extbuf;	/* ptr to mailbox extension buffer */
	uint32_t extsize;	/* size of mailbox extension buffer */
#endif	/* MBOX_EXT_SUPPORT */

} emlxs_mbq_t;
typedef emlxs_mbq_t MAILBOXQ;


/* We currently do not support IOCBs in SLI1 mode */
typedef struct {
	MAILBOX mbx;
#ifdef MBOX_EXT_SUPPORT
	uint8_t mbxExt[MBOX_EXTENSION_SIZE];
#endif	/* MBOX_EXT_SUPPORT */
	uint8_t pad[(SLI_SLIM1_SIZE-(sizeof (MAILBOX) + MBOX_EXTENSION_SIZE))];
} SLIM1;


typedef struct {
	MAILBOX mbx;
#ifdef MBOX_EXT_SUPPORT
	uint8_t mbxExt[MBOX_EXTENSION_SIZE];
#endif	/* MBOX_EXT_SUPPORT */
	PCB pcb;
	uint8_t IOCBs[SLI_IOCB_MAX_SIZE];
} SLIM2;



/*
 * This file defines the Header File for the FDMI HBA Management Service
 */

/*
 * FDMI HBA MAnagement Operations Command Codes
 */
#define	 SLI_MGMT_GRHL		0x100	/* Get registered HBA list */
#define	 SLI_MGMT_GHAT		0x101	/* Get HBA attributes */
#define	 SLI_MGMT_GRPL		0x102	/* Get registered Port list */
#define	 SLI_MGMT_GPAT		0x110	/* Get Port attributes */
#define	 SLI_MGMT_RHBA		0x200	/* Register HBA */
#define	 SLI_MGMT_RHAT		0x201	/* Register HBA atttributes */
#define	 SLI_MGMT_RPRT		0x210	/* Register Port */
#define	 SLI_MGMT_RPA		0x211	/* Register Port attributes */
#define	 SLI_MGMT_DHBA		0x300	/* De-register HBA */
#define	 SLI_MGMT_DPRT		0x310	/* De-register Port */

/*
 * Management Service Subtypes
 */
#define	 SLI_CT_FDMI_Subtypes	0x10


/*
 * HBA Management Service Reject Code
 */
#define	 REJECT_CODE		0x9	/* Unable to perform command request */

/*
 * HBA Management Service Reject Reason Code
 * Please refer to the Reason Codes above
 */

/*
 * HBA Attribute Types
 */
#define	 NODE_NAME		0x1
#define	 MANUFACTURER		0x2
#define	 SERIAL_NUMBER		0x3
#define	 MODEL			0x4
#define	 MODEL_DESCRIPTION	0x5
#define	 HARDWARE_VERSION	0x6
#define	 DRIVER_VERSION		0x7
#define	 OPTION_ROM_VERSION	0x8
#define	 FIRMWARE_VERSION	0x9
#define	 VENDOR_SPECIFIC	0xa
#define	 DRV_NAME		0xb
#define	 OS_NAME_VERSION	0xc
#define	 MAX_CT_PAYLOAD_LEN	0xd

/*
 * Port Attrubute Types
 */
#define	 SUPPORTED_FC4_TYPES	0x1
#define	 SUPPORTED_SPEED	0x2
#define	 PORT_SPEED		0x3
#define	 MAX_FRAME_SIZE		0x4
#define	 OS_DEVICE_NAME		0x5

union AttributesDef {
	/* Structure is in Big Endian format */
	struct {
		uint32_t AttrType:16;
		uint32_t AttrLen:16;
	} bits;
	uint32_t word;
};

/*
 * HBA Attribute Entry (8 - 260 bytes)
 */
typedef struct {
	union AttributesDef ad;
	union {
		uint32_t VendorSpecific;
		uint32_t SupportSpeed;
		uint32_t PortSpeed;
		uint32_t MaxFrameSize;
		uint32_t MaxCTPayloadLen;
		uint8_t SupportFC4Types[32];
		uint8_t OsDeviceName[256];
		uint8_t Manufacturer[64];
		uint8_t SerialNumber[64];
		uint8_t Model[256];
		uint8_t ModelDescription[256];
		uint8_t HardwareVersion[256];
		uint8_t DriverVersion[256];
		uint8_t OptionROMVersion[256];
		uint8_t FirmwareVersion[256];
		uint8_t DriverName[256];
		NAME_TYPE NodeName;
	} un;
} ATTRIBUTE_ENTRY, *PATTRIBUTE_ENTRY;


/*
 * HBA Attribute Block
 */
typedef struct {
	uint32_t EntryCnt;	/* Number of HBA attribute entries */
	ATTRIBUTE_ENTRY Entry;	/* Variable-length array */
} ATTRIBUTE_BLOCK, *PATTRIBUTE_BLOCK;


/*
 * Port Entry
 */
typedef struct {
	NAME_TYPE PortName;
} PORT_ENTRY, *PPORT_ENTRY;

/*
 * HBA Identifier
 */
typedef struct {
	NAME_TYPE PortName;
} HBA_IDENTIFIER, *PHBA_IDENTIFIER;

/*
 * Registered Port List Format
 */
typedef struct {
	uint32_t EntryCnt;
	PORT_ENTRY pe;	/* Variable-length array */
} REG_PORT_LIST, *PREG_PORT_LIST;

/*
 * Register HBA(RHBA)
 */
typedef struct {
	HBA_IDENTIFIER hi;
	REG_PORT_LIST rpl;	/* variable-length array */
	/* ATTRIBUTE_BLOCK   ab; */
} REG_HBA, *PREG_HBA;

/*
 * Register HBA Attributes (RHAT)
 */
typedef struct {
	NAME_TYPE HBA_PortName;
	ATTRIBUTE_BLOCK ab;
} REG_HBA_ATTRIBUTE, *PREG_HBA_ATTRIBUTE;

/*
 * Register Port Attributes (RPA)
 */
typedef struct {
	NAME_TYPE HBA_PortName;
	NAME_TYPE PortName;
	ATTRIBUTE_BLOCK ab;
} REG_PORT_ATTRIBUTE, *PREG_PORT_ATTRIBUTE;

/*
 * Get Registered HBA List (GRHL) Accept Payload Format
 */
typedef struct {
	uint32_t HBA__Entry_Cnt;   /* Number of Registered HBA Identifiers */
	NAME_TYPE HBA_PortName;    /* Variable-length array */
} GRHL_ACC_PAYLOAD, *PGRHL_ACC_PAYLOAD;

/*
 * Get Registered Port List (GRPL) Accept Payload Format
 */
typedef struct {
	uint32_t RPL_Entry_Cnt;	/* Number of Registered Port Entries */
	PORT_ENTRY Reg_Port_Entry[1];	/* Variable-length array */
} GRPL_ACC_PAYLOAD, *PGRPL_ACC_PAYLOAD;

/*
 * Get Port Attributes (GPAT) Accept Payload Format
 */

typedef struct {
	ATTRIBUTE_BLOCK pab;
} GPAT_ACC_PAYLOAD, *PGPAT_ACC_PAYLOAD;

/*
 * Use for Firmware DownLoad
 */

/* ------------------------  download.h  ------------------------------ */

#define	 REDUCED_SRAM_CFG	0x7FFFC	/* 9802DC */
#define	 FULL_SRAM_CFG		0x13FFFC	/* 9802   */

#define	 SLI_FW_TYPE_SHIFT(x) ((x << 20))
#define	 SLI_FW_ADAPTER_TYPE_MASK   0x00f00000
#define	 SLI_FW_TYPE_6000  SLI_FW_TYPE_SHIFT(0)
#define	 SLI_FW_TYPE_7000  SLI_FW_TYPE_SHIFT(1)
#define	 SLI_FW_TYPE_8000  SLI_FW_TYPE_SHIFT(2)
#define	 SLI_FW_TYPE_850   SLI_FW_TYPE_SHIFT(3)
#define	 SLI_FW_TYPE_9000  SLI_FW_TYPE_SHIFT(4)
#define	 SLI_FW_TYPE_950   SLI_FW_TYPE_SHIFT(5)
#define	 SLI_FW_TYPE_9802  SLI_FW_TYPE_SHIFT(6)	/* [022702] */
#define	 SLI_FW_TYPE_982   SLI_FW_TYPE_SHIFT(7)
#define	 SLI_FW_TYPE_10000 SLI_FW_TYPE_SHIFT(8)
#define	 SLI_FW_TYPE_1050  SLI_FW_TYPE_SHIFT(9)
#define	 SLI_FW_TYPE_X1000 SLI_FW_TYPE_SHIFT(0xa)
#define	 SLI_FW_TYPE_101   SLI_FW_TYPE_SHIFT(0xb)	/* LP101 */


enum emlxs_prog_type {
	TEST_PROGRAM,	/* 0 */
	UTIL_PROGRAM,	/* 1 */
	FUNC_FIRMWARE,	/* 2 */
	BOOT_BIOS,	/* 3 */
	CONFIG_DATA,	/* 4 */
	SEQUENCER_CODE,	/* 5 */
	SLI1_OVERLAY,	/* 6 */
	SLI2_OVERLAY,	/* 7 */
	GASKET,	/* 8 */
	HARDWARE_IMAGE,	/* 9 */
	SBUS_FCODE,	/* A */
	SLI3_OVERLAY,	/* B */
	RESERVED_C,
	RESERVED_D,
	SLI4_OVERLAY,	/* E */
	KERNEL_CODE,	/* F */
	MAX_PROG_TYPES

} emlxs_prog_type_t;


typedef struct emlxs_fw_file {
	uint32_t version;
	uint32_t revcomp;
	char label[16];
	uint32_t offset;

} emlxs_fw_file_t;

typedef struct emlxs_fw_image {
	emlxs_fw_file_t awc;
	emlxs_fw_file_t bwc;
	emlxs_fw_file_t dwc;
	emlxs_fw_file_t prog[MAX_PROG_TYPES];

} emlxs_fw_image_t;




#define	 NOP_IMAGE_TYPE		0xe1a00000

#define	 FLASH_BASE_ADR		0x01400000
#define	 DL_FROM_SLIM_OFFSET	MBOX_EXTENSION_OFFSET

#ifdef MBOX_EXT_SUPPORT
#define	 DL_SLIM_SEG_BYTE_COUNT	MBOX_EXTENSION_SIZE
#else
#define	 DL_SLIM_SEG_BYTE_COUNT	128
#endif	/* MBOX_EXT_SUPPORT */

#define	 SLI_CKSUM_LENGTH		4
#define	 SLI_CKSUM_SEED			0x55555555
#define	 SLI_CKSUM_ERR			0x1982abcd

#define	 AIF_NOOP			0xe1a00000
#define	 AIF_BLAL			0xeb000000
#define	 OS_EXIT			0xef000011
#define	 OS_GETENV			0xef000010
#define	 AIF_IMAGEBASE			0x00008000
#define	 AIF_BLZINIT			0xeb00000c
#define	 DEBUG_TASK			0xef041d41
#define	 AIF_DBG_SRC			2
#define	 AIF_DBG_LL			1
#define	 AIF_DATABASAT			0x100

#define	 JEDEC_ID_ADDRESS		0x0080001c
#define	 MAX_RBUS_SRAM_SIZE_ADR		0x788
#define	 MAX_IBUS_SRAM_SIZE_ADR		0x78c
#define	 FULL_RBUS_SRAM_CFG		0x7fffc
#define	 FULL_IBUS_SRAM_CFG		0x187fffc
#define	 REDUCED_RBUS_SRAM_CFG		0x5fffc
#define	 REDUCED_IBUS_SRAM_CFG		0x183fffc
#define	 FULL_SRAM_CFG_PROG_ID		1
#define	 REDUCED_SRAM_CFG_PROG_ID	2
#define	 OTHER_SRAM_CFG_PROG_ID		3

#define	 NO_FLASH_MEM_AVAIL		0xf1

#define	 PROG_TYPE_MASK			0xff000000
#define	 PROG_TYPE_SHIFT		24

#define	 FLASH_LOAD_LIST_ADR	0x79c
#define	 RAM_LOAD_ENTRY_SIZE	9
#define	 FLASH_LOAD_ENTRY_SIZE	6
#define	 RAM_LOAD_ENTRY_TYPE	0
#define	 FLASH_LOAD_ENTRY_TYPE	1

#define	 CFG_DATA_NO_REGION	-3

#define	 SLI_IMAGE_START	0x20080
#define	 SLI_VERSION_LOC	0x270

/* def for new 2MB Flash (Pegasus ...) */
#define	MBX_LOAD_AREA		0x81
#define	MBX_LOAD_EXP_ROM	0x9C

#define	FILE_TYPE_AWC		0xE1A01001
#define	FILE_TYPE_DWC		0xE1A02002
#define	FILE_TYPE_BWC		0xE1A03003

#define	AREA_ID_MASK		0xFFFFFF0F
#define	AREA_ID_AWC		0x00000001
#define	AREA_ID_DWC		0x00000002
#define	AREA_ID_BWC		0x00000003

#define	CMD_START_ERASE		1
#define	CMD_CONTINUE_ERASE	2
#define	CMD_DOWNLOAD		3
#define	CMD_END_DOWNLOAD	4

#define	RSP_ERASE_STARTED	1
#define	RSP_ERASE_COMPLETE	2
#define	RSP_DOWNLOAD_MORE	3
#define	RSP_DOWNLOAD_DONE	4

#define	EROM_CMD_FIND_IMAGE	8
#define	EROM_CMD_CONTINUE_ERASE	9
#define	EROM_CMD_COPY		10

#define	EROM_RSP_ERASE_STARTED	8
#define	EROM_RSP_ERASE_COMPLETE	9
#define	EROM_RSP_COPY_MORE	10
#define	EROM_RSP_COPY_DONE	11

#define	ALLext				1
#define	DWCext				2
#define	BWCext				3

#define	NO_ALL			    0
#define	ALL_WITHOUT_BWC		1
#define	ALL_WITH_BWC		2

#define	KERNEL_START_ADDRESS	0x000000
#define	DOWNLOAD_START_ADDRESS	0x040000
#define	EXP_ROM_START_ADDRESS	0x180000
#define	SCRATCH_START_ADDRESS	0x1C0000
#define	CONFIG_START_ADDRESS	0x1E0000


typedef struct SliAifHdr {
	uint32_t CompressBr;
	uint32_t RelocBr;
	uint32_t ZinitBr;
	uint32_t EntryBr;
	uint32_t Area_ID;
	uint32_t RoSize;
	uint32_t RwSize;
	uint32_t DbgSize;
	uint32_t ZinitSize;
	uint32_t DbgType;
	uint32_t ImageBase;
	uint32_t Area_Size;
	uint32_t AddressMode;
	uint32_t DataBase;
	uint32_t AVersion;
	uint32_t Spare2;
	uint32_t DebugSwi;
	uint32_t ZinitCode[15];
} AIF_HDR, *PAIF_HDR;

typedef struct ImageHdr {
	uint32_t BlockSize;
	PROG_ID Id;
	uint32_t Flags;
	uint32_t EntryAdr;
	uint32_t InitAdr;
	uint32_t ExitAdr;
	uint32_t ImageBase;
	uint32_t ImageSize;
	uint32_t ZinitSize;
	uint32_t RelocSize;
	uint32_t HdrCks;
} IMAGE_HDR, *PIMAGE_HDR;



typedef struct {
	PROG_ID prog_id;
#ifdef EMLXS_BIG_ENDIAN
	uint32_t pci_cfg_rsvd:27;
	uint32_t use_hdw_def:1;
	uint32_t pci_cfg_sel:3;
	uint32_t pci_cfg_lookup_sel:1;
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t pci_cfg_lookup_sel:1;
	uint32_t pci_cfg_sel:3;
	uint32_t use_hdw_def:1;
	uint32_t pci_cfg_rsvd:27;
#endif
	union {
		PROG_ID boot_bios_id;
		uint32_t boot_bios_wd[2];
	} u0;
	PROG_ID sli1_prog_id;
	PROG_ID sli2_prog_id;
	PROG_ID sli3_prog_id;
	PROG_ID sli4_prog_id;
	union {
		PROG_ID EROM_prog_id;
		uint32_t EROM_prog_wd[2];
	} u1;
} WAKE_UP_PARMS, *PWAKE_UP_PARMS;


#define	 PROG_DESCR_STR_LEN	24
#define	 MAX_LOAD_ENTRY		10

typedef struct {
	uint32_t next;
	uint32_t prev;
	uint32_t start_adr;
	uint32_t len;
	union {
		PROG_ID id;
		uint32_t wd[2];
	} un;
	uint8_t prog_descr[PROG_DESCR_STR_LEN];
} LOAD_ENTRY;

typedef struct {
	uint32_t head;
	uint32_t tail;
	uint32_t entry_cnt;
	LOAD_ENTRY load_entry[MAX_LOAD_ENTRY];
} LOAD_LIST;



#define	 SLI_HW_REVISION_CHECK(x, y)   ((x & 0xf0) == y)
#define	 SLI_FCODE_REVISION_CHECK(x, y)  (x == y)


/* Define the adapters */
#include <emlxs_adapters.h>

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_HW_H */
