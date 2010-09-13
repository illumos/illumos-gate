/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007-2009 Sam Leffler, Errno Consulting
 * Copyright (c) 2007-2009 Marvell Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

/*
 * Definitions for the Marvell Wireless LAN controller Hardware Access Layer.
 */

#ifndef _MWL_REG_H
#define	_MWL_REG_H

#ifdef __cplusplus
extern "C" {
#endif

#define	MWL_MBSS_SUPPORT		/* enable multi-bss support */

/*
 * Host/Firmware Interface definitions.
 */

/*
 * Define total number of TX queues in the shared memory.
 * This count includes the EDCA queues, Block Ack queues, and HCCA queues
 * In addition to this, there could be a management packet queue some
 * time in the future
 */
#define	NUM_EDCA_QUEUES		4
#define	NUM_HCCA_QUEUES		0
#define	NUM_BA_QUEUES		0
#define	NUM_MGMT_QUEUES		0
#define	NUM_ACK_EVENT_QUEUE	1
#define	TOTAL_TX_QUEUES		\
	(NUM_EDCA_QUEUES +	\
	NUM_HCCA_QUEUES +	\
	NUM_BA_QUEUES +		\
	NUM_MGMT_QUEUES +	\
	NUM_ACK_EVENT_QUEUE)
#define	MAX_TXWCB_QUEUES	TOTAL_TX_QUEUES - NUM_ACK_EVENT_QUEUE
#define	MAX_RXWCB_QUEUES	1

/*
 * Firmware download support.
 */
#define	FW_DOWNLOAD_BLOCK_SIZE	256
#define	FW_CHECK_USECS		(5*1000) /* 5ms */
#define	FW_MAX_NUM_CHECKS	200

#define	MWL_ANT_INFO_SUPPORT /* per-antenna data in rx descriptor */

#define	MACREG_REG_TSF_LOW	0xa600 /* TSF lo */
#define	MACREG_REG_TSF_HIGH	0xa604 /* TSF hi */
#define	MACREG_REG_CHIP_REV	0xa814 /* chip rev */

/*
 * Map to 0x80000000 (Bus control) on BAR0
 */
/* From host to ARM */
#define	MACREG_REG_H2A_INTERRUPT_EVENTS		0x00000C18
#define	MACREG_REG_H2A_INTERRUPT_CAUSE		0x00000C1C
#define	MACREG_REG_H2A_INTERRUPT_MASK		0x00000C20
#define	MACREG_REG_H2A_INTERRUPT_CLEAR_SEL	0x00000C24
#define	MACREG_REG_H2A_INTERRUPT_STATUS_MASK	0x00000C28
/* From ARM to host */
#define	MACREG_REG_A2H_INTERRUPT_EVENTS		0x00000C2C
#define	MACREG_REG_A2H_INTERRUPT_CAUSE		0x00000C30
#define	MACREG_REG_A2H_INTERRUPT_MASK		0x00000C34
#define	MACREG_REG_A2H_INTERRUPT_CLEAR_SEL	0x00000C38
#define	MACREG_REG_A2H_INTERRUPT_STATUS_MASK	0x00000C3C


/* Map to 0x80000000 on BAR1 */
#define	MACREG_REG_GEN_PTR		0x00000C10
#define	MACREG_REG_INT_CODE		0x00000C14
#define	MACREG_REG_SCRATCH		0x00000C40
#define	MACREG_REG_FW_PRESENT		0x0000BFFC

#define	MACREG_REG_PROMISCUOUS		0xA300
/* Bit definitio for MACREG_REG_A2H_INTERRUPT_CAUSE (A2HRIC) */
#define	MACREG_A2HRIC_BIT_TX_DONE	0x00000001 /* bit 0 */
#define	MACREG_A2HRIC_BIT_RX_RDY	0x00000002 /* bit 1 */
#define	MACREG_A2HRIC_BIT_OPC_DONE	0x00000004 /* bit 2 */
#define	MACREG_A2HRIC_BIT_MAC_EVENT	0x00000008 /* bit 3 */
#define	MACREG_A2HRIC_BIT_RX_PROBLEM	0x00000010 /* bit 4 */

#define	MACREG_A2HRIC_BIT_RADIO_OFF	0x00000020 /* bit 5 */
#define	MACREG_A2HRIC_BIT_RADIO_ON	0x00000040 /* bit 6 */

#define	MACREG_A2HRIC_BIT_RADAR_DETECT	0x00000080 /* bit 7 */

#define	MACREG_A2HRIC_BIT_ICV_ERROR	0x00000100 /* bit 8 */
#define	MACREG_A2HRIC_BIT_MIC_ERROR	0x00000200 /* bit 9 */
#define	MACREG_A2HRIC_BIT_QUEUE_EMPTY	0x00004000
#define	MACREG_A2HRIC_BIT_QUEUE_FULL	0x00000800
#define	MACREG_A2HRIC_BIT_CHAN_SWITCH	0x00001000
#define	MACREG_A2HRIC_BIT_TX_WATCHDOG	0x00002000
#define	MACREG_A2HRIC_BIT_BA_WATCHDOG	0x00000400
#define	MACREQ_A2HRIC_BIT_TX_ACK	0x00008000
#define	ISR_SRC_BITS	((MACREG_A2HRIC_BIT_RX_RDY)	| \
			(MACREG_A2HRIC_BIT_TX_DONE)	| \
			(MACREG_A2HRIC_BIT_OPC_DONE)	| \
			(MACREG_A2HRIC_BIT_MAC_EVENT)	| \
			(MACREG_A2HRIC_BIT_MIC_ERROR)	| \
			(MACREG_A2HRIC_BIT_ICV_ERROR)	| \
			(MACREG_A2HRIC_BIT_RADAR_DETECT)| \
			(MACREG_A2HRIC_BIT_CHAN_SWITCH)	| \
			(MACREG_A2HRIC_BIT_TX_WATCHDOG)	| \
			(MACREG_A2HRIC_BIT_QUEUE_EMPTY)	| \
			(MACREG_A2HRIC_BIT_BA_WATCHDOG)	| \
			(MACREQ_A2HRIC_BIT_TX_ACK))

#define	MACREG_A2HRIC_BIT_MASK	ISR_SRC_BITS

/* Bit definitio for MACREG_REG_H2A_INTERRUPT_CAUSE (H2ARIC) */
#define	MACREG_H2ARIC_BIT_PPA_READY	0x00000001 /* bit 0 */
#define	MACREG_H2ARIC_BIT_DOOR_BELL	0x00000002 /* bit 1 */
#define	ISR_RESET			(1<<15)

/* INT code register event definition */
#define	MACREG_INT_CODE_CMD_FINISHED	0x00000005

/*
 * Define OpMode for SoftAP/Station mode
 */

/*
 * The following mode signature has to be written to PCI scratch register#0
 * right after successfully downloading the last block of firmware and
 * before waiting for firmware ready signature
 */
#define	HostCmd_STA_MODE		0x5A
#define	HostCmd_SOFTAP_MODE		0xA5

#define	HostCmd_STA_FWRDY_SIGNATURE	0xF0F1F2F4
#define	HostCmd_SOFTAP_FWRDY_SIGNATURE	0xF1F2F4A5

#define	HostCmd_CMD_CODE_DNLD			0x0001
#define	HostCmd_CMD_GET_HW_SPEC			0x0003
#define	HostCmd_CMD_SET_HW_SPEC			0x0004
#define	HostCmd_CMD_MAC_MULTICAST_ADR		0x0010
#define	HostCmd_CMD_802_11_GET_STAT		0x0014
#define	HostCmd_CMD_MAC_REG_ACCESS		0x0019
#define	HostCmd_CMD_BBP_REG_ACCESS		0x001a
#define	HostCmd_CMD_RF_REG_ACCESS		0x001b
#define	HostCmd_CMD_802_11_RADIO_CONTROL	0x001c
#define	HostCmd_CMD_802_11_RF_TX_POWER		0x001e
#define	HostCmd_CMD_802_11_RF_ANTENNA		0x0020
#define	HostCmd_CMD_SET_BEACON			0x0100
#define	HostCmd_CMD_SET_AID			0x010d
#define	HostCmd_CMD_SET_RF_CHANNEL		0x010a
#define	HostCmd_CMD_SET_INFRA_MODE		0x010e
#define	HostCmd_CMD_SET_G_PROTECT_FLAG		0x010f
#define	HostCmd_CMD_802_11_RTS_THSD		0x0113
#define	HostCmd_CMD_802_11_SET_SLOT		0x0114

#define	HostCmd_CMD_802_11H_DETECT_RADAR	0x0120
#define	HostCmd_CMD_SET_WMM_MODE		0x0123
#define	HostCmd_CMD_HT_GUARD_INTERVAL		0x0124
#define	HostCmd_CMD_SET_FIXED_RATE		0x0126
#define	HostCmd_CMD_SET_LINKADAPT_CS_MODE	0x0129
#define	HostCmd_CMD_SET_MAC_ADDR		0x0202
#define	HostCmd_CMD_SET_RATE_ADAPT_MODE		0x0203
#define	HostCmd_CMD_GET_WATCHDOG_BITMAP		0x0205

/* SoftAP command code */
#define	HostCmd_CMD_BSS_START			0x1100
#define	HostCmd_CMD_SET_NEW_STN			0x1111
#define	HostCmd_CMD_SET_KEEP_ALIVE		0x1112
#define	HostCmd_CMD_SET_APMODE			0x1114
#define	HostCmd_CMD_SET_SWITCH_CHANNEL		0x1121

/*
 * @HWENCR@
 * Command to update firmware encryption keys.
 */
#define	HostCmd_CMD_UPDATE_ENCRYPTION		0x1122
/*
 * @11E-BA@
 * Command to create/destroy block ACK
 */
#define	HostCmd_CMD_BASTREAM			0x1125
#define	HostCmd_CMD_SET_RIFS			0x1126
#define	HostCmd_CMD_SET_N_PROTECT_FLAG		0x1131
#define	HostCmd_CMD_SET_N_PROTECT_OPMODE	0x1132
#define	HostCmd_CMD_SET_OPTIMIZATION_LEVEL	0x1133
#define	HostCmd_CMD_GET_CALTABLE		0x1134
#define	HostCmd_CMD_SET_MIMOPSHT		0x1135
#define	HostCmd_CMD_GET_BEACON			0x1138
#define	HostCmd_CMD_SET_REGION_CODE		0x1139
#define	HostCmd_CMD_SET_POWERSAVESTATION	0x1140
#define	HostCmd_CMD_SET_TIM			0x1141
#define	HostCmd_CMD_GET_TIM			0x1142
#define	HostCmd_CMD_GET_SEQNO			0x1143
#define	HostCmd_CMD_DWDS_ENABLE			0x1144
#define	HostCmd_CMD_AMPDU_RETRY_RATEDROP_MODE	0x1145
#define	HostCmd_CMD_CFEND_ENABLE		0x1146

/*
 * Define general result code for each command
 */
/* RESULT OK */
#define	HostCmd_RESULT_OK		0x0000
/* Genenral error */
#define	HostCmd_RESULT_ERROR		0x0001
/* Command is not valid */
#define	HostCmd_RESULT_NOT_SUPPORT	0x0002
/* Command is pending (will be processed) */
#define	HostCmd_RESULT_PENDING		0x0003
/* System is busy (command ignored) */
#define	HostCmd_RESULT_BUSY		0x0004
/* Data buffer is not big enough */
#define	HostCmd_RESULT_PARTIAL_DATA	0x0005

#define	HostCmd_CMD_SET_EDCA_PARAMS	0x0115

/*
 * Definition of action or option for each command
 */

/*
 * Define general purpose action
 */
#define	HostCmd_ACT_GEN_READ	0x0000
#define	HostCmd_ACT_GEN_WRITE	0x0001
#define	HostCmd_ACT_GEN_GET	0x0000
#define	HostCmd_ACT_GEN_SET	0x0001
#define	HostCmd_ACT_GEN_OFF	0x0000
#define	HostCmd_ACT_GEN_ON	0x0001

#define	HostCmd_ACT_DIFF_CHANNEL	0x0002
#define	HostCmd_ACT_GEN_SET_LIST	0x0002

/* Define action or option for HostCmd_FW_USE_FIXED_RATE */
#define	HostCmd_ACT_USE_FIXED_RATE	0x0001
#define	HostCmd_ACT_NOT_USE_FIXED_RATE	0x0002

/* Define action or option for HostCmd_CMD_802_11_SET_WEP */
#define	HostCmd_ACT_ADD		0x0002
#define	HostCmd_ACT_REMOVE	0x0004
#define	HostCmd_ACT_USE_DEFAULT	0x0008

/*
 * PUBLIC DEFINITIONS
 */
#define	RATE_INDEX_MAX_ARRAY	14
#define	WOW_MAX_STATION		32


#pragma pack(1)

struct mwl_ant_info {
	uint8_t		rssi_a;	/* RSSI for antenna A */
	uint8_t		rssi_b;	/* RSSI for antenna B */
	uint8_t		rssi_c;	/* RSSI for antenna C */
	uint8_t		rsvd1;	/* Reserved */
	uint8_t		nf_a;	/* Noise floor for antenna A */
	uint8_t		nf_b;	/* Noise floor for antenna B */
	uint8_t		nf_c;	/* Noise floor for antenna C */
	uint8_t		rsvd2;	/* Reserved */
	uint8_t		nf;	/* Noise floor */
	uint8_t		rsvd3[3]; /* Reserved - To make word aligned */
};

/*
 * Hardware tx/rx descriptors.
 *
 * NB: tx descriptor size must match f/w expected size
 * because f/w prefetch's the next descriptor linearly
 * and doesn't chase the next pointer.
 */
struct mwl_txdesc {
	uint32_t	Status;
#define	EAGLE_TXD_STATUS_IDLE		0x00000000
#define	EAGLE_TXD_STATUS_USED		0x00000001
#define	EAGLE_TXD_STATUS_OK		0x00000001
#define	EAGLE_TXD_STATUS_OK_RETRY	0x00000002
#define	EAGLE_TXD_STATUS_OK_MORE_RETRY	0x00000004
#define	EAGLE_TXD_STATUS_MULTICAST_TX	0x00000008
#define	EAGLE_TXD_STATUS_BROADCAST_TX	0x00000010
#define	EAGLE_TXD_STATUS_FAILED_LINK_ERROR		0x00000020
#define	EAGLE_TXD_STATUS_FAILED_EXCEED_LIMIT		0x00000040
#define	EAGLE_TXD_STATUS_FAILED_XRETRY	EAGLE_TXD_STATUS_FAILED_EXCEED_LIMIT
#define	EAGLE_TXD_STATUS_FAILED_AGING	0x00000080
#define	EAGLE_TXD_STATUS_FW_OWNED	0x80000000
	uint8_t		DataRate;
	uint8_t		TxPriority;
	uint16_t	QosCtrl;
	uint32_t	PktPtr;
	uint16_t	PktLen;
	uint8_t		DestAddr[6];
	uint32_t	pPhysNext;
	uint32_t	SapPktInfo;
#define	EAGLE_TXD_MODE_BONLY	1
#define	EAGLE_TXD_MODE_GONLY	2
#define	EAGLE_TXD_MODE_BG	3
#define	EAGLE_TXD_MODE_NONLY	4
#define	EAGLE_TXD_MODE_BN	5
#define	EAGLE_TXD_MODE_GN	6
#define	EAGLE_TXD_MODE_BGN	7
#define	EAGLE_TXD_MODE_AONLY	8
#define	EAGLE_TXD_MODE_AG	10
#define	EAGLE_TXD_MODE_AN	12
	uint16_t	Format;
#define	EAGLE_TXD_FORMAT	0x0001	/* frame format/rate */
#define	EAGLE_TXD_FORMAT_LEGACY	0x0000	/* legacy rate frame */
#define	EAGLE_TXD_FORMAT_HT	0x0001	/* HT rate frame */
#define	EAGLE_TXD_GI		0x0002	/* guard interval */
#define	EAGLE_TXD_GI_SHORT	0x0002	/* short guard interval */
#define	EAGLE_TXD_GI_LONG	0x0000	/* long guard interval */
#define	EAGLE_TXD_CHW		0x0004	/* channel width */
#define	EAGLE_TXD_CHW_20	0x0000	/* 20MHz channel width */
#define	EAGLE_TXD_CHW_40	0x0004	/* 40MHz channel width */
#define	EAGLE_TXD_RATE		0x01f8	/* tx rate (legacy)/ MCS */
#define	EAGLE_TXD_RATE_S	3
#define	EAGLE_TXD_ADV		0x0600	/* advanced coding */
#define	EAGLE_TXD_ADV_S		9
#define	EAGLE_TXD_ADV_NONE	0x0000
#define	EAGLE_TXD_ADV_LDPC	0x0200
#define	EAGLE_TXD_ADV_RS	0x0400
/* NB: 3 is reserved */
#define	EAGLE_TXD_ANTENNA	0x1800	/* antenna select */
#define	EAGLE_TXD_ANTENNA_S	11
#define	EAGLE_TXD_EXTCHAN	0x6000	/* extension channel */
#define	EAGLE_TXD_EXTCHAN_S	13
#define	EAGLE_TXD_EXTCHAN_HI	0x0000	/* above */
#define	EAGLE_TXD_EXTCHAN_LO	0x2000	/* below */
#define	EAGLE_TXD_PREAMBLE	0x8000
#define	EAGLE_TXD_PREAMBLE_SHORT 0x8000	/* short preamble */
#define	EAGLE_TXD_PREAMBLE_LONG 0x0000	/* long preamble */
	uint16_t	pad;		/* align to 4-byte boundary */
#define	EAGLE_TXD_FIXED_RATE	0x0100	/* get tx rate from Format */
#define	EAGLE_TXD_DONT_AGGR	0x0200	/* don't aggregate frame */
	uint32_t	ack_wcb_addr;
};

struct mwl_rxdesc {
	/* control element */
	uint8_t		RxControl;
#define	EAGLE_RXD_CTRL_DRIVER_OWN	0x00
#define	EAGLE_RXD_CTRL_OS_OWN		0x04
#define	EAGLE_RXD_CTRL_DMA_OWN		0x80
	/* received signal strengt indication */
	uint8_t		RSSI;
	/* status field w/ USED bit */
	uint8_t		Status;
#define	EAGLE_RXD_STATUS_IDLE		0x00
#define	EAGLE_RXD_STATUS_OK		0x01
#define	EAGLE_RXD_STATUS_MULTICAST_RX	0x02
#define	EAGLE_RXD_STATUS_BROADCAST_RX	0x04
#define	EAGLE_RXD_STATUS_FRAGMENT_RX	0x08
#define	EAGLE_RXD_STATUS_GENERAL_DECRYPT_ERR	0xff
#define	EAGLE_RXD_STATUS_DECRYPT_ERR_MASK	0x80
#define	EAGLE_RXD_STATUS_TKIP_MIC_DECRYPT_ERR	0x02
#define	EAGLE_RXD_STATUS_WEP_ICV_DECRYPT_ERR	0x04
#define	EAGLE_RXD_STATUS_TKIP_ICV_DECRYPT_ERR	0x08
	/* channel # pkt received on */
	uint8_t		Channel;
	/* total length of received data */
	uint16_t	PktLen;
	/* not used */
	uint8_t		SQ2;
	/* received data rate */
	uint8_t		Rate;
	/* physical address of payload data */
	uint32_t	pPhysBuffData;
	/* physical address of next RX desc */
	uint32_t	pPhysNext;
	/* received QosCtrl field variable */
	uint16_t	QosCtrl;
	/* like name states */
	uint16_t	HtSig2;
#ifdef MWL_ANT_INFO_SUPPORT
	/* antenna info */
	struct mwl_ant_info ai;
#endif
};
#pragma pack()



// =============================================================================
//			HOST COMMAND DEFINITIONS
// =============================================================================

//
// Definition of data structure for each command
//
// Define general data structure
#pragma pack(1)
typedef struct {
	uint16_t	Cmd;
	uint16_t	Length;
#ifdef MWL_MBSS_SUPPORT
	uint8_t		SeqNum;
	uint8_t		MacId;
#else
	uint16_t	SeqNum;
#endif
	uint16_t	Result;
} FWCmdHdr;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint8_t		annex;
	uint8_t		index;
	uint8_t		len;
	uint8_t		Reserverd;
#define	CAL_TBL_SIZE	160
	uint8_t	calTbl[CAL_TBL_SIZE];
} HostCmd_FW_GET_CALTABLE;

typedef struct {
	FWCmdHdr	CmdHdr;
	/* version of the HW */
	uint8_t		Version;
	/* host interface */
	uint8_t		HostIf;
	/* Max. number of WCB FW can handle */
	uint16_t	NumOfWCB;
	/* MaxNbr of MC addresses FW can handle */
	uint16_t	NumOfMCastAddr;
	/* MAC address programmed in HW */
	uint8_t		PermanentAddr[6];
	uint16_t	RegionCode;
	/* Number of antenna used */
	uint16_t	NumberOfAntenna;
	/* 4 byte of FW release number */
	uint32_t	FWReleaseNumber;
	uint32_t	WcbBase0;
	uint32_t	RxPdWrPtr;
	uint32_t	RxPdRdPtr;
	uint32_t	ulFwAwakeCookie;
	uint32_t	WcbBase1[3];
} HostCmd_DS_GET_HW_SPEC;

typedef struct {
	FWCmdHdr	CmdHdr;
	/* HW revision */
	uint8_t		Version;
	/* Host interface */
	uint8_t		HostIf;
	/* Max. number of Multicast address FW can handle */
	uint16_t	NumOfMCastAdr;
	/* MAC address */
	uint8_t		PermanentAddr[6];
	/* Region Code */
	uint16_t	RegionCode;
	/* 4 byte of FW release number */
	uint32_t	FWReleaseNumber;
	/* Firmware awake cookie */
	uint32_t	ulFwAwakeCookie;
	/* Device capabilities (see above) */
	uint32_t	DeviceCaps;
	/* Rx shared memory queue */
	uint32_t	RxPdWrPtr;
	/* TX queues in WcbBase array */
	uint32_t	NumTxQueues;
	/* TX WCB Rings */
	uint32_t	WcbBase[MAX_TXWCB_QUEUES];
	uint32_t	Flags;
#define	SET_HW_SPEC_DISABLEMBSS		0x08
#define	SET_HW_SPEC_HOSTFORM_BEACON	0x10
#define	SET_HW_SPEC_HOSTFORM_PROBERESP	0x20
#define	SET_HW_SPEC_HOST_POWERSAVE	0x40
#define	SET_HW_SPEC_HOSTENCRDECR_MGMT	0x80
	uint32_t	TxWcbNumPerQueue;
	uint32_t	TotalRxWcb;
}HostCmd_DS_SET_HW_SPEC;

// used for stand alone bssid sets/clears
typedef struct {
	FWCmdHdr	CmdHdr;
#ifdef MWL_MBSS_SUPPORT
	uint16_t	MacType;
#define	WL_MAC_TYPE_PRIMARY_CLIENT	0
#define	WL_MAC_TYPE_SECONDARY_CLIENT	1
#define	WL_MAC_TYPE_PRIMARY_AP		2
#define	WL_MAC_TYPE_SECONDARY_AP	3
#endif
	uint8_t		MacAddr[6];
} HostCmd_DS_SET_MAC,
	HostCmd_FW_SET_BSSID,
	HostCmd_FW_SET_MAC;

typedef struct {
	uint32_t	LegacyRateBitMap;
	uint32_t	HTRateBitMap;
	uint16_t	CapInfo;
	uint16_t	HTCapabilitiesInfo;
	uint8_t		MacHTParamInfo;
	uint8_t		Rev;
	struct {
		uint8_t		ControlChan;
		uint8_t		AddChan;
		uint16_t	OpMode;
		uint16_t	stbc;
	} AddHtInfo;
} PeerInfo_t;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	AID;
	uint8_t		MacAddr[6];
	uint16_t	StnId;
	uint16_t	Action;
	uint16_t	Reserved;
	PeerInfo_t	PeerInfo;
	uint8_t		Qosinfo;
	uint8_t		isQosSta;
	uint32_t	FwStaPtr;
} HostCmd_FW_SET_NEW_STN;

/* Define data structure for HostCmd_CMD_802_11_RF_ANTENNA */
typedef struct _HostCmd_DS_802_11_RF_ANTENNA {
	FWCmdHdr	CmdHdr;
	uint16_t	Action;
	/* Number of antennas or 0xffff(diversity) */
	uint16_t	AntennaMode;
} HostCmd_DS_802_11_RF_ANTENNA;

/* Define data structure for HostCmd_CMD_802_11_RADIO_CONTROL */
typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	Action;
	/*
	 *  @bit0: 1/0, on/off
	 *  @bit1: 1/0, long/short
	 *  @bit2: 1/0,auto/fix
	 */
	uint16_t	Control;
	uint16_t	RadioOn;
} HostCmd_DS_802_11_RADIO_CONTROL;

/* for HostCmd_CMD_SET_WMM_MODE */
typedef struct {
	FWCmdHdr	CmdHdr;
	/* 0->unset, 1->set */
	uint16_t	Action;
} HostCmd_FW_SetWMMMode;

/* bits 0-5 specify frequency band */
#define	FREQ_BAND_2DOT4GHZ	0x0001
#define	FREQ_BAND_4DOT9GHZ	0x0002	/* XXX not implemented */
#define	FREQ_BAND_5GHZ		0x0004
#define	FREQ_BAND_5DOT2GHZ	0x0008	/* XXX not implemented */
/* bits 6-10 specify channel width */
#define	CH_AUTO_WIDTH		0x0000	/* XXX not used? */
#define	CH_10_MHz_WIDTH		0x0040
#define	CH_20_MHz_WIDTH		0x0080
#define	CH_40_MHz_WIDTH		0x0100
/* bits 11-12 specify extension channel */
#define	EXT_CH_NONE		0x0000	/* no extension channel */
#define	EXT_CH_ABOVE_CTRL_CH	0x0800	/* extension channel above */
#define	EXT_CH_AUTO		0x1000	/* XXX not used? */
#define	EXT_CH_BELOW_CTRL_CH	0x1800	/* extension channel below */
/* bits 13-31 are reserved */

#define	FIXED_RATE_WITH_AUTO_RATE_DROP		0
#define	FIXED_RATE_WITHOUT_AUTORATE_DROP	1

#define	LEGACY_RATE_TYPE			0
#define	HT_RATE_TYPE				1

#define	RETRY_COUNT_VALID			0
#define	RETRY_COUNT_INVALID			1

// Define data structure for HostCmd_CMD_802_11_RF_CHANNEL
typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	Action;
	uint8_t		CurrentChannel;	/* channel # */
	uint32_t	ChannelFlags;	/* see below */
} HostCmd_FW_SET_RF_CHANNEL;

#define	TX_POWER_LEVEL_TOTAL	8

/* Define data structure for HostCmd_CMD_802_11_RF_TX_POWER */
typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	Action;
	uint16_t	SupportTxPowerLevel;
	uint16_t	CurrentTxPowerLevel;
	uint16_t	Reserved;
	uint16_t	PowerLevelList[TX_POWER_LEVEL_TOTAL];
} HostCmd_DS_802_11_RF_TX_POWER;

typedef struct {
	/*
	 * lower rate after the retry count
	 * 0: legacy, 1: HT
	 */
	uint32_t	FixRateType;
	/*
	 *  0: retry count is not valid
	 *  1: use retry count specified
	 */
	uint32_t	RetryCountValid;
} FIX_RATE_FLAG;

typedef  struct {
	FIX_RATE_FLAG	FixRateTypeFlags;
	/* legacy rate(not index) or an MCS code */
	uint32_t	FixedRate;
	uint32_t	RetryCount;
} FIXED_RATE_ENTRY;

typedef  struct {
	FWCmdHdr	CmdHdr;
	/*
	 * HostCmd_ACT_GEN_GET			0x0000
	 * HostCmd_ACT_GEN_SET 			0x0001
	 * HostCmd_ACT_NOT_USE_FIXED_RATE	0x0002
	 */
	uint32_t	Action;
	/* use fixed rate specified but firmware can drop */
	uint32_t	AllowRateDrop;
	uint32_t	EntryCount;
	FIXED_RATE_ENTRY FixedRateTable[4];
	uint8_t		MulticastRate;
	uint8_t		MultiRateTxType;
	uint8_t		ManagementRate;
} HostCmd_FW_USE_FIXED_RATE;

/* Define data structure for HostCmd_CMD_SET_RATE_ADAPT_MODE */
typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	Action;
	uint16_t	RateAdaptMode;
} HostCmd_DS_SET_RATE_ADAPT_MODE;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint8_t	OptLevel;
} HostCmd_FW_SET_OPTIMIZATION_LEVEL;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	regionCode;
} HostCmd_SET_REGIONCODE_INFO;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	Action;	/* 0: Get. 1:Set */
	uint32_t	Option;	/* 0: default. 1:Aggressive */
	uint32_t	Threshold;	/* Range 0-200, default 8 */
} HostCmd_FW_AMPDU_RETRY_RATEDROP_MODE;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint32_t	Enable;	/* 0 -- Disable. or 1 -- Enable */
} HostCmd_CFEND_ENABLE;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint32_t	Enable;	/* FALSE: Disable or TRUE: Enable */
} HostCmd_DS_BSS_START;

typedef struct {
	FWCmdHdr	CmdHdr;
} HostCmd_FW_SET_INFRA_MODE;

/* used for AID sets/clears */
typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	AssocID;
	uint8_t		MacAddr[6]; /* AP's Mac Address(BSSID) */
	uint32_t	GProtection;
	uint8_t		ApRates[RATE_INDEX_MAX_ARRAY];
} HostCmd_FW_SET_AID;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	Action;
	uint16_t	Threshold;
} HostCmd_DS_802_11_RTS_THSD;

/* Define data structure for HostCmd_CMD_SET_LINKADAPT_CS_MODE */
typedef struct {
	FWCmdHdr	CmdHdr;
	uint16_t	Action;
	uint16_t	CSMode;
} HostCmd_DS_SET_LINKADAPT_CS_MODE;

typedef struct {
	FWCmdHdr	CmdHdr;
	uint32_t	ActionType; /* ENCR_ACTION_TYPE */
	uint32_t	DataLength; /* size of the data buffer attached */
#ifdef MWL_MBSS_SUPPORT
	uint8_t	macaddr[6];
#endif
	uint8_t	ActionData[1];
} HostCmd_FW_UPDATE_ENCRYPTION;

/*
 * @HWENCR@
 * Hardware Encryption related data structures and constant definitions.
 * Note that all related changes are marked with the @HWENCR@ tag.
 */

#define	MAX_ENCR_KEY_LENGTH	16	/* max 128 bits - depends on type */
#define	MIC_KEY_LENGTH		8	/* size of Tx/Rx MIC key - 8 bytes */

#define	ENCR_KEY_TYPE_ID_WEP	0x00	/* Key type is WEP */
#define	ENCR_KEY_TYPE_ID_TKIP	0x01	/* Key type is TKIP */
#define	ENCR_KEY_TYPE_ID_AES	0x02	/* Key type is AES-CCMP	*/

/*
 * flags used in structure - same as driver EKF_XXX flags
 */
/* indicate key is in use */
#define	ENCR_KEY_FLAG_INUSE		0x00000001
/* Group key for RX only */
#define	ENCR_KEY_FLAG_RXGROUPKEY	0x00000002
/* Group key for TX */
#define	ENCR_KEY_FLAG_TXGROUPKEY	0x00000004
/* pairwise */
#define	ENCR_KEY_FLAG_PAIRWISE		0x00000008
/* only used for RX */
#define	ENCR_KEY_FLAG_RXONLY		0x00000010
/*
 * These flags are new additions - for hardware encryption commands only
 */
/* Key is for Authenticator */
#define	ENCR_KEY_FLAG_AUTHENTICATOR	0x00000020
/* Sequence counters valid */
#define	ENCR_KEY_FLAG_TSC_VALID		0x00000040
/* Tx key for WEP */
#define	ENCR_KEY_FLAG_WEP_TXKEY		0x01000000
/* Tx/Rx MIC keys are valid */
#define	ENCR_KEY_FLAG_MICKEY_VALID	0x02000000

/*
 * Key material definitions (for WEP, TKIP, & AES-CCMP)
 */

/*
 * WEP Key material definition
 * ----------------------------
 * WEPKey	--> An array of 'MAX_ENCR_KEY_LENGTH' bytes.
 * Note that we do not support 152bit WEP keys
 */
typedef struct {
	/* WEP key material (max 128bit) */
	uint8_t	KeyMaterial[MAX_ENCR_KEY_LENGTH];
} WEP_TYPE_KEY;

/*
 * TKIP Key material definition
 * ----------------------------
 * This structure defines TKIP key material. Note that
 * the TxMicKey and RxMicKey may or may not be valid.
 */
/*
 * TKIP Sequence counter - 24 bits
 * Incremented on each fragment MPDU
 */
typedef struct {
	uint16_t	low;
	uint32_t	high;
} ENCR_TKIPSEQCNT;

/*
 * TKIP Key material. Key type (group or pairwise key) is
 * determined by flags in KEY_PARAM_SET structure
 */
typedef struct {
	uint8_t		KeyMaterial[MAX_ENCR_KEY_LENGTH];
	uint8_t		TkipTxMicKey[MIC_KEY_LENGTH];
	uint8_t		TkipRxMicKey[MIC_KEY_LENGTH];
	ENCR_TKIPSEQCNT	TkipRsc;
	ENCR_TKIPSEQCNT	TkipTsc;
} TKIP_TYPE_KEY;

/*
 * AES-CCMP Key material definition
 * --------------------------------
 * This structure defines AES-CCMP key material.
 */
typedef struct {
	/* AES Key material */
	uint8_t	KeyMaterial[MAX_ENCR_KEY_LENGTH];
} AES_TYPE_KEY;

/*
 * UPDATE_ENCRYPTION command action type.
 */
typedef enum {
	/* request to enable/disable HW encryption */
	EncrActionEnableHWEncryption,
	/* request to set encryption key */
	EncrActionTypeSetKey,
	/* request to remove one or more keys */
	EncrActionTypeRemoveKey,
	EncrActionTypeSetGroupKey
} ENCR_ACTION_TYPE;

/*
 * Encryption key definition.
 * --------------------------
 * This structure provides all required/essential
 * information about the key being set/removed.
 */
typedef struct {
	uint16_t	Length;		/* Total length of this structure */
	uint16_t	KeyTypeId;	/* Key type - WEP, TKIP or AES-CCMP */
	uint32_t	KeyInfo;	/* key flags */
	uint32_t	KeyIndex; 	/* For WEP only - actual key index */
	uint16_t	KeyLen;		/* Size of the key */
	union {				/* Key material (variable size array) */
		WEP_TYPE_KEY	WepKey;
		TKIP_TYPE_KEY	TkipKey;
		AES_TYPE_KEY	AesKey;
	} Key;
#ifdef MWL_MBSS_SUPPORT
	uint8_t	Macaddr[6];
#endif
} KEY_PARAM_SET;


typedef struct {
	FWCmdHdr	CmdHdr;
	uint32_t	ActionType;	/* ENCR_ACTION_TYPE */
	uint32_t	DataLength;	/* size of the data buffer attached */
	KEY_PARAM_SET	KeyParam;
#ifndef MWL_MBSS_SUPPORT
	uint8_t		Macaddr[8];
#endif
} HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* _MWL_REG_H */
