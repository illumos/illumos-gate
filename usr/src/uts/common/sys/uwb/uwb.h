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

#ifndef _SYS_UWB_UWB_H
#define	_SYS_UWB_UWB_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * IOCTLs and related data structures for UWB Radio Controller drivers.
 */

/* IOCTLs */
#define	UWB_IOCTL_BASE			0x1000
#define	UWB_COMMAND			(UWB_IOCTL_BASE + 0x1)
#define	UWB_GET_NOTIFICATION		(UWB_IOCTL_BASE + 0x2)

#define	UWB_CE_TYPE_GENERAL 0		/* General Command/Event type */

/*
 * UWB Radio Controller Commands and Events:
 *
 * See WUSB spec 1.0 [Table 8-68]
 * See WHCI 0.95 [Table 3-2],[Table 3-5]
 */
/* Commands */
#define	UWB_CE_CHANNEL_CHANGE			16
#define	UWB_CE_DEV_ADDR_MGMT			17
#define	UWB_CE_GET_IE				18
#define	UWB_CE_RESET				19
#define	UWB_CE_SCAN				20
#define	UWB_CE_SET_BEACON_FILTER		21
#define	UWB_CE_SET_DRP_IE			22
#define	UWB_CE_SET_IE				23
#define	UWB_CE_SET_NOTIFICATION_FILTER		24
#define	UWB_CE_SET_TX_POWER			25
#define	UWB_CE_SLEEP				26
#define	UWB_CE_START_BEACON			27
#define	UWB_CE_STOP_BEACON			28
#define	UWB_CE_BP_MERGE				29
#define	UWB_CE_SEND_COMMAND_FRAME		30
#define	UWB_CE_SET_ASIE_NOTIFICATION		31

/* Notifications */
#define	UWB_NOTIF_IE_RECEIVED			0
#define	UWB_NOTIF_BEACON_RECEIVED 		1
#define	UWB_NOTIF_BEACON_SIZE_CHANGE    	2
#define	UWB_NOTIF_BPOIE_CHANGE			3
#define	UWB_NOTIF_BP_SLOT_CHANGE 		4
#define	UWB_NOTIF_BP_SWITCH_IE_RECEIVED 	5
#define	UWB_NOTIF_DEV_ADDR_CONFLICT 		6
#define	UWB_NOTIF_DRP_AVAILABILITY_CHANGE 	7
#define	UWB_NOTIF_DRP				8
#define	UWB_NOTIF_BP_SWITCH_STATUS 		9
#define	UWB_NOTIF_CMD_FRAME_RCV 		10
#define	UWB_NOTIF_CHANNEL_CHANGE_IE_RCV 	11
#define	UWB_NOTIF_RESERVED 			12

/*
 * Scan types.
 * WUSB spec 1.0 [Table 8-78. Scan RCCB]
 * WHCI 0.95 [Table 3-14. Scan RCCB Format]
 */
#define	UWB_RC_SCAN_ONLY			0
#define	UWB_RC_SCAN_OUTSIDE_BP			1
#define	UWB_RC_SCAN_WHILE_INACTIVE		2
#define	UWB_RC_SCAN_DISABLED			3
#define	UWB_RC_SCAN_ONLY_STARTTIME 		4

/*
 * See ECMA-368 [7.2.2 Device address]
 * Individual MAC sublayers are addressed via an EUI-48 [I3]
 * DevAddrs are 16-bit values
 */
typedef struct uwb_mac_addr {
	uint8_t addr[6];
} uwb_mac_addr_t;

typedef struct uwb_dev_addr {
	uint8_t addr[2];
} uwb_dev_addr_t;

/*
 * See ECMA-368 [16.8.6]
 * One superframe has 256 Medium Access Slots.
 * One superframe has 16 zones.
 */
#define	UWB_MAS_NUM 256
#define	UWB_ZONE_NUM 16

/* Type of DRP reservation. ECMA-368 [table 106] */
#define	UWB_DRP_TP_ALIEN	0
#define	UWB_DRP_TP_HARD		1
#define	UWB_DRP_TP_SOFT		2
#define	UWB_DRP_TP_PRVT		3
#define	UWB_DRP_TP_PCA		4
#define	UWB_DRP_TP_RESVD	5

/* DRP Reasons. ECMA-368 [table 107] */
#define	UWB_DRP_RS_ACCEP	0
#define	UWB_DRP_RS_CNFLCT	1
#define	UWB_DRP_RS_PNDNG	2
#define	UWB_DRP_RS_DENI		3
#define	UWB_DRP_RS_MODIF	4
#define	UWB_DRP_RS_RSEVD	5

/* Allocation of MAS slots in a DRP request. ECMA-368 */
typedef struct uwb_drp_bm_alloc {
	uint16_t zone;
	uint16_t mas;
} uwb_drp_bm_alloc_t;

/*  Information elements. ECMA-368 [Table 104] */
#define	UWB_IE_TIM		0
#define	UWB_IE_BPO		1
#define	UWB_IE_PCA_AVAIL 	2
#define	UWB_IE_DRP_AVAIL 	8
#define	UWB_IE_DRP 		9
#define	UWB_IE_HIB_MODE		10
#define	UWB_IE_BP_SWITCH 	11
#define	UWB_IE_MAC_CAP 		12
#define	UWB_IE_PHY_CAP 		13
#define	UWB_IE_PROBE 		14
#define	UWB_IE_APPSPEC_PROBE	15
#define	UWB_IE_LINK_FB		16
#define	UWB_IE_HIB_ANCHOR	17
#define	UWB_IE_CHNL_CHG		18
#define	UWB_IE_IDENT		19
#define	UWB_IE_MASTER_KEY_ID	20
#define	UWB_IE_RELQ_REQ		21
#define	UWB_IE_MAB		22
#define	UWB_IE_APP_SPEC		255

/* UWB Information Element header. ECMA-368 [16.8] */
typedef struct uwb_ie_head {
	uint8_t		id; 	/* Element ID */
	uint8_t		len; 	/* Length */
} uwb_ie_head_t;

/* Dynamic Reservation Protocol IE. ECMA-368 [16.8.6] */
typedef struct uwb_drp_ie {
	uwb_ie_head_t		head;
	uint16_t 		drp_ctrl;
	uwb_dev_addr_t		dev_addr;
	uwb_drp_bm_alloc_t	allocs[1];
} uwb_drp_ie_t;

/* Dynamic Reservation Protocol IE. ECMA-368 [16.8.7] */
typedef struct uwb_drp_avail_ie {
	uwb_ie_head_t	head;
	ulong_t 	bitmap[8];
} uwb_drp_avail_ie_t;


/* Data structures for UWB commands */

/* WUSB spec 1.0 [Table 8-65] Radio Control Command Block (RCCB) */
typedef struct uwb_rccb_head {
	uint8_t bCommandType;		/* Command Type */
	uint16_t wCommand;		/* Command code */
	uint8_t bCommandContext;	/* Context ID */
} uwb_rccb_head_t;

/* Generic RCCB Command */
typedef struct uwb_rccb_cmd {
	uwb_rccb_head_t rccb;
	uint8_t	buf[1];
} uwb_rccb_cmd_t;

/* WUSB spec 1.0. Table 8-78. Scan RCCB */
typedef struct uwb_rccb_scan {
	uwb_rccb_head_t rccb;
	uint8_t bChannelNumber;
	uint8_t bScanState;
	uint16_t wStartTime;
} uwb_rccb_scan_t;

/* WUSB spec 1.0 Table 8-93. Start Beaconing RCCB */
typedef struct uwb_rccb_start_beacon {
	uwb_rccb_head_t rccb;
	uint16_t 	wBPSTOffset;
	uint8_t 	bChannelNumber;
} uwb_rccb_start_beacon_t;

/* WUSB spec 1.0 Table 8-82. Set DRP IE RCCB */
typedef struct uwb_rccb_set_drp_ie {
	uwb_rccb_head_t rccb;
	uint16_t 	wIELength;
	uint8_t 	IEData[1];
} uwb_rccb_set_drp_ie_t;

/* WUSB spec 1.0 Table 8-84. Set IE RCCB */
typedef struct uwb_rccb_set_ie {
	uwb_rccb_head_t rccb;
	uint16_t 	wIELength;
	uint8_t 	IEData[1];
}uwb_rccb_set_ie_t;

/* WUSB spec 1.0 Table 8-72. Device Address Management RCCB */
typedef struct uwb_rccb_dev_addr_mgmt {
	uwb_rccb_head_t rccb;
	uint8_t 	bmOperationType;
	uint8_t 	baAddr[6];
} uwb_rccb_dev_addr_mgmt_t;

/* Data structures for UWB Command results (Events) */

/*  WUSB spec 1.0 Table 8-66. Radio Control Event Block (RCEB) */
typedef struct uwb_rceb_head {
	uint8_t 	bEventType;
	uint16_t 	wEvent;
	uint8_t 	bEventContext;
} uwb_rceb_head_t;

/*
 * Generic RCEB for commands that returns result code only.
 * Including channel change, scan, reset, etc.
 */
typedef struct uwb_rceb_result_code {
	uwb_rceb_head_t rceb;
	uint8_t 	bResultCode;
} uwb_rceb_result_code_t;

/*
 * WUSB 1.0 Table 8-73. Device Address Management RCEB
 * baAddr should be ignored if the Set bit in the associated
 * RCCB is set to 1. The spec is fixed in Errata.
 */
typedef struct uwb_rceb_dev_addr_mgmt {
	uwb_rceb_head_t rceb;
	uint8_t 	baAddr[6];
	uint8_t 	bResultCode;
} uwb_rceb_dev_addr_mgmt_t;

/* WUSB 1.0 Table 8-75. Get IE RCEB */
typedef struct uwb_rceb_get_ie {
	uwb_rceb_head_t rceb;
	uint16_t 	wIELength;
	uint8_t 	IEData[1];
} uwb_rceb_get_ie_t;

/* WUSB 1.0 Table 8-86. Set IE RCEB */
typedef struct uwb_rceb_set_ie {
	uwb_rceb_head_t rceb;
	uint16_t 	RemainingSpace;
	uint8_t 	bResultCode;
} uwb_rceb_set_ie_t;

/* WUSB 1.0 Table 8-83. Set DRP IE RCEB */
typedef struct uwb_rceb_set_drp_ie {
	uwb_rceb_head_t rceb;
	uint16_t 	wRemainingSpace;
	uint8_t 	bResultCode;
} uwb_rceb_set_drp_ie_t;


/* Data structures for UWB Notifications */

/* Notification from device */
typedef struct uwb_rceb_notif {
	uwb_rceb_head_t rceb;
	uint8_t		buf[1];
} uwb_rceb_notif_t;

typedef struct uwb_notif_get {
	/* wait for milliseconds untile get a notification */
	uint_t		timeout;
	uwb_rceb_notif_t notif;
} uwb_notif_get_t;

/*
 * UWB_NOTIF_BEACON_RECEIVED, Beacon received notification
 * WHCI [3.1.4.2].
 * NOTICE:In WUSB Spec, Table 8-98. No bBeaconType. Below follow
 * WHCI spec
 */
typedef struct uwb_rceb_beacon {
	uwb_rceb_head_t rceb;
	uint8_t 	bChannelNumber;
	uint8_t 	bBeaconType;
	uint16_t	wBPSTOffset;
	uint8_t		bLQI;
	uint8_t		bRSSI;
	uint16_t	wBeaconInfoLength;
	uint8_t		BeaconInfo[1];
} uwb_rceb_beacon_t;

/* MAC Header field values for beacon frames. ECMA 368 [table 96] */
typedef struct uwb_bcfrm_mac_hdr {
	uint16_t	Frame_Control;
	uwb_dev_addr_t	DestAddr;
	uwb_dev_addr_t	SrcAddr;
	uint16_t	Sequence_Control;
	uint16_t	Access_Information;
} uwb_bcfrm_mac_hdr_t;

/* Beacon Frame [ECMA-368] page 151 */
typedef struct uwb_beacon_frame {
	uwb_bcfrm_mac_hdr_t	hdr;
	uwb_mac_addr_t		Device_Identifier;
	uint8_t			Beacon_Slot_Number;
	uint8_t			Device_Control;
	uint8_t			IEData[1];
} uwb_beacon_frame_t;

/* WUSB 1.0. Table 8-99. Beacon Size Change Notification RCEB */
typedef struct uwb_rceb_beacon_size_change {
	uwb_rceb_head_t		rceb;
	uint16_t		wNewBeaconSize;
} uwb_rceb_beacon_size_change_t;

/* WUSB 1.0. Table 8-100. BPOIE Change Notification RCEB */
typedef struct uwb_rceb_bpoie_change {
	uwb_rceb_head_t		rceb;
	uint16_t		wBPOIELength;
	uint8_t			BPOIE[1];
} uwb_rceb_bpoie_change_t;

/* WHCI 0.95  Table 3-42. BP Slot Change Notification RCEB Format */
typedef struct uwb_rceb_bp_slot_change {
	uwb_rceb_head_t		rceb;
	uint8_t			bNewSlotNumber;
} uwb_rceb_bp_slot_change_t;

/* WHCI 0.95 Table 3-45. DRP Availability Changed Notification RCEB Format */
typedef struct uwb_rceb_drp_availability {
	uwb_rceb_head_t		rceb;
	uint8_t			DRPAvailability[32]; /* 256 bit bitmap */
} uwb_rceb_drp_availability_t;

/* WHCI 0.95 [3.1.4.9] * Table 3-46. DRP Notification RCEB Format */
typedef struct uwb_rceb_drp {
	uwb_rceb_head_t		rceb;
	uint16_t 		wSrcAddr;
	uint8_t 		bReason;
	uint8_t 		bBeaconSlotNumber;
	uint16_t 		wIELength;
	uint8_t 		IEData[1];
} uwb_rceb_drp_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_UWB_UWB_H */
