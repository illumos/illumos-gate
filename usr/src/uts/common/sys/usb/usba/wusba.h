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

#ifndef	_SYS_USB_WUSBA_H
#define	_SYS_USB_WUSBA_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Wireless USB feature selectors */
#define	WUSB_FEAT_TX_DRP_IE		0
#define	WUSB_FEAT_DEV_XMIT_PKT		1
#define	WUSB_FEAT_COUNT_PKTS		2
#define	WUSB_FEAT_CAPT_PKTS		3

/* Wireless USB status selector for GET_STATUS request */
#define	WUSB_STS_TYPE_STANDARD		0
#define	WUSB_STS_TYPE_WIRELESS_FEAT	1
#define	WUSB_STS_TYPE_CHANNEL_INFO	2
#define	WUSB_STS_TYPE_RECVD_DATA	3
#define	WUSB_STS_TYPE_MAS_AVAIL		4
#define	WUSB_STS_TYPE_TRANS_PWR		5

/*
 * Device buffer length for count packets and capture packet functions,
 * refer to WUSB 1.0 4.3.7.2
 */
#define	WUSB_COUNT_CAPT_PKT_LEN		512

/* Length for Wireless USB GET_STATUS request */
#define	WUSB_STANDARD_STS_LEN		2
#define	WUSB_FEAT_STAT_LEN		1
#define	WUSB_CHANNEL_INFO_STS_LEN	1
#define	WUSB_RECVD_DATA_STS_LEN		WUSB_COUNT_CAPT_PKT_LEN
#define	WUSB_MAS_AVAIL_STS_LEN		1
#define	WUSB_TRANS_PWR_STS_LEN		2

/* Wiless USB feature status bits */
#define	WUSB_TX_DRP_IE_STATUS		1
#define	WUSB_TRANS_PWR_STATUS		2
#define	WUSB_COUNT_PKTS_STATUS		4
#define	WUSB_CAPT_PKTS_STATUS		8

/* Status data */
typedef struct wusb_counted_pkt {
	uint8_t		recp_time[3];
	uint8_t		mac_header[6];
	uint8_t		lqi;
} wusb_counted_pkt_t;

typedef struct wusb_count_pkts {
	uint8_t			pkt_count;
	wusb_counted_pkt_t	pkt_block[51];
} wusb_count_pkts_t;

typedef struct wusb_trans_pwr {
	uint8_t		bTxNotifTransPwr;
	uint8_t		bTxBeaconTransPwr;
} wusb_trans_pwr_t;

/* Wireless USB data selectors for SetWUSBDate request */
#define	WUSB_DATA_DRPIE_INFO		1
#define	WUSB_DATA_TRANS_DATA		2
#define	WUSB_DATA_TRANS_PARAMS		3
#define	WUSB_DATA_RECV_PARAMS		4
#define	WUSB_DATA_TRANS_PWR		5

typedef struct wusb_trans_params {
	uint8_t		trans_time[3];
	uint8_t		trans_adjust;
} wusb_trans_params_t;

typedef struct wusb_recv_params {
	uint8_t		recv_filter;
	uint8_t		recv_channel;
	uint8_t		recv_start_time[3];
	uint8_t		recv_end_time[3];
} wusb_recv_params_t;

/* Wireless USB key index bits */
#define	WUSB_KEY_INDEX_MASK		0x0f
#define	WUSB_KEY_TYPE_MASK		0x30
#define	WUSB_KEY_TYPE_ASSOCIATION	0x10
#define	WUSB_KEY_TYPE_GTK		0x20
#define	WUSB_KEY_ORIGIN_MASK		0x40
#define	WUSB_KEY_ORIGIN_HOST		0x00
#define	WUSB_KEY_ORIGIN_DEV		0x40

typedef struct wusb_key {
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		key_index	:4,
			key_type	:2,
			key_origin	:1,
			key_resv	:1;
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t		key_resv	:1,
			key_origin	:1,
			key_type	:2,
			key_index	:4;
#endif
} wusb_key_t;

/* Wireless USB handshake data */
typedef struct wusb_hndshk_data {
	uint8_t		bMessageNumber;
	uint8_t		bStatus;
	uint8_t		tTKID[3];
	uint8_t		bReserved;
	uint8_t		CDID[16];
	uint8_t		Nonce[16];
	uint8_t		MIC[8];
} wusb_hndshk_data_t;

/* Handshake stage */
#define	WUSB_HNDSHK_MSG_NUM1		1
#define	WUSB_HNDSHK_MSG_NUM2		2
#define	WUSB_HNDSHK_MSG_NUM3		3

/* Handshake status */
#define	WUSB_HNDSHK_NORMAL		0
#define	WUSB_HNDSHK_ABORT_PER_POLICY	1
#define	WUSB_HNDSHK_IN_PROGRESS		2
#define	WUSB_HNDSHK_TKID_CONFLICT	3

#define	WUSB_HNDSHK_DATA_LEN		46

/* Wireless USB connection context */
#define	WUSB_CHID_LEN			16
#define	WUSB_CDID_LEN			16
#define	WUSB_CK_LEN			16
#define	WUSB_CC_LEN			48


/*
 * ****************************************
 * IE definitions
 * ****************************************
 */

/* Wireless USB channel IE identifiers */
#define	WUSB_IE_WCTA			0x80
#define	WUSB_IE_CONNECTACK		0x81
#define	WUSB_IE_HOSTINFO		0x82
#define	WUSB_IE_CHCHANGEANNOUNCE	0x83
#define	WUSB_IE_DEV_DISCONNECT		0x84
#define	WUSB_IE_HOST_DISCONNECT		0x85
#define	WUSB_IE_RELEASE_CHANNEL		0x86
#define	WUSB_IE_WORK			0x87
#define	WUSB_IE_CHANNEL_STOP		0x88
#define	WUSB_IE_DEV_KEEPALIVE		0x89
#define	WUSB_IE_ISOC_DISCARD		0x8a
#define	WUSB_IE_RESETDEVICE		0x8b
#define	WUSB_IE_XMIT_PACKET_ADJUST	0x8c

/* Array-based IE must not include more than 4 elements */
#define	WUSB_IE_MAX_ELEMENT		4
#define	WUSB_ACK_BLOCK_SIZE		18
#define	WUSB_ACK_IE_MAX_DATA_LEN	\
	(WUSB_ACK_BLOCK_SIZE * WUSB_IE_MAX_ELEMENT)
#define	WUSB_DISCONN_IE_MAX_DATA_LEN	(WUSB_IE_MAX_ELEMENT + 2)

typedef struct wusb_ie_header {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
} wusb_ie_header_t;

typedef struct wusb_connectack_block {
	uint8_t			CDID[16];
	uint8_t			bDeviceAddress;
	uint8_t			bReserved;
} wusb_connectack_block_t;

typedef struct wusb_ie_connect_ack {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	uint8_t			bAckBlock[WUSB_ACK_IE_MAX_DATA_LEN];
} wusb_ie_connect_ack_t;

typedef struct wusb_ie_host_info {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	uint8_t			bmAttributes[2];
	uint8_t			CHID[16];
} wusb_ie_host_info_t;

#define	WUSB_HI_RECONN_ONLY	0x00
#define	WUSB_HI_CONN_LMTED	0x01
#define	WUSB_HI_CONN_ALL	0x03
#define	WUSB_HI_P2P_DRD_CAP	0x04
#define	WUSB_HI_STRIDX_SHIFT	3
#define	WUSB_HI_STRIDX_MASK	0x38

typedef struct wusb_ie_chchange_announce {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	uint8_t			bNewPHYChannelNumber;
	uint8_t			SwitchTime[3];
} wusb_ie_chchange_announce_t;

/* the size must be even multiple of 2 bytes */
typedef struct wusb_ie_dev_disconnect {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	uint8_t			bDeviceAddress[WUSB_DISCONN_IE_MAX_DATA_LEN];
} wusb_ie_dev_disconnect_t;

typedef wusb_ie_dev_disconnect_t wusb_ie_keepalive_t;

typedef struct wusb_ie_host_disconnect {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
} wusb_ie_host_disconnect_t;

typedef struct wusb_udrb {
	uint16_t		wStart;
	uint16_t		wDurationValue;
	uint8_t			bDeviceAddress;
	uint8_t			bReserved;
} wusb_udrb_t;

typedef struct wusb_ie_release_channel {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	wusb_udrb_t		udrb[WUSB_IE_MAX_ELEMENT];
} wusb_ie_release_channel_t;

typedef struct wusb_ie_channel_stop {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	uint8_t			bmAttributes;
	uint8_t			StopTime[3];
} wusb_ie_channel_stop_t;

typedef struct wusb_ie_isoc_discard {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	uint8_t			bDiscardID;
	uint8_t			bDeviceAddress;
	uint8_t			bmAttributes;
	uint8_t			bFirstReceiveWindowPosition;
	uint16_t		wNumberDiscardedPackets;
	uint16_t		wNumberDiscardedSegments;
	uint8_t			bmDeviceReceiveWindow[4];
} wusb_ie_isoc_discard_t;

typedef struct wusb_ie_reset_device {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	uint8_t			CDID[4 * WUSB_IE_MAX_ELEMENT];
} wusb_ie_reset_device_t;

typedef struct wusb_ie_xmit_packet_adjust {
	uint8_t			bLength;
	uint8_t			bIEIdentifier;
	uint8_t			bTransmitAdjustment;
	uint8_t			bReserved;
} wusb_ie_xmit_packet_adjust_t;

/*
 * **************************************
 * Device notification definitions
 * **************************************
 */

/* Device notification message types */
#define	WUSB_DN_CONNECT			1
#define	WUSB_DN_DISCONNECT		2
#define	WUSB_DN_EPRDY			3
#define	WUSB_DN_MASAVAILCHANGED		4
#define	WUSB_DN_REMOTEWAKEUP		5
#define	WUSB_DN_SLEEP			6
#define	WUSB_DN_ALIVE			7

/* WUSB Errata 06.12 specifies WUSB header must not be included */
typedef struct wusb_dn_header {
	uint8_t			bType;
} wusb_dn_header_t;

#define	WUSB_DN_CONN_PKT_LEN		19
#define	WUSB_DN_DISCONN_PKT_LEN		1
#define	WUSB_DN_EPRDY_HDR_LEN		2
#define	WUSB_DN_MASAVAILCHANGED_PKT_LEN	1
#define	WUSB_DN_SLEEP_PKT_LEN		2
#define	WUSB_DN_REMOTEWAKEUP_PKT_LEN	1
#define	WUSB_DN_ALIVE_PKT_LEN		1

typedef struct wusb_dn_connect {
	uint8_t			bType;
	uint8_t			bmConnAttributes[2];
	uint8_t			CDID[16];
} wusb_dn_connect_t;

typedef struct wusb_dn_disconnect {
	uint8_t			bType;
} wusb_dn_disconnect_t;

typedef struct wusb_dn_eprdy {
	uint8_t			bType;
	uint8_t			bLength;
	uint8_t			bEPsReadyArray[1];
} wusb_dn_eprdy_t;

typedef struct wusb_dn_masavail_changed {
	uint8_t			bType;
} wusb_dn_masavail_changed_t;

typedef struct wusb_dn_sleep {
	uint8_t			bType;
	uint8_t			bmSlpAttributes;
} wusb_dn_sleep_t;

typedef struct wusb_dn_remote_wakeup {
	uint8_t			bType;
} wusb_dn_remote_wakeup_t;

typedef struct wusb_dn_alive {
	uint8_t			bType;
} wusb_dn_alive_t;

#define	WUSB_DN_CONN_NEW		0x01
#define	WUSB_DN_CONN_BEACON_MASK	0x06
#define	WUSB_DN_CONN_SELF_BEACON	0x02
#define	WUSB_DN_CONN_DIRECTED_BEACON	0x04
#define	WUSB_DN_CONN_NO_BEACON		0x06

#define	WUSB_DN_SLP_ATTR_GTS		0
#define	WUSB_DN_SLP_ATTR_WTS		1

/*
 * WUSB data rate definitions. See WUSB 7.4.1.1
 */
#define	WUSB_DATA_RATE_BIT_53	1 << 0	/* 53.3 Mbps */
#define	WUSB_DATA_RATE_BIT_80	1 << 1	/* 80 Mbps */
#define	WUSB_DATA_RATE_BIT_106	1 << 2	/* 106.7 Mbps */
#define	WUSB_DATA_RATE_BIT_160	1 << 3	/* 160 Mbps */
#define	WUSB_DATA_RATE_BIT_200	1 << 4	/* 200 Mbps */
#define	WUSB_DATA_RATE_BIT_320	1 << 5	/* 320 Mbps */
#define	WUSB_DATA_RATE_BIT_400	1 << 6	/* 400 Mbps */
#define	WUSB_DATA_RATE_BIT_480	1 << 7	/* 480 Mbps */

/*
 * WUSB PHY Transfer Rate. See WUSB 5.6
 */
#define	WUSB_PHY_TX_RATE_53	0	/* 53.3 Mbps */
#define	WUSB_PHY_TX_RATE_80	1	/* 80 Mbps */
#define	WUSB_PHY_TX_RATE_106	2	/* 106.7 Mbps */
#define	WUSB_PHY_TX_RATE_160	3	/* 160 Mbps */
#define	WUSB_PHY_TX_RATE_200	4	/* 200 Mbps */
#define	WUSB_PHY_TX_RATE_320	5	/* 320 Mbps */
#define	WUSB_PHY_TX_RATE_400	6	/* 400 Mbps */
#define	WUSB_PHY_TX_RATE_480	7	/* 480 Mbps */
#define	WUSB_PHY_TX_RATE_RES	8	/* 8~1F, reserved */

/*
 * *****************************************
 * crypto definition
 * *****************************************
 */

typedef struct wusb_ccm_nonce {
	uint64_t		sfn;
	uint32_t		tkid;
	uint16_t		daddr;
	uint16_t		saddr;
} wusb_ccm_nonce_t;

#define	CCM_MAC_LEN		8	/* from WUSB 6.4 */
#define	CCM_NONCE_LEN		13	/* from WUSB 6.4 */

/* WUSB encryption types. see table 7-35 */
#define	WUSB_ENCRYP_TYPE_UNSECURE	0
#define	WUSB_ENCRYP_TYPE_WIRED		1
#define	WUSB_ENCRYP_TYPE_CCM_1		2
#define	WUSB_ENCRYP_TYPE_RSA_1		3

/* association, refer to WUSB AM Spec 3.8 */
enum wusb_association_attr {
	attrAssociationTypeId			= 0x0000,
	attrAssociationSubTypeId		= 0x0001,
	attrLength				= 0x0002,
	attrAssociationStatus			= 0x0004,
	attrLangID				= 0x0008,
	attrDeviceFriendlyName			= 0x000B,
	attrHostFriendlyName			= 0x000C,
	attrCHID				= 0x1000,
	attrCDID				= 0x1001,
	attrConnectionContext			= 0x1002,
	attrBandGroups				= 0x1004
};

typedef	uint16_t	wusb_asso_attr_t;

typedef struct wusb_cbaf_info_item {
	wusb_asso_attr_t	typeID;
	uint16_t		length;
} wusb_cbaf_info_item_t;

#define	fieldAssociationTypeId			"\x00\x00\x02\x00"
#define	fieldAssociationSubTypeId		"\x01\x00\x02\x00"
#define	fieldLength				"\x02\x00\x04\x00"
#define	fieldAssociationStatus			"\x04\x00\x04\x00"
#define	fieldLangID				"\x08\x00\x02\x00"
#define	fieldDeviceFriendlyName			"\x0B\x00\x40\x00"
#define	fieldHostFriendlyName			"\x0C\x00\x40\x00"
#define	fieldCHID				"\x00\x10\x10\x00"
#define	fieldCDID				"\x01\x10\x10\x00"
#define	fieldConnectionContext			"\x02\x10\x30\x00"
#define	fieldBandGroups				"\x04\x10\x02\x00"


#ifdef __cplusplus
}
#endif

#endif /* _SYS_USB_WUSBA_H */
