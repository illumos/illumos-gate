/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2008 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_NET80211_PROTO_H
#define	_SYS_NET80211_PROTO_H

/*
 * 802.11 protocol definitions
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	IEEE80211_ADDR_LEN	6	/* size of 802.11 address */
#define	IEEE80211_ADDR_COPY(dst, src)	\
	((void) bcopy(src, dst, IEEE80211_ADDR_LEN))
#define	IEEE80211_ADDR_EQ(a1, a2)	\
	(bcmp(a1, a2, IEEE80211_ADDR_LEN) == 0)
/* is 802.11 address multicast/broadcast? */
#define	IEEE80211_IS_MULTICAST(addr)	\
	((((uint8_t *)addr)[0]) & 0x01)

/*
 * Size of an ACK control frame in bytes.
 */
#define	IEEE80211_ACK_SIZE	(2 + 2 + IEEE80211_ADDR_LEN + 4)

#define	WME_NUM_AC		4	/* 4 AC categories */

/*
 * The formation of some management frames requires guidance to
 * deal with legacy clients.  When the client is identified as
 * "legacy 11b" this parameter can be passed in the arg param of a
 * IEEE80211_SEND_MGMT call.
 */
#define	IEEE80211_SEND_LEGACY_11B	0x1	/* legacy 11b client */
#define	IEEE80211_SEND_LEGACY_11	0x2	/* other legacy client */
#define	IEEE80211_SEND_LEGACY		0x3	/* any legacy client */

/*
 * Protocol Physical Layer
 */

/* XXX not really a mode; there are really multiple PHY's */
enum ieee80211_phymode {
	IEEE80211_MODE_AUTO	= 0,	/* autoselect */
	IEEE80211_MODE_11A	= 1,	/* 5GHz, OFDM */
	IEEE80211_MODE_11B	= 2,	/* 2GHz, CCK */
	IEEE80211_MODE_11G	= 3,	/* 2GHz, OFDM */
	IEEE80211_MODE_FH	= 4,	/* 2GHz, GFSK */
	IEEE80211_MODE_TURBO_A	= 5,	/* 5GHz, OFDM, 2x clock */
	IEEE80211_MODE_TURBO_G	= 6,	/* 2GHz, OFDM, 2x clock */
	IEEE80211_MODE_STURBO_A	= 7,	/* 5GHz, OFDM, 2x clock, static */
	IEEE80211_MODE_11NA	= 8,	/* 5GHz, w/ HT */
	IEEE80211_MODE_11NG	= 9	/* 2GHz, w/ HT */
};
#define	IEEE80211_MODE_MAX	(IEEE80211_MODE_11NG + 1)

enum ieee80211_phytype {
	IEEE80211_T_DS,		/* direct sequence spread spectrum */
	IEEE80211_T_FH,		/* frequency hopping */
	IEEE80211_T_OFDM,	/* frequency division multiplexing */
	IEEE80211_T_TURBO,	/* high rate OFDM, aka turbo mode */
	IEEE80211_T_HT		/* high throughput, full GI */
};
#define	IEEE80211_T_CCK	IEEE80211_T_DS	/* more common nomenclature */

enum ieee80211_opmode {
	IEEE80211_M_STA		= 1,	/* infrastructure station */
	IEEE80211_M_IBSS 	= 0,	/* IBSS (adhoc) station */
	IEEE80211_M_AHDEMO	= 3,	/* Old lucent compatible adhoc demo */
	IEEE80211_M_HOSTAP	= 6,	/* Software Access Point */
	IEEE80211_M_MONITOR	= 8	/* Monitor mode */
};

/*
 * 802.11g protection mode.
 */
enum ieee80211_protmode {
	IEEE80211_PROT_NONE	= 0,	/* no protection */
	IEEE80211_PROT_CTSONLY	= 1,	/* CTS to self */
	IEEE80211_PROT_RTSCTS	= 2	/* RTS-CTS */
};

/*
 * generic definitions for IEEE 802.11 frames
 */
#pragma pack(1)
struct ieee80211_frame {
	uint8_t		i_fc[2]; /* [0]-protocol version, [1]-type & subtype */
	uint8_t		i_dur[2];
	uint8_t		i_addr1[IEEE80211_ADDR_LEN];
	uint8_t		i_addr2[IEEE80211_ADDR_LEN];
	uint8_t		i_addr3[IEEE80211_ADDR_LEN];
	uint8_t		i_seq[2];
	/* possibly followed by addr4[IEEE80211_ADDR_LEN]; */
	/* see below */
};

struct ieee80211_qosframe {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_addr1[IEEE80211_ADDR_LEN];
	uint8_t		i_addr2[IEEE80211_ADDR_LEN];
	uint8_t		i_addr3[IEEE80211_ADDR_LEN];
	uint8_t		i_seq[2];
	uint8_t		i_qos[2];
	/* possibly followed by addr4[IEEE80211_ADDR_LEN]; */
	/* see below */
};

struct ieee80211_qoscntl {
	uint8_t		i_qos[2];
};

struct ieee80211_frame_addr4 {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_addr1[IEEE80211_ADDR_LEN];
	uint8_t		i_addr2[IEEE80211_ADDR_LEN];
	uint8_t		i_addr3[IEEE80211_ADDR_LEN];
	uint8_t		i_seq[2];
	uint8_t		i_addr4[IEEE80211_ADDR_LEN];
};

struct ieee80211_qosframe_addr4 {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_addr1[IEEE80211_ADDR_LEN];
	uint8_t		i_addr2[IEEE80211_ADDR_LEN];
	uint8_t		i_addr3[IEEE80211_ADDR_LEN];
	uint8_t		i_seq[2];
	uint8_t		i_addr4[IEEE80211_ADDR_LEN];
	uint8_t		i_qos[2];
};

/* Start part(LLC and SNAP) of payload of IEEE80211 frame */
struct ieee80211_llc {
	/* LLC */
	uint8_t		illc_dsap;
	uint8_t		illc_ssap;
	uint8_t		illc_control;
	/* SNAP */
	uint8_t		illc_oc[3]; /* protocol ID or organization code */
	uint16_t	illc_ether_type; /* ethernet type */
};

/*
 * Management Notification Frame
 */
struct ieee80211_mnf {
	uint8_t		mnf_category;
	uint8_t		mnf_action;
	uint8_t		mnf_dialog;
	uint8_t		mnf_status;
};

/*
 * Control frames.
 */
struct ieee80211_frame_min {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_addr1[IEEE80211_ADDR_LEN];
	uint8_t		i_addr2[IEEE80211_ADDR_LEN];
	/* FCS */
};

struct ieee80211_frame_rts {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_ra[IEEE80211_ADDR_LEN];
	uint8_t		i_ta[IEEE80211_ADDR_LEN];
	/* FCS */
};

struct ieee80211_frame_cts {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_ra[IEEE80211_ADDR_LEN];
	/* FCS */
};

struct ieee80211_frame_ack {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_ra[IEEE80211_ADDR_LEN];
	/* FCS */
};

struct ieee80211_frame_pspoll {
	uint8_t		i_fc[2];
	uint8_t		i_aid[2];
	uint8_t		i_bssid[IEEE80211_ADDR_LEN];
	uint8_t		i_ta[IEEE80211_ADDR_LEN];
	/* FCS */
};

struct ieee80211_frame_cfend {		/* NB: also CF-End+CF-Ack */
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];	/* should be zero */
	uint8_t		i_ra[IEEE80211_ADDR_LEN];
	uint8_t		i_bssid[IEEE80211_ADDR_LEN];
	/* FCS */
};

struct ieee80211_frame_bar {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_ra[IEEE80211_ADDR_LEN];
	uint8_t		i_ta[IEEE80211_ADDR_LEN];
	uint16_t	i_ctl;
	uint16_t	i_seq;
	/* FCS */
};

struct ieee80211_tim_ie {
	uint8_t		tim_ie;			/* IEEE80211_ELEMID_TIM */
	uint8_t		tim_len;
	uint8_t		tim_count;		/* DTIM count */
	uint8_t		tim_period;		/* DTIM period */
	uint8_t		tim_bitctl;		/* bitmap control */
	uint8_t		tim_bitmap[1];		/* variable-length bitmap */
};

/*
 * 802.11i/WPA information element (maximally sized).
 */
struct ieee80211_ie_wpa {
	uint8_t		wpa_id;		 /* IEEE80211_ELEMID_VENDOR */
	uint8_t		wpa_len;	 /* length in bytes */
	uint8_t		wpa_oui[3];	 /* 0x00, 0x50, 0xf2 */
	uint8_t		wpa_type;	 /* OUI type */
	uint16_t	wpa_version;	 /* spec revision */
	uint32_t	wpa_mcipher[1];	 /* multicast/group key cipher */
	uint16_t	wpa_uciphercnt;	 /* # pairwise key ciphers */
	uint32_t	wpa_uciphers[8]; /* ciphers */
	uint16_t	wpa_authselcnt;	 /* authentication selector cnt */
	uint32_t	wpa_authsels[8]; /* selectors */
	uint16_t	wpa_caps;	 /* 802.11i capabilities */
	uint16_t	wpa_pmkidcnt;	 /* 802.11i pmkid count */
	uint16_t	wpa_pmkids[8];	 /* 802.11i pmkids */
};

/*
 * WME AC parameter field
 */
struct ieee80211_wme_acparams {
	uint8_t		acp_aci_aifsn;
	uint8_t		acp_logcwminmax;
	uint16_t	acp_txop;
};

/*
 * WME Parameter Element
 */
struct ieee80211_wme_param {
	uint8_t		wme_id;
	uint8_t		wme_len;
	uint8_t		wme_oui[3];
	uint8_t		wme_oui_type;
	uint8_t		wme_oui_sybtype;
	uint8_t		wme_version;
	uint8_t		wme_qosInfo;
#define	WME_QOSINFO_COUNT	0x0f	/* Mask for param count field */
	uint8_t		wme_reserved;
	struct ieee80211_wme_acparams	wme_acParams[WME_NUM_AC];
};

/*
 * WME/802.11e information element.
 */
struct ieee80211_wme_info {
	uint8_t		wme_id;		/* IEEE80211_ELEMID_VENDOR */
	uint8_t		wme_len;	/* length in bytes */
	uint8_t		wme_oui[3];	/* 0x00, 0x50, 0xf2 */
	uint8_t		wme_type;	/* OUI type */
	uint8_t		wme_subtype;	/* OUI subtype */
	uint8_t		wme_version;	/* spec revision */
	uint8_t		wme_info;	/* QoS info */
};

/*
 * WME/802.11e Tspec Element
 */
struct ieee80211_wme_tspec {
	uint8_t		ts_id;
	uint8_t		ts_len;
	uint8_t		ts_oui[3];
	uint8_t		ts_oui_type;
	uint8_t		ts_oui_subtype;
	uint8_t		ts_version;
	uint8_t		ts_tsinfo[3];
	uint8_t		ts_nom_msdu[2];
	uint8_t		ts_max_msdu[2];
	uint8_t		ts_min_svc[4];
	uint8_t		ts_max_svc[4];
	uint8_t		ts_inactv_intv[4];
	uint8_t		ts_susp_intv[4];
	uint8_t		ts_start_svc[4];
	uint8_t		ts_min_rate[4];
	uint8_t		ts_mean_rate[4];
	uint8_t		ts_max_burst[4];
	uint8_t		ts_min_phy[4];
	uint8_t		ts_peak_rate[4];
	uint8_t		ts_delay[4];
	uint8_t		ts_surplus[2];
	uint8_t		ts_medium_time[2];
};

/*
 * 802.11n Management Action Frames
 */
/* generic frame format */
struct ieee80211_action {
	uint8_t		ia_category;
	uint8_t		ia_action;
};

/* HT - recommended transmission channel width */
struct ieee80211_action_ht_txchwidth {
	struct ieee80211_action	at_header;
	uint8_t		at_chwidth;
};

struct ieee80211_action_ht_mimopowersave {
	struct ieee80211_action am_header;
	uint8_t		am_control;
};

/* BA - ADDBA request */
struct ieee80211_action_ba_addbarequest {
	struct ieee80211_action rq_header;
	uint8_t		rq_dialogtoken;
	uint16_t	rq_baparamset;
	uint16_t	rq_batimeout;		/* in TUs */
	uint16_t	rq_baseqctl;
};

/* BA - ADDBA response */
struct ieee80211_action_ba_addbaresponse {
	struct ieee80211_action rs_header;
	uint8_t		rs_dialogtoken;
	uint16_t	rs_statuscode;
	uint16_t	rs_baparamset;
	uint16_t	rs_batimeout;		/* in TUs */
};

/* BA - DELBA */
struct ieee80211_action_ba_delba {
	struct ieee80211_action dl_header;
	uint16_t	dl_baparamset;
	uint16_t	dl_reasoncode;
};

struct ieee80211_ba_request {
	uint16_t	rq_barctl;
	uint16_t	rq_barseqctl;
};

/*
 * 802.11n HT Capability IE
 * NB: these reflect D1.10
 */
struct ieee80211_ie_htcap {
	uint8_t		hc_id;			/* element ID */
	uint8_t		hc_len;			/* length in bytes */
	uint16_t	hc_cap;			/* HT caps (see below) */
	uint8_t		hc_param;		/* HT params (see below) */
	uint8_t 	hc_mcsset[16]; 		/* supported MCS set */
	uint16_t	hc_extcap;		/* extended HT capabilities */
	uint32_t	hc_txbf;		/* txbf capabilities */
	uint8_t		hc_antenna;		/* antenna capabilities */
};

/*
 * 802.11n HT Information IE
 */
struct ieee80211_ie_htinfo {
	uint8_t		hi_id;			/* element ID */
	uint8_t		hi_len;			/* length in bytes */
	uint8_t		hi_ctrlchannel;		/* primary channel */
	uint8_t		hi_byte1;		/* ht ie byte 1 */
	uint8_t		hi_byte2;		/* ht ie byte 2 */
	uint8_t		hi_byte3;		/* ht ie byte 3 */
	uint16_t	hi_byte45;		/* ht ie bytes 4+5 */
	uint8_t 	hi_basicmcsset[16]; 	/* basic MCS set */
};
#pragma pack()

#define	IEEE80211_FC0_VERSION_MASK		0x03
#define	IEEE80211_FC0_VERSION_SHIFT		0
#define	IEEE80211_FC0_VERSION_0			0x00
#define	IEEE80211_FC0_TYPE_MASK			0x0c
#define	IEEE80211_FC0_TYPE_SHIFT		2
#define	IEEE80211_FC0_TYPE_MGT			0x00
#define	IEEE80211_FC0_TYPE_CTL			0x04
#define	IEEE80211_FC0_TYPE_DATA			0x08
#define	IEEE80211_FC0_SUBTYPE_MASK		0xf0
#define	IEEE80211_FC0_SUBTYPE_SHIFT		4
/* for TYPE_MGT */
#define	IEEE80211_FC0_SUBTYPE_ASSOC_REQ		0x00
#define	IEEE80211_FC0_SUBTYPE_ASSOC_RESP	0x10
#define	IEEE80211_FC0_SUBTYPE_REASSOC_REQ	0x20
#define	IEEE80211_FC0_SUBTYPE_REASSOC_RESP	0x30
#define	IEEE80211_FC0_SUBTYPE_PROBE_REQ		0x40
#define	IEEE80211_FC0_SUBTYPE_PROBE_RESP	0x50
#define	IEEE80211_FC0_SUBTYPE_BEACON		0x80
#define	IEEE80211_FC0_SUBTYPE_ATIM		0x90
#define	IEEE80211_FC0_SUBTYPE_DISASSOC		0xa0
#define	IEEE80211_FC0_SUBTYPE_AUTH		0xb0
#define	IEEE80211_FC0_SUBTYPE_DEAUTH		0xc0
#define	IEEE80211_FC0_SUBTYPE_ACTION		0xd0
/* for TYPE_CTL */
#define	IEEE80211_FC0_SUBTYPE_BAR		0x80
#define	IEEE80211_FC0_SUBTYPE_PS_POLL		0xa0
#define	IEEE80211_FC0_SUBTYPE_RTS		0xb0
#define	IEEE80211_FC0_SUBTYPE_CTS		0xc0
#define	IEEE80211_FC0_SUBTYPE_ACK		0xd0
#define	IEEE80211_FC0_SUBTYPE_CF_END		0xe0
#define	IEEE80211_FC0_SUBTYPE_CF_END_ACK	0xf0
/* for TYPE_DATA (bit combination) */
#define	IEEE80211_FC0_SUBTYPE_DATA		0x00
#define	IEEE80211_FC0_SUBTYPE_CF_ACK		0x10
#define	IEEE80211_FC0_SUBTYPE_CF_POLL		0x20
#define	IEEE80211_FC0_SUBTYPE_CF_ACPL		0x30
#define	IEEE80211_FC0_SUBTYPE_NODATA		0x40
#define	IEEE80211_FC0_SUBTYPE_CFACK		0x50
#define	IEEE80211_FC0_SUBTYPE_CFPOLL		0x60
#define	IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK	0x70
#define	IEEE80211_FC0_SUBTYPE_QOS		0x80
#define	IEEE80211_FC0_SUBTYPE_QOS_NULL		0xc0

#define	IEEE80211_FC1_DIR_MASK			0x03
#define	IEEE80211_FC1_DIR_NODS			0x00	/* STA->STA */
#define	IEEE80211_FC1_DIR_TODS			0x01	/* STA->AP  */
#define	IEEE80211_FC1_DIR_FROMDS		0x02	/* AP ->STA */
#define	IEEE80211_FC1_DIR_DSTODS		0x03	/* AP ->AP  */

#define	IEEE80211_FC1_MORE_FRAG			0x04
#define	IEEE80211_FC1_RETRY			0x08
#define	IEEE80211_FC1_PWR_MGT			0x10
#define	IEEE80211_FC1_MORE_DATA			0x20
#define	IEEE80211_FC1_WEP			0x40
#define	IEEE80211_FC1_ORDER			0x80

#define	IEEE80211_SEQ_FRAG_MASK			0x000f
#define	IEEE80211_SEQ_FRAG_SHIFT		0
#define	IEEE80211_SEQ_SEQ_MASK			0xfff0
#define	IEEE80211_SEQ_SEQ_SHIFT			4	/* 4bit frag number */
#define	IEEE80211_SEQ_RANGE			4096

#define	IEEE80211_SEQ_ADD(seq, incr) \
	(((seq) + (incr)) & (IEEE80211_SEQ_RANGE - 1))
#define	IEEE80211_SEQ_INC(seq)	IEEE80211_SEQ_ADD(seq, 1)
#define	IEEE80211_SEQ_SUB(a, b) \
	(((a) + IEEE80211_SEQ_RANGE - (b)) & (IEEE80211_SEQ_RANGE - 1))

#define	IEEE80211_SEQ_BA_RANGE			2048	/* 2^11 */
#define	IEEE80211_SEQ_BA_BEFORE(a, b) \
	(IEEE80211_SEQ_SUB(b, a+1) < IEEE80211_SEQ_BA_RANGE-1)

/* Length of management frame variable-length components in bytes */
#define	IEEE80211_NWID_LEN			32	/* SSID */
#define	IEEE80211_FH_LEN			5	/* FH parameters */
#define	IEEE80211_DS_LEN			1	/* DS parameters */
#define	IEEE80211_IBSS_LEN			4	/* IBSS parameters */
#define	IEEE80211_ERP_LEN			1	/* ERP information */

#define	IEEE80211_QOS_TXOP			0x00ff
/* bit 8 is reserved */
#define	IEEE80211_QOS_AMSDU			0x80
#define	IEEE80211_QOS_AMSDU_S			7
#define	IEEE80211_QOS_ACKPOLICY			0x60
#define	IEEE80211_QOS_ACKPOLICY_S		5
#define	IEEE80211_QOS_ACKPOLICY_NOACK		0x20	/* No ACK required */
#define	IEEE80211_QOS_ACKPOLICY_BA		0x60	/* Block ACK */
#define	IEEE80211_QOS_ESOP			0x10
#define	IEEE80211_QOS_ESOP_S			4
#define	IEEE80211_QOS_TID			0x0f

/* does frame have QoS sequence control data */
#define	IEEE80211_QOS_HAS_SEQ(wh) \
	(((wh)->i_fc[0] & \
	(IEEE80211_FC0_TYPE_MASK | IEEE80211_FC0_SUBTYPE_QOS)) == \
	(IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS))

#define	WME_NUM_AC		4	/* 4 AC categories */
#define	WME_NUM_TID		16	/* 16 tids */

#define	WME_PARAM_ACI		0x60	/* Mask for ACI field */
#define	WME_PARAM_ACI_S		5	/* Shift for ACI field */
#define	WME_PARAM_ACM		0x10	/* Mask for ACM bit */
#define	WME_PARAM_ACM_S		4	/* Shift for ACM bit */
#define	WME_PARAM_AIFSN		0x0f	/* Mask for aifsn field */
#define	WME_PARAM_AIFSN_S	0	/* Shift for aifsn field */
#define	WME_PARAM_LOGCWMIN	0x0f	/* Mask for CwMin field (in log) */
#define	WME_PARAM_LOGCWMIN_S	0	/* Shift for CwMin field */
#define	WME_PARAM_LOGCWMAX	0xf0	/* Mask for CwMax field (in log) */
#define	WME_PARAM_LOGCWMAX_S	4	/* Shift for CwMax field */

#define	WME_AC_TO_TID(_ac) (       \
	((_ac) == WME_AC_VO) ? 6 : \
	((_ac) == WME_AC_VI) ? 5 : \
	((_ac) == WME_AC_BK) ? 1 : \
	0)

#define	TID_TO_WME_AC(_tid) (      \
	((_tid) == 0 || (_tid) == 3) ? WME_AC_BE : \
	((_tid) < 3) ? WME_AC_BK : \
	((_tid) < 6) ? WME_AC_VI : \
	WME_AC_VO)

#define	IEEE80211_MNF_SETUP_REQ		0
#define	IEEE80211_MNF_SETUP_RESP	1
#define	IEEE80211_MNF_TEARDOWN		2

#define	IEEE80211_ACTION_CAT_QOS	0	/* QoS */
#define	IEEE80211_ACTION_CAT_BA		3	/* BA */
#define	IEEE80211_ACTION_CAT_HT		7	/* HT */

#define	IEEE80211_ACTION_HT_TXCHWIDTH	0	/* recommend xmit chan width */
#define	IEEE80211_ACTION_HT_MIMOPWRSAVE	1	/* MIMO power save */

#define	IEEE80211_A_HT_TXCHWIDTH_20	0
#define	IEEE80211_A_HT_TXCHWIDTH_2040	1

#define	IEEE80211_A_HT_MIMOPWRSAVE_ENA		0x01	/* PS enabled */
#define	IEEE80211_A_HT_MIMOPWRSAVE_MODE		0x02
#define	IEEE80211_A_HT_MIMOPWRSAVE_MODE_S	1
#define	IEEE80211_A_HT_MIMOPWRSAVE_DYNAMIC	0x02	/* Dynamic Mode */
#define	IEEE80211_A_HT_MIMOPWRSAVE_STATIC	0x00	/* no SM packets */
/* bits 2-7 reserved */

/* Block Ack actions */
#define	IEEE80211_ACTION_BA_ADDBA_REQUEST	0   /* ADDBA request */
#define	IEEE80211_ACTION_BA_ADDBA_RESPONSE	1   /* ADDBA response */
#define	IEEE80211_ACTION_BA_DELBA		2   /* DELBA */

/* Block Ack Parameter Set */
#define	IEEE80211_BAPS_BUFSIZ	0xffc0		/* buffer size */
#define	IEEE80211_BAPS_BUFSIZ_S	6
#define	IEEE80211_BAPS_TID	0x003c		/* TID */
#define	IEEE80211_BAPS_TID_S	2
#define	IEEE80211_BAPS_POLICY	0x0002		/* block ack policy */
#define	IEEE80211_BAPS_POLICY_S	1

#define	IEEE80211_BAPS_POLICY_DELAYED	(0<<IEEE80211_BAPS_POLICY_S)
#define	IEEE80211_BAPS_POLICY_IMMEDIATE	(1<<IEEE80211_BAPS_POLICY_S)

/* Block Ack Sequence Control */
#define	IEEE80211_BASEQ_START	0xfff0		/* starting seqnum */
#define	IEEE80211_BASEQ_START_S	4
#define	IEEE80211_BASEQ_FRAG	0x000f		/* fragment number */
#define	IEEE80211_BASEQ_FRAG_S	0

/* Delayed Block Ack Parameter Set */
#define	IEEE80211_DELBAPS_TID	0xf000		/* TID */
#define	IEEE80211_DELBAPS_TID_S	12
#define	IEEE80211_DELBAPS_INIT	0x0800		/* initiator */
#define	IEEE80211_DELBAPS_INIT_S 11

/* BAR Control */
#define	IEEE80211_BAR_TID	0xf000		/* TID */
#define	IEEE80211_BAR_TID_S	12
#define	IEEE80211_BAR_COMP	0x0004		/* compressed */
#define	IEEE80211_BAR_MTID	0x0002
#define	IEEE80211_BAR_NOACK	0x0001		/* no-ack policy */

/* HT capability flags (ht_cap) */
#define	IEEE80211_HTCAP_LDPC		0x0001	/* LDPC supported */
#define	IEEE80211_HTCAP_CHWIDTH40	0x0002	/* 20/40 supported */
#define	IEEE80211_HTCAP_SMPS		0x000c	/* SM Power Save mode */
#define	IEEE80211_HTCAP_SMPS_OFF	0x0000	/* none (static mode) */
#define	IEEE80211_HTCAP_SMPS_DYNAMIC	0x0004	/* send RTS first */
/* NB: SMPS value 2 is reserved */
#define	IEEE80211_HTCAP_SMPS_ENA	0x000c	/* enabled */
#define	IEEE80211_HTCAP_GREENFIELD	0x0010	/* Greenfield supported */
#define	IEEE80211_HTCAP_SHORTGI20	0x0020	/* Short GI in 20MHz */
#define	IEEE80211_HTCAP_SHORTGI40	0x0040	/* Short GI in 40MHz */
#define	IEEE80211_HTCAP_TXSTBC		0x0080	/* STBC tx ok */
#define	IEEE80211_HTCAP_RXSTBC		0x0300  /* STBC rx support */
#define	IEEE80211_HTCAP_RXSTBC_S	8
#define	IEEE80211_HTCAP_RXSTBC_1STREAM	0x0100  /* 1 spatial stream */
#define	IEEE80211_HTCAP_RXSTBC_2STREAM	0x0200  /* 1-2 spatial streams */
#define	IEEE80211_HTCAP_RXSTBC_3STREAM	0x0300  /* 1-3 spatial streams */
#define	IEEE80211_HTCAP_DELBA		0x0400	/* HT DELBA supported */
#define	IEEE80211_HTCAP_MAXAMSDU	0x0800	/* max A-MSDU length */
#define	IEEE80211_HTCAP_MAXAMSDU_7935	0x0800	/* 7935 octets */
#define	IEEE80211_HTCAP_MAXAMSDU_3839	0x0000	/* 3839 octets */
#define	IEEE80211_HTCAP_DSSSCCK40	0x1000  /* DSSS/CCK in 40MHz */
#define	IEEE80211_HTCAP_PSMP		0x2000  /* PSMP supported */
#define	IEEE80211_HTCAP_40INTOLERANT	0x4000  /* 40MHz intolerant */
#define	IEEE80211_HTCAP_LSIGTXOPPROT	0x8000  /* L-SIG TXOP prot */

/* HT parameters (hc_param) */
#define	IEEE80211_HTCAP_MAXRXAMPDU	0x03	/* max rx A-MPDU factor */
#define	IEEE80211_HTCAP_MAXRXAMPDU_S	0
#define	IEEE80211_HTCAP_MAXRXAMPDU_8K	0
#define	IEEE80211_HTCAP_MAXRXAMPDU_16K	1
#define	IEEE80211_HTCAP_MAXRXAMPDU_32K	2
#define	IEEE80211_HTCAP_MAXRXAMPDU_64K	3
#define	IEEE80211_HTCAP_MPDUDENSITY	0x1c	/* min MPDU start spacing */
#define	IEEE80211_HTCAP_MPDUDENSITY_S	2
#define	IEEE80211_HTCAP_MPDUDENSITY_NA	0	/* no time restriction */
#define	IEEE80211_HTCAP_MPDUDENSITY_025	1	/* 1/4 us */
#define	IEEE80211_HTCAP_MPDUDENSITY_05	2	/* 1/2 us */
#define	IEEE80211_HTCAP_MPDUDENSITY_1	3	/* 1 us */
#define	IEEE80211_HTCAP_MPDUDENSITY_2	4	/* 2 us */
#define	IEEE80211_HTCAP_MPDUDENSITY_4	5	/* 4 us */
#define	IEEE80211_HTCAP_MPDUDENSITY_8	6	/* 8 us */
#define	IEEE80211_HTCAP_MPDUDENSITY_16	7	/* 16 us */

/* HT extended capabilities (hc_extcap) */
#define	IEEE80211_HTCAP_PCO		0x0001	/* PCO capable */
#define	IEEE80211_HTCAP_PCOTRANS	0x0006	/* PCO transition time */
#define	IEEE80211_HTCAP_PCOTRANS_S	1
#define	IEEE80211_HTCAP_PCOTRANS_04	0x0002	/* 400 us */
#define	IEEE80211_HTCAP_PCOTRANS_15	0x0004	/* 1.5 ms */
#define	IEEE80211_HTCAP_PCOTRANS_5	0x0006	/* 5 ms */
/* bits 3-7 reserved */
#define	IEEE80211_HTCAP_MCSFBACK	0x0300	/* MCS feedback */
#define	IEEE80211_HTCAP_MCSFBACK_S	8
#define	IEEE80211_HTCAP_MCSFBACK_NONE	0x0000	/* nothing provided */
#define	IEEE80211_HTCAP_MCSFBACK_UNSOL	0x0200	/* unsolicited feedback */
#define	IEEE80211_HTCAP_MCSFBACK_MRQ	0x0300	/* " "+respond to MRQ */
#define	IEEE80211_HTCAP_HTC		0x0400	/* +HTC support */
#define	IEEE80211_HTCAP_RDR		0x0800
					/* reverse direction responder */
/* bits 12-15 reserved */

/* byte1 */
#define	IEEE80211_HTINFO_2NDCHAN	0x03	/* secondary/ext chan offset */
#define	IEEE80211_HTINFO_2NDCHAN_S	0
#define	IEEE80211_HTINFO_2NDCHAN_NONE	0x00	/* no secondary/ext channel */
#define	IEEE80211_HTINFO_2NDCHAN_ABOVE	0x01	/* above private channel */
/* NB: 2 is reserved */
#define	IEEE80211_HTINFO_2NDCHAN_BELOW	0x03	/* below primary channel */
#define	IEEE80211_HTINFO_TXWIDTH	0x04	/* tx channel width */
#define	IEEE80211_HTINFO_TXWIDTH_20	0x00	/* 20MHz width */
#define	IEEE80211_HTINFO_TXWIDTH_2040	0x04	/* any supported width */
#define	IEEE80211_HTINFO_RIFSMODE	0x08	/* Reduced IFS (RIFS) use */
#define	IEEE80211_HTINFO_RIFSMODE_PROH	0x00	/* RIFS use prohibited */
#define	IEEE80211_HTINFO_RIFSMODE_PERM	0x08	/* RIFS use permitted */
#define	IEEE80211_HTINFO_PMSPONLY	0x10	/* PSMP required to associate */
#define	IEEE80211_HTINFO_SIGRAN		0xe0	/* shortest Service Interval */
#define	IEEE80211_HTINFO_SIGRAN_S	5
#define	IEEE80211_HTINFO_SIGRAN_5	0x00	/* 5 ms */
/* XXX add rest */

/* bytes 2+3 */
#define	IEEE80211_HTINFO_OPMODE		0x03	/* operating mode */
#define	IEEE80211_HTINFO_OPMODE_S	0
#define	IEEE80211_HTINFO_OPMODE_PURE	0x00	/* no protection */
#define	IEEE80211_HTINFO_OPMODE_PROTOPT	0x01	/* protection optional */
#define	IEEE80211_HTINFO_OPMODE_HT20PR	0x02	/* protection for HT20 sta's */
#define	IEEE80211_HTINFO_OPMODE_MIXED	0x03	/* protection for legacy sta */
#define	IEEE80211_HTINFO_NONGF_PRESENT	0x04	/* non-GF sta's present */
#define	IEEE80211_HTINFO_TXBL		0x08	/* transmit burst limit */
#define	IEEE80211_HTINFO_NONHT_PRESENT	0x10	/* non-HT sta's present */
/* bits 5-15 reserved */

/* bytes 4+5 */
#define	IEEE80211_HTINFO_2NDARYBEACON	0x01
#define	IEEE80211_HTINFO_LSIGTXOPPROT	0x02
#define	IEEE80211_HTINFO_PCO_ACTIVE	0x04
#define	IEEE80211_HTINFO_40MHZPHASE	0x08

/* byte5 */
#define	IEEE80211_HTINFO_BASIC_STBCMCS	0x7f
#define	IEEE80211_HTINFO_BASIC_STBCMCS_S 0
#define	IEEE80211_HTINFO_DUALPROTECTED	0x80

/*
 * Length of management frame information elements containing
 * a variable-length component is:
 *    element_id(1 byte) + length(1 byte) + component(variable bytes)
 */
#define	IEEE80211_ELEM_LEN(complen)		(2 + (complen))

/*
 * minimal length of beacon/probe response frame elements
 *  time stamp[8] + beacon interval[2] + capability[2]
 */
#define	IEEE80211_BEACON_ELEM_MIN		12
/*
 * Minimal length of authentication frame elements
 *    algorithm[2] + sequence[2] + status[2]
 */
#define	IEEE80211_AUTH_ELEM_MIN			6
/*
 * Minimal length of association response frame elements
 *    capability[2] + status[2] + association ID[2]
 */
#define	IEEE80211_ASSOC_RESP_ELEM_MIN		6

#define	IEEE80211_CAPINFO_ESS			0x0001
#define	IEEE80211_CAPINFO_IBSS			0x0002
#define	IEEE80211_CAPINFO_CF_POLLABLE		0x0004
#define	IEEE80211_CAPINFO_CF_POLLREQ		0x0008
#define	IEEE80211_CAPINFO_PRIVACY		0x0010
#define	IEEE80211_CAPINFO_SHORT_PREAMBLE	0x0020
#define	IEEE80211_CAPINFO_PBCC			0x0040
#define	IEEE80211_CAPINFO_CHNL_AGILITY		0x0080
#define	IEEE80211_CAPINFO_SPECTRUM_MGMT		0x0100
/* bits 8-9 are reserved */
#define	IEEE80211_CAPINFO_SHORT_SLOTTIME	0x0400
#define	IEEE80211_CAPINFO_RSN			0x0800
/* bit 12 is reserved */
#define	IEEE80211_CAPINFO_DSSSOFDM		0x2000
/* bits 14-15 are reserved */

/*
 * Management information element payloads.
 */

enum {
	IEEE80211_ELEMID_SSID			= 0,
	IEEE80211_ELEMID_RATES			= 1,
	IEEE80211_ELEMID_FHPARMS		= 2,
	IEEE80211_ELEMID_DSPARMS		= 3,
	IEEE80211_ELEMID_CFPARMS		= 4,
	IEEE80211_ELEMID_TIM			= 5,
	IEEE80211_ELEMID_IBSSPARMS		= 6,
	IEEE80211_ELEMID_COUNTRY		= 7,
	IEEE80211_ELEMID_CHALLENGE		= 16,
	/* 17-31 reserved for challenge text extension */
	IEEE80211_ELEMID_PWRCNSTR		= 32,
	IEEE80211_ELEMID_PWRCAP			= 33,
	IEEE80211_ELEMID_TPCREQ			= 34,
	IEEE80211_ELEMID_TPCREP			= 35,
	IEEE80211_ELEMID_SUPPCHAN		= 36,
	IEEE80211_ELEMID_CHANSWITCHANN		= 37,
	IEEE80211_ELEMID_MEASREQ		= 38,
	IEEE80211_ELEMID_MEASREP		= 39,
	IEEE80211_ELEMID_QUIET			= 40,
	IEEE80211_ELEMID_IBSSDFS		= 41,
	IEEE80211_ELEMID_ERP			= 42,
	IEEE80211_ELEMID_HTCAP			= 45,
	IEEE80211_ELEMID_RSN			= 48,
	IEEE80211_ELEMID_XRATES			= 50,
	IEEE80211_ELEMID_HTINFO			= 61,
	/* 128-129 proprietary elements used by Agere chipsets */
	IEEE80211_ELEMID_AGERE1			= 128,
	IEEE80211_ELEMID_AGERE2			= 129,
	IEEE80211_ELEMID_TPC			= 150,
	IEEE80211_ELEMID_CCKM			= 156,
	IEEE80211_ELEMID_VENDOR			= 221	/* vendor private */
};

#define	BCM_OUI			0x4c9000	/* Broadcom OUI */
#define	BCM_OUI_HTCAP		51		/* pre-draft HTCAP ie */
#define	BCM_OUI_HTINFO		52		/* pre-draft HTINFO ie */

#define	WPA_OUI			0xf25000
#define	WPA_OUI_TYPE		0x01
#define	WPA_VERSION		1		/* current supported version */

#define	IEEE80211_CHALLENGE_LEN			128

#define	IEEE80211_RATE_BASIC			0x80
#define	IEEE80211_RATE_VAL			0x7f

/* EPR information element flags */
#define	IEEE80211_ERP_NON_ERP_PRESENT		0x01
#define	IEEE80211_ERP_USE_PROTECTION		0x02
#define	IEEE80211_ERP_LONG_PREAMBLE		0x04

#define	IEEE80211_AUTH_ALG_OPEN			0x0000
#define	IEEE80211_AUTH_ALG_SHARED		0x0001
#define	IEEE80211_AUTH_ALG_LEAP			0x0080


enum {
	IEEE80211_AUTH_OPEN_REQUEST		= 1,
	IEEE80211_AUTH_OPEN_RESPONSE		= 2
};

enum {
	IEEE80211_AUTH_SHARED_REQUEST		= 1,
	IEEE80211_AUTH_SHARED_CHALLENGE		= 2,
	IEEE80211_AUTH_SHARED_RESPONSE		= 3,
	IEEE80211_AUTH_SHARED_PASS		= 4
};

/*
 * Reason codes
 *
 * Unlisted codes are reserved
 */
enum {
	IEEE80211_REASON_UNSPECIFIED		= 1,
	IEEE80211_REASON_AUTH_EXPIRE		= 2,
	IEEE80211_REASON_AUTH_LEAVE		= 3,
	IEEE80211_REASON_ASSOC_EXPIRE		= 4,
	IEEE80211_REASON_ASSOC_TOOMANY		= 5,
	IEEE80211_REASON_NOT_AUTHED		= 6,
	IEEE80211_REASON_NOT_ASSOCED		= 7,
	IEEE80211_REASON_ASSOC_LEAVE		= 8,
	IEEE80211_REASON_ASSOC_NOT_AUTHED	= 9,
	IEEE80211_REASON_DISASSOC_PWRCAP_BAD	= 10,	/* 11h */
	IEEE80211_REASON_DISASSOC_SUPCHAN_BAD	= 11,	/* 11h */
	IEEE80211_REASON_IE_INVALID		= 13,	/* 11i */
	IEEE80211_REASON_MIC_FAILURE		= 14,	/* 11i */
	IEEE80211_REASON_4WAY_HANDSHAKE_TIMEOUT	= 15,	/* 11i */
	IEEE80211_REASON_GROUP_KEY_UPDATE_TIMEOUT = 16,	/* 11i */
	IEEE80211_REASON_IE_IN_4WAY_DIFFERS	= 17,	/* 11i */
	IEEE80211_REASON_GROUP_CIPHER_INVALID	= 18,	/* 11i */
	IEEE80211_REASON_PAIRWISE_CIPHER_INVALID = 19,	/* 11i */
	IEEE80211_REASON_AKMP_INVALID		= 20,	/* 11i */
	IEEE80211_REASON_UNSUPP_RSN_IE_VERSION	= 21,	/* 11i */
	IEEE80211_REASON_INVALID_RSN_IE_CAP	= 22,	/* 11i */
	IEEE80211_REASON_802_1X_AUTH_FAILED	= 23,	/* 11i */
	IEEE80211_REASON_CIPHER_SUITE_REJECTED	= 24	/* 11i */
};

/*
 * Status codes
 *
 * Unlisted codes are reserved and unused
 */
enum {
	IEEE80211_STATUS_SUCCESS		= 0,
	IEEE80211_STATUS_UNSPECIFIED		= 1,
	IEEE80211_STATUS_CAPINFO		= 10,
	IEEE80211_STATUS_NOT_ASSOCED		= 11,
	IEEE80211_STATUS_OTHER			= 12,
	IEEE80211_STATUS_ALG			= 13,
	IEEE80211_STATUS_SEQUENCE		= 14,
	IEEE80211_STATUS_CHALLENGE		= 15,
	IEEE80211_STATUS_TIMEOUT		= 16,
	IEEE80211_STATUS_TOOMANY		= 17,
	IEEE80211_STATUS_BASIC_RATE		= 18,
	IEEE80211_STATUS_SP_REQUIRED		= 19,	/* 11b */
	IEEE80211_STATUS_PBCC_REQUIRED		= 20,	/* 11b */
	IEEE80211_STATUS_CA_REQUIRED		= 21,	/* 11b */
	IEEE80211_STATUS_SPECMGMT_REQUIRED	= 22,	/* 11h */
	IEEE80211_STATUS_PWRCAP_REQUIRED	= 23,	/* 11h */
	IEEE80211_STATUS_SUPCHAN_REQUIRED	= 24,	/* 11h */
	IEEE80211_STATUS_SHORTSLOT_REQUIRED	= 25,	/* 11g */
	IEEE80211_STATUS_DSSSOFDM_REQUIRED	= 26,	/* 11g */
	IEEE80211_STATUS_INVALID_IE		= 40,	/* 11i */
	IEEE80211_STATUS_GROUP_CIPHER_INVALID	= 41,	/* 11i */
	IEEE80211_STATUS_PAIRWISE_CIPHER_INVALID = 42,	/* 11i */
	IEEE80211_STATUS_AKMP_INVALID		= 43,	/* 11i */
	IEEE80211_STATUS_UNSUPP_RSN_IE_VERSION	= 44,	/* 11i */
	IEEE80211_STATUS_INVALID_RSN_IE_CAP	= 45,	/* 11i */
	IEEE80211_STATUS_CIPHER_SUITE_REJECTED	= 46	/* 11i */
};

#define	IEEE80211_WEP_KEYLEN		5	/* 40bit */
#define	IEEE80211_WEP_IVLEN		3	/* 24bit */
#define	IEEE80211_WEP_KIDLEN		1	/* 1 octet */
#define	IEEE80211_WEP_CRCLEN		4	/* CRC-32 */
#define	IEEE80211_WEP_NKID		4	/* number of key ids */

/*
 * 802.11i defines an extended IV for use with non-WEP ciphers.
 * When the EXTIV bit is set in the key id byte an additional
 * 4 bytes immediately follow the IV for TKIP.  For CCMP the
 * EXTIV bit is likewise set but the 8 bytes represent the
 * CCMP header rather than IV+extended-IV.
 */
#define	IEEE80211_WEP_EXTIV		0x20
#define	IEEE80211_WEP_EXTIVLEN		4	/* extended IV length */
#define	IEEE80211_WEP_MICLEN		8	/* trailing MIC */

#define	IEEE80211_CRC_LEN		4

/*
 * Maximum acceptable MTU is defined by 802.11
 * Min is arbitrarily chosen > IEEE80211_MIN_LEN.
 */
#define	IEEE80211_MTU_MAX		2304
#define	IEEE80211_MTU_MIN		32
#define	IEEE80211_MTU			1500

#define	IEEE80211_MAX_LEN				\
	(sizeof (struct ieee80211_frame_addr4) +	\
	(IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN + IEEE80211_WEP_CRCLEN) + \
	IEEE80211_MTU_MAX + IEEE80211_CRC_LEN)
#define	IEEE80211_ACK_LEN				\
	(sizeof (struct ieee80211_frame_ack) + IEEE80211_CRC_LEN)
#define	IEEE80211_MIN_LEN				\
	(sizeof (struct ieee80211_frame_min) + IEEE80211_CRC_LEN)

/*
 * The 802.11 spec says at most 2007 stations may be
 * associated at once.  For most AP's this is way more
 * than is feasible so we use a default of 128.  This
 * number may be overridden by the driver and/or by
 * user configuration.
 */
#define	IEEE80211_AID_MAX		2007
#define	IEEE80211_AID_DEF		128

#define	IEEE80211_AID(b)		((b) &~ 0xc000)

/*
 * RTS frame length parameters.  The default is specified in
 * the 802.11 spec as 512; we treat it as implementation-dependent
 * so it's defined in ieee80211_var.h.  The max may be wrong
 * for jumbo frames.
 */
#define	IEEE80211_RTS_MIN		1
#define	IEEE80211_RTS_MAX		2346

/*
 * TX fragmentation parameters.  As above for RTS, we treat
 * default as implementation-dependent so define it elsewhere.
 */
#define	IEEE80211_FRAG_MIN		256
#define	IEEE80211_FRAG_MAX		2346

/* flags for ieee80211_fix_rate() */
#define	IEEE80211_F_DOSORT		0x00000001 /* sort rate list */
#define	IEEE80211_F_DOFRATE		0x00000002 /* use fixed rate */
#define	IEEE80211_F_DONEGO		0x00000004 /* calc negotiated rate */
#define	IEEE80211_F_DODEL		0x00000008 /* delete ignore rate */
#define	IEEE80211_F_DOBRS		0x00000010 /* check basic rate set */
#define	IEEE80211_F_JOIN		0x00000020 /* sta joining our bss */

/*
 * Beacon frames constructed by ieee80211_beacon_alloc
 * have the following structure filled in so drivers
 * can update the frame later w/ minimal overhead.
 */
struct ieee80211_beacon_offsets {
	uint16_t	*bo_caps;	/* capabilities */
	uint8_t		*bo_tim;	/* start of atim/dtim */
	uint8_t		*bo_wme;	/* start of WME parameters */
	uint8_t		*bo_trailer;	/* start of fixed-size trailer */
	uint16_t	bo_tim_len;	/* atim/dtim length in bytes */
	uint16_t	bo_trailer_len;	/* trailer length in bytes */
	uint8_t		*bo_erp;	/* start of ERP element */
	uint8_t		*bo_htinfo;	/* start of HT info element */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NET80211_PROTO_H */
