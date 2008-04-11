/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	IEEE80211_MODE_TURBO_G	= 6	/* 2GHz, OFDM, 2x clock */
};
#define	IEEE80211_MODE_MAX	(IEEE80211_MODE_TURBO_G+1)

enum ieee80211_phytype {
	IEEE80211_T_DS,		/* direct sequence spread spectrum */
	IEEE80211_T_FH,		/* frequency hopping */
	IEEE80211_T_OFDM,	/* frequency division multiplexing */
	IEEE80211_T_TURBO	/* high rate OFDM, aka turbo mode */
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

struct ieee80211_frame_addr4 {
	uint8_t		i_fc[2];
	uint8_t		i_dur[2];
	uint8_t		i_addr1[IEEE80211_ADDR_LEN];
	uint8_t		i_addr2[IEEE80211_ADDR_LEN];
	uint8_t		i_addr3[IEEE80211_ADDR_LEN];
	uint8_t		i_seq[2];
	uint8_t		i_addr4[IEEE80211_ADDR_LEN];
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
#define	IEEE80211_MNF_SETUP_REQ	0
#define	IEEE80211_MNF_SETUP_RESP	1
#define	IEEE80211_MNF_TEARDOWN	2

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
	uint8_t		wme_reserved;
	struct ieee80211_wme_acparams	wme_acParams[WME_NUM_AC];
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
/* for TYPE_CTL */
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

/* Length of management frame variable-length components in bytes */
#define	IEEE80211_NWID_LEN			32	/* SSID */
#define	IEEE80211_FH_LEN			5	/* FH parameters */
#define	IEEE80211_DS_LEN			1	/* DS parameters */
#define	IEEE80211_IBSS_LEN			4	/* IBSS parameters */
#define	IEEE80211_ERP_LEN			1	/* ERP information */

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
	IEEE80211_ELEMID_ERP			= 42,
	IEEE80211_ELEMID_RSN			= 48,
	IEEE80211_ELEMID_XRATES			= 50,
	/* 128-129 proprietary elements used by Agere chipsets */
	IEEE80211_ELEMID_AGERE1			= 128,
	IEEE80211_ELEMID_AGERE2			= 129,
	IEEE80211_ELEMID_TPC			= 150,
	IEEE80211_ELEMID_CCKM			= 156,
	IEEE80211_ELEMID_VENDOR			= 221	/* vendor private */
};

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
	IEEE80211_REASON_INVALID_POWER		= 10,
	IEEE80211_REASON_RSN_REQUIRED		= 11,
	IEEE80211_REASON_RSN_INCONSISTENT	= 12,
	IEEE80211_REASON_IE_INVALID		= 13,
	IEEE80211_REASON_MIC_FAILURE		= 14
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
	IEEE80211_STATUS_SP_REQUIRED		= 19,
	IEEE80211_STATUS_PBCC_REQUIRED		= 20,
	IEEE80211_STATUS_CA_REQUIRED		= 21,
	IEEE80211_STATUS_TOO_MANY_STATIONS	= 22,
	IEEE80211_STATUS_RATES			= 23,
	IEEE80211_STATUS_SHORTSLOT_REQUIRED	= 25,
	IEEE80211_STATUS_DSSSOFDM_REQUIRED	= 26
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
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NET80211_PROTO_H */
