/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2002-2004 Sam Leffler, Errno Consulting
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
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
 *
 */

/*
 * IEEE 802.11 generic handler definitions.
 *
 * This code is derived from NetBSD code; their copyright notice follows.
 */

/*
 * Copyright (c) 2000, 2001 The NetBSD Foundation, Inc.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


/*
 * The atheros IEEE80211a/b/g chipsets just implement a IEEE80211
 * phisical layer protocol, all IEEE80211 MAC layer functions are
 * done by the driver. These functions include scan, association/
 * disassociation, authentication/deauthentication, probe request,
 * beacon processing, WEP processing, etc. All the data structs,
 * constant denifition and function declaration related to IEEE802.11
 * are defined here. Actually, ath_ieee80211.h and ath_ieee80211.c
 * are general for most 802.11a/b/g chipsets. GLDv3 should consider
 * a WiFi extension and then all IEEE802.11 supporting would be
 * integrated into GLDv3.
 */

#ifndef _ATH_IEEE80211_H
#define	_ATH_IEEE80211_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/sysmacros.h>
#include <sys/gld.h>
#include <sys/stream.h>
#include <sys/int_types.h>
#include <sys/note.h>
#include <sys/list.h>

/* Bit map related macros. */
#define	setbit(a, i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a, i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a, i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a, i)	(((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)


/*
 * We always fill constant in LLC
 * and SANP fields of the payload.
 */
#define	LLC_DSAP	0xAA
#define	LLC_SSAP	0xAA
#define	LLC_CONTROL	0x03
#define	SNAP_OC0	0x0
#define	SNAP_OC1	0x0
#define	SNAP_OC2	0x0

#define	IEEE80211_ADDR_LEN	6	/* size of 802.11 address */
#define	IEEE80211_TXPOWER_MAX	100	/* .5 dbM */
#define	IEEE80211_TXPOWER_MIN	0	/* kill radio */
/*
 * Size of an ACK control frame in bytes.
 */
#define	IEEE80211_ACK_SIZE	(2 + 2 + IEEE80211_ADDR_LEN + 4)


/* Constant for "Frame Control" field of IEEE80211 frame header */
#define	IEEE80211_FC0_VERSION_MASK		0x03
#define	IEEE80211_FC0_VERSION_SHIFT		0
#define	IEEE80211_FC0_VERSION_0			0x00
#define	IEEE80211_FC0_TYPE_MASK			0x0c
#define	IEEE80211_FC0_TYPE_SHIFT		2
#define	IEEE80211_FC0_TYPE_MGT			0x00	/* management frame */
#define	IEEE80211_FC0_TYPE_CTL			0x04	/* control frame */
#define	IEEE80211_FC0_TYPE_DATA			0x08	/* data frame */
#define	IEEE80211_FC0_SUBTYPE_MASK		0xf0
#define	IEEE80211_FC0_SUBTYPE_SHIFT		4

/* sub types of management frame(bit combination) */
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

/* sub types of control frame(bit combination) */
#define	IEEE80211_FC0_SUBTYPE_PS_POLL		0xa0
#define	IEEE80211_FC0_SUBTYPE_RTS		0xb0
#define	IEEE80211_FC0_SUBTYPE_CTS		0xc0
#define	IEEE80211_FC0_SUBTYPE_ACK		0xd0
#define	IEEE80211_FC0_SUBTYPE_CF_END		0xe0
#define	IEEE80211_FC0_SUBTYPE_CF_END_ACK	0xf0

/* sub types of data frame(bit combination) */
#define	IEEE80211_FC0_SUBTYPE_DATA		0x00
#define	IEEE80211_FC0_SUBTYPE_CF_ACK		0x10
#define	IEEE80211_FC0_SUBTYPE_CF_POLL		0x20
#define	IEEE80211_FC0_SUBTYPE_CF_ACPL		0x30
#define	IEEE80211_FC0_SUBTYPE_NODATA		0x40
#define	IEEE80211_FC0_SUBTYPE_CFACK		0x50
#define	IEEE80211_FC0_SUBTYPE_CFPOLL		0x60
#define	IEEE80211_FC0_SUBTYPE_CF_ACK_CF_ACK	0x70

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
#define	IEEE80211_SEQ_SEQ_SHIFT			4

#define	IEEE80211_NWID_LEN			32

#define	IEEE80211_RATE2MBS(r)	(((r) & IEEE80211_RATE_VAL) / 2)
#define	IEEE80211_IS_SUBTYPE(_fc, _type) \
	(((_fc) & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_##_type)

#define	IEEE80211_BEACON_INTERVAL(beacon) \
	((beacon)[8] | ((beacon)[9] << 8))
#define	IEEE80211_BEACON_CAPABILITY(beacon) \
	((beacon)[10] | ((beacon)[11] << 8))

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
/* bits 11-12 are reserved */
#define	IEEE80211_CAPINFO_DSSSOFDM		0x2000
/* bits 14-15 are reserved */

/*
 * Management information elements
 */
#define	IEEE80211_ELEMID_SSID			0
#define	IEEE80211_ELEMID_RATES			1
#define	IEEE80211_ELEMID_FHPARMS		2
#define	IEEE80211_ELEMID_DSPARMS		3
#define	IEEE80211_ELEMID_CFPARMS		4
#define	IEEE80211_ELEMID_TIM			5
#define	IEEE80211_ELEMID_IBSSPARMS		6
#define	IEEE80211_ELEMID_COUNTRY		7
#define	IEEE80211_ELEMID_CHALLENGE		16
#define	IEEE80211_ELEMID_ERP			42
#define	IEEE80211_ELEMID_XRATES			50


/* Classes for WME streams */
#define	WME_AC_BE	0
#define	WME_AC_BK	1
#define	WME_AC_VI	2
#define	WME_AC_VO	3

#define	IEEE80211_RATE_BASIC			0x80
#define	IEEE80211_RATE_VAL			0x7f

/* EPR information element flags */
#define	IEEE80211_ERP_NON_ERP_PRESENT		0x01
#define	IEEE80211_ERP_USE_PROTECTION		0x02
#define	IEEE80211_ERP_BARKER_MODE		0x04

/*
 * AUTH management packets
 *
 *	octet algo[2]
 *	octet seq[2]
 *	octet status[2]
 *	octet chal.id
 *	octet chal.length
 *	octet chal.text[253]
 */

#define	IEEE80211_AUTH_ALGORITHM(auth) \
	((auth)[0] | ((auth)[1] << 8))
#define	IEEE80211_AUTH_TRANSACTION(auth) \
	((auth)[2] | ((auth)[3] << 8))
#define	IEEE80211_AUTH_STATUS(auth) \
	((auth)[4] | ((auth)[5] << 8))

#define	IEEE80211_AUTH_ALG_OPEN			0x0000
#define	IEEE80211_AUTH_ALG_SHARED		0x0001

#define	IEEE80211_AUTH_OPEN_REQUEST		1
#define	IEEE80211_AUTH_OPEN_RESPONSE		2

#define	IEEE80211_AUTH_SHARED_REQUEST		1
#define	IEEE80211_AUTH_SHARED_CHALLENGE		2
#define	IEEE80211_AUTH_SHARED_RESPONSE		3
#define	IEEE80211_AUTH_SHARED_PASS		4

/*
 * Reason codes
 * Unlisted codes are reserved
 */

#define	IEEE80211_REASON_UNSPECIFIED		1
#define	IEEE80211_REASON_AUTH_EXPIRE		2
#define	IEEE80211_REASON_AUTH_LEAVE		3
#define	IEEE80211_REASON_ASSOC_EXPIRE		4
#define	IEEE80211_REASON_ASSOC_TOOMANY		5
#define	IEEE80211_REASON_NOT_AUTHED		6
#define	IEEE80211_REASON_NOT_ASSOCED		7
#define	IEEE80211_REASON_ASSOC_LEAVE		8
#define	IEEE80211_REASON_ASSOC_NOT_AUTHED	9

#define	IEEE80211_STATUS_SUCCESS		0
#define	IEEE80211_STATUS_UNSPECIFIED		1
#define	IEEE80211_STATUS_CAPINFO		10
#define	IEEE80211_STATUS_NOT_ASSOCED		11
#define	IEEE80211_STATUS_OTHER			12
#define	IEEE80211_STATUS_ALG			13
#define	IEEE80211_STATUS_SEQUENCE		14
#define	IEEE80211_STATUS_CHALLENGE		15
#define	IEEE80211_STATUS_TIMEOUT		16
#define	IEEE80211_STATUS_TOOMANY		17
#define	IEEE80211_STATUS_BASIC_RATE		18
#define	IEEE80211_STATUS_SP_REQUIRED		19
#define	IEEE80211_STATUS_PBCC_REQUIRED		20
#define	IEEE80211_STATUS_CA_REQUIRED		21
#define	IEEE80211_STATUS_TOO_MANY_STATIONS	22
#define	IEEE80211_STATUS_RATES			23
#define	IEEE80211_STATUS_SHORTSLOT_REQUIRED	25
#define	IEEE80211_STATUS_DSSSOFDM_REQUIRED	26

#define	IEEE80211_WEP_KEYLEN			5	/* 40bit */
#define	IEEE80211_WEP_IVLEN			3	/* 24bit */
#define	IEEE80211_WEP_KIDLEN			1	/* 1 octet */
#define	IEEE80211_WEP_CRCLEN			4	/* CRC-32 */
#define	IEEE80211_WEP_NKID			4	/* number of key ids */

#define	IEEE80211_CRC_LEN			4

#define	IEEE80211_MTU				1500
#define	IEEE80211_MAX_LEN			(2300 + IEEE80211_CRC_LEN + \
	(IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN + IEEE80211_WEP_CRCLEN))

/*
 * RTS frame length parameters.  The default is specified in
 * the 802.11 spec.  The max may be wrong for jumbo frames.
 */
#define	IEEE80211_RTS_DEFAULT			512
#define	IEEE80211_RTS_MIN			1
#define	IEEE80211_RTS_MAX			IEEE80211_MAX_LEN

#define	IEEE80211_CHAN_ANY	0xffff		/* token for ``any channel'' */

#define	IEEE80211_AUTH_NONE	0
#define	IEEE80211_AUTH_OPEN	1
#define	IEEE80211_AUTH_SHARED	2

#define	IEEE80211_PSCAN_WAIT 	5		/* passive scan wait */
#define	IEEE80211_TRANS_WAIT 	5		/* transition wait */
#define	IEEE80211_INACT_WAIT	5		/* inactivity timer interval */
#define	IEEE80211_INACT_MAX	(300/IEEE80211_INACT_WAIT)

/*
 * Structure for IEEE 802.11 drivers.
 */

#define	IEEE80211_CHAN_MAX	255
#define	IEEE80211_CHAN_ANYC \
	((struct ieee80211channel *)IEEE80211_CHAN_ANY)

#define	IEEE80211_RATE_SIZE	8		/* 802.11 standard */
#define	IEEE80211_RATE_MAXSIZE	15		/* max rates we'll handle */
#define	IEEE80211_KEYBUF_SIZE	16
#define	IEEE80211_NODE_HASHSIZE	32
/* simple hash is enough for variation of macaddr */
#define	IEEE80211_NODE_HASH(addr)	\
	(((uint8_t *)(addr))[IEEE80211_ADDR_LEN - 1] % IEEE80211_NODE_HASHSIZE)
#define	IEEE80211_RV(v)	((v) & IEEE80211_RATE_VAL)
#define	IEEE80211_ISPROBE(_wh)	IEEE80211_IS_SUBTYPE((_wh)->ifrm_fc[0], \
	PROBE_RESP)
#define	IEEE80211_RATE(_ix)	(in->in_rates.ir_rates[(_ix)] & \
	IEEE80211_RATE_VAL)
/* Verify the existence and length of __elem or get out. */
#define	IEEE80211_VERIFY_ELEMENT(__elem, __maxlen, __wh) do {		\
	if ((__elem) == NULL) {						\
		ath_problem("ath: no #__elem \n");			\
		return;							\
	}								\
	if ((__elem)[1] > (__maxlen)) {					\
		ath_problem("ath: bad "#__elem " len %d from %s\n",	\
		    (__elem)[1],					\
		    ieee80211_ether_sprintf((__wh)->ifrm_addr2));	\
		return;							\
	}								\
	_NOTE(CONSTANTCONDITION)					\
} while (0)


enum ieee80211_phytype {
	IEEE80211_T_DS,			/* direct sequence spread spectrum */
	IEEE80211_T_FH,			/* frequency hopping */
	IEEE80211_T_OFDM,		/* frequency division multiplexing */
	IEEE80211_T_TURBO		/* high rate OFDM, aka turbo mode */
};
#define	IEEE80211_T_CCK	IEEE80211_T_DS	/* more common nomenclature */

/* not really a mode; there are really multiple PHY's */
enum ieee80211_phymode {
	IEEE80211_MODE_AUTO	= 0,	/* autoselect */
	IEEE80211_MODE_11A	= 1,	/* 5GHz, OFDM */
	IEEE80211_MODE_11B	= 2,	/* 2GHz, CCK */
	IEEE80211_MODE_11G	= 3,	/* 2GHz, OFDM */
	IEEE80211_MODE_TURBO	= 4	/* 5GHz, OFDM, 2x clock */
};
#define	IEEE80211_MODE_MAX	(IEEE80211_MODE_TURBO+1)

enum ieee80211_opmode {
	IEEE80211_M_STA		= 1,	/* infrastructure station */
	IEEE80211_M_IBSS 	= 0,	/* IBSS (adhoc) station */
	IEEE80211_M_AHDEMO	= 3,	/* Old lucent compatible adhoc demo */
	IEEE80211_M_HOSTAP	= 6	/* Software Access Point */
};

enum ieee80211_state {
	IEEE80211_S_INIT,		/* default state */
	IEEE80211_S_SCAN,		/* scanning */
	IEEE80211_S_AUTH,		/* try to authenticate */
	IEEE80211_S_ASSOC,		/* try to assoc */
	IEEE80211_S_RUN			/* associated */
};

/*
 * Channels are specified by frequency and attributes.
 */
struct ieee80211channel {
	uint16_t	ich_freq;	/* setting in Mhz */
	uint16_t	ich_flags;	/* see below */
};

/* bits 0-3 are for private use by drivers */
/* channel attributes */
#define	IEEE80211_CHAN_TURBO	0x0010	/* Turbo channel */
#define	IEEE80211_CHAN_CCK	0x0020	/* CCK channel */
#define	IEEE80211_CHAN_OFDM	0x0040	/* OFDM channel */
#define	IEEE80211_CHAN_2GHZ	0x0080	/* 2 GHz spectrum channel. */
#define	IEEE80211_CHAN_5GHZ	0x0100	/* 5 GHz spectrum channel */
#define	IEEE80211_CHAN_PASSIVE	0x0200	/* Only passive scan allowed */
#define	IEEE80211_CHAN_DYN	0x0400	/* Dynamic CCK-OFDM channel */

/*
 * Useful combinations of channel characteristics.
 */
#define	IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_T \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)

#define	IEEE80211_IS_CHAN_A(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define	IEEE80211_IS_CHAN_B(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define	IEEE80211_IS_CHAN_PUREG(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define	IEEE80211_IS_CHAN_G(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define	IEEE80211_IS_CHAN_T(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_T) == IEEE80211_CHAN_T)

#define	IEEE80211_IS_CHAN_2GHZ(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_2GHZ) != 0)
#define	IEEE80211_IS_CHAN_5GHZ(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_5GHZ) != 0)
#define	IEEE80211_IS_CHAN_OFDM(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_OFDM) != 0)
#define	IEEE80211_IS_CHAN_CCK(_ch) \
	(((_ch)->ich_flags & IEEE80211_CHAN_CCK) != 0)

#pragma pack(1)
/* Header of IEEE 802.11 frame */
struct ieee80211_frame {
	uint8_t	ifrm_fc[2];
	uint8_t	ifrm_dur[2];
	uint8_t	ifrm_addr1[IEEE80211_ADDR_LEN];
	uint8_t	ifrm_addr2[IEEE80211_ADDR_LEN];
	uint8_t	ifrm_addr3[IEEE80211_ADDR_LEN];
	uint8_t	ifrm_seq[2];
	/*
	 * i_addr4 is present only when it's a data
	 * frame from one AP to another AP. The driver
	 * doesn't work in AP mode, so we never transmit
	 * or receive a frame containing i_addr4 field.
	 */
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
#pragma pack()

struct ieee80211_rateset {
	uint8_t		ir_nrates;
	uint8_t		ir_rates[IEEE80211_RATE_MAXSIZE];
};

/* Number of history entries to keep (per node) */
#define	IEEE80211_RECV_HIST_LEN		16
#define	IEEE80211_JIFFIES_NONE		((uint32_t)(~0))

struct ieee80211_recv_hist {
	uint32_t	irh_jiffies;	/* kernel timestamp */
	uint8_t		irh_rssi;	/* recv ssi */
	uint32_t	irh_rstamp;	/* recv timestamp */
	uint8_t		irh_rantenna;	/* recv antenna */
};


/*
 * Node specific information.
 */
struct ieee80211_node {
	/* hardware */
	struct ieee80211_recv_hist in_recv_hist[IEEE80211_RECV_HIST_LEN];
	int32_t			in_hist_cur;
	uint16_t		in_txpower;	/* current transmit power */

	/* header */
	uint8_t			in_macaddr[IEEE80211_ADDR_LEN];
	uint8_t			in_bssid[IEEE80211_ADDR_LEN];

	/* beacon, probe response */
	uint8_t			in_tstamp[8];	/* from last rcv'd beacon */
	uint16_t		in_intval;	/* beacon interval */
	uint16_t		in_capinfo;	/* capabilities */
	uint8_t			in_esslen;
	uint8_t			in_essid[IEEE80211_NWID_LEN];
	struct ieee80211_rateset in_rates;	/* negotiated rate set */
	uint8_t			*in_country;	/* country information */
	struct ieee80211channel	*in_chan;
	uint16_t		in_fhdwell;	/* FH only */
	uint8_t			in_fhindex;	/* FH only */
	uint8_t			in_erp;		/* 11g only */

	/* DTIM and contention free period (CFP) */
	uint8_t			in_dtimperiod;
	uint8_t			in_cfpperiod;	/* # of DTIMs between CFPs */
	uint16_t		in_cfpduremain;	/* remaining cfp duration */
	uint16_t		in_cfpmaxduration; /* max CFP duration in TU */
	uint16_t		in_nextdtim;	/* time to next DTIM */
	uint16_t		in_timoffset;

	/* others */
	uint16_t		in_associd;	/* assoc response */
	uint16_t		in_txseq;	/* seq to be transmitted */
	uint16_t		in_rxseq;	/* seq previous received */
	int32_t			in_fails;	/* failure count to associate */
	int32_t			in_inact;	/* inactivity mark count */
	int32_t			in_txrate;	/* index to in_rates[] */

	/* we're in the list of isc->isc_in_list */
	list_node_t		in_node;

	/* we're in the list of isc->isc_inhash_list */
	list_node_t		in_hash_node;
};

/* in_chan encoding for FH phy */
#define	IEEE80211_FH_CHANMOD	80
#define	IEEE80211_FH_CHAN(set, pat) \
	(((set)-1) * IEEE80211_FH_CHANMOD + (pat))
#define	IEEE80211_FH_CHANSET(chan)	((chan)/IEEE80211_FH_CHANMOD+1)
#define	IEEE80211_FH_CHANPAT(chan)	((chan)%IEEE80211_FH_CHANMOD)

#define	HEADERSPACE roundup(sizeof (struct ieee80211_frame) + \
	    IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN + \
	    sizeof (struct ieee80211_llc) + 1, 4)

struct ieee80211_wepkey {
	int32_t			iwk_len;
	uint8_t			iwk_key[IEEE80211_KEYBUF_SIZE];
};

typedef struct ieee80211com {
	/* The following items are not changed during their lifetime */
	gld_mac_info_t	*isc_dev;
	struct ieee80211_rateset isc_sup_rates[IEEE80211_MODE_MAX];
	struct ieee80211channel isc_channels[IEEE80211_CHAN_MAX + 1];
	uint8_t		isc_chan_avail[
			    roundup(IEEE80211_CHAN_MAX, NBBY)];
	uint32_t	isc_caps;		/* capabilities */
	uint16_t	isc_modecaps;		/* set of mode capabilities */
	enum ieee80211_phytype isc_phytype;	/* wrong for multi-mode */
	uint16_t	isc_bmisstimeout;	/* beacon miss threshold ms */
	uint16_t	isc_scan_interval;	/* scan interval(ms) */
	uint16_t	isc_cali_interval;	/* calibrate interval(ms) */
	uint16_t	isc_ratectl_interval;	/* rate ctl interval(ms) */
	int32_t		(*isc_mgmt_send)(struct ieee80211com *, mblk_t *);
	void		(*isc_recv_mgmt[16])(struct ieee80211com *, mblk_t *,
			    int32_t, uint32_t, uint32_t);
	int32_t		(*isc_send_mgmt[16])(struct ieee80211com *,
			    struct ieee80211_node *, int32_t, int32_t);
	int32_t		(*isc_new_state)(struct ieee80211com *,
			    enum ieee80211_state);
	struct ieee80211_node *(*isc_node_alloc)(struct ieee80211com *);
	void		(*isc_node_free)(struct ieee80211com *,
			    struct ieee80211_node *);
	void		(*isc_node_copy)(struct ieee80211_node *,
			    const struct ieee80211_node *);
	void		(*isc_calibrate)(struct ieee80211com *);
	void		(*isc_rate_ctl)(struct ieee80211com *,
			    struct ieee80211_node *);
	int		(*isc_gld_send)(gld_mac_info_t *, mblk_t *);
	int		(*isc_gld_reset)(gld_mac_info_t *);
	int		(*isc_gld_start)(gld_mac_info_t *);
	int		(*isc_gld_stop)(gld_mac_info_t *);
	int32_t		(*isc_gld_saddr)(gld_mac_info_t *, uint8_t *macaddr);
	int		(*isc_gld_set_promiscuous)(gld_mac_info_t *,
			    int mode);
	int		(*isc_gld_gstat)(gld_mac_info_t *,
			    struct gld_stats *);
	int		(*isc_gld_ioctl)(gld_mac_info_t *, queue_t *, mblk_t *);
	int		(*isc_gld_set_multicast)(gld_mac_info_t *,
			    uint8_t *, int);
	uint32_t	(*isc_gld_intr)(gld_mac_info_t *);

	/*
	 * The following items could only be
	 * changed by ioctl after initialization.
	 */
	uint8_t		isc_macaddr[IEEE80211_ADDR_LEN];
	int32_t		isc_fixed_rate;		/* index to ic_sup_rates[] */
	uint16_t	isc_rtsthreshold;
	uint16_t	isc_fragthreshold;
	uint16_t	isc_lintval;		/* listen interval */
	uint16_t	isc_txpower;		/* tx power setting (dbM) */
	int32_t		isc_des_esslen;
	uint8_t		isc_des_essid[IEEE80211_NWID_LEN];
	struct ieee80211channel *isc_des_chan;	/* desired channel */
	uint8_t		isc_des_bssid[IEEE80211_ADDR_LEN];
	struct ieee80211_wepkey isc_nw_keys[IEEE80211_WEP_NKID];
	int32_t		isc_wep_txkey;		/* default tx key index */
	uint8_t		isc_nickname[IEEE80211_NWID_LEN];
	int32_t		isc_nicknamelen;

	/* The following items are changed dynamically */
	kthread_t	*isc_mf_thread;
	uint32_t	isc_mfthread_switch;	/* 0/1 indicate off/on */
	kcondvar_t	isc_mfthread_cv;
	kcondvar_t	isc_scan_cv;
	int32_t		isc_mgt_timeout;	/* mgmt timeout */
	int32_t		isc_inact_timeout;	/* inactivity timer wait */
	uint8_t		isc_chan_active[
			    roundup(IEEE80211_CHAN_MAX, NBBY)];
	uint8_t		isc_chan_scan[
			    roundup(IEEE80211_CHAN_MAX, NBBY)];
	uint32_t	isc_flags;		/* state flags */
	uint16_t	isc_curmode;		/* current mode */
	enum ieee80211_opmode isc_opmode;	/* operation mode */
	enum ieee80211_state isc_state;		/* 802.11 state */
	struct ieee80211_node *isc_bss;		/* info for this node */
	struct ieee80211channel *isc_ibss_chan;	/* current channel */
	list_t		isc_in_list;		/* information of all nodes */
	list_t		isc_inhash_list[IEEE80211_NODE_HASHSIZE];
	uint32_t	isc_iv;			/* initial vector for wep */
	kmutex_t	isc_genlock;		/* mutex for the whole struct */
}ieee80211com_t;

#define	IEEE80211_SEND_MGMT(isc, in, type, arg)	do { \
if ((isc)->isc_send_mgmt[(type)>>IEEE80211_FC0_SUBTYPE_SHIFT] != NULL) \
	(*(isc)->isc_send_mgmt[(type)>>IEEE80211_FC0_SUBTYPE_SHIFT]) \
	    (isc, in, type, arg); \
_NOTE(CONSTANTCONDITION) \
} while (0)

#define	IEEE80211_ADDR_EQ(a1, a2)	(bcmp(a1, a2, IEEE80211_ADDR_LEN) == 0)
#define	IEEE80211_ADDR_COPY(dst, src)	bcopy(src, dst, IEEE80211_ADDR_LEN)

/* multicast, broadcast */
#define	ETHER_IS_MULTICAST(addr)	(*(addr) & 0x01)
#define	IEEE80211_IS_MULTICAST(a)	ETHER_IS_MULTICAST(a)

/* ic_flags */
#define	IEEE80211_F_ASCAN	0x00000001	/* STATUS: active scan */
#define	IEEE80211_F_SIBSS	0x00000002	/* STATUS: start IBSS */
#define	IEEE80211_F_WEPON	0x00000100	/* CONF: WEP enabled */
#define	IEEE80211_F_IBSSON	0x00000200	/* CONF: IBSS creation enable */
#define	IEEE80211_F_PMGTON	0x00000400	/* CONF: Power mgmt enable */
#define	IEEE80211_F_DESBSSID	0x00000800	/* CONF: des_bssid is set */
#define	IEEE80211_F_SCANAP	0x00001000	/* CONF: Scanning AP */
#define	IEEE80211_F_ROAMING	0x00002000	/* CONF: roaming enabled */
#define	IEEE80211_F_SWRETRY	0x00004000	/* CONF: sw tx retry enabled */
#define	IEEE80211_F_TXPMGT	0x00018000	/* STATUS: tx power */
#define	IEEE80211_F_TXPOW_OFF	0x00000000	/* TX Power: radio disabled */
#define	IEEE80211_F_TXPOW_FIXED	0x00008000	/* TX Power: fixed rate */
#define	IEEE80211_F_TXPOW_AUTO	0x00010000	/* TX Power: undefined */
#define	IEEE80211_F_SHSLOT	0x00020000	/* CONF: short slot time */
#define	IEEE80211_F_SHPREAMBLE	0x00040000	/* CONF: short preamble */

/* ic_capabilities */
#define	IEEE80211_C_WEP		0x00000001	/* CAPABILITY: WEP available */
#define	IEEE80211_C_IBSS	0x00000002	/* CAPABILITY: IBSS available */
#define	IEEE80211_C_PMGT	0x00000004	/* CAPABILITY: Power mgmt */
#define	IEEE80211_C_HOSTAP	0x00000008	/* CAPABILITY: HOSTAP avail */
#define	IEEE80211_C_AHDEMO	0x00000010	/* CAPABILITY: Old Adhoc Demo */
#define	IEEE80211_C_SWRETRY	0x00000020	/* CAPABILITY: sw tx retry */
#define	IEEE80211_C_TXPMGT	0x00000040	/* CAPABILITY: tx power mgmt */
#define	IEEE80211_C_SHSLOT	0x00000080	/* CAPABILITY: short slottime */
#define	IEEE80211_C_SHPREAMBLE	0x00000100	/* CAPABILITY: short preamble */

/* flags for ieee80211_fix_rate() */
#define	IEEE80211_F_DOSORT	0x00000001	/* sort rate list */
#define	IEEE80211_F_DOFRATE	0x00000002	/* use fixed rate */
#define	IEEE80211_F_DONEGO	0x00000004	/* calc negotiated rate */
#define	IEEE80211_F_DODEL	0x00000008	/* delete ignore rate */

int32_t ieee80211_ifattach(gld_mac_info_t *);
void ieee80211_ifdetach(gld_mac_info_t *);
void ieee80211_input(ieee80211com_t *, mblk_t *,
    int32_t, uint32_t, uint32_t);
int32_t	ieee80211_mgmt_output(ieee80211com_t *, struct ieee80211_node *,
    mblk_t *, int32_t);
mblk_t *ieee80211_fill_header(ieee80211com_t *isc, mblk_t *mp_gld,
    int32_t wep_txkey, struct ieee80211_node *in);
mblk_t *ieee80211_decap(mblk_t *);
extern const int8_t *ieee80211_essid_sprintf(uint8_t *, uint32_t);
void ieee80211_dump_pkt(uint8_t *, int32_t, int32_t, int32_t);
struct ieee80211_node *ieee80211_find_node(ieee80211com_t *, uint8_t *);
struct ieee80211_node *ieee80211_lookup_node(ieee80211com_t *,
    uint8_t *macaddr, struct ieee80211channel *);

/*
 * The following functions are almost the same, except that we should
 * already hold isc_genlock before calling _ieee80211_new_state.
 */
int ieee80211_new_state(ieee80211com_t *, enum ieee80211_state, int32_t);
int _ieee80211_new_state(ieee80211com_t *, enum ieee80211_state, int32_t);

uint32_t ieee80211_mhz2ieee(uint32_t, uint32_t);
uint32_t ieee80211_chan2ieee(ieee80211com_t *, struct ieee80211channel *);
uint32_t ieee80211_ieee2mhz(uint32_t, uint32_t);
enum ieee80211_phymode ieee80211_chan2mode(ieee80211com_t *,
    struct ieee80211channel *);
const int8_t *ieee80211_ether_sprintf(const uint8_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ATH_IEEE80211_H */
