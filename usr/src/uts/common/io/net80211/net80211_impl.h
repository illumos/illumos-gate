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

#ifndef _SYS_NET80211_IMPL_H
#define	_SYS_NET80211_IMPL_H

#include <sys/sysmacros.h>
#include <sys/list.h>
#include <sys/note.h>
#include <sys/net80211_proto.h>
#include <sys/net80211.h>
#include <sys/mac_wifi.h>

/*
 * IEEE802.11 kernel support module
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	IEEE80211_TXPOWER_MAX	100	/* .5 dbM */
#define	IEEE80211_TXPOWER_MIN	0	/* kill radio */

#define	IEEE80211_DTIM_MAX	15	/* max DTIM period */
#define	IEEE80211_DTIM_MIN	1	/* min DTIM period */
#define	IEEE80211_DTIM_DEFAULT	1	/* default DTIM period */

/* NB: min+max come from WiFi requirements */
#define	IEEE80211_BINTVAL_MAX	1000	/* max beacon interval (TU's) */
#define	IEEE80211_BINTVAL_MIN	25	/* min beacon interval (TU's) */
#define	IEEE80211_BINTVAL_DEFAULT 100	/* default beacon interval (TU's) */

#define	IEEE80211_BMISS_MAX	2	/* maximum consecutive bmiss allowed */
#define	IEEE80211_SWBMISS_THRESHOLD 50	/* s/w bmiss threshold (TU's) */
#define	IEEE80211_HWBMISS_DEFAULT 7	/* h/w bmiss threshold (beacons) */

#define	IEEE80211_PS_SLEEP	0x1	/* STA is in power saving mode */
#define	IEEE80211_PS_MAX_QUEUE	50	/* maximum saved packets */

#define	IEEE80211_RTS_DEFAULT	IEEE80211_RTS_MAX
#define	IEEE80211_FRAG_DEFAULT	IEEE80211_FRAG_MAX

/*
 * The RSSI values of two node are taken as almost the same when
 * the difference between these two node's RSSI values is within
 * IEEE80211_RSSI_CMP_THRESHOLD
 */
#define	IEEE80211_RSSI_CMP_THRESHOLD	5

/*
 * Each ieee80211com instance has a single timer that fires once a
 * second.  This is used to initiate various work depending on the
 * state of the instance: scanning (passive or active), ``transition''
 * (waiting for a response to a management frame when operating
 * as a station), and node inactivity processing (when operating
 * as an AP).  For inactivity processing each node has a timeout
 * set in it's in_inact field that is decremented on each timeout
 * and the node is reclaimed when the counter goes to zero.  We
 * use different inactivity timeout values depending on whether
 * the node is associated and authorized (either by 802.1x or
 * open/shared key authentication) or associated but yet to be
 * authorized.  The latter timeout is shorter to more aggressively
 * reclaim nodes that leave part way through the 802.1x exchange.
 *
 * IEEE80211_INACT_WAIT defines node table's inactivity interval in
 * seconds. On timeout, node table's registered nt_timeout callback
 * function is executed. Each node in the node table has a timeout
 * set in its in_inact field with IEEE80211_INACT_<state>. In
 * nt_timeout function, node table is iterated and each node's
 * in_inact is decremented. So IEEE80211_INACT_<state> is defined in
 * the form [inact_sec]/IEEE80211_INACT_WAIT.
 *
 */
#define	IEEE80211_INACT_WAIT	15	/* inactivity interval (secs) */
#define	IEEE80211_INACT_INIT	(30/IEEE80211_INACT_WAIT)	/* initial */
#define	IEEE80211_INACT_ASSOC	(180/IEEE80211_INACT_WAIT)
					/* associated but not authorized */
#define	IEEE80211_INACT_RUN	(300/IEEE80211_INACT_WAIT)	/* authorized */
#define	IEEE80211_INACT_PROBE	(30/IEEE80211_INACT_WAIT)	/* probe */
#define	IEEE80211_INACT_SCAN	(300/IEEE80211_INACT_WAIT)	/* scanned */

#define	IEEE80211_TRANS_WAIT 	5	/* mgt frame tx timer (secs) */

/*
 * Useful combinations of channel characteristics.
 */
#define	IEEE80211_CHAN_FHSS	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define	IEEE80211_CHAN_A	\
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_B	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define	IEEE80211_CHAN_PUREG	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define	IEEE80211_CHAN_G	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)
#define	IEEE80211_CHAN_T	\
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_108G	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_TURBO)
#define	IEEE80211_CHAN_ST	\
	(IEEE80211_CHAN_T | IEEE80211_CHAN_STURBO)

#define	IEEE80211_CHAN_ALL	\
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_GFSK | \
	IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM | IEEE80211_CHAN_DYN |	\
	IEEE80211_CHAN_HT)
#define	IEEE80211_CHAN_ALLTURBO	\
	(IEEE80211_CHAN_ALL | IEEE80211_CHAN_TURBO | IEEE80211_CHAN_STURBO)

#define	IEEE80211_IS_CHAN_FHSS(_c)	\
	(((_c)->ich_flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define	IEEE80211_IS_CHAN_A(_c)		\
	(((_c)->ich_flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define	IEEE80211_IS_CHAN_B(_c)		\
	(((_c)->ich_flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define	IEEE80211_IS_CHAN_PUREG(_c)	\
	(((_c)->ich_flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define	IEEE80211_IS_CHAN_G(_c)		\
	(((_c)->ich_flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define	IEEE80211_IS_CHAN_ANYG(_c)	\
	(IEEE80211_IS_CHAN_PUREG(_c) || IEEE80211_IS_CHAN_G(_c))
#define	IEEE80211_IS_CHAN_T(_c)		\
	(((_c)->ich_flags & IEEE80211_CHAN_T) == IEEE80211_CHAN_T)
		/* IEEE80211_IS_CHAN_108A */
#define	IEEE80211_IS_CHAN_108G(_c)	\
	(((_c)->ich_flags & IEEE80211_CHAN_108G) == IEEE80211_CHAN_108G)
#define	IEEE80211_IS_CHAN_ST(_c)	\
	(((_c)->ich_flags & IEEE80211_CHAN_ST) == IEEE80211_CHAN_ST)

#define	IEEE80211_IS_CHAN_OFDM(_c)	\
	((_c)->ich_flags & IEEE80211_CHAN_OFDM)
#define	IEEE80211_IS_CHAN_CCK(_c)	\
	((_c)->ich_flags & IEEE80211_CHAN_CCK)
#define	IEEE80211_IS_CHAN_GFSK(_c)	\
	((_c)->ich_flags & IEEE80211_CHAN_GFSK)
#define	IEEE80211_IS_CHAN_PASSIVE(_c)	\
	((_c)->ich_flags & IEEE80211_CHAN_PASSIVE)

#define	IEEE80211_IS_CHAN_STURBO(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_STURBO)
#define	IEEE80211_IS_CHAN_DTURBO(_c) \
	(((_c)->ich_flags & \
	(IEEE80211_CHAN_TURBO | IEEE80211_CHAN_STURBO)) == IEEE80211_CHAN_TURBO)
#define	IEEE80211_IS_CHAN_HALF(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_HALF)
#define	IEEE80211_IS_CHAN_QUARTER(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_QUARTER)
#define	IEEE80211_IS_CHAN_FULL(_c) \
	((_c)->ich_flags & (IEEE80211_CHAN_QUARTER | IEEE80211_CHAN_HALF))
#define	IEEE80211_IS_CHAN_GSM(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_GSM)

#define	IEEE80211_IS_CHAN_HT(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_HT)
#define	IEEE80211_IS_CHAN_HT20(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_HT20)
#define	IEEE80211_IS_CHAN_HT40(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_HT40)
#define	IEEE80211_IS_CHAN_HT40U(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_HT40U)
#define	IEEE80211_IS_CHAN_HT40D(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_HT40D)
#define	IEEE80211_IS_CHAN_HTA(_c) \
	(IEEE80211_IS_CHAN_5GHZ(_c) && \
	((_c)->ich_flags & IEEE80211_CHAN_HT))
#define	IEEE80211_IS_CHAN_HTG(_c) \
	(IEEE80211_IS_CHAN_2GHZ(_c) && \
	((_c)->ich_flags & IEEE80211_CHAN_HT))
#define	IEEE80211_IS_CHAN_DFS(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_DFS)
#define	IEEE80211_IS_CHAN_NOADHOC(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_NOADHOC)
#define	IEEE80211_IS_CHAN_NOHOSTAP(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_NOHOSTAP)
#define	IEEE80211_IS_CHAN_11D(_c) \
	((_c)->ich_flags & IEEE80211_CHAN_11D)

/* ni_chan encoding for FH phy */
#define	IEEE80211_FH_CHANMOD	80
#define	IEEE80211_FH_CHAN(set, pat)	\
	(((set) - 1) * IEEE80211_FH_CHANMOD + (pat))
#define	IEEE80211_FH_CHANSET(chan)	\
	((chan) / IEEE80211_FH_CHANMOD + 1)
#define	IEEE80211_FH_CHANPAT(chan)	\
	((chan) % IEEE80211_FH_CHANMOD)

#define	IEEE80211_NODE_AUTH	0x0001		/* authorized for data */
#define	IEEE80211_NODE_QOS	0x0002		/* QoS enabled */
#define	IEEE80211_NODE_ERP	0x0004		/* ERP enabled */
#define	IEEE80211_NODE_PWR_MGT	0x0010		/* power save mode enabled */
#define	IEEE80211_NODE_AREF	0x0020		/* authentication ref held */

#define	IEEE80211_MAXRSSI	127

/* Debug Flags */
#define	IEEE80211_MSG_BRUSSELS  0x80000000	/* BRUSSELS */
#define	IEEE80211_MSG_DEBUG	0x40000000	/* IFF_DEBUG equivalent */
#define	IEEE80211_MSG_DUMPPKTS	0x20000000	/* IFF_LINK2 equivalant */
#define	IEEE80211_MSG_CRYPTO	0x10000000	/* crypto work */
#define	IEEE80211_MSG_INPUT	0x08000000	/* input handling */
#define	IEEE80211_MSG_XRATE	0x04000000	/* rate set handling */
#define	IEEE80211_MSG_ELEMID	0x02000000	/* element id parsing */
#define	IEEE80211_MSG_NODE	0x01000000	/* node handling */
#define	IEEE80211_MSG_ASSOC	0x00800000	/* association handling */
#define	IEEE80211_MSG_AUTH	0x00400000	/* authentication handling */
#define	IEEE80211_MSG_SCAN	0x00200000	/* scanning */
#define	IEEE80211_MSG_OUTPUT	0x00100000	/* output handling */
#define	IEEE80211_MSG_STATE	0x00080000	/* state machine */
#define	IEEE80211_MSG_POWER	0x00040000	/* power save handling */
#define	IEEE80211_MSG_DOT1X	0x00020000	/* 802.1x authenticator */
#define	IEEE80211_MSG_DOT1XSM	0x00010000	/* 802.1x state machine */
#define	IEEE80211_MSG_RADIUS	0x00008000	/* 802.1x radius client */
#define	IEEE80211_MSG_RADDUMP	0x00004000	/* dump 802.1x radius packets */
#define	IEEE80211_MSG_RADKEYS	0x00002000	/* dump 802.1x keys */
#define	IEEE80211_MSG_WPA	0x00001000	/* WPA/RSN protocol */
#define	IEEE80211_MSG_ACL	0x00000800	/* ACL handling */
#define	IEEE80211_MSG_WME	0x00000400	/* WME protocol */
#define	IEEE80211_MSG_SUPERG	0x00000200	/* Atheros SuperG protocol */
#define	IEEE80211_MSG_DOTH	0x00000100	/* 802.11h support */
#define	IEEE80211_MSG_INACT	0x00000080	/* inactivity handling */
#define	IEEE80211_MSG_ROAM	0x00000040	/* sta-mode roaming */
#define	IEEE80211_MSG_CONFIG	0x00000020	/* wificonfig/dladm */
#define	IEEE80211_MSG_ACTION	0x00000010	/* action frame handling */
#define	IEEE80211_MSG_HT	0x00000008	/* 11n mode debug */
#define	IEEE80211_MSG_ANY	0xffffffff	/* anything */

/* Error flags returned by ieee80211_match_bss */
#define	IEEE80211_BADCHAN	0x01
#define	IEEE80211_BADOPMODE	0x02
#define	IEEE80211_BADPRIVACY	0x04
#define	IEEE80211_BADRATE	0x08
#define	IEEE80211_BADESSID	0x10
#define	IEEE80211_BADBSSID	0x20
#define	IEEE80211_NODEFAIL	0x40

typedef struct ieee80211_impl {
	struct ieee80211com	*ic;
	uint8_t			im_chan_avail[IEEE80211_CHAN_BYTES];
	uint8_t			im_chan_scan[IEEE80211_CHAN_BYTES];

	uint8_t			im_bmiss_count;	/* current beacon miss count */
	int32_t			im_bmiss_max;	/* max bmiss before scan */
	timeout_id_t		im_swbmiss;
	uint16_t		im_swbmiss_count; /* beacons in last period */
	uint16_t		im_swbmiss_period;	/* s/w bmiss period */

	int32_t			im_mgt_timer;	/* mgmt timeout, secs */
	int32_t			im_inact_timer;	/* inactivity timer wait, sec */
	int32_t			im_inact_init;	/* initial setting */
	int32_t			im_inact_assoc;	/* assoc but not authorized */
	int32_t			im_inact_run;	/* authorized setting */
	int32_t			im_inact_probe;	/* inactive probe time */

	kcondvar_t		im_scan_cv;	/* wait scan complete */
} ieee80211_impl_t;

/*
 * Parameters supplied when adding/updating an entry in a
 * scan cache.  Pointer variables should be set to NULL
 * if no data is available.  Pointer references can be to
 * local data; any information that is saved will be copied.
 * All multi-byte values must be in host byte order.
 */
struct ieee80211_scanparams {
	uint16_t		capinfo;	/* 802.11 capabilities */
	enum ieee80211_phytype	phytype;
	uint16_t		fhdwell;	/* FHSS dwell interval */
	uint8_t			chan;
	uint8_t			bchan;
	uint8_t			fhindex;
	uint8_t			erp;
	uint16_t		bintval;
	uint8_t			timoff;
	uint8_t			*tim;
	uint8_t			*tstamp;
	uint8_t			*country;
	uint8_t			*ssid;
	uint8_t			*rates;
	uint8_t			*xrates;
	uint8_t			*wpa;
	uint8_t			*wme;
	uint8_t			*htcap;
	uint8_t			*htinfo;
};

#define	IEEE80211_SEND_MGMT(_ic, _in, _type, _arg)			\
	((*(_ic)->ic_send_mgmt)((_ic), (_in), (_type), (_arg)))

/* Verify the existence and length of __elem or get out. */
#define	IEEE80211_VERIFY_ELEMENT(__elem, __maxlen, __func) do {		\
	_NOTE(CONSTCOND)						\
	if ((__elem) == NULL) {						\
		ieee80211_err("ieee80211: no #__elem \n");		\
		__func;							\
	}								\
	if ((__elem)[1] > (__maxlen)) {					\
		ieee80211_err("ieee80211: bad "#__elem " len %d\n",	\
		    (__elem)[1]);					\
		__func;							\
	}								\
	_NOTE(CONSTCOND)						\
} while (0)

#define	IEEE80211_VERIFY_LENGTH(_len, _minlen, _func) do {		\
	_NOTE(CONSTCOND)						\
	if ((_len) < (_minlen)) {					\
		ieee80211_dbg(IEEE80211_MSG_ELEMID,			\
		    "ie of type %s too short",				\
		    ieee80211_mgt_subtype_name[subtype >>		\
			IEEE80211_FC0_SUBTYPE_SHIFT]);			\
		_func;							\
	}								\
	_NOTE(CONSTCOND)						\
} while (0)

#define	IEEE80211_VERIFY_SSID(_in, _ssid, _func) do {			\
	_NOTE(CONSTCOND)						\
	ASSERT((_in) != NULL);						\
	if ((_ssid)[1] != 0 &&						\
	    ((_ssid)[1] != (_in)->in_esslen ||				\
	    bcmp((_ssid) + 2, (_in)->in_essid, (_ssid)[1]) != 0)) {	\
		_func;							\
	}								\
	_NOTE(CONSTCOND)						\
} while (0)

#define	ieee80211_setbit(a, i)	((a)[(i)/NBBY] |= (1 << ((i)%NBBY)))
#define	ieee80211_clrbit(a, i)	((a)[(i)/NBBY] &= ~(1 << ((i)%NBBY)))
#define	ieee80211_isset(a, i)	((a)[(i)/NBBY] & (1 << ((i)%NBBY)))
#define	ieee80211_isclr(a, i)	(!((a)[(i)/NBBY] & (1 << ((i)%NBBY))))

#define	IEEE80211_N(a)		(sizeof (a) / sizeof (a[0]))

#define	IEEE80211_LOCK(_ic)		\
	mutex_enter(&(_ic)->ic_genlock)
#define	IEEE80211_UNLOCK(_ic)		\
	mutex_exit(&(_ic)->ic_genlock)
#define	IEEE80211_IS_LOCKED(_ic)	\
	mutex_owned(&(_ic)->ic_genlock)
#define	IEEE80211_LOCK_ASSERT(_ic)	\
	ASSERT(mutex_owned(&(_ic)->ic_genlock))

#define	IEEE80211_NODE_LOCK(_nt)		\
	mutex_enter(&(_nt)->nt_nodelock)
#define	IEEE80211_NODE_UNLOCK(_nt)		\
	mutex_exit(&(_nt)->nt_nodelock)
#define	IEEE80211_NODE_IS_LOCKED(_nt)		\
	mutex_owned(&(_nt)->nt_nodelock)
#define	IEEE80211_NODE_LOCK_ASSERT(_nt)		\
	ASSERT(mutex_owned(&(_nt)->nt_nodelock))
#define	ieee80211_node_hash(addr)		\
	(((uint8_t *)(addr))[IEEE80211_ADDR_LEN - 1] % IEEE80211_NODE_HASHSIZE)

#define	IEEE80211_SCAN_LOCK(_nt)	mutex_enter(&(_nt)->nt_scanlock)
#define	IEEE80211_SCAN_UNLOCK(_nt)	mutex_exit(&(_nt)->nt_scanlock)

#define	IEEE80211_RV(v)			((v) & IEEE80211_RATE_VAL)

#define	IEEE80211_SUBTYPE_NAME(subtype)		\
	ieee80211_mgt_subtype_name[(subtype) >> IEEE80211_FC0_SUBTYPE_SHIFT]

extern const char *ieee80211_mgt_subtype_name[];
extern const char *ieee80211_phymode_name[];

void ieee80211_err(const int8_t *, ...);
void ieee80211_dbg(uint32_t, const int8_t *, ...);

void ieee80211_notify(ieee80211com_t *, wpa_event_type);
void ieee80211_mac_update(ieee80211com_t *);

uint64_t ieee80211_read_6(uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t);

/* node */
void ieee80211_node_attach(ieee80211com_t *);
void ieee80211_node_lateattach(ieee80211com_t *);
void ieee80211_node_detach(ieee80211com_t *);
void ieee80211_reset_bss(ieee80211com_t *);
void ieee80211_cancel_scan(ieee80211com_t *);
void ieee80211_add_scan(ieee80211com_t *, const struct ieee80211_scanparams *,
    const struct ieee80211_frame *, int, int, int);
void ieee80211_init_neighbor(ieee80211_node_t *, const struct ieee80211_frame *,
    const struct ieee80211_scanparams *);
ieee80211_node_t *ieee80211_add_neighbor(ieee80211com_t *,
    const struct ieee80211_frame *, const struct ieee80211_scanparams *);
void ieee80211_create_ibss(ieee80211com_t *, struct ieee80211_channel *);
ieee80211_node_t *ieee80211_fakeup_adhoc_node(ieee80211_node_table_t *,
    const uint8_t *);
ieee80211_node_t *ieee80211_tmp_node(ieee80211com_t *, const uint8_t *);
void ieee80211_setcurchan(ieee80211com_t *, struct ieee80211_channel *);

/* proto */
void ieee80211_proto_attach(ieee80211com_t *);
int ieee80211_fix_rate(ieee80211_node_t *, struct ieee80211_rateset *, int);
void ieee80211_setbasicrates(struct ieee80211_rateset *,
    enum ieee80211_phymode);
void ieee80211_reset_erp(ieee80211com_t *);
void ieee80211_set_shortslottime(ieee80211com_t *, boolean_t);

/* input */
int ieee80211_setup_rates(ieee80211_node_t *, const uint8_t *,
    const uint8_t *, int);
void ieee80211_recv_mgmt(ieee80211com_t *, mblk_t *, ieee80211_node_t *,
    int, int, uint32_t);

/* output */
int ieee80211_send_probereq(ieee80211_node_t *, const uint8_t *,
    const uint8_t *, const uint8_t *, const uint8_t *, size_t, const void *,
    size_t);
int ieee80211_send_mgmt(ieee80211com_t *, ieee80211_node_t *, int, int);
int ieee80211_send_nulldata(ieee80211_node_t *);
int ieee80211_mgmt_output(ieee80211com_t *, ieee80211_node_t *, mblk_t *,
    int, int);

/* crypto */
struct ieee80211_key *ieee80211_crypto_getkey(ieee80211com_t *);
uint8_t ieee80211_crypto_getciphertype(ieee80211com_t *);

/* generic */
mblk_t *ieee80211_getmgtframe(uint8_t **, int);
void ieee80211_notify_node_join(ieee80211com_t *, ieee80211_node_t *);
void ieee80211_notify_node_leave(ieee80211com_t *, ieee80211_node_t *);

/* WME */
void	ieee80211_wme_initparams(struct ieee80211com *);
void	ieee80211_wme_updateparams(struct ieee80211com *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NET80211_IMPL_H */
