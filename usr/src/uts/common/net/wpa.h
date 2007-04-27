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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Macro and data structures defined for 802.11i.
 */

#ifndef	__WPA_H
#define	__WPA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <inet/wifi_ioctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SERVICE_NAME			"network/wpa"
#define	WPA_DOOR 			"/var/run/wpa_door"
#define	SVC_METHOD			"/usr/lib/inet/wpad"

#define	IEEE80211_ADDR_LEN		6
#define	IEEE80211_MAX_WPA_IE		40	/* IEEE802.11i */
#define	WPA_STRSIZE			256
/*
 * Max size of optional information elements.  We artificially
 * constrain this; it's limited only by the max frame size (and
 * the max parameter size of the wireless extensions).
 */
#define	IEEE80211_MAX_OPT_IE		256

/*
 * Parameters.
 * WL_WPA_BASE + 0x1, 5, 6 reserved to be compatible with FreeBSD.
 */
#define	WL_WPA_BASE			(WL_PARAMETERS_BASE + 0x500)
#define	WL_SETOPTIE			(WL_WPA_BASE + 0x0)
#define	WL_WPA				(WL_WPA_BASE + 0x2)
#define	WL_KEY				(WL_WPA_BASE + 0x3)
#define	WL_DELKEY			(WL_WPA_BASE + 0x4)
#define	WL_SCANRESULTS			(WL_WPA_BASE + 0x7)
#define	WL_MLME				(WL_WPA_BASE + 0x8)
#define	WL_CAPABILITY			(WL_WPA_BASE + 0x9)

typedef struct wl_wpa_ie {
    uint32_t	wpa_ie_len;
    char 	wpa_ie[1];	/* it's the head of wpa_ie */
} wl_wpa_ie_t;

typedef struct wl_wpa {
    uint32_t	wpa_flag;
} wl_wpa_t;

typedef struct wl_capability {
    uint32_t	caps;
} wl_capability_t;

#define	IEEE80211_KEYBUF_SIZE		16	/* 128-bit TKIP & CCMP key */
#define	IEEE80211_MICBUF_SIZE		(8+8)	/* 8 byte tx, 8 byte rx */

/*
 * NB: these values are ordered carefully; there are lots of
 * of implications in any reordering.  In particular beware
 * that 4 is not used to avoid conflicting with IEEE80211_F_PRIVACY.
 */
#define	IEEE80211_CIPHER_WEP		0
#define	IEEE80211_CIPHER_TKIP		1
#define	IEEE80211_CIPHER_AES_OCB	2
#define	IEEE80211_CIPHER_AES_CCM	3
#define	IEEE80211_CIPHER_CKIP		4
#define	IEEE80211_CIPHER_NONE		5	/* pseudo value */

#define	IEEE80211_CIPHER_MAX		(IEEE80211_CIPHER_NONE+1)

/* Key Flags */
#define	IEEE80211_KEY_XMIT		0x01	/* key used for xmit */
#define	IEEE80211_KEY_RECV		0x02	/* key used for recv */

#define	IEEE80211_KEY_DEFAULT		0x80	/* default xmit key */

/*
 * WPA/RSN get/set key request.  Specify the key/cipher
 * type and whether the key is to be used for sending and/or
 * receiving.  The key index should be set only when working
 * with global keys (use IEEE80211_KEYIX_NONE for ``no index'').
 * Otherwise a unicast/pairwise key is specified by the bssid
 * (on a station) or mac address (on an ap).  They key length
 * must include any MIC key data; otherwise it should be no
 * more than IEEE80211_KEYBUF_SIZE.
 */
#pragma pack(1)
typedef struct wl_key {
	uint8_t		ik_type;	/* key/cipher type */
	uint8_t		ik_pad;

	uint16_t	ik_keyix;	/* key index */
	uint8_t		ik_keylen;	/* key length in bytes */
	uint8_t		ik_flags;

	uint8_t		ik_macaddr[IEEE80211_ADDR_LEN];
	uint64_t	ik_keyrsc;	/* key receive sequence counter */
	uint64_t	ik_keytsc;	/* key transmit sequence counter */

	uint8_t ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
} wl_key_t;
#pragma pack()

struct wpa_ess {
	uint8_t		bssid[IEEE80211_ADDR_LEN];
	uint8_t		ssid[MAX_ESSID_LENGTH];
	uint32_t	ssid_len;

	uint8_t		wpa_ie[IEEE80211_MAX_WPA_IE];
	uint32_t	wpa_ie_len;
	int		freq;
};

typedef struct wl_del_key {
	uint8_t		idk_keyix;	/* key index */
	uint8_t		idk_macaddr[IEEE80211_ADDR_LEN];
}wl_del_key_t;

typedef struct wl_countermeasures {
	uint32_t	cm_flag;
} wl_countermeasures_t;

typedef struct wl_drop_unenc {
	uint32_t	drop_flag;
} wl_drop_unenc_t;

typedef struct wl_wpa_ess {
	uint32_t	count;
	struct wpa_ess	ess[1];
} wl_wpa_ess_t;

#define	IEEE80211_MLME_ASSOC		1	/* associate station */
#define	IEEE80211_MLME_DISASSOC		2	/* disassociate station */
#define	IEEE80211_MLME_DEAUTH		3	/* deauthenticate station */
#define	IEEE80211_MLME_AUTHORIZE	4	/* authorize station */
#define	IEEE80211_MLME_UNAUTHORIZE	5	/* unauthorize station */

/*
 *  * MLME state manipulation request.  IEEE80211_MLME_ASSOC
 *   * only makes sense when operating as a station.  The other
 *    * requests can be used when operating as a station or an
 *     * ap (to effect a station).
 */
typedef struct wl_mlme {
	uint8_t		im_op;		/* operation to perform */
	uint16_t	im_reason;	/* 802.11 reason code */
	uint8_t		im_macaddr[IEEE80211_ADDR_LEN];
} wl_mlme_t;

/*
 * State machine events
 */
typedef enum {
	EVENT_ASSOC,
	EVENT_DISASSOC,
	EVENT_SCAN_RESULTS
} wpa_event_type;

typedef struct  wl_events {
	wpa_event_type	event;
} wl_events_t;

#ifdef __cplusplus
}
#endif

#endif /* __WPA_H */
