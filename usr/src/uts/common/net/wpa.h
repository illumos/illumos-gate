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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Macro and data structures defined for 802.11i.
 */

#ifndef	__WPA_H
#define	__WPA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <inet/wifi_ioctl.h>
#include <sys/net80211_crypto.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SERVICE_NAME		"network/wpa"
#define	WPA_DOOR 		"/var/run/wpa_door"
#define	SVC_METHOD		"/usr/lib/inet/wpad"

/*
 * Parameters.
 */
#define	WL_WPA_BASE		(WL_PARAMETERS_BASE + 0x500)
#define	WL_SETOPTIE		(WL_WPA_BASE + 0x0)
#define	WL_WPA			(WL_WPA_BASE + 0x2)
#define	WL_KEY			(WL_WPA_BASE + 0x3)
#define	WL_DELKEY		(WL_WPA_BASE + 0x4)
#define	WL_SCANRESULTS		(WL_WPA_BASE + 0x7)
#define	WL_MLME			(WL_WPA_BASE + 0x8)
#define	WL_CAPABILITY		(WL_WPA_BASE + 0x9)

typedef struct wl_wpa_ie {
	uint32_t	wpa_ie_len;
	char		wpa_ie[1];	/* it's the head of wpa_ie */
} wl_wpa_ie_t;

typedef struct wl_wpa {
	uint32_t	wpa_flag;
} wl_wpa_t;

typedef struct wl_capability {
	uint32_t	caps;
} wl_capability_t;

/*
 * WPA/RSN get/set key request.
 * ik_type  : wep/tkip/aes
 * ik_keyix : should be between 0 and 3, 0 will be used as default key.
 * ik_keylen: key length in bytes.
 * ik_keydata and ik_keylen include the DATA key and MIC key.
 * ik_keyrsc/ik_keytsc: rx/tx seq number.
 */
#pragma pack(1)
typedef struct wl_key {
	uint8_t		ik_type;
	uint8_t		ik_pad;

	uint16_t	ik_keyix;
	uint8_t		ik_keylen;
	uint8_t		ik_flags;

	uint8_t		ik_macaddr[IEEE80211_ADDR_LEN];
	uint64_t	ik_keyrsc;
	uint64_t	ik_keytsc;

	uint8_t ik_keydata[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
} wl_key_t;
#pragma pack()

typedef struct wl_del_key {
	uint8_t		idk_keyix;
	uint8_t		idk_macaddr[IEEE80211_ADDR_LEN];
} wl_del_key_t;

struct wpa_ess {
	uint8_t		bssid[IEEE80211_ADDR_LEN];
	uint8_t		ssid[MAX_ESSID_LENGTH];
	uint32_t	ssid_len;

	uint8_t		wpa_ie[IEEE80211_MAX_WPA_IE];
	uint32_t	wpa_ie_len;
	int		freq;
};

typedef struct wl_wpa_ess {
	uint32_t	count;
	struct wpa_ess	ess[1];
} wl_wpa_ess_t;

/*
 * structure for WL_MLME state manipulation request.
 * im_op: operations include auth/deauth/assoc/disassoc,
 * im_reason: 802.11 reason code
 */
typedef struct wl_mlme {
	uint8_t		im_op;
	uint16_t	im_reason;
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
