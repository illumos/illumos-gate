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

#ifndef	_SYS_MAC_WIFI_H
#define	_SYS_MAC_WIFI_H

/*
 * WiFi MAC-Type Plugin
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/net80211_proto.h>

#ifdef	_KERNEL

#define	MAC_PLUGIN_IDENT_WIFI	"mac_wifi"

/*
 * Maximum size of a WiFi header based on current implementation.
 * May change in the future as new features are added.
 */
#define	WIFI_HDRSIZE (sizeof (struct ieee80211_qosframe_addr4) + \
    IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN + IEEE80211_WEP_EXTIVLEN + \
    sizeof (struct ieee80211_llc))

enum wifi_stat {
	/* statistics described in ieee802.11(5) */
	WIFI_STAT_TX_FRAGS = MACTYPE_STAT_MIN,
	WIFI_STAT_MCAST_TX,
	WIFI_STAT_TX_FAILED,
	WIFI_STAT_TX_RETRANS,
	WIFI_STAT_TX_RERETRANS,
	WIFI_STAT_RTS_SUCCESS,
	WIFI_STAT_RTS_FAILURE,
	WIFI_STAT_ACK_FAILURE,
	WIFI_STAT_RX_FRAGS,
	WIFI_STAT_MCAST_RX,
	WIFI_STAT_FCS_ERRORS,
	WIFI_STAT_WEP_ERRORS,
	WIFI_STAT_RX_DUPS
};

/*
 * WiFi security modes recognized by the plugin.
 */
enum wifi_secmode {
	WIFI_SEC_NONE,
	WIFI_SEC_WEP,
	WIFI_SEC_WPA
};

/*
 * WiFi data passed between the drivers and the plugin.
 *
 * Field definitions:
 *
 *	wd_opts		Currently set to 0. If new features require the
 * 			introduction of new wifi_data_t fields, then the
 *			presence of those fields must be indicated to the
 *			plugin via wd_opts flags.  This allows the drivers
 *			and the plugin to evolve independently.
 *
 *	wd_bssid	Current associated BSSID (or IBSSID), used when
 *			generating data packet headers for transmission.
 *
 *	wd_opmode	Current operation mode; any ieee80211_opmode is
 *			supported.
 *
 *	wd_secalloc	Current allocation policy for security-related
 *			WiFi headers, used when generating packets for
 *			transmission.  The plugin will allocate header
 *		        space for the security portion, and fill in any
 *			fixed-contents fields.
 *
 *	wd_qospad	Generally, QoS data field takes 2 bytes, but
 *			some special hardwares, such as Atheros, will need the
 *			802.11 header padded to a 32-bit boundary for 4-address
 *			and QoS frames, at this time, it's 4 bytes.
 */
typedef struct wifi_data {
	uint_t			wd_opts;
	uint8_t			wd_bssid[IEEE80211_ADDR_LEN];
	enum ieee80211_opmode	wd_opmode;
	enum wifi_secmode	wd_secalloc;
	uint_t			wd_qospad;
} wifi_data_t;

extern uint8_t wifi_bcastaddr[];

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAC_WIFI_H */
