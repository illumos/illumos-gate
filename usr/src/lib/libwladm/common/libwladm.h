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

#ifndef _LIBWLADM_H
#define	_LIBWLADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

/*
 * General libwladm definitions and functions.
 *
 * These interfaces are ON consolidation-private.
 * For documentation, refer to PSARC/2006/623.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	WLADM_MAX_ESSID_LEN		32	/* per 802.11 spec */
#define	WLADM_BSSID_LEN			6	/* per 802.11 spec */
#define	WLADM_STRSIZE			256

#define	WLADM_CONNECT_TIMEOUT_DEFAULT	10
#define	WLADM_OPT_CREATEIBSS		0x00000001
#define	WLADM_OPT_NOSCAN		0x00000002

typedef struct wladm_essid {
	char	we_bytes[WLADM_MAX_ESSID_LEN];
} wladm_essid_t;

typedef struct wladm_bssid {
	uint8_t	wb_bytes[WLADM_BSSID_LEN];
} wladm_bssid_t;

typedef enum {
	WLADM_SECMODE_NONE = 1,
	WLADM_SECMODE_WEP
} wladm_secmode_t;

typedef enum {
	WLADM_STRENGTH_VERY_WEAK = 1,
	WLADM_STRENGTH_WEAK,
	WLADM_STRENGTH_GOOD,
	WLADM_STRENGTH_VERY_GOOD,
	WLADM_STRENGTH_EXCELLENT
} wladm_strength_t;

typedef enum {
	WLADM_MODE_NONE = 0,
	WLADM_MODE_80211A,
	WLADM_MODE_80211B,
	WLADM_MODE_80211G
} wladm_mode_t;

typedef enum {
	WLADM_AUTH_OPEN = 1,
	WLADM_AUTH_SHARED
} wladm_auth_t;

typedef enum {
	WLADM_BSSTYPE_BSS = 1,
	WLADM_BSSTYPE_IBSS,
	WLADM_BSSTYPE_ANY
} wladm_bsstype_t;

typedef enum {
	WLADM_LINK_STATUS_DISCONNECTED = 1,
	WLADM_LINK_STATUS_CONNECTED
} wladm_linkstatus_t;

typedef enum {
	WLADM_STATUS_OK = 0,
	WLADM_STATUS_BADARG,
	WLADM_STATUS_FAILED,
	WLADM_STATUS_NOTSUP,
	WLADM_STATUS_ISCONN,
	WLADM_STATUS_NOTCONN,
	WLADM_STATUS_NOTFOUND,
	WLADM_STATUS_BADVAL,
	WLADM_STATUS_LINKINVAL,
	WLADM_STATUS_NOMEM,
	WLADM_STATUS_TIMEDOUT,
	WLADM_STATUS_PROPRDONLY,
	WLADM_STATUS_TOOSMALL,
	WLADM_STATUS_BADVALCNT
} wladm_status_t;

typedef uint32_t wladm_speed_t;
typedef	uint32_t wladm_channel_t;

enum {
	WLADM_WLAN_ATTR_ESSID	= 0x00000001,
	WLADM_WLAN_ATTR_BSSID	= 0x00000002,
	WLADM_WLAN_ATTR_SECMODE	= 0x00000004,
	WLADM_WLAN_ATTR_STRENGTH = 0x00000008,
	WLADM_WLAN_ATTR_MODE	= 0x00000010,
	WLADM_WLAN_ATTR_SPEED	= 0x00000020,
	WLADM_WLAN_ATTR_AUTH	= 0x00000040,
	WLADM_WLAN_ATTR_BSSTYPE	= 0x00000080,
	WLADM_WLAN_ATTR_CHANNEL	= 0x00000100
};
typedef struct wladm_wlan_attr {
	uint_t			wa_valid;
	wladm_essid_t		wa_essid;
	wladm_bssid_t		wa_bssid;
	wladm_secmode_t		wa_secmode;
	wladm_strength_t	wa_strength;
	wladm_mode_t		wa_mode;
	wladm_speed_t		wa_speed;
	wladm_auth_t		wa_auth;
	wladm_bsstype_t		wa_bsstype;
	wladm_channel_t		wa_channel;
} wladm_wlan_attr_t;

enum {
	WLADM_LINK_ATTR_STATUS	= 0x00000001,
	WLADM_LINK_ATTR_WLAN	= 0x00000002
};
typedef struct wladm_link_attr {
	uint_t			la_valid;
	wladm_linkstatus_t	la_status;
	wladm_wlan_attr_t	la_wlan_attr;
} wladm_link_attr_t;

#define	WLADM_WEPKEY64_LEN		5 	/* per WEP spec */
#define	WLADM_WEPKEY128_LEN		13 	/* per WEP spec */
#define	WLADM_MAX_WEPKEY_LEN		13	/* per WEP spec */
#define	WLADM_MAX_WEPKEYS		4 	/* MAX_NWEPKEYS */
#define	WLADM_MAX_WEPKEYNAME_LEN	64
typedef struct wladm_wep_key {
	uint_t		wk_idx;
	uint_t		wk_len;
	uint8_t		wk_val[WLADM_MAX_WEPKEY_LEN];
	char		wk_name[WLADM_MAX_WEPKEYNAME_LEN];
} wladm_wep_key_t;

typedef enum {
	WLADM_PROP_VAL_CURRENT = 1,
	WLADM_PROP_VAL_DEFAULT,
	WLADM_PROP_VAL_MODIFIABLE
} wladm_prop_type_t;

extern wladm_status_t	wladm_scan(const char *, void *,
			    boolean_t (*)(void *, wladm_wlan_attr_t *));
extern wladm_status_t	wladm_connect(const char *, wladm_wlan_attr_t *,
			    int, void *, uint_t, uint_t);
extern wladm_status_t	wladm_disconnect(const char *);
extern wladm_status_t	wladm_get_link_attr(const char *, wladm_link_attr_t *);
extern wladm_status_t	wladm_walk(void *, boolean_t (*)(void *, const char *));
extern boolean_t	wladm_is_valid(const char *);
extern wladm_status_t	wladm_set_prop(const char *, const char *, char **,
			    uint_t, char **);
extern wladm_status_t	wladm_walk_prop(const char *, void *,
			    boolean_t (*)(void *, const char *));
extern wladm_status_t	wladm_get_prop(const char *, wladm_prop_type_t,
			    const char *, char **, uint_t *);

extern const char	*wladm_essid2str(wladm_essid_t *, char *);
extern const char	*wladm_bssid2str(wladm_bssid_t *, char *);
extern const char	*wladm_secmode2str(wladm_secmode_t *, char *);
extern const char	*wladm_strength2str(wladm_strength_t *, char *);
extern const char	*wladm_mode2str(wladm_mode_t *, char *);
extern const char	*wladm_speed2str(wladm_speed_t *, char *);
extern const char	*wladm_auth2str(wladm_auth_t *, char *);
extern const char	*wladm_bsstype2str(wladm_bsstype_t *, char *);
extern const char	*wladm_linkstatus2str(wladm_linkstatus_t *, char *);
extern const char	*wladm_status2str(wladm_status_t, char *);

extern wladm_status_t	wladm_str2essid(const char *, wladm_essid_t *);
extern wladm_status_t	wladm_str2bssid(const char *, wladm_bssid_t *);
extern wladm_status_t	wladm_str2secmode(const char *, wladm_secmode_t *);
extern wladm_status_t	wladm_str2strength(const char *, wladm_strength_t *);
extern wladm_status_t	wladm_str2mode(const char *, wladm_mode_t *);
extern wladm_status_t	wladm_str2speed(const char *, wladm_speed_t *);
extern wladm_status_t	wladm_str2auth(const char *, wladm_auth_t *);
extern wladm_status_t	wladm_str2bsstype(const char *, wladm_bsstype_t *);
extern wladm_status_t	wladm_str2linkstatus(const char *,
			    wladm_linkstatus_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBWLADM_H */
