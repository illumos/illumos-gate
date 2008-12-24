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

#ifndef _LIBDLWLAN_H
#define	_LIBDLWLAN_H

/*
 * This file includes structures, macros and routines used by WLAN link
 * administration.
 */

#include <sys/types.h>
#include <libdladm.h>

/*
 * General libdlwlan definitions and functions.
 *
 * These interfaces are ON consolidation-private.
 * For documentation, refer to PSARC/2006/623.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	DLADM_WLAN_MAX_ESSID_LEN    (32 + 1)	/* per 802.11 spec */
						/* max essid length is 32 */
						/* one more for '\0' */
#define	DLADM_WLAN_BSSID_LEN		6	/* per 802.11 spec */
#define	DLADM_WLAN_WPA_KEY_LEN		32	/* per 802.11i spec */
#define	DLADM_WLAN_MAX_WPA_IE_LEN	40	/* per 802.11i spec */

#define	DLADM_WLAN_CONNECT_TIMEOUT_DEFAULT	10
#define	DLADM_WLAN_CONNECT_CREATEIBSS		0x00000001
#define	DLADM_WLAN_CONNECT_NOSCAN		0x00000002

typedef struct dladm_wlan_essid {
	char	we_bytes[DLADM_WLAN_MAX_ESSID_LEN];
} dladm_wlan_essid_t;

typedef struct dladm_wlan_bssid {
	uint8_t	wb_bytes[DLADM_WLAN_BSSID_LEN];
} dladm_wlan_bssid_t;

typedef struct dladm_wlan_ess {
	dladm_wlan_bssid_t	we_bssid;
	dladm_wlan_essid_t	we_ssid;
	uint_t			we_ssid_len;
	uint8_t			we_wpa_ie[DLADM_WLAN_MAX_WPA_IE_LEN];
	uint_t			we_wpa_ie_len;
	int			we_freq;
} dladm_wlan_ess_t;

typedef enum {
	DLADM_WLAN_CIPHER_WEP		= 0,
	DLADM_WLAN_CIPHER_TKIP,
	DLADM_WLAN_CIPHER_AES_OCB,
	DLADM_WLAN_CIPHER_AES_CCM,
	DLADM_WLAN_CIPHER_CKIP,
	DLADM_WLAN_CIPHER_NONE
} dladm_wlan_cipher_t;

typedef enum {
	DLADM_WLAN_MLME_ASSOC		= 1,	/* associate station */
	DLADM_WLAN_MLME_DISASSOC	= 2	/* disassociate station */
} dladm_wlan_mlme_op_t;

typedef enum {
	DLADM_WLAN_REASON_UNSPECIFIED	= 1,
	DLADM_WLAN_REASON_DISASSOC_LEAVING	= 5
} dladm_wlan_reason_t;

typedef enum {
	DLADM_WLAN_SECMODE_NONE = 1,
	DLADM_WLAN_SECMODE_WEP,
	DLADM_WLAN_SECMODE_WPA
} dladm_wlan_secmode_t;

typedef enum {
	DLADM_WLAN_STRENGTH_VERY_WEAK = 1,
	DLADM_WLAN_STRENGTH_WEAK,
	DLADM_WLAN_STRENGTH_GOOD,
	DLADM_WLAN_STRENGTH_VERY_GOOD,
	DLADM_WLAN_STRENGTH_EXCELLENT
} dladm_wlan_strength_t;

typedef enum {
	DLADM_WLAN_MODE_NONE = 0,
	DLADM_WLAN_MODE_80211A,
	DLADM_WLAN_MODE_80211B,
	DLADM_WLAN_MODE_80211G
} dladm_wlan_mode_t;

typedef enum {
	DLADM_WLAN_AUTH_OPEN = 1,
	DLADM_WLAN_AUTH_SHARED
} dladm_wlan_auth_t;

typedef enum {
	DLADM_WLAN_BSSTYPE_BSS = 1,
	DLADM_WLAN_BSSTYPE_IBSS,
	DLADM_WLAN_BSSTYPE_ANY
} dladm_wlan_bsstype_t;

typedef enum {
	DLADM_WLAN_LINK_DISCONNECTED = 1,
	DLADM_WLAN_LINK_CONNECTED
} dladm_wlan_linkstatus_t;

typedef uint32_t dladm_wlan_speed_t;
typedef	uint32_t dladm_wlan_channel_t;

enum {
	DLADM_WLAN_ATTR_ESSID	= 0x00000001,
	DLADM_WLAN_ATTR_BSSID	= 0x00000002,
	DLADM_WLAN_ATTR_SECMODE	= 0x00000004,
	DLADM_WLAN_ATTR_STRENGTH = 0x00000008,
	DLADM_WLAN_ATTR_MODE	= 0x00000010,
	DLADM_WLAN_ATTR_SPEED	= 0x00000020,
	DLADM_WLAN_ATTR_AUTH	= 0x00000040,
	DLADM_WLAN_ATTR_BSSTYPE	= 0x00000080,
	DLADM_WLAN_ATTR_CHANNEL	= 0x00000100
};
typedef struct dladm_wlan_attr {
	uint_t			wa_valid;
	dladm_wlan_essid_t	wa_essid;
	dladm_wlan_bssid_t	wa_bssid;
	dladm_wlan_secmode_t	wa_secmode;
	dladm_wlan_strength_t	wa_strength;
	dladm_wlan_mode_t	wa_mode;
	dladm_wlan_speed_t	wa_speed;
	dladm_wlan_auth_t	wa_auth;
	dladm_wlan_bsstype_t	wa_bsstype;
	dladm_wlan_channel_t	wa_channel;
} dladm_wlan_attr_t;

enum {
	DLADM_WLAN_LINKATTR_STATUS	= 0x00000001,
	DLADM_WLAN_LINKATTR_WLAN	= 0x00000002
};
typedef struct dladm_wlan_linkattr {
	uint_t			la_valid;
	dladm_wlan_linkstatus_t	la_status;
	dladm_wlan_attr_t	la_wlan_attr;
} dladm_wlan_linkattr_t;

#define	DLADM_WLAN_WEPKEY64_LEN		5 	/* per WEP spec */
#define	DLADM_WLAN_WEPKEY128_LEN	13 	/* per WEP spec */
#define	DLADM_WLAN_MAX_KEY_LEN		64	/* per WEP/WPA spec */
#define	DLADM_WLAN_MAX_WEPKEYS		4 	/* MAX_NWEPKEYS */
#define	DLADM_WLAN_MAX_KEYNAME_LEN	64
typedef struct dladm_wlan_key {
	uint_t		wk_idx;
	uint_t		wk_len;
	uint8_t		wk_val[DLADM_WLAN_MAX_KEY_LEN];
	char		wk_name[DLADM_WLAN_MAX_KEYNAME_LEN];
	uint_t		wk_class;
} dladm_wlan_key_t;

extern dladm_status_t	dladm_wlan_scan(dladm_handle_t, datalink_id_t, void *,
			    boolean_t (*)(void *, dladm_wlan_attr_t *));
extern dladm_status_t	dladm_wlan_connect(dladm_handle_t, datalink_id_t,
			    dladm_wlan_attr_t *, int, void *, uint_t, uint_t);
extern dladm_status_t	dladm_wlan_disconnect(dladm_handle_t, datalink_id_t);
extern dladm_status_t	dladm_wlan_get_linkattr(dladm_handle_t, datalink_id_t,
			    dladm_wlan_linkattr_t *);
/* WPA support routines */
extern dladm_status_t	dladm_wlan_wpa_get_sr(dladm_handle_t, datalink_id_t,
			    dladm_wlan_ess_t *, uint_t, uint_t *);
extern dladm_status_t	dladm_wlan_wpa_set_ie(dladm_handle_t, datalink_id_t,
			    uint8_t *, uint_t);
extern dladm_status_t	dladm_wlan_wpa_set_wpa(dladm_handle_t, datalink_id_t,
			    boolean_t);
extern dladm_status_t	dladm_wlan_wpa_del_key(dladm_handle_t, datalink_id_t,
			    uint_t, const dladm_wlan_bssid_t *);
extern dladm_status_t	dladm_wlan_wpa_set_key(dladm_handle_t, datalink_id_t,
			    dladm_wlan_cipher_t, const dladm_wlan_bssid_t *,
			    boolean_t, uint64_t, uint_t, uint8_t *, uint_t);
extern dladm_status_t	dladm_wlan_wpa_set_mlme(dladm_handle_t, datalink_id_t,
			    dladm_wlan_mlme_op_t,
			    dladm_wlan_reason_t, dladm_wlan_bssid_t *);

extern const char	*dladm_wlan_essid2str(dladm_wlan_essid_t *, char *);
extern const char	*dladm_wlan_bssid2str(dladm_wlan_bssid_t *, char *);
extern const char	*dladm_wlan_secmode2str(dladm_wlan_secmode_t *, char *);
extern const char	*dladm_wlan_strength2str(dladm_wlan_strength_t *,
			    char *);
extern const char	*dladm_wlan_mode2str(dladm_wlan_mode_t *, char *);
extern const char	*dladm_wlan_speed2str(dladm_wlan_speed_t *, char *);
extern const char	*dladm_wlan_auth2str(dladm_wlan_auth_t *, char *);
extern const char	*dladm_wlan_bsstype2str(dladm_wlan_bsstype_t *, char *);
extern const char	*dladm_wlan_linkstatus2str(dladm_wlan_linkstatus_t *,
			    char *);

extern dladm_status_t	dladm_wlan_str2essid(const char *,
			    dladm_wlan_essid_t *);
extern dladm_status_t	dladm_wlan_str2bssid(const char *,
			    dladm_wlan_bssid_t *);
extern dladm_status_t	dladm_wlan_str2secmode(const char *,
			    dladm_wlan_secmode_t *);
extern dladm_status_t	dladm_wlan_str2strength(const char *,
			    dladm_wlan_strength_t *);
extern dladm_status_t	dladm_wlan_str2mode(const char *,
			    dladm_wlan_mode_t *);
extern dladm_status_t	dladm_wlan_str2speed(const char *,
			    dladm_wlan_speed_t *);
extern dladm_status_t	dladm_wlan_str2auth(const char *,
			    dladm_wlan_auth_t *);
extern dladm_status_t	dladm_wlan_str2bsstype(const char *,
			    dladm_wlan_bsstype_t *);
extern dladm_status_t	dladm_wlan_str2linkstatus(const char *,
			    dladm_wlan_linkstatus_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLWLAN_H */
