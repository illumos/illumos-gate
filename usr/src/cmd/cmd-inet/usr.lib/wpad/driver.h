/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */
#ifndef __DRIVER_H
#define	__DRIVER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libdlwlan.h>
#include <libdllink.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum { WPA_ALG_NONE, WPA_ALG_WEP, WPA_ALG_TKIP, WPA_ALG_CCMP } wpa_alg;
typedef enum { CIPHER_NONE, CIPHER_WEP40, CIPHER_TKIP, CIPHER_CCMP,
	CIPHER_WEP104 } wpa_cipher;
typedef enum { KEY_MGMT_802_1X, KEY_MGMT_PSK, KEY_MGMT_NONE } wpa_key_mgmt;

struct wpa_driver_ops {
	int (*get_bssid)(datalink_id_t, char *);
	int (*get_ssid)(datalink_id_t, char *);
	int (*set_wpa)(datalink_id_t, boolean_t);
	int (*set_key)(datalink_id_t, wpa_alg, uint8_t *,
	    int, boolean_t, uint8_t *, uint32_t, uint8_t *, uint32_t);
	int (*scan)(datalink_id_t);
	int (*get_scan_results)(datalink_id_t, dladm_wlan_ess_t *, uint32_t);
	int (*disassociate)(datalink_id_t, int);
	int (*associate)(datalink_id_t, const char *, uint8_t *, uint32_t);
};

#ifdef __cplusplus
}
#endif

#endif /* __DRIVER_H */
