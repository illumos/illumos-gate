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

#ifndef _LIBNWAM_H
#define	_LIBNWAM_H

#include <netinet/in.h>

/*
 * This file defines the programming interface for libnwam.  It is a private
 * (undocumented, subject to change) interface shared between the NWAM GUI and
 * nwamd.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libnwam_wlan_attr_s {
	const char		*wla_essid;
	const char		*wla_bssid;
	const char		*wla_secmode;
	const char		*wla_strength;
	const char		*wla_mode;
	const char		*wla_speed;
	const char		*wla_auth;
	const char		*wla_bsstype;
	int			wla_channel;
} libnwam_wlan_attr_t;

/* Number of strings above; used for internal allocation purposes */
#define	WLA_NUM_STRS	8

/*
 * The descriptive event types shared with nwamd and with the GUI client.  With
 * all events other than deInitial, led_interface is always valid.  The other
 * fields are present when indicated, and otherwise must be left unused.
 */
typedef enum libnwam_descr_evtype_e {
	deInitial,		/* no other fields; new active client */
	deInterfaceUp,		/* led_v4address led_prefixlen */
	deInterfaceDown,	/* led_cause */
	deInterfaceAdded,
	deInterfaceRemoved,
	deWlanConnectFail,
	deWlanDisconnect,	/* led_wlan */
	deWlanConnected,	/* led_wlan */
	deLLPSelected,
	deLLPUnselected,	/* led_cause */
	deULPActivated,
	deULPDeactivated,
	deScanChange,
	deScanSame,
	deWlanKeyNeeded,	/* led_wlan */
	deWlanSelectionNeeded
} libnwam_descr_evtype_t;

typedef enum libnwam_diag_cause_e {
	dcNone = 0,		/* no cause */
	dcDHCP,			/* DHCP left interface down or with zero addr */
	dcTimer,		/* gave up on DHCP; switching to next best */
	dcUnplugged,		/* interface lost RUNNING flag */
	dcUser,			/* user changed priority */
	dcBetter,		/* higher-priority interface became RUNNING */
	dcNewAP,		/* scan completed on higher-priority i/f */
	dcGone,			/* periodic wireless scan showed disconnect */
	dcFaded,		/* periodic scan showed "very weak" signal */
	dcAllDown,		/* all-but-one taken down (initial LLP) */
	dcUnwanted,		/* another higher-priority interface is up */
	dcShutdown,		/* daemon is being shut down */
	dcSelect,		/* different AP selected (forced down/up) */
	dcRemoved,		/* interface removed from system */
	dcFailed		/* interface bring-up failed */
} libnwam_diag_cause_t;

typedef struct libnwam_event_data_s {
	libnwam_descr_evtype_t	led_type;
	libnwam_diag_cause_t	led_cause;
	struct in_addr		led_v4address;	/* deInterfaceUp only */
	int			led_prefixlen;	/* deInterfaceUp only */
	libnwam_wlan_attr_t	led_wlan;
	char			*led_interface;
} libnwam_event_data_t;

typedef enum libnwam_ipv4src_e {
	IPV4SRC_STATIC,
	IPV4SRC_DHCP
} libnwam_ipv4src_t;

typedef enum libnwam_interface_type_e {
	IF_UNKNOWN,
	IF_WIRED,
	IF_WIRELESS,
	IF_TUN
} libnwam_interface_type_t;

typedef struct libnwam_llp_s {
	const char	*llp_interface;
	int		llp_pri;	/* lower number => higher priority */
	libnwam_interface_type_t llp_type;
	libnwam_ipv4src_t llp_ipv4src;
	boolean_t	llp_primary;	/* selected primary interface */
	boolean_t	llp_locked;	/* selected is locked */
	boolean_t	llp_link_failed; /* unusable due to link failure */
	boolean_t	llp_dhcp_failed; /* unusable due to DHCP failure */
	boolean_t	llp_link_up;	/* datalink layer is up */
	boolean_t	llp_need_wlan;	/* wlan/AP not yet selected */
	boolean_t	llp_need_key;	/* wlan key not set */
} libnwam_llp_t;

typedef struct libnwam_wlan_s {
	libnwam_wlan_attr_t wlan_attrs;
	const char	*wlan_interface;
	boolean_t	wlan_known;
	boolean_t	wlan_haskey;
	boolean_t	wlan_connected;
} libnwam_wlan_t;

typedef struct libnwam_known_ap_s {
	const char	*ka_essid;
	const char	*ka_bssid;
	boolean_t	ka_haskey;
} libnwam_known_ap_t;

extern libnwam_event_data_t *libnwam_wait_event(void);
extern void libnwam_free_event(libnwam_event_data_t *);
extern libnwam_llp_t *libnwam_get_llp_list(uint_t *);
extern void libnwam_free_llp_list(libnwam_llp_t *);
extern int libnwam_set_llp_priority(const char *, int);
extern int libnwam_lock_llp(const char *);
extern libnwam_wlan_t *libnwam_get_wlan_list(uint_t *);
extern void libnwam_free_wlan_list(libnwam_wlan_t *);
extern libnwam_known_ap_t *libnwam_get_known_ap_list(uint_t *);
extern void libnwam_free_known_ap_list(libnwam_known_ap_t *);
extern int libnwam_add_known_ap(const char *, const char *);
extern int libnwam_delete_known_ap(const char *, const char *);
extern int libnwam_select_wlan(const char *, const char *, const char *);
extern int libnwam_wlan_key(const char *, const char *, const char *,
    const char *);
#pragma weak libnwam_wlan_key_secmode
extern int libnwam_wlan_key_secmode(const char *, const char *, const char *,
    const char *, const char *);
extern int libnwam_start_rescan(const char *);
extern int libnwam_fini(void);
extern int libnwam_init(int);

#ifdef __cplusplus
}
#endif

#endif /* _LIBNWAM_H */
