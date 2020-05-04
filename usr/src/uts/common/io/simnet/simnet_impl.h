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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	_SYS_SIMNET_IMPL_H
#define	_SYS_SIMNET_IMPL_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/mutex.h>
#include <sys/mac.h>
#include <sys/net80211.h>
#include <inet/wifi_ioctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_SIMNET_ESSCONF	25	/* Max num of WiFi scan results */
#define	MAX_ESSLIST_ARGS	10	/* Max num of ESS list arguments */
#define	MAX_ESSLIST_ARGLEN	50	/* Max ESS list argument len */

struct simnet_dev;

typedef struct simnet_wifidev {
	struct simnet_dev	*swd_sdev;
	wl_essid_t		swd_essid;
	wl_bssid_t		swd_bssid;
	wl_rssi_t		swd_rssi; /* signal strength */
	wl_linkstatus_t		swd_linkstatus;
	int			swd_esslist_num;
	wl_ess_conf_t		*swd_esslist[MAX_SIMNET_ESSCONF];
} simnet_wifidev_t;

typedef struct simnet_stats {
	uint64_t		rbytes;
	uint64_t		obytes;
	uint64_t		xmit_errors;
	uint64_t		xmit_count;
	uint64_t		recv_count;
	uint64_t		recv_errors;
} simnet_stats_t;

typedef struct simnet_dev {
	list_node_t		sd_listnode;
	uint_t			sd_type;	/* WiFi, Ethernet etc. */
	datalink_id_t		sd_link_id;
	zoneid_t		sd_zoneid;	/* zone where created */
	struct simnet_dev	*sd_peer_dev;	/* Attached peer, if any */
	uint_t			sd_flags;	/* Device flags SDF_* */
	uint_t			sd_refcount;
	/* Num of active threads using the device */
	uint_t			sd_threadcount;
	kcondvar_t		sd_threadwait;
	mac_handle_t		sd_mh;
	simnet_wifidev_t	*sd_wifidev;
	boolean_t		sd_promisc;
	kmutex_t		sd_instlock;
	/* Num of multicast addresses stored in sd_mcastaddrs */
	uint_t			sd_mcastaddr_count;
	/* Multicast address list stored in single buffer */
	uint8_t			*sd_mcastaddrs;
	uint_t			sd_mac_len;
	uchar_t			sd_mac_addr[MAXMACADDRLEN];
	simnet_stats_t		sd_stats;

	/* Capabilities */
	uint_t			sd_rx_cksum;
	uint_t			sd_tx_cksum;
	boolean_t		sd_lso;
} simnet_dev_t;

/* Simnet dladm private properties. */
#define	SD_PROP_RX_IP_CKSUM	"_rx_ipv4_cksum"
#define	SD_PROP_TX_ULP_CKSUM	"_tx_ulp_cksum"
#define	SD_PROP_TX_IP_CKSUM	"_tx_ipv4_cksum"
#define	SD_PROP_LSO		"_lso"

/* Simnet device flags */
#define	SDF_SHUTDOWN	0x00000001	/* Device shutdown, no new ops */
#define	SDF_STARTED	0x00000002	/* Device started, allow ops */

#define	SIMNET_MAX_MTU	9000		/* Max MTU supported by simnet driver */
#define	SD_LSO_MAXLEN	65535		/* Max LSO supported by simnet driver */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SIMNET_IMPL_H */
