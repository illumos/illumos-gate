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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * This file captures the MAC client API definitions. It can be
 * included from any MAC clients.
 */

#ifndef	_SYS_MAC_CLIENT_H
#define	_SYS_MAC_CLIENT_H

#include <sys/mac.h>
#include <sys/mac_flow.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * MAC client interface.
 */

typedef struct __mac_client_handle *mac_client_handle_t;
typedef struct __mac_unicast_handle *mac_unicast_handle_t;
typedef struct __mac_promisc_handle *mac_promisc_handle_t;
typedef struct __mac_perim_handle *mac_perim_handle_t;
typedef uintptr_t mac_tx_cookie_t;

typedef void (*mac_tx_notify_t)(void *, mac_tx_cookie_t);

typedef enum {
	MAC_DIAG_NONE,
	MAC_DIAG_MACADDR_NIC,
	MAC_DIAG_MACADDR_INUSE,
	MAC_DIAG_MACADDR_INVALID,
	MAC_DIAG_MACADDRLEN_INVALID,
	MAC_DIAG_MACFACTORYSLOTINVALID,
	MAC_DIAG_MACFACTORYSLOTUSED,
	MAC_DIAG_MACFACTORYSLOTALLUSED,
	MAC_DIAG_MACFACTORYNOTSUP,
	MAC_DIAG_MACPREFIX_INVALID,
	MAC_DIAG_MACPREFIXLEN_INVALID,
	MAC_DIAG_MACNO_HWRINGS
} mac_diag_t;

/*
 * These are used when MAC clients what to specify tx and rx rings
 * properties. MAC_RXRINGS_NONE/MAC_TXRINGS_NONE mean that we should
 * not reserve any rings while MAC_RXRINGS_DONTCARE/MAC_TXRINGS_DONTCARE
 * mean that the system can decide if it wants to reserve rings or
 * not.
 */
#define	MAC_RXRINGS_NONE	0
#define	MAC_TXRINGS_NONE	MAC_RXRINGS_NONE
#define	MAC_RXRINGS_DONTCARE	-1
#define	MAC_TXRINGS_DONTCARE	MAC_RXRINGS_DONTCARE

typedef enum {
	MAC_CLIENT_PROMISC_ALL,
	MAC_CLIENT_PROMISC_FILTERED,
	MAC_CLIENT_PROMISC_MULTI
} mac_client_promisc_type_t;

/* flags passed to mac_unicast_add() */
#define	MAC_UNICAST_NODUPCHECK			0x0001
#define	MAC_UNICAST_PRIMARY			0x0002
#define	MAC_UNICAST_HW				0x0004
#define	MAC_UNICAST_VNIC_PRIMARY		0x0008
#define	MAC_UNICAST_TAG_DISABLE			0x0010
#define	MAC_UNICAST_STRIP_DISABLE		0x0020
#define	MAC_UNICAST_DISABLE_TX_VID_CHECK	0x0040

/* flags passed to mac_client_open */
#define	MAC_OPEN_FLAGS_IS_VNIC			0x0001
#define	MAC_OPEN_FLAGS_EXCLUSIVE		0x0002
#define	MAC_OPEN_FLAGS_IS_AGGR_PORT		0x0004
#define	MAC_OPEN_FLAGS_SHARES_DESIRED		0x0008
#define	MAC_OPEN_FLAGS_USE_DATALINK_NAME	0x0010
#define	MAC_OPEN_FLAGS_MULTI_PRIMARY		0x0020
#define	MAC_OPEN_FLAGS_NO_UNICAST_ADDR		0x0040

/* flags passed to mac_client_close */
#define	MAC_CLOSE_FLAGS_IS_VNIC		0x0001
#define	MAC_CLOSE_FLAGS_EXCLUSIVE	0x0002
#define	MAC_CLOSE_FLAGS_IS_AGGR_PORT	0x0004

/* flags passed to mac_promisc_add() */
#define	MAC_PROMISC_FLAGS_NO_TX_LOOP		0x0001
#define	MAC_PROMISC_FLAGS_NO_PHYS		0x0002
#define	MAC_PROMISC_FLAGS_VLAN_TAG_STRIP	0x0004
#define	MAC_PROMISC_FLAGS_NO_COPY		0x0008

/* flags passed to mac_tx() */
#define	MAC_DROP_ON_NO_DESC	0x01 /* freemsg() if no tx descs */
#define	MAC_TX_NO_ENQUEUE	0x02 /* don't enqueue mblks if not xmit'ed */
#define	MAC_TX_NO_HOLD		0x04 /* don't bump the active Tx count */

extern int mac_client_open(mac_handle_t, mac_client_handle_t *, char *,
    uint16_t);
extern void mac_client_close(mac_client_handle_t, uint16_t);

extern int mac_unicast_add(mac_client_handle_t, uint8_t *, uint16_t,
    mac_unicast_handle_t *, uint16_t, mac_diag_t *);
extern int mac_unicast_add_set_rx(mac_client_handle_t, uint8_t *, uint16_t,
    mac_unicast_handle_t *, uint16_t, mac_diag_t *, mac_rx_t, void *);
extern int mac_unicast_remove(mac_client_handle_t, mac_unicast_handle_t);

extern int mac_multicast_add(mac_client_handle_t, const uint8_t *);
extern void mac_multicast_remove(mac_client_handle_t, const uint8_t *);

extern void mac_rx_set(mac_client_handle_t, mac_rx_t, void *);
extern void mac_rx_clear(mac_client_handle_t);
extern void mac_secondary_dup(mac_client_handle_t, mac_client_handle_t);
extern void mac_secondary_cleanup(mac_client_handle_t);
extern mac_tx_cookie_t mac_tx(mac_client_handle_t, mblk_t *,
    uintptr_t, uint16_t, mblk_t **);
extern boolean_t mac_tx_is_flow_blocked(mac_client_handle_t, mac_tx_cookie_t);
extern uint64_t mac_client_stat_get(mac_client_handle_t, uint_t);

extern int mac_promisc_add(mac_client_handle_t, mac_client_promisc_type_t,
    mac_rx_t, void *, mac_promisc_handle_t *, uint16_t);
extern void mac_promisc_remove(mac_promisc_handle_t);

extern mac_notify_handle_t mac_notify_add(mac_handle_t, mac_notify_t, void *);
extern int mac_notify_remove(mac_notify_handle_t, boolean_t);
extern void mac_notify_remove_wait(mac_handle_t);
extern int mac_rename_primary(mac_handle_t, const char *);
extern	char *mac_client_name(mac_client_handle_t);

extern int mac_open(const char *, mac_handle_t *);
extern void mac_close(mac_handle_t);
extern uint64_t mac_stat_get(mac_handle_t, uint_t);

extern int mac_unicast_primary_set(mac_handle_t, const uint8_t *);
extern void mac_unicast_primary_get(mac_handle_t, uint8_t *);
extern void mac_unicast_primary_info(mac_handle_t, char *, boolean_t *);

extern void mac_unicast_secondary_get(mac_client_handle_t, uint8_t *);

extern boolean_t mac_dst_get(mac_handle_t, uint8_t *);

extern int mac_addr_random(mac_client_handle_t, uint_t, uint8_t *,
    mac_diag_t *);

extern int mac_addr_factory_reserve(mac_client_handle_t, int *);
extern void mac_addr_factory_release(mac_client_handle_t, uint_t);
extern void mac_addr_factory_value(mac_handle_t, int, uchar_t *, uint_t *,
    char *, boolean_t *);
extern uint_t mac_addr_factory_num(mac_handle_t);

extern mac_tx_notify_handle_t mac_client_tx_notify(mac_client_handle_t,
    mac_tx_notify_t, void *);

extern int mac_client_set_resources(mac_client_handle_t,
    mac_resource_props_t *);
extern void mac_client_get_resources(mac_client_handle_t,
    mac_resource_props_t *);
extern void mac_client_get_eff_resources(mac_client_handle_t,
    mac_resource_props_t *);

/* bridging-related interfaces */
extern int mac_set_pvid(mac_handle_t, uint16_t);
extern uint16_t mac_get_pvid(mac_handle_t);
extern uint32_t mac_get_llimit(mac_handle_t);
extern uint32_t mac_get_ldecay(mac_handle_t);

extern int mac_share_capable(mac_handle_t);
extern int mac_share_bind(mac_client_handle_t, uint64_t, uint64_t *);
extern void mac_share_unbind(mac_client_handle_t);

extern int mac_set_mtu(mac_handle_t, uint_t, uint_t *);

extern void mac_client_set_rings(mac_client_handle_t, int, int);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAC_CLIENT_H */
