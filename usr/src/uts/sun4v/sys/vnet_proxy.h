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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VNET_PROXY_H
#define	_VNET_PROXY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * vnet proxy client is a low level driver which provides link specific
 * functionality required by the vnet device. The vnet leaf driver and vnet
 * proxy implement generic mac functionality required by the mac module as
 * part of NEMO network stack. A vnet proxy provides these entry points
 * as defined below in the vnet_proxy_ops structure. Note that some of the
 * entry points may not be implemented by certain modules and will be
 * initialized to NULL. All entry points return 0 for success and non zero
 * for failure.
 */

typedef	uint64_t	vp_handle_t;	/* vnet proxy handle */

typedef struct vnet_proxy_ops {

/*
 * vp_start() enables the client to send and receive data and generate
 * interrupts. In addition a client may register opaque objects to be
 * passed during transmit. This is done by a client which provides links
 * to specific destination mac addresses by calling vnet_add_fdb().
 * (described below: Functions exported by vnet).
 * vp_stop() disables the client from generating interrupts and IO.
 * The client will also unregister any opaque objects using vnet_del_fdb().
 */
    int	(*vp_start)(vp_handle_t vp_handle);
    int	(*vp_stop)(vp_handle_t vp_handle);

/*
 * vp_tx() is invoked to transmit a packet. The first argument points
 * to the client specific opaque object.
 * The vp_tx routine must return 0 if unable to send the packet (eg, due to
 * lack of resources).
 */
    int	(*vp_tx)(void *arg, mblk_t *mp);

/*
 * vp_resources() is called to enable the client register its receive
 * resources.
 */
    int	(*vp_resources)(vp_handle_t vp_handle);

/*
 * vp_multicast() is used to add/remove addresses to and from the set of
 * multicast addresses for which the client will receive packets.
 * If the second argument is B_TRUE then the address pointed to by the
 * third argument should be added to the set. If the second argument is
 * B_FALSE then the address pointed to by the third argument should be
 * removed.
 */
    int	(*vp_multicast)(vp_handle_t vp_handle, boolean_t add,
		const uint8_t *mca);

/*
 * vp_promisc() is used to set the promiscuity of the client.
 * If the second argument is B_TRUE then the client should receive all
 * packets. If it is set to B_FALSE then only packets destined for the
 * vnet device's unicast address and broadcast address should be received.
 */
    int	(*vp_promisc)(vp_handle_t vp_handle, boolean_t on);

/* vp_unicast() is used to set a new unicast address for the vnet device */
    int	(*vp_unicast)(vp_handle_t vp_handle, const uint8_t *mca);

/* TBD: vp_statistics */
    uint64_t	(*vp_statistics)(vp_handle_t vp_handle, enum mac_stat);

/* TBD: vp_ctl is used to to support client specific control commands */
    int	(*vp_ctl)(vp_handle_t vp_handle, mblk_t *mp);

} vnet_proxy_ops_t;

/* vnet_proxy entry point types */

typedef int	(*vp_start_t)(vp_handle_t);
typedef int 	(*vp_stop_t)(vp_handle_t);
typedef int	(*vp_tx_t)(void *, mblk_t *);
typedef int	(*vp_resources_t)(vp_handle_t);
typedef int	(*vp_multicast_t)(vp_handle_t, boolean_t,
			const uint8_t *);
typedef int 	(*vp_promisc_t)(vp_handle_t, boolean_t);
typedef int	(*vp_unicast_t)(vp_handle_t, const uint8_t *);
typedef uint64_t	(*vp_statistics_t)(vp_handle_t, enum mac_stat);
typedef int	(*vp_ctl_t)(vp_handle_t, mblk_t *);

/*
 * The client calls this function to add/remove an entry into vnet's FBD.
 */
void vnet_add_fdb(void *arg, uint8_t *macaddr, vp_tx_t vp_tx, void *txarg);
void vnet_del_fdb(void *arg, uint8_t *macaddr);
void vnet_modify_fdb(void *arg, uint8_t *macaddr, vp_tx_t vp_tx, void *txarg);
void vnet_add_def_rte(void *arg, vp_tx_t vp_tx, void *txarg);
void vnet_del_def_rte(void *arg);

#ifdef __cplusplus
}
#endif

#endif	/* _VNET_PROXY_H */
