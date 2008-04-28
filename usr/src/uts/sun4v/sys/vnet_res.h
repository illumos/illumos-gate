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

#ifndef _VNET_RES_H
#define	_VNET_RES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Vio network resource types.
 * VIO_NET_RES_LDC_SERVICE:
 *			An LDC based resource corresonding to vswitch
 *			service. This means, all broadcast pakets need
 *			to be sent via this resource. Unicast packets
 *			that have no known end point will also be sent
 *			via this resource, but only if no Hybrid resource
 *			is available.
 *
 * VIO_NET_RES_LDC_GUEST:
 *			An LDC based resource corresponding to another
 *			guest domain. This means, unicast packets to that
 *			guest's mac addres will be sent via this resource.
 *
 * VIO_NET_RES_HYBRID:
 *			A Hybrid resource. Even though this resource may
 *			be capable of transmitting the broadcast/multicast
 *			traffic, it will be used only for transmitting
 *			uni-cast traffic.
 *			This is because the broadcast/multicast traffic needs
 *			to be sent to the vswitch so that those packets
 *			are sent to other guest domains and vswitch interface.
 */
typedef enum {
	VIO_NET_RES_LDC_SERVICE,
	VIO_NET_RES_LDC_GUEST,
	VIO_NET_RES_HYBRID
} vio_net_res_type_t;

/* A handle returned by vio_net_resource_reg() interface */
typedef void *vio_net_handle_t;


/*
 * Callback functions returned via the reg() interfce.
 *
 * vio_net_rx_cb:	Used for passing the packets that are received
 *			by a device. This is equivalent of mac_rx().
 *
 * vio_net_tx_update:   Used for re-starting the transmission. This
 *			is an equivalent of mac_tx_update().
 *
 * vio_net_report_err:	Used for reporting any errors with the resource.
 */
typedef void (*vio_net_rx_cb_t)(vio_net_handle_t, mblk_t *);
typedef void (*vio_net_tx_update_t)(vio_net_handle_t);

typedef enum {
	VIO_NET_RES_DOWN,		/* Resource down */
	VIO_VNET_RES_ERR		/* Resource encountered an error */
} vio_net_err_val_t;

typedef void (*vio_net_report_err_t)(vio_net_handle_t, vio_net_err_val_t err);

typedef struct vio_net_callbacks_s {
	vio_net_rx_cb_t		vio_net_rx_cb;
	vio_net_tx_update_t	vio_net_tx_update;
	vio_net_report_err_t	vio_net_report_err;
} vio_net_callbacks_t;


/*
 * vio_net_resource_reg -- An interface to register a resource with vnet.
 *
 *	macp:		A mac_register_t structure representing the
 *			device and its MAC driver callbacks.
 *	type:		Type of the device.
 *
 *	local-macaddr:	A MAC address to which this resource belongs to.
 *
 *	rem_macaddr:	A MAC address of the peer. This is only applicable
 *			to LDC based resource. This argument is ignored
 *			for HYBRID resource.
 *	vhp:		A handle returned by this interface. After a
 *			successful return of this interface,
 *			all other interaction will use this handle.
 *
 *	vcb:		A set of callbacks returned by this interface
 *			for the use of the devices to pass packets etc.
 *
 * Return value: 0 for success, non-zero errno value appropriate for the error.
 */
int vio_net_resource_reg(mac_register_t *macp,
    vio_net_res_type_t type, ether_addr_t local_maddr, ether_addr_t rem_maddr,
    vio_net_handle_t *vhp, vio_net_callbacks_t *vcb);

/* A useful typedef for consumers of this interface */
typedef int (*vio_net_resource_reg_t)(mac_register_t *macp,
    vio_net_res_type_t type, ether_addr_t local_maddr, ether_addr_t rem_maddr,
    vio_net_handle_t *vhp, vio_net_callbacks_t *vcb);



/*
 * vio_net_resource_unreg -- Unregisters a resource.
 *
 *	vhp:  handle that was returned by the resource_reg() interface.
 */
void vio_net_resource_unreg(vio_net_handle_t vhp);

/* A useful typedef for consumers of this interface */
typedef void (*vio_net_resource_unreg_t)(vio_net_handle_t vhp);

#ifdef __cplusplus
}
#endif

#endif	/* _VNET_RES_H */
