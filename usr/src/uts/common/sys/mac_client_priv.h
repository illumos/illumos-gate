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
 * This file contains *private* MAC API definitions. This header file
 * should only be included by kernel components which are part of the
 * GLDv3 stack (dld, dls, aggr, softmac).
 */

#ifndef	_SYS_MAC_CLIENT_PRIV_H
#define	_SYS_MAC_CLIENT_PRIV_H

#include <sys/mac.h>
#include <sys/mac_flow.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#ifdef DEBUG
#define	MAC_PERIM_HELD(mph)		mac_perim_held(mph)
#else
#define	MAC_PERIM_HELD(mph)
#endif

extern boolean_t mac_rx_bypass_set(mac_client_handle_t, mac_direct_rx_t,
    void *);
extern void mac_rx_bypass_enable(mac_client_handle_t);
extern void mac_rx_bypass_disable(mac_client_handle_t);

extern const mac_info_t *mac_info(mac_handle_t);
extern boolean_t mac_info_get(const char *, mac_info_t *);
extern boolean_t mac_promisc_get(mac_handle_t);

extern int mac_start(mac_handle_t);
extern void mac_stop(mac_handle_t);

extern void mac_ioctl(mac_handle_t, queue_t *, mblk_t *);
extern link_state_t mac_link_get(mac_handle_t);
extern void mac_resource_set(mac_client_handle_t, mac_resource_add_t, void *);
extern dev_info_t *mac_devinfo_get(mac_handle_t);
extern void *mac_driver(mac_handle_t);
extern boolean_t mac_capab_get(mac_handle_t, mac_capab_t, void *);
extern boolean_t mac_sap_verify(mac_handle_t, uint32_t, uint32_t *);
extern mblk_t *mac_header(mac_handle_t, const uint8_t *, uint32_t, mblk_t *,
    size_t);
extern int mac_header_info(mac_handle_t, mblk_t *, mac_header_info_t *);
extern int mac_vlan_header_info(mac_handle_t, mblk_t *, mac_header_info_t *);
extern mblk_t *mac_header_cook(mac_handle_t, mblk_t *);
extern mblk_t *mac_header_uncook(mac_handle_t, mblk_t *);

extern void mac_resource_set_common(mac_client_handle_t,
    mac_resource_add_t, mac_resource_remove_t, mac_resource_quiesce_t,
    mac_resource_restart_t, mac_resource_bind_t, void *);

extern	void mac_perim_enter_by_mh(mac_handle_t, mac_perim_handle_t *);
extern	int mac_perim_enter_by_macname(const char *, mac_perim_handle_t *);
extern	int mac_perim_enter_by_linkid(datalink_id_t, mac_perim_handle_t *);
extern	void mac_perim_exit(mac_perim_handle_t);
extern	boolean_t mac_perim_held(mac_handle_t);

extern	uint16_t mac_client_vid(mac_client_handle_t);
extern int mac_vnic_unicast_set(mac_client_handle_t, const uint8_t *);
extern boolean_t mac_client_is_vlan_vnic(mac_client_handle_t);

extern void mac_client_poll_enable(mac_client_handle_t);
extern void mac_client_poll_disable(mac_client_handle_t);

/*
 * Flow-related APIs for MAC clients.
 */

extern void mac_link_init_flows(mac_client_handle_t);
extern void mac_link_release_flows(mac_client_handle_t);
extern int mac_link_flow_add(datalink_id_t, char *, flow_desc_t *,
    mac_resource_props_t *);
extern int mac_link_flow_remove(char *);
extern int mac_link_flow_modify(char *, mac_resource_props_t *);
extern boolean_t mac_link_has_flows(mac_client_handle_t);

typedef struct {
	char			fi_flow_name[MAXFLOWNAMELEN];
	datalink_id_t		fi_link_id;
	flow_desc_t		fi_flow_desc;
	mac_resource_props_t	fi_resource_props;
} mac_flowinfo_t;

extern int mac_link_flow_walk(datalink_id_t,
    int (*)(mac_flowinfo_t *, void *), void *);
extern int mac_link_flow_info(char *, mac_flowinfo_t *);

extern void mac_rx_client_quiesce(mac_client_handle_t);
extern void mac_rx_client_restart(mac_client_handle_t);
extern void mac_tx_client_quiesce(mac_client_handle_t);
extern void mac_tx_client_condemn(mac_client_handle_t);
extern void mac_tx_client_restart(mac_client_handle_t);
extern void mac_srs_perm_quiesce(mac_client_handle_t, boolean_t);
extern int mac_hwrings_get(mac_client_handle_t, mac_group_handle_t *,
    mac_ring_handle_t *, mac_ring_type_t);
extern uint_t mac_hwring_getinfo(mac_ring_handle_t);
extern void mac_hwring_setup(mac_ring_handle_t, mac_resource_handle_t,
    mac_ring_handle_t);
extern void mac_hwring_teardown(mac_ring_handle_t);
extern int mac_hwring_disable_intr(mac_ring_handle_t);
extern int mac_hwring_enable_intr(mac_ring_handle_t);
extern int mac_hwring_start(mac_ring_handle_t);
extern void mac_hwring_stop(mac_ring_handle_t);
extern mblk_t *mac_hwring_poll(mac_ring_handle_t, int);
extern mblk_t *mac_hwring_tx(mac_ring_handle_t, mblk_t *);
extern int mac_hwring_getstat(mac_ring_handle_t, uint_t, uint64_t *);
extern mblk_t *mac_hwring_send_priv(mac_client_handle_t,
    mac_ring_handle_t, mblk_t *);

#define	MAC_HWRING_POLL(ring, bytes)			\
	(((ring)->mr_info.mri_poll)			\
	((ring)->mr_info.mri_driver, (bytes)))

extern int mac_hwgroup_addmac(mac_group_handle_t, const uint8_t *);
extern int mac_hwgroup_remmac(mac_group_handle_t, const uint8_t *);

extern void mac_set_upper_mac(mac_client_handle_t, mac_handle_t,
    mac_resource_props_t *);

extern int mac_mark_exclusive(mac_handle_t);
extern void mac_unmark_exclusive(mac_handle_t);

extern uint_t mac_hwgrp_num(mac_handle_t, int);
extern void mac_get_hwrxgrp_info(mac_handle_t, int, uint_t *, uint_t *,
    uint_t *, uint_t *, uint_t *, char *);
extern void mac_get_hwtxgrp_info(mac_handle_t, int, uint_t *, uint_t *,
    uint_t *, uint_t *, uint_t *, char *);

extern uint_t mac_txavail_get(mac_handle_t);
extern uint_t mac_rxavail_get(mac_handle_t);
extern uint_t mac_txrsvd_get(mac_handle_t);
extern uint_t mac_rxrsvd_get(mac_handle_t);
extern uint_t mac_rxhwlnksavail_get(mac_handle_t);
extern uint_t mac_rxhwlnksrsvd_get(mac_handle_t);
extern uint_t mac_txhwlnksavail_get(mac_handle_t);
extern uint_t mac_txhwlnksrsvd_get(mac_handle_t);

extern int32_t mac_client_intr_cpu(mac_client_handle_t);
extern void mac_client_set_intr_cpu(void *, mac_client_handle_t, int32_t);
extern void *mac_get_devinfo(mac_handle_t);

extern boolean_t mac_is_vnic(mac_handle_t);
extern uint32_t mac_no_notification(mac_handle_t);

extern int mac_set_prop(mac_handle_t, mac_prop_id_t, char *, void *, uint_t);
extern int mac_get_prop(mac_handle_t, mac_prop_id_t, char *, void *, uint_t);
extern int mac_prop_info(mac_handle_t, mac_prop_id_t, char *, void *,
    uint_t, mac_propval_range_t *, uint_t *);
extern boolean_t mac_prop_check_size(mac_prop_id_t, uint_t, boolean_t);

extern uint64_t mac_pseudo_rx_ring_stat_get(mac_ring_handle_t, uint_t);
extern uint64_t mac_pseudo_tx_ring_stat_get(mac_ring_handle_t, uint_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_MAC_CLIENT_PRIV_H */
