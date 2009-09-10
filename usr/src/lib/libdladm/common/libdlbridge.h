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

#ifndef _LIBDLBRIDGE_H
#define	_LIBDLBRIDGE_H

/*
 * This file includes structures, macros and routines used by bridge
 * administration.
 */

#include <sys/types.h>
#include <libdladm.h>
#include <uid_stp.h>
#include <net/bridge.h>
#include <net/trill.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	DLADM_BRIDGE_PROT_UNKNOWN = 0,	/* internal only */
	DLADM_BRIDGE_PROT_STP,
	DLADM_BRIDGE_PROT_TRILL
} dladm_bridge_prot_t;

/* Utility functions to accept bridge protection options */
extern dladm_status_t	dladm_bridge_str2prot(const char *,
    dladm_bridge_prot_t *);
extern const char	*dladm_bridge_prot2str(dladm_bridge_prot_t);

/* Retrieve bridge properties from SMF */
extern dladm_status_t	dladm_bridge_get_properties(const char *,
    UID_STP_CFG_T *, dladm_bridge_prot_t *);
extern dladm_status_t	dladm_bridge_run_properties(const char *,
    UID_STP_CFG_T *, dladm_bridge_prot_t *);

/* Create new bridge and configure SMF properties */
extern dladm_status_t	dladm_bridge_configure(dladm_handle_t, const char *,
    const UID_STP_CFG_T *, dladm_bridge_prot_t, uint32_t);

/* Enable a newly created bridge in SMF */
extern dladm_status_t	dladm_bridge_enable(const char *);
/* Delete a previously created bridge */
extern dladm_status_t	dladm_bridge_delete(dladm_handle_t, const char *,
    uint32_t);

/* Retrieve bridge state from running bridge daemon and get bridge port list */
extern dladm_status_t	dladm_bridge_state(const char *, UID_STP_STATE_T *);
extern datalink_id_t	*dladm_bridge_get_portlist(const char *, uint_t *);
extern void		dladm_bridge_free_portlist(datalink_id_t *);

/* Set/remove bridge link membership and retreive bridge from member link */
extern dladm_status_t	dladm_bridge_setlink(dladm_handle_t, datalink_id_t,
    const char *);
extern dladm_status_t	dladm_bridge_getlink(dladm_handle_t, datalink_id_t,
    char *, size_t);

/* Retrieve bridge port status */
extern dladm_status_t	dladm_bridge_link_state(dladm_handle_t, datalink_id_t,
    UID_STP_PORT_STATE_T *);
/* Check valid bridge name */
extern boolean_t	dladm_valid_bridgename(const char *);
/* Convert bridge observability node name to bridge name */
extern boolean_t	dladm_observe_to_bridge(char *);
/* Retrieve bridge forwarding table entries */
extern bridge_listfwd_t	*dladm_bridge_get_fwdtable(dladm_handle_t, const char *,
    uint_t *);
extern void		dladm_bridge_free_fwdtable(bridge_listfwd_t *);

/* Retrive TRILL nicknames list */
extern trill_listnick_t *dladm_bridge_get_trillnick(const char *, uint_t *);
extern void		dladm_bridge_free_trillnick(trill_listnick_t *);
/* Store and retrieve TRILL nickname from TRILL SMF service configuration  */
extern uint16_t		dladm_bridge_get_nick(const char *);
extern void		dladm_bridge_set_nick(const char *, uint16_t);
/* Retrieve undocumented private properties from bridge SMF service config */
extern dladm_status_t	dladm_bridge_get_privprop(const char *,
    boolean_t *, uint32_t *);

/* Internal to libdladm */
extern dladm_status_t	dladm_bridge_get_port_cfg(dladm_handle_t, datalink_id_t,
    int, int *);
extern dladm_status_t	dladm_bridge_get_forwarding(dladm_handle_t,
    datalink_id_t, uint_t *);
extern dladm_status_t	dladm_bridge_refresh(dladm_handle_t, datalink_id_t);

/* Bridge connection; used only between libdladm and bridged for status */
#define	DOOR_DIRNAME	"/var/run/bridge_door"
typedef enum bridge_door_type_e {
	bdcBridgeGetConfig,
	bdcBridgeGetState,
	bdcBridgeGetPorts,
	bdcBridgeGetRefreshCount,
	bdcPortGetConfig,
	bdcPortGetState,
	bdcPortGetForwarding
} bridge_door_type_t;

typedef struct bridge_door_cmd_s {
	bridge_door_type_t bdc_type;
	datalink_id_t bdc_linkid;
} bridge_door_cmd_t;

typedef struct bridge_door_cfg_s {
	UID_STP_CFG_T		bdcf_cfg;
	dladm_bridge_prot_t	bdcf_prot;
} bridge_door_cfg_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLBRIDGE_H */
