/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _WRSM_NC_H
#define	_WRSM_NC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * this file is include by consumers of NC interfaces
 */

#include <sys/wrsm_config.h>
#include <sys/wrsm_common.h>
#include <sys/wrsm.h>
#include <sys/wrsm_transport.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct wci_ids {
	int port;		/* safari port id */
	lcwci_handle_t lcwci;
} wci_ids_t;


/*
 * wrsm_mh data structures
 */

typedef struct wrsm_mh_reachable {
	int nhops[WRSM_MAX_WNODES];
	int stripes[WRSM_MAX_WNODES];
	boolean_t changed[WRSM_MAX_WNODES];
	wnodeid_t first_hop[WRSM_MAX_WNODES];
} wrsm_mh_reachable_t;


/*
 * The following data structures are to support for queueing events to the
 * per controller NR event thread.
 */

typedef enum {
	wrsm_evt_mhdirect,
	wrsm_evt_mhreroute,
	wrsm_evt_force_reroute,
	wrsm_evt_add_passthrough,
	wrsm_evt_send_ptlist,
	wrsm_evt_recv_ptlist,
	wrsm_evt_wakeup,
	wrsm_evt_sessup,
	wrsm_evt_sessdown,
	wrsm_evt_connect,
	wrsm_evt_smallputmap,
	wrsm_evt_barriermap,
	wrsm_evt_segmap,
	wrsm_evt_disconnect,
	wrsm_evt_unpublish,
	wrsm_evt_access
} wrsm_nr_event_type_t;

#ifdef DEBUG
#define	WRSM_EVTSTRING(e)					\
	((e == wrsm_evt_mhdirect) ? "mhdirect" :		\
	(e == wrsm_evt_mhreroute) ? "mhreroute" :		\
	(e == wrsm_evt_force_reroute) ? "force_reroute" :	\
	(e == wrsm_evt_add_passthrough) ? "add_passthrough" :	\
	(e == wrsm_evt_send_ptlist) ? "send_ptlist" :		\
	(e == wrsm_evt_recv_ptlist) ? "recv_ptlist" :		\
	(e == wrsm_evt_sessup) ? "sessup" :			\
	(e == wrsm_evt_sessdown) ? "sessdown" :			\
	(e == wrsm_evt_connect) ? "connect" :			\
	(e == wrsm_evt_smallputmap) ? "smallputmap" :		\
	(e == wrsm_evt_barriermap) ? "barriermap" :		\
	(e == wrsm_evt_segmap) ? "segmap" :			\
	(e == wrsm_evt_disconnect) ? "disconnect" :		\
	(e == wrsm_evt_unpublish) ? "unpublish" :		\
	(e == wrsm_evt_access) ? "access" :		\
	(e == wrsm_evt_wakeup) ? "wakeup" : "unknown")
#endif


typedef struct wrsm_evt_mhevent {
	ncwci_handle_t wci;
	wrsm_mh_reachable_t mh_reachable;
} wrsm_evt_mhevent_t;

typedef struct wrsm_evt_forcereroute {
	ncwci_handle_t wci;
} wrsm_evt_forcereroute_t;

typedef struct wrsm_evt_addpt {
	wrsm_node_t *node;
} wrsm_evt_addpt_t;

typedef struct wrsm_evt_send_ptlist {
	cnode_bitmask_t list;		/* cnodes to send pt_counter msg to */
} wrsm_evt_send_ptlist_t;

typedef struct wrsm_evt_recv_ptlist {
	cnodeid_t cnodeid;
	cnode_bitmask_t pt_provided;	/* cnodes allowed PT forwarding */
	int pt_route_counter;		/* incr when pt_provided changes */
} wrsm_evt_recv_ptlist_t;

typedef struct wrsm_evt_sess {
	cnodeid_t cnodeid;
} wrsm_evt_sess_t;

typedef struct wrsm_nr_event {
	wrsm_nr_event_type_t type;
	union {
		wrsm_evt_mhevent_t mhevent;
		wrsm_evt_forcereroute_t forcereroute;
		wrsm_evt_addpt_t addpt;
		wrsm_evt_send_ptlist_t send_ptlist;
		wrsm_evt_recv_ptlist_t recv_ptlist;
		wrsm_evt_sess_t sess;
		wrsm_message_t msg;
	} data;
	struct wrsm_nr_event *next;
} wrsm_nr_event_t;

void wrsm_nr_add_event(wrsm_network_t *network, wrsm_nr_event_t *event_data,
    boolean_t release_lock);



/*
 * the following functions are used by the Config Layer
 */

/*
 * find network structure from controller id or dev_info_t pointer
 */
wrsm_network_t *wrsm_nc_ctlr_to_network(uint32_t rsm_ctrl_id);
wrsm_network_t *wrsm_nc_cnodeid_to_network(cnodeid_t);

/*
 * save away new config info; disable current config
 */
int wrsm_nc_replaceconfig(uint32_t rsm_ctlr_id,
    wrsm_controller_t *config, dev_info_t *dip, int num_attached,
    wci_ids_t *attached_wcis);

/*
 * clean up/stop using old nodes, wcis, links
 */
int wrsm_nc_cleanconfig(uint32_t rsm_ctlr_id, int num_reconfig,
    wci_ids_t *reconfig_wcis);

/*
 * make sure all old links are down; bring up new links
 */
int wrsm_nc_installconfig(uint32_t rsm_ctlr_id);

/*
 * start using new links
 */
int wrsm_nc_enableconfig(uint32_t rsm_ctlr_id, int num_reconfig,
    wci_ids_t *reconfig_wcis);

/*
 * check whether config is in installed_up state
 */
boolean_t wrsm_nc_is_installed_up(uint_t rsm_ctlr_id);


/*
 * install and enable new config
 */
int wrsm_nc_initialconfig(uint32_t rsm_ctlr_id,
    wrsm_controller_t *config, dev_info_t *dip, int num_attached,
    wci_ids_t *attached_wcis);

/*
 * uninstall config for an RSM controller; delete RSM controller
 */
int wrsm_nc_removeconfig(uint32_t rsm_ctlr_id);

/*
 * enable sessions in RSM controller
 */
int wrsm_nc_startconfig(uint32_t rsm_ctlr_id);

/*
 * enable sessions in RSM controller
 */
int wrsm_nc_stopconfig(uint32_t rsm_ctlr_id);

/*
 * notify the NR that all links on a WCI are up
 */
void wrsm_nr_all_links_up(ncwci_handle_t nc);

/*
 * find out if node connected to a link has a valid session
 */
int wrsm_nr_session_up(ncwci_handle_t ncwci, wnodeid_t wnid);

/*
 * clear cluster write lockout on a remote cnode
 */
void wrsm_nr_clear_lockout(ncwci_handle_t wci, ncslice_t ncslice);

/*
 * a new WCI has been attached
 */
int wrsm_nc_newwci(uint32_t rsm_ctlr_id, safari_port_t safid,
    lcwci_handle_t lcwci, wrsm_controller_t *config);

/*
 * an attached wci is being detached
 */
int wrsm_nc_removewci(uint32_t rsm_ctlr_id, safari_port_t safid);

/*
 * the following functions are used by memory segments
 */
int wrsm_nc_create_errorpage(wrsm_network_t *network,
    wrsm_cmmu_tuple_t **errorpage_tuplep, pfn_t *errorpage_pfnp,
    boolean_t sleep);


/*
 * the following functions are used by the LC
 */
void wrsm_mh_link_is_up(ncwci_handle_t ncwci, uint32_t
    local_linknum, wnodeid_t remote_wnode);
void wrsm_mh_link_is_down(ncwci_handle_t ncwci, uint32_t
    local_linknum, wnodeid_t remote_wnode);

/*
 * the following functions are used by the driver
 */

int wrsm_nc_suspend(uint_t rsm_ctlr_id);
int wrsm_nc_resume(uint_t rsm_ctlr_id);


/* this is an RSMPI function */
int wrsm_get_peers(rsm_controller_handle_t controller, rsm_addr_t *addr_list,
    uint_t count, uint_t *num_addrs);

/*
 * returns controller number given nc handle. Used by lc since the lc
 * cannot dereference the config fields in softstate as they may be null
 */
uint32_t wrsm_nr_getcontroller_id(ncwci_handle_t ncwci);
/*
 * The plugin library (librsmwrsm) opens controllers, in order to prevent the
 * the config layer from removing a controller (network) that the plugin is
 * using, the driver must return busy. open and close controller below
 * increment/decrement a counter for the removeconfig to check before removing
 * a config.
 */
int wrsm_nc_open_controller(uint_t rsm_ctlr_id);
void wrsm_nc_close_controller(uint_t rsm_ctlr_id);
int wrsm_nc_getlocalnode_ioctl(int minor, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rval_p);

/* logs system events for use by user applications via the sysdaemond to see */
void wrsm_nr_logevent(wrsm_network_t *network, wrsm_node_t *node,
    wrsm_sys_event_t eventtype, char *reason);
#ifdef	__cplusplus
}
#endif

#endif /* _WRSM_NC_H */
