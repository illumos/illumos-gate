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

#ifndef _WRSM_NC_IMPL_H
#define	_WRSM_NC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * this file is included by modules that are part of the NC
 */

#include <sys/wrsm_common.h>
#include <sys/wrsm_config.h>
#include <sys/wrsm_plat.h>


#ifdef	__cplusplus
extern "C" {
#endif

#define	WRSM_PTRETRY_TIMEOUT	(10 * hz)
#define	WRSM_ENABLE_TIMEOUT	(5 * hz)

#define	WRSM_INID2DNID_ENTRIES	16
#define	WRSM_MAX_STRIPEWCIS	4
#define	WNODE_UNREACHABLE	(-1)

typedef unsigned char wrsm_linknum_t;
typedef unsigned char inid_t;

typedef struct wrsm_mh_reroute_state wrsm_mh_reroute_state_t;
typedef struct wrsm_nc_strgrp wrsm_nc_strgrp_t;




/*
 * arg to wci_routechange()
 *
 * controls how the gain or loss of a wnode route affects which
 * nodes have their ncslice routes re-evaluated.
 */
typedef enum {
	wci_reroute_all,	/* route eval on all interested nodes */
	wci_reroute_direct,	/* route eval only on direct connect nodes */
	wci_reroute_pending,	/* only route eval nodes using lost routes */
	wci_reroute_disabled,	/* teardown routes on nodes using lost routes */
	wci_reroute_force	/* reroute_all, changed and unchanged wnodes */
} wrsm_wci_reroute_t;

#ifdef DEBUG
#define	WCI_RTSTRING(e)							\
	((e == wci_reroute_all) ? "reroute_all" :			\
	(e == wci_reroute_direct) ? "reroute_direct" :			\
	(e == wci_reroute_pending) ? "reroute_pending" :		\
	(e == wci_reroute_disabled) ? "reroute_disabled" :		\
	(e == wci_reroute_force) ? "reroute_force" :	"unknown")
#endif


typedef enum {
	wci_rerouted,			/* no multi-hop reroute needed */
	wci_in_reroute,			/* MH currently recalculating routes */
	wci_need_reroute,		/* wci needs an MH reroute */
	wci_force_reroute		/* force an MH reroute */
} wrsm_wci_state_t;


typedef struct wrsm_inid2dnid_entry {
	int stripes;			/* 0 - unique wnodes: 1, 2, 3, or 4 */
	boolean_t changed;		/* different than the installed entry */
	wnode_bitmask_t wnode_bitmask;	/* wnodes this inid uses */
	wnodeid_t  wnode_list[WRSM_MAX_DNIDS]; /* wnodes this inid uses */
	cnode_bitmask_t cnode_routes;	/* cnodes this inid routes to */
	cnode_bitmask_t users;		/* cnodes using this route */
	cnode_bitmask_t reserved;	/* cnodes that plan to use this route */
} wrsm_inid2dnid_entry_t;

typedef struct wrsm_wnodeinfo {
	boolean_t valid;		/* valid wnode in this configuration */
	cnodeid_t cnodeid;		/* cnode this wnode routes to */
	cnode_bitmask_t interested;	/* cnodes that could use this route */
	cnode_bitmask_t users;		/* cnodes using this route */
	cnode_bitmask_t reserved;	/* cnodes that plan to use this route */
} wrsm_wnodeinfo_t;


/*
 * wci related information private to the NR
 */
typedef struct nrwci {
	wrsm_mh_reachable_t mh_reachable; /* wnode reachability */
	wrsm_wnodeinfo_t wnodeinfo[WRSM_MAX_WNODES]; /* wrsm_node, users */
	wrsm_inid2dnid_entry_t inid2dnid[WRSM_INID2DNID_ENTRIES];
					/* inid2dnid table settings */
	boolean_t using_inids;		/* current/new routes use inids */
	boolean_t reserved_inids;	/* reserved inids for 1-wnode routes */
	boolean_t inids_enabled;	/* inids enabled in the hardware */
	boolean_t need_hw_update;	/* # inids changed since HW write */
	wrsm_nc_strgrp_t *sg;		/* stripe group wci is in */
	cnode_bitmask_t cnode_retry;	/* cnodes should retry using this wci */
} nr_wci_t;


typedef struct wrsm_ncwci {
	wrsm_network_t *network;	/* RSM controller this belongs to */
	lcwci_handle_t lcwci;		/* LC's handle for this wci */
	wrsm_availability_t availability; /* configuration state */
	wrsm_wci_state_t reroute_state;	/* multi-hop rereroute needed? */
	wrsm_wci_data_t *config;	/* configuration data for wci links */
	nr_wci_t nr;				/* NR state */
	wrsm_mh_reroute_state_t *mh_state; 	/* MH state */
	boolean_t linksup;		/* used during install/enable */
	struct wrsm_ncwci *next;	/* next wci in controller */
} wrsm_ncwci_t;


struct wrsm_nc_strgrp {
	wrsm_network_t *network;	/* RSM controller this belongs to */
	wrsm_stripe_group_t *config;	/* config info */
	wrsm_availability_t availability; /* configuration state */
	int attached_wcis;		/* attached wcis in stripe group */
	boolean_t striping_on;		/* are wcis programmed to stripe? */
	wrsm_ncwci_t *wcis[WRSM_MAX_STRIPEWCIS]; /* wcis in stripe order */
	ncslice_bitmask_t wci_ncslices[WRSM_MAX_STRIPEWCIS];
					/* ncslices forced onto single wci */
	cnode_bitmask_t users;		/* cnodes using this stripe group */
	cnode_bitmask_t cnode_retry;	/* cnodes should try using this sg */
	struct wrsm_nc_strgrp *next;	/* next stripe group in ctlr */
};


typedef struct inidwnode_route {
	wrsm_ncwci_t *wci;
	enum {
		nid_route_inid,
		nid_route_wnode
	} route_type;
	wnodeid_t id;	/* inids and wnids are the same size */
} inidwnode_route_t;


typedef struct ncslice_route {
	wrsm_preferred_route_t *proute;	/* preferred route used */
	wrsm_nc_strgrp_t *sg;
	/*
	 * total # links used in ncslice route; combined striping provided
	 * by route map striping, inid2dnid striping, and wci striping
	 */
	int stripes;
	int nwcis;		/* number of wcis used */
	cnode_bitmask_t switches;	/* switches used by this route */
	/*
	 * the actual inid/wnode routes used; one per wci
	 */
	inidwnode_route_t wroutes[WRSM_MAX_STRIPEWCIS];
	boolean_t nostripe;	/* is wci striping disabled on this route? */
} ncslice_route_t;

/*
 * This state is used by ncslice_apply_routes to update ncslice routes for
 * each node.
 */
typedef enum {
	ncslice_use_current,		/* current route is still ok */
	ncslice_use_new_route,		/* use a new route */
	ncslice_remove_route,		/* remove route (to remove node) */
	ncslice_use_errloopback,	/* use errloopack route */
	ncslice_no_route		/* route has been removed */
} reroute_type_t;

#ifdef DEBUG
#define	ROUTEINFO_MSGSTRING(e)					\
	((e == ncslice_use_current) ? "use_current" :		\
	(e == ncslice_use_new_route) ? "use_new_route" :	\
	(e == ncslice_remove_route) ? "remove_route" :		\
	(e == ncslice_use_errloopback) ? "use_errloopback" :\
	(e == ncslice_no_route) ? "no_route" :	"unknown")
#endif

struct wrsm_node_routeinfo {
	wrsm_routing_policy_t *policy;	/* routing config policy */
	boolean_t check_route;		/* route needs to be checked */
	reroute_type_t route_state;	/* what routing should be applied? */
	ncslice_route_t current_route;	/* installed route */
	ncslice_route_t new_route;	/* newly chosen route */
	boolean_t direct_connect;	/* using a direct connect route */
	cnode_bitmask_t pt_provided;	/* cnodes allowed PT forwarding */
	int pt_route_counter;		/* incr when pt_provided changes */
	int pt_rerouting;		/* remote node is rerouting */
	cnode_bitmask_t pt_interested;	/* cnodes could use this PT route */
	cnode_bitmask_t pt_users;	/* cnodes using this PT route */
	wrsm_preferred_route_t *extended_routes; /* wci loopback routes */
	wrsm_preferred_route_t **orig_routes; /* policy supplied routes */
	int orig_nroutes;		/* count of policy supplied routes */
	uint32_t num_rte_changes;	/* count of route changes */
	kstat_t *wrsm_route_ksp;	/* pointer to route kstat */
};


typedef enum {
	pt_route_counter,
	pt_reroute_start,
	pt_reroute_finish
} pt_msgtype_t;

typedef struct wrsm_ptlist_msg {
	cnode_bitmask_t pt_provided;	/* cnodes allowed PT forwarding */
	int pt_route_counter;		/* incr when pt_provided changes */
	pt_msgtype_t pt_msgtype;	/* routechange, or rerouting? */
} wrsm_ptlist_msg_t;

#ifdef DEBUG
#define	PT_MSGSTRING(e)						\
	((e == pt_route_counter) ? "route_counter" :		\
	(e == pt_reroute_start) ? "reroute_start" :		\
	(e == pt_reroute_finish) ? "reroute_finish" :	"unknown")
#endif


/*
 * wcis and stripe groups are linked lists. wci list is ordered by
 * (safari) port, and stripe group list is ordered by stripe group id
 */
struct wrsm_nr {
	kmutex_t lock;
	wrsm_ncwci_t *wcis;		/* pointers to wcis */
	krwlock_t wcilist_rw;		/* protects wcis linked list */
	wrsm_nc_strgrp_t *sgs;		/* pointer to stripe groups */
	cnode_bitmask_t pt_provided;	/* passthru to these nodes is on */
	cnode_bitmask_t pt_retrylist;	/* need to send pt message to these */
	timeout_id_t pt_retry_timeout_id; /* timeout to resend pt messages */
	boolean_t need_pt_retry_timeout; /* resched timeout after suspend */
	int pt_route_counter;		/* incr when pt_provided changes */
	boolean_t init_cmmu;		/* cmmu init needed on new config */
	kthread_t *event_thread;
	kcondvar_t event_cv;		/* cv for event thread */
	boolean_t stop_event_thr;	/* flag telling event thread to exit */
	uint64_t event_thr_loopcnt;	/* number of time evt thr has looped */
	wrsm_nr_event_t *events;	/* events to be processed */
	wrsm_nr_event_t *last_event;	/* last event on queue */
	boolean_t wait_wcis_rerouting;	/* waiting for wci reroutes */
	boolean_t wait_eventdrain;	/* waiting for event drain */
	uint_t wait_pause;		/* waiting for evt thr to pause */
	boolean_t pausing;		/* evt thread is paused */
	kcondvar_t config_cv;		/* cv for config related events */
	timeout_id_t wcireroute_timeout_id; /* wci reroute timeout */
	boolean_t need_wcireroute_timeout; /* resched timeout after suspend */
	int waiting_linksup;		/* # wcis whose links aren't all up */
	int suspended;			/* controller is suspended */
	wrsm_ncowner_map_t ncslice_responder[WRSM_MAX_NCSLICES];
					/*
					 * which wci/stripe group responds
					 * to this ncslice
					 */
};

/*
 * counting wcis for kstats
 */
void wrsm_get_wci_num(wrsm_network_t *network, uint_t *num_wcis,
	uint_t *avail_wcis);

/*
 * register control interfaces
 */
void wrsm_nc_config_linksup(void *arg);

/*
 * NR interfaces
 */
int wrsm_nr_verifyconfig(wrsm_network_t *network, wrsm_controller_t *config,
    int attached_cnt, wci_ids_t *attached_wcis);
boolean_t wrsm_nr_initialconfig(wrsm_network_t *network, int attached_cnt,
    wci_ids_t *attached_wcis);
int wrsm_nr_replaceconfig(wrsm_network_t *network, wrsm_controller_t *config,
    int num_wcis, wci_ids_t *attached_wcis);
int wrsm_nr_cleanconfig(wrsm_network_t *network, int num_wcis,
    wci_ids_t *reroute_wcis);
int wrsm_nr_installconfig(wrsm_network_t *network);
int wrsm_nr_enableconfig(wrsm_network_t *network, int num_wcis,
    wci_ids_t *reroute_wcis);
void wrsm_nr_removeconfig(wrsm_network_t *network);
int wrsm_nr_attachwci(wrsm_network_t *network, safari_port_t saf_id,
    lcwci_handle_t lcwci, wrsm_controller_t *config, boolean_t init_cmmu,
    boolean_t pause_evt_thread);
int wrsm_nr_enablewci(wrsm_network_t *network, safari_port_t saf_id,
    boolean_t dr_attach);
int wrsm_nr_detachwci(wrsm_network_t *network, safari_port_t saf_id,
    boolean_t force);
void wrsm_nr_mhdirect(wrsm_ncwci_t *wci, wrsm_mh_reachable_t *reachable);
void wrsm_nr_mhreroute(wrsm_ncwci_t *wci, wrsm_mh_reachable_t *reachable);
int wrsm_nr_suspend(wrsm_network_t *network);
int wrsm_nr_resume(wrsm_network_t *network);

/*
 * MH interfaces
 */
void wrsm_mh_new_wci(wrsm_ncwci_t *wci);
void wrsm_mh_remove_wci(wrsm_ncwci_t *wci);
boolean_t wrsm_mh_reroute(wrsm_ncwci_t *wci);
int wrsm_mh_wnode_to_link(ncwci_handle_t ncwci, int wnodeid);
boolean_t wrsm_mh_link_to_wnode(ncwci_handle_t ncwci, int link, int wnodeid);

#ifdef	__cplusplus
}
#endif

#endif /* _WRSM_NC_IMPL_H */
